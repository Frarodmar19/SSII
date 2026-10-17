"""
pki/revoke.py - Revocación de certificados y actualización de la CRL
"""

import datetime
import sqlite3
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID

from pki.crl import generate_crl

DB_PATH = Path("server/byodsec.db")


def get_crl_reason(reason_str: str) -> x509.ReasonFlags:
    """Mapea una cadena de texto al flag de motivo de revocación RFC 5280."""
    mapping = {
        "unspecified": x509.ReasonFlags.unspecified,
        "key_compromise": x509.ReasonFlags.key_compromise,
        "ca_compromise": x509.ReasonFlags.ca_compromise,
        "affiliation_changed": x509.ReasonFlags.affiliation_changed,
        "superseded": x509.ReasonFlags.superseded,
        "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
        "certificate_hold": x509.ReasonFlags.certificate_hold,
    }
    return mapping.get(reason_str.lower(), x509.ReasonFlags.unspecified)


def revoke_certificate(
    serial_str: str,
    reason: str = "key_compromise",
    db_path: Path = DB_PATH,
) -> bool:
    """
    Revoca un certificado en la BD y actualiza crl.pem.
    El serial puede recibirse en formato decimal o hexadecimal.
    """
    if not db_path.exists():
        print(f"[-] Error: Base de datos no encontrada en {db_path}")
        return False

    now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()

    # 1. Actualizar el estado en SQLite
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT serial, username, status FROM certificates WHERE serial = ?",
        (serial_str,),
    )
    row = cursor.fetchone()

    if not row:
        print(f"[-] No se encontró el certificado con serial: {serial_str}")
        conn.close()
        return False

    _, username, current_status = row
    if current_status == "revoked":
        print(f"[*] El certificado {serial_str} (usuario: {username}) ya estaba revocado.")
        conn.close()
        return True

    # Actualizar únicamente el estado y campos permitidos (los triggers impiden tocar pubkey/fingerprint)
    cursor.execute(
        """
        UPDATE certificates
        SET status = 'revoked', revoked_at = ?, reason = ?
        WHERE serial = ?
        """,
        (now_ts, reason, serial_str),
    )
    conn.commit()
    print(f"[+] Certificado {serial_str} ({username}) marcado como REVOCADO en la BD.")

    # 2. Obtener todos los certificados revocados para reconstruir crl.pem
    cursor.execute(
        "SELECT serial, revoked_at, reason FROM certificates WHERE status = 'revoked'"
    )
    revoked_rows = cursor.fetchall()
    conn.close()

    revoked_list = []
    for s_str, r_ts, r_reason in revoked_rows:
        try:
            # Los seriales pueden guardarse en formato int o hex string
            s_int = int(s_str, 16) if s_str.startswith("0x") else int(s_str)
        except ValueError:
            s_int = int(s_str, 16)

        rev_date = datetime.datetime.fromtimestamp(r_ts, tz=datetime.timezone.utc)
        flag = get_crl_reason(r_reason or "unspecified")
        revoked_list.append((s_int, rev_date, flag))

    # 3. Regenerar y firmar la CRL v2
    generate_crl(revoked_list)
    print(f"[+] Lista CRL actualizada con éxito.")
    return True


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python -m pki.revoke <serial_number> [motivo]")
        sys.exit(1)

    target_serial = sys.argv[1]
    target_reason = sys.argv[2] if len(sys.argv) > 2 else "key_compromise"
    revoke_certificate(target_serial, target_reason)