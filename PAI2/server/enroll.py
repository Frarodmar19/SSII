"""
server/enroll.py - Lógica de enrolamiento de dispositivos y emisión de certificados
Proyecto: PAI-2 BYODSEC (Rol A)
"""

import datetime
import time
from pathlib import Path
from typing import Dict, Any, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

from server.db import DB_PATH, get_db_connection
from server.auth import authenticate_user
from pki.issue import sign_csr, CA_CERT_PATH


def extract_cn_from_csr(csr: x509.CertificateSigningRequest) -> str:
    """Extrae el Common Name del sujeto de una CSR."""
    cns = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cns:
        raise ValueError("La CSR no contiene un Common Name (CN).")
    return cns[0].value


def process_enrollment(
    data: Dict[str, Any],
    db_path: Path = DB_PATH,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Procesa la solicitud de enrolamiento.
    Entrada esperada en data:
        - username (str)
        - password (str)
        - role (str)
        - csr_pem (str)

    Retorna: (éxito: bool, respuesta: dict)
    """
    username = data.get("username")
    password = data.get("password")
    role_requested = data.get("role")
    csr_pem_str = data.get("csr_pem")

    if not all([username, password, csr_pem_str]):
        return False, {"status": "error", "code": "BAD_REQUEST", "detail": "Faltan campos obligatorios."}

    # 1. Autenticar credenciales del usuario
    ok, auth_detail = authenticate_user(username, password, db_path=db_path)
    if not ok:
        return False, {"status": "error", "code": auth_detail, "detail": "Credenciales inválidas o cuenta bloqueada."}

    # 2. Parsear y verificar la CSR recibida
    try:
        csr_bytes = csr_pem_str.encode("utf-8") if isinstance(csr_pem_str, str) else csr_pem_str
        csr = x509.load_pem_x509_csr(csr_bytes)
        if not csr.is_signature_valid:
            return False, {"status": "error", "code": "INVALID_CSR", "detail": "La firma de la CSR no es válida."}
        
        csr_cn = extract_cn_from_csr(csr)
    except Exception as e:
        return False, {"status": "error", "code": "MALFORMED_CSR", "detail": str(e)}

    # 3. Comprobar que el CN coincide estrictamente con el username autenticado
    if csr_cn != username:
        return False, {
            "status": "error",
            "code": "CERT_MISMATCH",
            "detail": f"El CN de la CSR ('{csr_cn}') no coincide con el usuario ('{username}')."
        }

    # 4. Firmar el certificado usando la CA raíz
    try:
        cert = sign_csr(csr_bytes, valid_days=180)
    except Exception as e:
        return False, {"status": "error", "code": "SIGNING_FAILED", "detail": f"Error firmando el certificado: {e}"}

    # 5. Extraer metadatos para la base de datos (compatible con versiones nuevas y anteriores)
    serial_str = hex(cert.serial_number)
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    pubkey_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    try:
        not_before = cert.not_valid_before_utc.timestamp()
        not_after = cert.not_valid_after_utc.timestamp()
    except AttributeError:
        # Fallback para versiones previas de cryptography
        not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc).timestamp()
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc).timestamp()

    # 6. Registrar el certificado en SQLite
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO certificates (
                serial, username, fingerprint_sha256, pubkey_pem,
                not_before, not_after, status, revoked_at, reason
            ) VALUES (?, ?, ?, ?, ?, ?, 'valid', NULL, NULL)
            """,
            (serial_str, username, fingerprint, pubkey_pem, not_before, not_after),
        )
        conn.commit()
    except Exception as e:
        conn.close()
        return False, {"status": "error", "code": "DB_ERROR", "detail": f"Error guardando certificado: {e}"}
    finally:
        conn.close()

    # 7. Leer la CA raíz para adjuntarla
    with open(CA_CERT_PATH, "r", encoding="utf-8") as f:
        ca_pem = f.read()

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    return True, {
        "status": "ok",
        "serial": serial_str,
        "cert_pem": cert_pem,
        "ca_pem": ca_pem,
    }


if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric import ec

    print("[*] Generando par de claves y CSR para 'test_docente'...")
    client_key = ec.generate_private_key(ec.SECP384R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "test_docente"),
        ]))
        .sign(client_key, hashes.SHA384())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    payload = {
        "username": "test_docente",
        "password": "ClaveSegura2026!",
        "role": "PDI",
        "csr_pem": csr_pem,
    }

    print("[*] Procesando enrolamiento...")
    success, res = process_enrollment(payload)
    print(f"    Resultado: {success}")
    if success:
        print(f"    Serial asignado: {res['serial']}")
        print("    Certificado emitido con éxito.")
    else:
        print(f"    Error: {res}")