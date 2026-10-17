"""
server/verify_audit.py - Verificación de integridad de la cadena de auditoría
Proyecto: PAI-2 BYODSEC (Rol A)
"""

import hmac
import hashlib
import json
import sys
from pathlib import Path

from server.audit import AUDIT_LOG_PATH, AUDIT_HMAC_KEY, GENESIS_HASH


def verify_audit_log(log_path: Path = AUDIT_LOG_PATH, key: bytes = AUDIT_HMAC_KEY) -> bool:
    """Verifica la cadena de hashes de audit.jsonl línea por línea."""
    if not log_path.exists():
        print(f"[-] No se encontró el archivo de auditoría en: {log_path}")
        return False

    with open(log_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    if not lines:
        print("[!] El archivo de auditoría está vacío.")
        return True

    expected_prev_hash = GENESIS_HASH

    for idx, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            print(f"[-] Error en línea {idx}: JSON malformado.")
            return False

        current_hash = record.get("hash")
        prev_hash = record.get("prev_hash")

        # 1. Comprobar enlace con el hash anterior
        if prev_hash != expected_prev_hash:
            print(f"[-] Rotura de cadena en línea {idx}:")
            print(f"    Esperado prev_hash: {expected_prev_hash}")
            print(f"    Encontrado:         {prev_hash}")
            return False

        # 2. Recalcular el HMAC de la línea
        data_to_verify = dict(record)
        data_to_verify.pop("hash", None)

        payload = prev_hash + json.dumps(data_to_verify, sort_keys=True)
        computed_hash = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(current_hash, computed_hash):
            print(f"[-] Firma inválida en línea {idx} (contenido manipulado):")
            print(f"    Hash registrado: {current_hash}")
            print(f"    Hash calculado:  {computed_hash}")
            return False

        expected_prev_hash = current_hash

    print(f"[+] Integridad verificada con éxito: {len(lines)} registros auditados correctamente.")
    return True


if __name__ == "__main__":
    valid = verify_audit_log()
    sys.exit(0 if valid else 1)