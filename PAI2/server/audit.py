"""
server/audit.py - Registro de auditoría JSON Lines encadenado con HMAC-SHA256
Proyecto: PAI-2 BYODSEC (Rol A)
"""

import hmac
import hashlib
import json
import time
from pathlib import Path
from typing import Optional

AUDIT_LOG_DIR = Path("evidence/logs")
AUDIT_LOG_PATH = AUDIT_LOG_DIR / "audit.jsonl"
GENESIS_HASH = "0" * 64

# Clave simétrica para firmar la auditoría (en producción se carga desde variable de entorno o almacén seguro)
AUDIT_HMAC_KEY = b"byodsec_audit_integrity_key_st20_2026!"


def get_last_hash(log_path: Path = AUDIT_LOG_PATH) -> str:
    """Lee la última línea del archivo para obtener el prev_hash."""
    if not log_path.exists() or log_path.stat().st_size == 0:
        return GENESIS_HASH

    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        if not lines:
            return GENESIS_HASH
        last_line = lines[-1].strip()
        if not last_line:
            return GENESIS_HASH
        try:
            record = json.loads(last_line)
            return record.get("hash", GENESIS_HASH)
        except json.JSONDecodeError:
            return GENESIS_HASH


def log_event(
    event: str,
    user: Optional[str] = None,
    ip: Optional[str] = None,
    cert_serial: Optional[str] = None,
    tls_version: Optional[str] = "TLSv1.3",
    cipher: Optional[str] = None,
    detail: Optional[str] = None,
    log_path: Path = AUDIT_LOG_PATH,
    key: bytes = AUDIT_HMAC_KEY,
) -> dict:
    """
    Registra un evento encadenado criptográficamente en audit.jsonl.
    Eventos válidos: ENROLL, CONNECT, TLS_FAIL, LOGIN_OK, LOGIN_FAIL, LOCKED, LOGOUT, DISCONNECT.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = get_last_hash(log_path)
    now = time.time()

    record_data = {
        "ts": now,
        "event": event,
        "user": user or "ANONYMOUS",
        "ip": ip or "127.0.0.1",
        "cert_serial": cert_serial,
        "tls_version": tls_version,
        "cipher": cipher,
        "detail": detail or "",
        "prev_hash": prev_hash,
    }

    # Serialización canónica para cálculo estricto del HMAC
    payload_to_sign = prev_hash + json.dumps(record_data, sort_keys=True)
    record_hash = hmac.new(key, payload_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    record_data["hash"] = record_hash

    # Guardar la línea en audit.jsonl
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record_data, sort_keys=True) + "\n")

    return record_data


if __name__ == "__main__":
    print("[*] Escribiendo eventos de prueba en la auditoría...")
    r1 = log_event("ENROLL", user="test_docente", detail="Certificado emitido con éxito.")
    print(f"    [1] Evento: {r1['event']}, Hash: {r1['hash'][:16]}...")

    r2 = log_event("LOGIN_OK", user="test_docente", ip="192.168.1.50", cipher="TLS_AES_256_GCM_SHA384")
    print(f"    [2] Evento: {r2['event']}, Prev: {r2['prev_hash'][:16]}..., Hash: {r2['hash'][:16]}...")