"""
tests/test_audit.py - Validación de la cadena HMAC en audit.jsonl (RS4)
"""

import json
from server.audit import log_event
from server.verify_audit import verify_audit_log


def test_audit_integrity():
    log_event("CONNECT", user="pdi_001", detail="Conexión de prueba para test")
    log_event("DISCONNECT", user="pdi_001", detail="Desconexión de prueba")

    assert verify_audit_log() is True


def test_audit_tampering_detection(tmp_path):
    """Comprueba que alterar un registro rompe la verificación HMAC."""
    test_log = tmp_path / "tampered_audit.jsonl"

    log_event("LOGIN_OK", user="pdi_002", log_path=test_log)
    log_event("LOGOUT", user="pdi_002", log_path=test_log)

    assert verify_audit_log(log_path=test_log) is True

    # Manipular el usuario del primer registro
    with open(test_log, "r", encoding="utf-8") as f:
        lines = f.readlines()

    record = json.loads(lines[0])
    record["user"] = "atacante_mitm"
    lines[0] = json.dumps(record, sort_keys=True) + "\n"

    with open(test_log, "w", encoding="utf-8") as f:
        f.writelines(lines)

    assert verify_audit_log(log_path=test_log) is False