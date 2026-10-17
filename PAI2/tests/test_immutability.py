"""
tests/test_immutability.py - Validación de los triggers de inmutabilidad (RF1)
"""

import sqlite3
import pytest
from pathlib import Path
from server.db import get_db_connection, DB_PATH


def test_prevent_cert_identity_update():
    conn = get_db_connection(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT serial, username FROM certificates LIMIT 1")
    row = cursor.fetchone()
    assert row is not None, "Debe existir al menos un certificado para la prueba."
    serial, username = row

    # Intento 1: Modificar usuario vinculado -> Debe abortar
    with pytest.raises(sqlite3.DatabaseError) as exc_info:
        cursor.execute(
            "UPDATE certificates SET username = 'hacker' WHERE serial = ?",
            (serial,),
        )
    assert "Inmutabilidad violada" in str(exc_info.value)

    # Intento 2: Modificar huella sha256 -> Debe abortar
    with pytest.raises(sqlite3.DatabaseError) as exc_info:
        cursor.execute(
            "UPDATE certificates SET fingerprint_sha256 = '000000000000' WHERE serial = ?",
            (serial,),
        )
    assert "Inmutabilidad violada" in str(exc_info.value)

    conn.close()


def test_prevent_cert_delete():
    conn = get_db_connection(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT serial FROM certificates LIMIT 1")
    row = cursor.fetchone()
    assert row is not None
    serial = row[0]

    # Intento 3: Eliminar certificado -> Debe abortar
    with pytest.raises(sqlite3.DatabaseError) as exc_info:
        cursor.execute("DELETE FROM certificates WHERE serial = ?", (serial,))
    assert "Inmutabilidad violada" in str(exc_info.value)

    conn.close()


def test_allow_revocation_update():
    """Comprueba que actualizar el estado a 'revoked' sí esté permitido."""
    conn = get_db_connection(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT serial FROM certificates WHERE status = 'valid' LIMIT 1")
    row = cursor.fetchone()
    if row:
        serial = row[0]
        cursor.execute(
            "UPDATE certificates SET status = 'revoked', reason = 'test' WHERE serial = ?",
            (serial,),
        )
        conn.commit()

        cursor.execute("SELECT status FROM certificates WHERE serial = ?", (serial,))
        new_status = cursor.fetchone()[0]
        assert new_status == "revoked"

    conn.close()