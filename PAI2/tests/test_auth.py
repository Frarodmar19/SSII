"""
tests/test_auth.py - Validación de scrypt y bloqueo tras 5 intentos (RF2)
"""

import time
import pytest
from server.auth import register_user, authenticate_user, MAX_FAILED_ATTEMPTS
from server.db import get_db_connection, DB_PATH


def test_user_registration_and_auth():
    test_u = f"test_auth_{int(time.time())}"
    test_p = "ClaveValida1234!"

    register_user(test_u, test_p, "PAS")

    # Autenticación correcta
    ok, role = authenticate_user(test_u, test_p)
    assert ok is True
    assert role == "PAS"

    # Contraseña incorrecta
    ok_fail, detail = authenticate_user(test_u, "ClaveErronea")
    assert ok_fail is False
    assert detail == "AUTH_FAILED"


def test_account_lockout_after_max_attempts():
    test_u = f"test_lock_{int(time.time())}"
    test_p = "Clave1234!"

    # Limpiar o registrar usuario nuevo para garantizar 0 intentos previos
    register_user(test_u, test_p, "INV")

    # 5 intentos fallidos consecutivos
    for i in range(1, MAX_FAILED_ATTEMPTS + 1):
        ok, detail = authenticate_user(test_u, f"Fallo_{i}")
        assert ok is False
        if i < MAX_FAILED_ATTEMPTS:
            assert detail == "AUTH_FAILED"
        else:
            assert detail == "LOCKED"

    # Sexto intento con password correcto: debe seguir bloqueado
    ok_locked, detail_locked = authenticate_user(test_u, test_p)
    assert ok_locked is False
    assert detail_locked == "LOCKED"