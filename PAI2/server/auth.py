"""
server/auth.py - Autenticación con scrypt y control de bloqueo
Proyecto: PAI-2 BYODSEC (Rol A)
"""

import hashlib
import hmac
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Optional, Tuple

from server.db import DB_PATH, get_db_connection

# Parámetros recomendados para scrypt (RFC 7914)
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SEC = 900  # 15 minutos de bloqueo


def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """
    Deriva la clave usando hashlib.scrypt.
    Retorna una tupla: (hash_hex, salt_hex)
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    
    pwd_bytes = password.encode("utf-8")
    derived = hashlib.scrypt(
        pwd_bytes,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=0,
        dklen=64,
    )
    return derived.hex(), salt.hex()


def verify_password(password: str, stored_hash_hex: str, salt_hex: str) -> bool:
    """Verifica la contraseña contra el hash almacenado en tiempo constante."""
    salt = bytes.fromhex(salt_hex)
    pwd_bytes = password.encode("utf-8")
    derived = hashlib.scrypt(
        pwd_bytes,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=0,
        dklen=64,
    )
    # Comparación en tiempo constante para mitigar ataques de temporización
    return hmac.compare_digest(derived.hex(), stored_hash_hex)


def register_user(
    username: str,
    password: str,
    role: str,
    db_path: Path = DB_PATH,
) -> bool:
    """Registra un nuevo usuario en la base de datos con su sal y hash scrypt."""
    if role not in ("PDI", "PAS", "INV"):
        raise ValueError("Rol no válido. Debe ser 'PDI', 'PAS' o 'INV'.")

    pwd_hash, salt = hash_password(password)
    now = time.time()

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO users (username, role, pwd_hash, salt, failed_attempts, locked_until, created_at)
            VALUES (?, ?, ?, ?, 0, 0, ?)
            """,
            (username, role, pwd_hash, salt, now),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def authenticate_user(
    username: str,
    password: str,
    db_path: Path = DB_PATH,
) -> Tuple[bool, str]:
    """
    Autentica a un usuario comprobando bloqueo e intentos fallidos.
    Retorna: (éxito: bool, mensaje_o_rol: str)
    """
    now = time.time()
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT role, pwd_hash, salt, failed_attempts, locked_until
        FROM users WHERE username = ?
        """,
        (username,),
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        return False, "USER_NOT_FOUND"

    role, stored_hash, salt_hex, failed_attempts, locked_until = row

    # 1. Comprobar si la cuenta está bloqueada
    if locked_until > now:
        conn.close()
        return False, "LOCKED"

    # 2. Verificar la contraseña
    if verify_password(password, stored_hash, salt_hex):
        # Contraseña correcta: resetear contador de intentos y bloqueo
        cursor.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE username = ?",
            (username,),
        )
        conn.commit()
        conn.close()
        return True, role
    else:
        # Contraseña incorrecta: incrementar contador
        new_attempts = failed_attempts + 1
        new_locked_until = 0
        status_msg = "AUTH_FAILED"

        if new_attempts >= MAX_FAILED_ATTEMPTS:
            new_locked_until = now + LOCKOUT_DURATION_SEC
            status_msg = "LOCKED"

        cursor.execute(
            """
            UPDATE users
            SET failed_attempts = ?, locked_until = ?
            WHERE username = ?
            """,
            (new_attempts, new_locked_until, username),
        )
        conn.commit()
        conn.close()
        return False, status_msg


if __name__ == "__main__":
    # Prueba rápida del módulo
    test_user = "test_docente"
    test_pass = "ClaveSegura2026!"
    
    print("[*] Registrando usuario de prueba...")
    if register_user(test_user, test_pass, "PDI"):
        print("[+] Usuario registrado con éxito.")
    else:
        print("[*] El usuario ya existía.")

    print("[*] Probando autenticación válida...")
    ok, res = authenticate_user(test_user, test_pass)
    print(f"    Resultado: ok={ok}, rol={res}")

    print("[*] Probando contraseña errónea...")
    ok, res = authenticate_user(test_user, "ClaveIncorrecta")
    print(f"    Resultado: ok={ok}, detalle={res}")