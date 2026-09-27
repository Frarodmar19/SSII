from datetime import datetime, timedelta
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Instancia del hasher usando Argon2id (parámetros seguros)
ph = PasswordHasher()

# Hash 'dummy' precalculado para mitigar timing attacks si el usuario no existe
DUMMY_HASH = ph.hash("DummyPassword123!")


def hash_password(password: str) -> str:
    """Genera un hash Argon2id con salt aleatorio automático."""
    return ph.hash(password)


def verify_password(password_hash: str, password_provided: str) -> bool:
    """Verifica una contraseña contra un hash Argon2id."""
    try:
        return ph.verify(password_hash, password_provided)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def generate_session_key_256bit() -> str:
    """Genera una clave de sesión de 256 bits (32 bytes) usando un PRNG criptográfico."""
    return secrets.token_hex(32)


def generate_session_token() -> str:
    """Genera un token de sesión seguro."""
    return secrets.token_hex(16)


def safe_compare(val1: str, val2: str) -> bool:
    """Comparación en tiempo constante usando secrets.compare_digest (RS4)."""
    return secrets.compare_digest(val1, val2)