import hashlib
import hmac
import json
from datetime import datetime, timedelta
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# ROL A


# Instancia del hasher usando Argon2id (parámetros seguros)
ph = PasswordHasher()

# Hash 'dummy' precalculado para mitigar timing attacks si el usuario no existe
DUMMY_HASH = ph.hash("DummyPassword123!")


#Hashing y verificacion de contraseñas
# genera hash incluyendo parametros criptografios, la salt y firma diigest de Argon2id
def hash_password(password: str) -> str:
    """Genera un hash Argon2id con salt aleatorio automático."""
    return ph.hash(password)


#Compara la contraseña que envia el usuario con el hash almacenado
def verify_password(password_hash: str, password_provided: str) -> bool:
    """Verifica una contraseña contra un hash Argon2id."""
    try:
        return ph.verify(password_hash, password_provided)
    except VerifyMismatchError:
        return False
    except Exception:
        return False

# Generacion de claves criptográficas y tokens
def generate_session_key_256bit() -> str:
    """Genera una clave de sesión de 256 bits (32 bytes) usando un PRNG criptográfico."""
    return secrets.token_hex(32)


def generate_session_token() -> str:
    """Genera un token de sesión seguro."""
    return secrets.token_hex(16)

#Comparacion segura en tiempo constante (requisito RS4)
def safe_compare(val1: str, val2: str) -> bool:
    """Comparación en tiempo constante usando secrets.compare_digest (RS4)."""
    return secrets.compare_digest(val1, val2)


# ROL B: INTEGRIDAD DE MENSAJES Y FIRMA HMAC-SHA256 (RS2 / RS3 / RS4)


def generar_clave_sesion():
    """
    RS2: Genera una clave simétrica K de 256 bits (32 bytes) en crudo (bytes).
    Utiliza el PRNG del sistema operativo (CSPRNG).
    """
    return secrets.token_bytes(32)


def construir_mensaje_a_firmar(nonce, timestamp, payload):
    """
    RS2: Genera la cadena canónica que une los metadatos de sesión y los datos transferidos.
    Estructura del buffer: Nonce || Timestamp || Canonical_JSON_Payload
    - sort_keys=True: garantiza el mismo orden de claves lexicográfico en emisor y receptor.
    - separators=(',', ':'): elimina espacios en blanco para asegurar consistencia byte a byte.
    """
    payload_canonico = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    mensaje_plano = f"{nonce}{timestamp}{payload_canonico}"
    return mensaje_plano.encode("utf-8")


def firmar_mensaje(session_key, nonce, timestamp, payload):
    """
    RS2: Calcula el código de autenticación de mensajes HMAC-SHA256.
    Asegura la autenticidad e integridad del mensaje frente a alteraciones en tránsito (MitM).
    Devuelve el digest en formato hexadecimal (64 caracteres en minúsculas).
    """
    if isinstance(session_key, str):
        session_key = bytes.fromhex(session_key)

    mensaje_bytes = construir_mensaje_a_firmar(nonce, timestamp, payload)
    firma = hmac.new(session_key, mensaje_bytes, hashlib.sha256).hexdigest()
    return firma


def verificar_firma(session_key, nonce, timestamp, payload, firma_recibida):
    """
    RS2 / RS4: Verifica la integridad del payload calculando el HMAC esperado
    y comparándolo en tiempo constante mediante secrets.compare_digest().
    Previene activamente ataques de canal lateral basados en análisis de tiempos (Timing Attacks).
    """
    firma_esperada = firmar_mensaje(session_key, nonce, timestamp, payload)
    return secrets.compare_digest(firma_esperada, firma_recibida)