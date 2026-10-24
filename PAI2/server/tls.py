import os
import ssl

# Rutas base dentro del proyecto
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CA_PEM = os.path.join(BASE_DIR, "pki", "ca", "ca.pem")
CRL_PEM = os.path.join(BASE_DIR, "pki", "ca", "crl.pem")
SERVER_CERT = os.path.join(BASE_DIR, "pki", "server", "server.pem")
SERVER_KEY = os.path.join(BASE_DIR, "pki", "server", "server.key")
OPENSSL_CONF = os.path.join(BASE_DIR, "server", "openssl.cnf")

# OpenSSL lee OPENSSL_CONF al importar `ssl`; aquí ya es tarde para el proceso actual,
# pero se deja para procesos hijos. gateway.py la fija antes de cualquier import.
os.environ.setdefault("OPENSSL_CONF", OPENSSL_CONF)

# Suites TLS 1.3 permitidas (RS2): AEAD de 256 bits; PFS la aporta el (EC)DHE de TLS 1.3
ALLOWED_TLS13_SUITES = {"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}


def enforce_tls13_policy(context: ssl.SSLContext) -> ssl.SSLContext:
    """Falla en cerrado si OpenSSL no ha cargado openssl.cnf y ofrecería otras suites TLS 1.3."""
    offered = {c["name"] for c in context.get_ciphers() if c.get("protocol") == "TLSv1.3"}
    extra = offered - ALLOWED_TLS13_SUITES
    if extra:
        raise RuntimeError(
            f"Política RS2 no aplicada: OpenSSL ofrece {sorted(extra)}. "
            f"Exporta OPENSSL_CONF={OPENSSL_CONF} antes de arrancar Python."
        )
    return context

def get_server_enroll_context() -> ssl.SSLContext:
    """Contexto TLS 1.3 para el puerto de enrolamiento (8443).
    Solo requiere certificado de servidor (autenticación unidireccional)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    return enforce_tls13_policy(context)

def get_server_gateway_context() -> ssl.SSLContext:
    """Contexto TLS 1.3 para el canal seguro principal (9443).
    Requiere mTLS estricto (CERT_REQUIRED), validación de CRL y desactivación de tickets (PFS)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Cargar certificado y clave del servidor
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    
    # Configurar mTLS estricto exigiendo certificado de cliente
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=CA_PEM)
    
    # Cargar CRL para rechazar certificados revocados y activar comprobación en hoja
    try:
        context.load_verify_locations(cafile=CRL_PEM)
        context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF
    except Exception as e:
        print(f"[WARN] No se pudo cargar la CRL o configurar su verificación: {e}")
        
    # Desactivar reanudación por sesión (tickets) para garantizar Perfect Forward Secrecy estricta
    if hasattr(context, "num_tickets"):
        context.num_tickets = 0
    context.options |= ssl.OP_NO_TICKET

    return enforce_tls13_policy(context)

def get_client_context(client_cert: str, client_key: str) -> ssl.SSLContext:
    """Contexto TLS 1.3 para el cliente, cargando su certificado y clave (mTLS)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=CA_PEM)
    context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    return context

def get_client_enroll_context() -> ssl.SSLContext:
    """Contexto TLS 1.3 para el cliente en el enrolamiento (solo confía en la CA raíz)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=CA_PEM)
    return context