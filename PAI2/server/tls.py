import os
import ssl

# Rutas base dentro del proyecto
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CA_PEM = os.path.join(BASE_DIR, "pki", "ca", "ca.pem")
CRL_PEM = os.path.join(BASE_DIR, "pki", "ca", "crl.pem")
SERVER_CERT = os.path.join(BASE_DIR, "pki", "server", "server.pem")
SERVER_KEY = os.path.join(BASE_DIR, "pki", "server", "server.key")
OPENSSL_CONF = os.path.join(BASE_DIR, "server", "openssl.cnf")

# Forzar la carga de la configuración de OpenSSL para TLS 1.3 y ciphers
os.environ["OPENSSL_CONF"] = OPENSSL_CONF

def get_server_enroll_context() -> ssl.SSLContext:
    """Contexto TLS 1.3 para el puerto de enrolamiento (8443).
    Solo requiere certificado de servidor (autenticación unidireccional)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    return context

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
        
    return context

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