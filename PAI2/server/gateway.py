import os
import sys

# RS2: OpenSSL lee OPENSSL_CONF al importar `ssl` (asyncio lo importa), así que se fija
# antes de cualquier otro import. Sin esto se aceptaría TLS_AES_128_GCM_SHA256.
os.environ.setdefault(
    "OPENSSL_CONF",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "openssl.cnf"),
)

import asyncio  # noqa: E402
import json  # noqa: E402
import ssl  # noqa: E402
import struct  # noqa: E402

# Asegurar que se encuentra la ruta del proyecto
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.tls import CRL_PEM, get_server_enroll_context, get_server_gateway_context
from server.auth import authenticate_user
from server.audit import log_event
from server.enroll import process_enrollment

# Tabla de sesiones activas en memoria
ACTIVE_SESSIONS = {}

# Puertos y dirección configurables (Docker / pruebas); por defecto los del contrato
BIND_HOST = os.environ.get("GATEWAY_BIND", "0.0.0.0")
ENROLL_PORT = int(os.environ.get("GATEWAY_ENROLL_PORT", "8443"))
GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "9443"))
HANDSHAKE_TIMEOUT = float(os.environ.get("GATEWAY_HANDSHAKE_TIMEOUT", "30"))

async def read_frame(reader: asyncio.StreamReader) -> dict:
    """Lee una trama de 4 bytes (longitud big-endian) + JSON UTF-8 (máx 64KB)."""
    header = await reader.readexactly(4)
    length = struct.unpack("!I", header)[0]
    if length > 65536:
        raise ValueError("Trama excede el tamaño máximo permitido de 64 KB")
    data = await reader.readexactly(length)
    return json.loads(data.decode("utf-8"))

async def write_frame(writer: asyncio.StreamWriter, response: dict):
    """Envía una respuesta estructurada en trama de 4 bytes + JSON."""
    payload = json.dumps(response).encode("utf-8")
    header = struct.pack("!I", len(payload))
    writer.write(header + payload)
    await writer.drain()

# --- Manejador del Puerto 8443 (Enrolamiento) ---
async def handle_enroll_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "unknown"
    try:
        frame = await read_frame(reader)
        action = frame.get("action")
        
        if action == "ENROLL":
            # Empaquetar los datos para pasárselos al diccionario que espera el Rol A
            enroll_payload = {
                "username": frame.get("username"),
                "password": frame.get("password"),
                "role": frame.get("role", "INV"),
                "csr_pem": frame.get("csr_pem")
            }
            
            # Llamada correcta a la función del Rol A
            success, response = process_enrollment(enroll_payload)
            
            if success:
                log_event("ENROLL", user=frame.get("username"), ip=ip, detail="Enrolamiento exitoso")
            else:
                log_event("ENROLL", user=frame.get("username"), ip=ip, detail=f"Fallo de enrolamiento: {response.get('code')}")
                
            await write_frame(writer, response)
    except Exception as e:
        print(f"[Error 8443] {e}")
    finally:
        writer.close()
        await writer.wait_closed()

# --- Manejador del Puerto 9443 (Canal Seguro mTLS + Gateway) ---
async def handle_gateway_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "unknown"
    
    # Extraer información del certificado del cliente presentado en el handshake mTLS
    ssl_sock = writer.get_extra_info("ssl_object")
    cert_serial = "unknown"
    cert_cn = None
    tls_version = ssl_sock.version() if ssl_sock else "TLSv1.3"
    cipher_info = ssl_sock.cipher() if ssl_sock else ("unknown", "unknown", 0)
    cipher_name = cipher_info[0] if cipher_info else "unknown"

    if ssl_sock:
        peercert = ssl_sock.getpeercert()
        # Extraer el número de serie
        serial_number = peercert.get("serialNumber")
        if serial_number:
            cert_serial = str(serial_number)
        
        # Extraer el Common Name (CN) del subject
        subject = peercert.get("subject", [])
        for sub in subject:
            for key, val in sub:
                if key == "commonName":
                    cert_cn = val

    session_id = None
    authenticated_user = None

    try:
        while True:
            try:
                frame = await read_frame(reader)
            except asyncio.IncompleteReadError:
                break
                
            action = frame.get("action")
            
            if action == "LOGIN":
                username = frame.get("username")
                password = frame.get("password")
                
                # Verificación estricta: El CN del certificado mTLS debe coincidir con el usuario del login
                if cert_cn and cert_cn != username:
                    response = {"status": "error", "code": "CERT_MISMATCH"}
                    log_event("TLS_FAIL", user=username, ip=ip, cert_serial=cert_serial, tls_version=tls_version, cipher=cipher_name, detail="CN de certificado no coincide con usuario")
                    await write_frame(writer, response)
                    break
                
                # Validar credenciales contra la base de datos (Rol A: auth.py)
                # scrypt (~50 ms, 16 MiB) se ejecuta en un hilo para no bloquear el bucle asyncio:
                # en línea, 300 logins simultáneos se serializaban y retrasaban todos los handshakes.
                auth_success, err_code = await asyncio.to_thread(authenticate_user, username, password)
                
                if auth_success:
                    session_id = f"sess_{username}_{os.urandom(4).hex()}"
                    authenticated_user = username
                    ACTIVE_SESSIONS[session_id] = username
                    
                    response = {"status": "ok", "session_id": session_id}
                    log_event("LOGIN_OK", user=username, ip=ip, cert_serial=cert_serial, tls_version=tls_version, cipher=cipher_name, detail="Login exitoso en dos capas")
                else:
                    response = {"status": "error", "code": err_code}
                    event_type = "LOCKED" if err_code == "LOCKED" else "LOGIN_FAIL"
                    log_event(event_type, user=username, ip=ip, cert_serial=cert_serial, tls_version=tls_version, cipher=cipher_name, detail=f"Fallo de login: {err_code}")
                
                await write_frame(writer, response)
                
            elif action == "MSG":
                sess_id = frame.get("session_id")
                body = frame.get("body")
                
                if not sess_id or sess_id not in ACTIVE_SESSIONS:
                    await write_frame(writer, {"status": "error", "code": "UNAUTHORIZED_SESSION"})
                    continue
                    
                user = ACTIVE_SESSIONS[sess_id]
                print(f"[MSG] Recibido de {user}: {body}")
                await write_frame(writer, {"status": "ok", "echo": body, "info": "Mensaje procesado de forma segura por el Gateway"})
                
            elif action == "LOGOUT":
                sess_id = frame.get("session_id")
                if sess_id in ACTIVE_SESSIONS:
                    user = ACTIVE_SESSIONS.pop(sess_id)
                    log_event("LOGOUT", user=user, ip=ip, cert_serial=cert_serial, detail="Cierre de sesión solicitado")
                
                # Responder e iniciar cierre seguro con close_notify
                await write_frame(writer, {"status": "ok", "message": "bye"})
                break
            else:
                await write_frame(writer, {"status": "error", "code": "BAD_FRAME"})
                break
                
    except Exception as e:
        print(f"[Error 9443] {e}")
    finally:
        if authenticated_user:
            log_event("DISCONNECT", user=authenticated_user, ip=ip, cert_serial=cert_serial, detail="Desconexión del socket")
        writer.close()
        await writer.wait_closed()

class ReloadingContext:
    """Contexto TLS que se reconstruye cuando cambia crl.pem.

    load_verify_locations() copia la CRL al crear el contexto, así que sin esto un
    certificado revocado con pki/revoke.py seguía entrando hasta reiniciar el gateway.
    """

    def __init__(self, factory, watched: str):
        self.factory = factory
        self.watched = watched
        self._mtime = self._stat()
        self.context = factory()

    def _stat(self):
        try:
            return os.stat(self.watched).st_mtime_ns
        except OSError:
            return None

    def get(self) -> ssl.SSLContext:
        mtime = self._stat()
        if mtime != self._mtime:
            self.context = self.factory()
            self._mtime = mtime
            print("[*] CRL modificada: contexto mTLS recargado")
        return self.context


def tls_guard(handler, context, port: int):
    """Hace el handshake TLS explícitamente para poder auditar los rechazos (RS4).

    Con start_server(ssl=...) asyncio descarta en silencio los handshakes fallidos
    (sin certificado, certificado revocado o de otra CA, TLS 1.2, suite no permitida),
    así que no quedaba rastro de los intentos de suplantación.
    """
    async def guarded(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "unknown"
        try:
            ctx = context.get() if isinstance(context, ReloadingContext) else context
            await asyncio.wait_for(writer.start_tls(ctx), HANDSHAKE_TIMEOUT)
        except (ssl.SSLError, ConnectionError, asyncio.TimeoutError, OSError) as e:
            reason = getattr(e, "reason", None) or type(e).__name__
            log_event("TLS_FAIL", ip=ip, tls_version=None, detail=f"Handshake rechazado en :{port}: {reason}")
            writer.transport.abort()
            return
        await handler(reader, writer)
    return guarded


async def main():
    enroll_ctx = get_server_enroll_context()
    gateway_ctx = ReloadingContext(get_server_gateway_context, CRL_PEM)

    server_enroll = await asyncio.start_server(
        tls_guard(handle_enroll_connection, enroll_ctx, ENROLL_PORT), BIND_HOST, ENROLL_PORT, backlog=1024)
    server_gateway = await asyncio.start_server(
        tls_guard(handle_gateway_connection, gateway_ctx, GATEWAY_PORT), BIND_HOST, GATEWAY_PORT, backlog=1024)

    print("[*] Gateway TLS 1.3 arrancado:")
    print(f"    - Puerto {ENROLL_PORT}: Enrolamiento activo")
    print(f"    - Puerto {GATEWAY_PORT}: Canal seguro mTLS activo")
    
    async with server_enroll, server_gateway:
        await asyncio.gather(server_enroll.serve_forever(), server_gateway.serve_forever())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Servidor detenido por el operador.")