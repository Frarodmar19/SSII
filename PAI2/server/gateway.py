import asyncio
import json
import struct
import os
import sys

# Asegurar que se encuentra la ruta del proyecto
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.tls import get_server_enroll_context, get_server_gateway_context
from server.auth import authenticate_user
from server.audit import log_event
from server.enroll import process_enrollment

# Tabla de sesiones activas en memoria
ACTIVE_SESSIONS = {}

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
                auth_success, err_code = authenticate_user(username, password)
                
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

async def main():
    enroll_ctx = get_server_enroll_context()
    gateway_ctx = get_server_gateway_context()
    
    server_enroll = await asyncio.start_server(handle_enroll_connection, "0.0.0.0", 8443, ssl=enroll_ctx)
    server_gateway = await asyncio.start_server(handle_gateway_connection, "0.0.0.0", 9443, ssl=gateway_ctx)
    
    print("[*] Gateway TLS 1.3 arrancado:")
    print("    - Puerto 8443: Enrolamiento activo")
    print("    - Puerto 9443: Canal seguro mTLS activo")
    
    async with server_enroll, server_gateway:
        await asyncio.gather(server_enroll.serve_forever(), server_gateway.serve_forever())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Servidor detenido por el operador.")