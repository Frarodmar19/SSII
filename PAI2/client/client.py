import asyncio
import json
import struct
import ssl
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from server.tls import get_client_context, get_client_enroll_context

async def send_frame(writer, data: dict):
    payload = json.dumps(data).encode("utf-8")
    header = struct.pack("!I", len(payload))
    writer.write(header + payload)
    await writer.drain()

async def read_frame(reader) -> dict:
    header = await reader.readexactly(4)
    length = struct.unpack("!I", header)[0]
    data = await reader.readexactly(length)
    return json.loads(data.decode("utf-8"))

async def run_client_demo(username: str, password: str, cert_path: str, key_path: str):
    print(f"\n--- Iniciando prueba de cliente para: {username} ---")

    # Contexto mTLS para conectar al puerto 9443
    context = get_client_context(cert_path, key_path)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", 9443, ssl=context)
        print("[+] Handshake TLS 1.3 y mTLS completado con éxito.")

        # 1. Enviar petición LOGIN
        print("[*] Enviando credenciales LOGIN...")
        await send_frame(writer, {"action": "LOGIN", "username": username, "password": password})
        resp = await read_frame(reader)
        print(f"[*] Respuesta LOGIN: {resp}")

        if resp.get("status") == "ok":
            session_id = resp.get("session_id")

            # 2. Enviar mensaje seguro (MSG)
            print("[*] Enviando mensaje seguro (MSG)...")
            await send_frame(writer, {"action": "MSG", "session_id": session_id, "body": f"Hola Gateway, soy {username} transmitiendo seguro."})
            msg_resp = await read_frame(reader)
            print(f"[*] Respuesta MSG: {msg_resp}")

            # 3. Cerrar sesión correctamente (LOGOUT)
            print("[*] Solicitando LOGOUT y cierre close_notify...")
            await send_frame(writer, {"action": "LOGOUT", "session_id": session_id})
            logout_resp = await read_frame(reader)
            print(f"[*] Respuesta LOGOUT: {logout_resp}")

        writer.close()
        await writer.wait_closed()
        print("[+] Conexión cerrada limpiamente.")

    except Exception as e:
        print(f"[-] Error en la conexión del cliente: {e}")

if __name__ == "__main__":
    # Prueba rápida con un usuario precargado por el seed (pdi_001).
    # Ejecuta antes seed_users.py para que existan el certificado y la clave.
    user = "pdi_001"
    pwd = "PasswordSegura2026!"
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    c_cert = os.path.join(base_dir, "pki", "clients", user, "client.pem")
    c_key = os.path.join(base_dir, "pki", "clients", user, "client.key")

    asyncio.run(run_client_demo(user, pwd, c_cert, c_key))
