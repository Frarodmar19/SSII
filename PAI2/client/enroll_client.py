import asyncio
import json
import struct
import os
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes # Asegúrate de importar hashes

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from server.tls import get_client_enroll_context

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

def generate_local_csr_and_key(username: str, output_dir: str):
    """Genera una clave privada ECDSA (P-384) y una CSR localmente.
    La clave privada NUNCA sale del dispositivo."""
    os.makedirs(output_dir, exist_ok=True)
    
    # Generar par de claves con curva P-384 (acorde a la PKI del Rol A)
    private_key = ec.generate_private_key(ec.SECP384R1())
    
    # Generar la CSR con el CN (Common Name) igual al nombre de usuario y firmada con SHA384
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])
    ).sign(private_key, hashes.SHA384())  # <-- CORREGIDO AQUÍ
    
    # Serializar clave privada y CSR en formato PEM
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    
    # Guardar clave privada localmente
    key_path = os.path.join(output_dir, "server.key")
    with open(key_path, "wb") as f:
        f.write(key_pem)
        
    return csr_pem.decode("utf-8")

async def enroll_device(username: str, password: str, role: str):
    print(f"[*] Generando clave privada y CSR local para el usuario: {username}...")
    
    # Directorio local donde el cliente guardará sus credenciales obtenidas
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    client_dir = os.path.join(base_dir, "pki", "clients", username)
    
    csr_pem = generate_local_csr_and_key(username, client_dir)
    
    # Contexto TLS para enrolamiento (puerto 8443, solo valida certificado de servidor)
    context = get_client_enroll_context()
    
    print(f"[*] Conectando al puerto de enrolamiento (8443) para registrarse...")
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", 8443, ssl=context)
        
        # Enviar trama ENROLL
        payload = {
            "action": "ENROLL",
            "username": username,
            "password": password,
            "role": role,
            "csr_pem": csr_pem
        }
        await send_frame(writer, payload)
        
        # Recibir respuesta del Gateway
        response = await read_frame(reader)
        
        if response.get("status") == "ok":
            cert_pem = response.get("cert_pem")
            
            # Guardar el certificado de cliente recibido
            cert_path = os.path.join(client_dir, "server.pem")
            with open(cert_path, "w", encoding="utf-8") as f:
                f.write(cert_pem)
                
            print(f"[+] ¡Enrolamiento exitoso! Certificado guardado en: {cert_path}")
        else:
            print(f"[-] Error en el enrolamiento: {response.get('code')}")
            
        writer.close()
        await writer.wait_closed()
        
    except Exception as e:
        print(f"[-] Error de conexión durante el enrolamiento: {e}")

if __name__ == "__main__":
    # Prueba rápida de enrolamiento para un nuevo usuario
    import sys
    test_user = sys.argv[1] if len(sys.argv) > 1 else "nuevo_usuario"
    test_pwd = sys.argv[2] if len(sys.argv) > 2 else "PasswordSegura2026!"
    test_role = "INV"
    
    asyncio.run(enroll_device(test_user, test_pwd, test_role))