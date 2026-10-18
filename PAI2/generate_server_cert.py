import os
import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

os.makedirs("pki/server", exist_ok=True)

# Localizar la CA del Rol A
ca_cert_path = "pki/ca/ca.pem"
ca_key_path = "pki/ca/ca.key"

if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
    # Buscar alternativas comunes de nombres de la CA
    ca_cert_path = "pki/ca/ca.crt"

print("[*] Cargando la CA raíz del proyecto...")
with open(ca_cert_path, "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

with open(ca_key_path, "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)

print("[*] Generando clave privada ECDSA (P-384) para el servidor...")
private_key = ec.generate_private_key(ec.SECP384R1())

# Construir la CSR para el servidor
subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

print("[*] Emitiendo y firmando el certificado del servidor con la CA...")
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(ca_cert.subject)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]),
        critical=False,
    )
    .sign(ca_key, hashes.SHA384())
)

# Guardar clave privada (server.key)
with open("pki/server/server.key", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# Guardar certificado público (server.pem)
with open("pki/server/server.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print(f"[+] ¡Certificado de servidor firmado por la CA y guardado en pki/server/!")