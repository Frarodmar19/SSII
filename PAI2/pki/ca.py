"""
pki/ca.py - Generación de la Autoridad de Certificación (Root CA)
Algoritmo: ECDSA P-384 / SHA-384
"""

import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

CA_DIR = Path("pki/ca")
CA_KEY_PATH = CA_DIR / "ca.key"
CA_CERT_PATH = CA_DIR / "ca.pem"


def generate_ca(ca_dir: Path = CA_DIR, force: bool = False):
    ca_dir.mkdir(parents=True, exist_ok=True)
    key_path = ca_dir / "ca.key"
    cert_path = ca_dir / "ca.pem"

    if key_path.exists() and cert_path.exists() and not force:
        print(f"[*] La CA ya existe en {ca_dir}. Usa force=True para regenerar.")
        return key_path, cert_path

    # 1. Generar clave privada ECDSA P-384
    private_key = ec.generate_private_key(ec.SECP384R1())

    # 2. Construir el Subject e Issuer (Autofirmado)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sevilla"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BYODSEC Security Team 20"),
        x509.NameAttribute(NameOID.COMMON_NAME, "BYODSEC Root CA"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    
    # 3. Construir el certificado X.509v3
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))  # 10 años
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,  # Imprescindible para firmar certs
                crl_sign=True,        # Imprescindible para firmar CRL
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )

    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA384(),
    )

    # 4. Guardar clave privada (formato PEM PKCS#8)
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # 5. Guardar certificado CA (formato PEM)
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"[+] CA generada con éxito:")
    print(f"    - Clave privada: {key_path}")
    print(f"    - Certificado:   {cert_path}")
    return key_path, cert_path


if __name__ == "__main__":
    generate_ca()