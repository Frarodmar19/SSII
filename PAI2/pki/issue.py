"""
pki/issue.py - Emisión de certificados X.509v3 para servidor y clientes
"""

import datetime
from pathlib import Path
from typing import Optional, List
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pki.ca import CA_KEY_PATH, CA_CERT_PATH


def load_ca(ca_key_path: Path = CA_KEY_PATH, ca_cert_path: Path = CA_CERT_PATH):
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


def issue_server_cert(
    out_dir: Path = Path("pki/server"),
    common_name: str = "gateway.byodsec.local",
    alt_names: Optional[List[str]] = None,
    valid_days: int = 365,
):
    """Genera clave y certificado X.509v3 para el Gateway (Servidor)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = load_ca()

    # Clave privada del servidor
    server_key = ec.generate_private_key(ec.SECP384R1())

    if alt_names is None:
        alt_names = ["localhost", "127.0.0.1", "gateway"]

    san_list = []
    for name in alt_names:
        try:
            ip = ipaddress.ip_address(name)
            san_list.append(x509.IPAddress(ip))
        except ValueError:
            san_list.append(x509.DNSName(name))

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BYODSEC Security Team 20"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA384())

    key_file = out_dir / "server.key"
    cert_file = out_dir / "server.pem"

    with open(key_file, "wb") as f:
        f.write(
            server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Certificado de servidor emitido en: {cert_file}")
    return key_file, cert_file


def sign_csr(csr_pem: bytes, valid_days: int = 180) -> x509.Certificate:
    """Firma un CSR presentado por un cliente en el proceso de enrolamiento."""
    ca_key, ca_cert = load_ca()
    csr = x509.load_pem_x509_csr(csr_pem)

    if not csr.is_signature_valid:
        raise ValueError("La firma del CSR no es válida.")

    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA384())
    return cert