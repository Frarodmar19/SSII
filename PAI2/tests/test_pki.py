"""
tests/test_pki.py - Validación de la jerarquía PKI, extensiones X.509v3 y CRL (RS1)
"""

import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pki.ca import CA_KEY_PATH, CA_CERT_PATH, generate_ca
from pki.issue import load_ca, issue_server_cert, sign_csr
from pki.crl import generate_crl, CRL_PATH


def test_root_ca_properties():
    """Verifica que la CA raíz use ECDSA P-384, SHA-384 y sea autofirmada con basicConstraints ca=True."""
    generate_ca()
    ca_key, ca_cert = load_ca()

    # 1. Verificar curva elíptica P-384 y algoritmo de firma SHA-384
    assert isinstance(ca_key.curve, ec.SECP384R1)
    assert isinstance(ca_cert.public_key().curve, ec.SECP384R1)
    assert ca_cert.signature_hash_algorithm.name == "sha384"

    # 2. Autofirmado: Issuer == Subject
    assert ca_cert.issuer == ca_cert.subject

    # 3. BasicConstraints ca=True
    basic_constraints = ca_cert.extensions.get_extension_for_oid(
        ExtensionOID.BASIC_CONSTRAINTS
    ).value
    assert basic_constraints.ca is True

    # 4. KeyUsage: key_cert_sign y crl_sign
    key_usage = ca_cert.extensions.get_extension_for_oid(
        ExtensionOID.KEY_USAGE
    ).value
    assert key_usage.key_cert_sign is True
    assert key_usage.crl_sign is True


def test_server_certificate_extensions(tmp_path):
    """Verifica que el certificado del servidor tenga SERVER_AUTH, SAN y CA=False."""
    key_file, cert_file = issue_server_cert(
        out_dir=tmp_path,
        common_name="gateway.test.local",
        alt_names=["gateway.test.local", "127.0.0.1"],
    )

    with open(cert_file, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    # CA=False
    bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    assert bc.ca is False

    # EKU: SERVER_AUTH
    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku

    # SAN presente
    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    dns_names = [name.value for name in san if isinstance(name, x509.DNSName)]
    assert "gateway.test.local" in dns_names


def test_client_certificate_issuance():
    """Verifica la firma de una CSR de cliente: EKU CLIENT_AUTH y firma válida por la CA."""
    _, ca_cert = load_ca()

    # Crear clave y CSR de cliente
    client_key = ec.generate_private_key(ec.SECP384R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "pdi_test_pki"),
        ]))
        .sign(client_key, hashes.SHA384())
    )

    # Corregido: serialization en lugar de x509.serialization
    cert = sign_csr(csr.public_bytes(serialization.Encoding.PEM))

    # Sujeto y Emisor
    assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "pdi_test_pki"
    assert cert.issuer == ca_cert.subject

    # EKU: CLIENT_AUTH
    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku


def test_crl_generation(tmp_path):
    """Verifica que la CRL incluya el serial revocado y esté firmada por la CA."""
    test_crl_path = tmp_path / "test_crl.pem"
    test_serial = 0x123456789ABCDEF
    rev_date = datetime.datetime.now(datetime.timezone.utc)

    generate_crl(
        [(test_serial, rev_date, x509.ReasonFlags.key_compromise)],
        out_path=test_crl_path,
    )

    with open(test_crl_path, "rb") as f:
        crl = x509.load_pem_x509_crl(f.read())

    assert crl.is_signature_valid(load_ca()[0].public_key())
    revoked_entry = crl.get_revoked_certificate_by_serial_number(test_serial)
    assert revoked_entry is not None
    assert revoked_entry.serial_number == test_serial