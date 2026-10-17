"""
pki/crl.py - Generación y firma de Certificate Revocation List (CRL v2)
Algoritmo: ECDSA P-384 / SHA-384
"""

import datetime
from pathlib import Path
from typing import List, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from pki.ca import CA_DIR
from pki.issue import load_ca

CRL_PATH = CA_DIR / "crl.pem"


def generate_crl(
    revoked_certs: List[Tuple[int, datetime.datetime, x509.ReasonFlags]],
    out_path: Path = CRL_PATH,
) -> Path:
    """
    Genera y firma una CRL con una lista de tuplas: (serial_number, fecha_revocacion, motivo)
    """
    ca_key, ca_cert = load_ca()
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - datetime.timedelta(minutes=1))
        .next_update(now + datetime.timedelta(days=7))  # Validez de 7 días
    )

    for serial, rev_date, reason in revoked_certs:
        rev_entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(rev_date)
            .add_extension(x509.CRLReason(reason), critical=False)
            .build()
        )
        builder = builder.add_revoked_certificate(rev_entry)

    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA384())

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    print(f"[+] CRL actualizada y guardada en {out_path} ({len(revoked_certs)} certificados revocados)")
    return out_path


if __name__ == "__main__":
    # Genera una CRL inicial vacía
    generate_crl([])