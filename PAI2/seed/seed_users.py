"""
seed/seed_users.py - Precarga de 300 usuarios y certificados (RF5)
Proyecto: PAI-2 BYODSEC (Rol A)
"""

import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from server.db import DB_PATH, init_db, get_db_connection
from server.auth import hash_password
from server.audit import log_event
from pki.ca import generate_ca, CA_CERT_PATH, CA_KEY_PATH
from pki.issue import load_ca

CLIENTS_DIR = Path("pki/clients")
DEFAULT_PASSWORD = "PasswordSegura2026!"


def seed_database(num_pdi: int = 120, num_pas: int = 100, num_inv: int = 80, force: bool = False):
    """Genera 300 usuarios con sus claves, certificados y registros de BD."""
    init_db()
    generate_ca()
    ca_key, ca_cert = load_ca()

    conn = get_db_connection(DB_PATH)
    cursor = conn.cursor()

    users_to_create = []
    for i in range(1, num_pdi + 1):
        users_to_create.append((f"pdi_{i:03d}", "PDI"))
    for i in range(1, num_pas + 1):
        users_to_create.append((f"pas_{i:03d}", "PAS"))
    for i in range(1, num_inv + 1):
        users_to_create.append((f"inv_{i:03d}", "INV"))

    total = len(users_to_create)
    print(f"[*] Iniciando precarga de {total} usuarios y certificados...")

    now_dt = datetime.datetime.now(datetime.timezone.utc)
    now_ts = now_dt.timestamp()

    created_count = 0

    for username, role in users_to_create:
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone() and not force:
            continue

        # 1. Registrar usuario en tabla users
        pwd_hash, salt = hash_password(DEFAULT_PASSWORD)
        cursor.execute(
            """
            INSERT OR REPLACE INTO users (username, role, pwd_hash, salt, failed_attempts, locked_until, created_at)
            VALUES (?, ?, ?, ?, 0, 0, ?)
            """,
            (username, role, pwd_hash, salt, now_ts),
        )

        # 2. Generar clave privada ECDSA P-384 para el cliente
        client_key = ec.generate_private_key(ec.SECP384R1())

        # 3. Construir y firmar certificado con la CA
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BYODSEC Security Team 20"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now_dt - datetime.timedelta(minutes=5))
            .not_valid_after(now_dt + datetime.timedelta(days=180))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
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
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        )

        cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA384())

        # 4. Guardar ficheros en disco (pki/clients/<username>/)
        user_dir = CLIENTS_DIR / username
        user_dir.mkdir(parents=True, exist_ok=True)
        key_path = user_dir / "client.key"
        cert_path = user_dir / "client.pem"

        with open(key_path, "wb") as f:
            f.write(
                client_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # 5. Insertar en tabla certificates
        serial_str = hex(cert.serial_number)
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        pubkey_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        try:
            nb = cert.not_valid_before_utc.timestamp()
            na = cert.not_valid_after_utc.timestamp()
        except AttributeError:
            nb = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc).timestamp()
            na = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc).timestamp()

        cursor.execute(
            """
            INSERT OR REPLACE INTO certificates (
                serial, username, fingerprint_sha256, pubkey_pem,
                not_before, not_after, status, revoked_at, reason
            ) VALUES (?, ?, ?, ?, ?, ?, 'valid', NULL, NULL)
            """,
            (serial_str, username, fingerprint, pubkey_pem, nb, na),
        )

        # 6. Registrar en auditoría
        log_event("ENROLL", user=username, cert_serial=serial_str, detail="Precarga automatizada (seed)")
        created_count += 1

        if created_count % 50 == 0 or created_count == total:
            conn.commit()
            print(f"    -> {created_count}/{total} usuarios generados...")

    conn.commit()
    conn.close()
    print(f"[+] Precarga finalizada. {created_count} usuarios listos con credenciales y certificados.")


if __name__ == "__main__":
    seed_database()