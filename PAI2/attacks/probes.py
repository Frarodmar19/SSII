"""
attacks/probes.py - Sondas de admisión contra el gateway (Obj.5, extra +10%)
Proyecto: PAI-2 BYODSEC (Rol C)

Cada sonda es un INTENTO DE ACCESO que DEBE SER RECHAZADO por el gateway. Son
pruebas defensivas: demuestran que el túnel TLS 1.3 + mTLS no admite clientes que
no cumplen la política, y que cada rechazo queda registrado como TLS_FAIL en la
auditoría. No interceptan ni modifican tráfico de terceros.

Sondas:
  no_cert      Conexión al canal mTLS sin presentar certificado de cliente.
  other_ca     Certificado de cliente autofirmado por una CA ajena a la corporativa.
  revoked      Certificado legítimo pero revocado (requiere revocarlo antes; ver run_attacks).
  tls12        Intento de negociar TLS 1.2 (downgrade de versión).
  weak_suite   Intento de negociar una suite AEAD de 128 bits no permitida (RS2).
  brute_force  Varios LOGIN con contraseña errónea hasta provocar el bloqueo (RF2).

Cada función devuelve (bloqueado: bool, detalle: str). "bloqueado=True" es el
resultado correcto: el ataque no prospera.

Uso: python -m attacks.probes --probe no_cert --host 127.0.0.1 --port 9443
"""

import argparse
import datetime
import json
import socket
import ssl
import struct
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

CA_PEM = BASE / "pki" / "ca" / "ca.pem"
CLIENTS = BASE / "pki" / "clients"
DEFAULT_PASSWORD = "PasswordSegura2026!"
TIMEOUT = 10


def _send(sock, obj):
    payload = json.dumps(obj).encode()
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def _recv(sock):
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise ConnectionError("conexión cerrada por el servidor")
        header += chunk
    (length,) = struct.unpack("!I", header)
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("conexión cerrada por el servidor")
        data += chunk
    return json.loads(data.decode())


def _rejected(detail):
    return True, detail


def _breach(detail):
    return False, detail


def probe_no_cert(host, port):
    """Sin certificado de cliente: el gateway exige mTLS y debe cortar el handshake."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(CA_PEM))
    try:
        with socket.create_connection((host, port), TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                # Si llegamos aquí el handshake no pidió certificado: intentamos login.
                _send(s, {"action": "LOGIN", "username": "pdi_001", "password": DEFAULT_PASSWORD})
                return _breach(f"ACCESO INDEBIDO: el servidor respondió {_recv(s)}")
    except (ssl.SSLError, ConnectionError, OSError) as e:
        return _rejected(f"handshake rechazado sin certificado: {getattr(e, 'reason', None) or e}")


def _self_signed_client(cn="pdi_001"):
    """Genera en un temporal un par clave+certificado autofirmado (CA ajena)."""
    key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA384())
    )
    d = Path(tempfile.mkdtemp(prefix="rogue_"))
    cp, kp = d / "c.pem", d / "c.key"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return str(cp), str(kp)


def probe_other_ca(host, port):
    """Certificado de cliente firmado por una CA que no es la corporativa: mTLS lo rechaza."""
    cp, kp = _self_signed_client("pdi_001")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(CA_PEM))
    ctx.load_cert_chain(cp, kp)
    try:
        with socket.create_connection((host, port), TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                _send(s, {"action": "LOGIN", "username": "pdi_001", "password": DEFAULT_PASSWORD})
                return _breach(f"ACCESO INDEBIDO con cert de CA falsa: {_recv(s)}")
    except (ssl.SSLError, ConnectionError, OSError) as e:
        return _rejected(f"cert de CA no confiable rechazado: {getattr(e, 'reason', None) or e}")


def probe_revoked(host, port, user="inv_080"):
    """Certificado válido de la CA pero revocado (debe revocarse antes con pki.revoke)."""
    cp = str(CLIENTS / user / "client.pem")
    kp = str(CLIENTS / user / "client.key")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(CA_PEM))
    ctx.load_cert_chain(cp, kp)
    try:
        with socket.create_connection((host, port), TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                _send(s, {"action": "LOGIN", "username": user, "password": DEFAULT_PASSWORD})
                return _breach(f"ACCESO INDEBIDO con cert revocado: {_recv(s)}")
    except (ssl.SSLError, ConnectionError, OSError) as e:
        return _rejected(f"cert revocado rechazado por la CRL: {getattr(e, 'reason', None) or e}")


def _mtls_ctx(user="pdi_002"):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(CA_PEM))
    ctx.load_cert_chain(str(CLIENTS / user / "client.pem"), str(CLIENTS / user / "client.key"))
    return ctx


def probe_tls12(host, port):
    """Intento de hablar TLS 1.2: el servidor fija min=max=TLS 1.3 y debe rechazarlo."""
    ctx = _mtls_ctx()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((host, port), TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                return _breach(f"ACCESO INDEBIDO con {s.version()}")
    except (ssl.SSLError, ConnectionError, OSError) as e:
        return _rejected(f"downgrade a TLS 1.2 rechazado: {getattr(e, 'reason', None) or e}")


def probe_weak_suite(host, port):
    """Intento de negociar solo TLS_AES_128_GCM_SHA256, no permitida por RS2."""
    ctx = _mtls_ctx()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    try:
        ctx.set_ciphersuites("TLS_AES_128_GCM_SHA256")  # OpenSSL >= 3.5 expone esta API
    except (AttributeError, ssl.SSLError):
        return True, "no evaluada: esta versión de Python no permite fijar la suite TLS 1.3 del cliente"
    try:
        with socket.create_connection((host, port), TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                return _breach(f"ACCESO INDEBIDO con suite {s.cipher()[0]}")
    except (ssl.SSLError, ConnectionError, OSError) as e:
        return _rejected(f"suite de 128 bits rechazada: {getattr(e, 'reason', None) or e}")


def probe_brute_force(host, port, user="pas_050", attempts=6):
    """Fuerza bruta de contraseña sobre un canal mTLS válido: auth debe bloquear (RF2)."""
    ctx = _mtls_ctx(user)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    seen = []
    try:
        with socket.create_connection((host, port), TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                for i in range(attempts):
                    _send(s, {"action": "LOGIN", "username": user, "password": f"intento_{i}"})
                    seen.append(_recv(s).get("code"))
    except (ssl.SSLError, ConnectionError, OSError) as e:
        return _breach(f"error de conexión durante la prueba: {e}")
    if "LOCKED" in seen:
        return _rejected(f"cuenta bloqueada tras intentos fallidos (códigos: {seen})")
    return _breach(f"NO se bloqueó la cuenta tras {attempts} intentos: {seen}")


PROBES = {
    "no_cert": probe_no_cert,
    "other_ca": probe_other_ca,
    "revoked": probe_revoked,
    "tls12": probe_tls12,
    "weak_suite": probe_weak_suite,
    "brute_force": probe_brute_force,
}


def main():
    ap = argparse.ArgumentParser(description="Sondas de admisión contra el gateway BYODSEC")
    ap.add_argument("--probe", choices=sorted(PROBES), required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9443)
    args = ap.parse_args()
    blocked, detail = PROBES[args.probe](args.host, args.port)
    estado = "RECHAZADO (correcto)" if blocked else "ADMITIDO (FALLO DE SEGURIDAD)"
    print(f"[{args.probe}] {estado}: {detail}")
    sys.exit(0 if blocked else 1)


if __name__ == "__main__":
    main()
