"""
attacks/rogue_server.py - Suplantación de servidor con CA falsa (Obj.5, extra +10%)
Proyecto: PAI-2 BYODSEC (Rol C)

Simula a un atacante que levanta un gateway falso con un certificado "localhost"
emitido por SU PROPIA CA, para hacerse pasar por el gateway legítimo y capturar las
credenciales de un dispositivo BYOD.

La prueba demuestra la defensa, no el ataque: el cliente legítimo solo confía en la
CA corporativa (pki/ca/ca.pem), así que ABORTA el handshake al ver un certificado de
otra CA y NO llega a enviar usuario ni contraseña. El servidor falso no recibe
ningún secreto.

No intercepta ni reenvía tráfico real hacia el gateway verdadero: es un extremo
aislado que existe solo para que el cliente lo rechace.

Uso: python -m attacks.rogue_server            (hace de servidor y de cliente y reporta)
"""

import datetime
import socket
import ssl
import sys
import tempfile
import threading
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

CORP_CA = BASE / "pki" / "ca" / "ca.pem"


def _make_fake_server_cert():
    """CA falsa del atacante que emite un cert 'localhost' con el que intenta colarse."""
    d = Path(tempfile.mkdtemp(prefix="fakeca_"))
    ca_key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA Falsa del Atacante")])
    ca_cert = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA384())
    )
    srv_key = ec.generate_private_key(ec.SECP384R1())
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name).public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(ca_key, hashes.SHA384())
    )
    cp, kp = d / "srv.pem", d / "srv.key"
    cp.write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(srv_key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    return str(cp), str(kp)


def run_demo(host="127.0.0.1", port=0):
    cp, kp = _make_fake_server_cert()
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    srv_ctx.load_cert_chain(cp, kp)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(1)
    bound_port = listener.getsockname()[1]

    captured = {"secret_leaked": False, "detail": ""}

    def rogue_server():
        try:
            raw, _ = listener.accept()
            with srv_ctx.wrap_socket(raw, server_side=True) as s:
                data = s.recv(4096)  # solo llega aquí si el cliente aceptó el cert falso
                captured["secret_leaked"] = bool(data)
                captured["detail"] = f"el cliente envió {len(data)} bytes al servidor falso"
        except (ssl.SSLError, OSError) as e:
            captured["detail"] = f"el cliente abortó el handshake: {getattr(e, 'reason', None) or e}"
        finally:
            listener.close()

    t = threading.Thread(target=rogue_server, daemon=True)
    t.start()

    # Cliente legítimo: confía solo en la CA corporativa.
    cli_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cli_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    cli_ctx.load_verify_locations(cafile=str(CORP_CA))
    client_aborted = False
    client_detail = ""
    try:
        with socket.create_connection((host, bound_port), 10) as raw:
            with cli_ctx.wrap_socket(raw, server_hostname="localhost") as s:
                s.sendall(b'{"action":"LOGIN","username":"pdi_001","password":"PasswordSegura2026!"}')
                client_detail = "el cliente aceptó el certificado falso y envió credenciales"
    except ssl.SSLCertVerificationError as e:
        client_aborted = True
        client_detail = f"verificación fallida ({e.verify_message or e.reason})"
    except (ssl.SSLError, OSError) as e:
        client_aborted = True
        client_detail = f"{getattr(e, 'reason', None) or e}"
    t.join(timeout=5)

    ok = client_aborted and not captured["secret_leaked"]
    return ok, client_detail, captured["detail"]


if __name__ == "__main__":
    ok, cli, srv = run_demo()
    print("[suplantación de servidor con CA falsa]")
    print(f"  Cliente legítimo: {cli}")
    print(f"  Servidor falso:   {srv}")
    print(f"  Resultado: {'DEFENSA OK, no se filtraron credenciales' if ok else 'FALLO: credenciales expuestas'}")
    sys.exit(0 if ok else 1)
