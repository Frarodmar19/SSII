"""
attacks/capture_plain_vs_tunnel.py - Evidencia de confidencialidad del canal (RS4)
Proyecto: PAI-2 BYODSEC (Rol C)

Captura dos LOGIN idénticos y demuestra el contraste:

  01_plain_login.pcap    contra el servidor de referencia en claro (bench/plain_server):
                         usuario y contraseña viajan legibles.
  02_tunnel_login.pcap   contra el gateway TLS 1.3 + mTLS (:9443):
                         el mismo contenido va cifrado; en el pcap no aparece.

Al terminar busca la contraseña en texto plano dentro de cada captura y lo informa.
Esto NO es un ataque: es la prueba de que el túnel protege lo que el canal en claro
expone, usando tráfico propio generado para la demostración.

Uso: sudo -E python -m attacks.capture_plain_vs_tunnel --iface lo
"""

import argparse
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

PCAP_DIR = BASE / "evidence" / "pcap"
CA_PEM = BASE / "pki" / "ca" / "ca.pem"
CLIENTS = BASE / "pki" / "clients"
MARKER_USER = "pdi_007"
MARKER_PWD = "PasswordSegura2026!"


def _login_frame():
    body = ('{"action":"LOGIN","username":"%s","password":"%s"}' % (MARKER_USER, MARKER_PWD)).encode()
    return struct.pack("!I", len(body)) + body


def plain_login(host, port):
    with socket.create_connection((host, port), 10) as s:
        s.sendall(_login_frame())
        s.recv(4096)


def tunnel_login(host, port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(CA_PEM))
    ctx.load_cert_chain(str(CLIENTS / MARKER_USER / "client.pem"), str(CLIENTS / MARKER_USER / "client.key"))
    with socket.create_connection((host, port), 10) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as s:
            s.sendall(_login_frame())
            s.recv(4096)


def capture(name, iface, port, action):
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    path = PCAP_DIR / name
    proc = subprocess.Popen(["tcpdump", "-i", iface, "-w", str(path), "-U", f"tcp port {port}"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.8)
    try:
        action()
    finally:
        time.sleep(0.4)
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=5)
    return path


def password_in_pcap(path):
    """True si la contraseña aparece en claro dentro del pcap."""
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    return MARKER_PWD.encode() in raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="lo")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--plain-port", type=int, default=9080)
    ap.add_argument("--tls-port", type=int, default=9443)
    args = ap.parse_args()

    p_plain = capture("01_plain_login.pcap", args.iface, args.plain_port,
                      lambda: plain_login(args.host, args.plain_port))
    p_tls = capture("02_tunnel_login.pcap", args.iface, args.tls_port,
                    lambda: tunnel_login(args.host, args.tls_port))

    plain_leak = password_in_pcap(p_plain)
    tls_leak = password_in_pcap(p_tls)
    print("[*] Confidencialidad del canal (contraseña en claro dentro del .pcap):")
    print(f"  Canal en claro  ({p_plain.name}): contraseña visible = {plain_leak}")
    print(f"  Túnel TLS 1.3   ({p_tls.name}): contraseña visible = {tls_leak}")
    ok = plain_leak is True and tls_leak is False
    print(f"  Resultado: {'OK, el túnel oculta lo que el canal en claro expone' if ok else 'revisar captura'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
