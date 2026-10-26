"""
tests/test_attacks.py - La bateria de ataques contra el tunel es rechazada (Obj.5, RS2)

Levanta un entorno aislado en un directorio temporal (CA, certificado de servidor,
unos pocos usuarios con certificado y el gateway en puertos efimeros) y comprueba
que cada intento de acceso que no cumple la politica es rechazado y no filtra datos.
"""

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parent.parent

# Artefactos generados que no se copian al entorno de prueba (se regeneran dentro).
_SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache", ".venv", "venv", "evidence"}


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _ignore(dirpath, names):
    skip = {n for n in names if n in _SKIP_DIRS or n.endswith(".db")}
    if Path(dirpath).resolve() == (BASE / "pki"):
        skip.update({"ca", "clients", "server"})
    return skip


@pytest.fixture(scope="module")
def gateway(tmp_path_factory):
    env_dir = tmp_path_factory.mktemp("byodsec_env")
    shutil.copytree(BASE, env_dir, ignore=_ignore, dirs_exist_ok=True)

    py = sys.executable

    def run(code):
        subprocess.run([py, "-c", code], cwd=env_dir, check=True,
                       env={**os.environ, "PYTHONPATH": str(env_dir)})

    run("from pki.ca import generate_ca; generate_ca(force=True)")
    run("from pki.issue import issue_server_cert; issue_server_cert()")
    run("from pki.crl import generate_crl; generate_crl([])")
    run("from seed.seed_users import seed_database; seed_database(num_pdi=3, num_pas=3, num_inv=3)")

    enroll_port, gw_port = _free_port(), _free_port()
    env = {**os.environ, "PYTHONPATH": str(env_dir),
           "GATEWAY_ENROLL_PORT": str(enroll_port), "GATEWAY_PORT": str(gw_port),
           "OPENSSL_CONF": str(env_dir / "server" / "openssl.cnf")}
    proc = subprocess.Popen([py, "-u", "server/gateway.py"], cwd=env_dir, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", gw_port), 0.3).close()
            break
        except OSError:
            if proc.poll() is not None:
                raise RuntimeError("el gateway termino: " + (proc.stdout.read() if proc.stdout else ""))
            time.sleep(0.2)
    else:
        proc.terminate()
        raise RuntimeError("el gateway no arranco a tiempo")

    old = os.getcwd()
    os.chdir(env_dir)
    sys.path.insert(0, str(env_dir))
    try:
        yield "127.0.0.1", gw_port
    finally:
        os.chdir(old)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _probes():
    import importlib
    import attacks.probes as p
    return importlib.reload(p)


def test_no_cert_is_rejected(gateway):
    blocked, detail = _probes().probe_no_cert(*gateway)
    assert blocked, detail


def test_other_ca_cert_is_rejected(gateway):
    blocked, detail = _probes().probe_other_ca(*gateway)
    assert blocked, detail


def test_tls12_downgrade_is_rejected(gateway):
    blocked, detail = _probes().probe_tls12(*gateway)
    assert blocked, detail


def test_brute_force_locks_account(gateway):
    blocked, detail = _probes().probe_brute_force(*gateway, user="pas_002")
    assert blocked, detail


def test_rogue_server_does_not_get_credentials():
    import importlib
    import attacks.rogue_server as rs
    importlib.reload(rs)
    ok, client_detail, server_detail = rs.run_demo()
    assert ok, f"cliente: {client_detail} | servidor: {server_detail}"
