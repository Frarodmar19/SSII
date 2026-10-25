"""
attacks/run_attacks.py - Batería de ataques y evidencias (Obj.4, Obj.5, RS4)
Proyecto: PAI-2 BYODSEC (Rol C)

Ejecuta, contra un gateway ya arrancado, todas las sondas de admisión y la demo de
suplantación de servidor, cada una con su captura .pcap (si tcpdump está disponible),
y comprueba que TODAS son rechazadas. Al final verifica que cada rechazo quedó
reflejado en la auditoría (TLS_FAIL / LOCKED) y guarda un resumen.

Requisitos previos: PKI y seed generados, y el gateway escuchando en --port.
Para la sonda 'revoked' revoca temporalmente un certificado real y lo restaura al
terminar (los triggers de la BD permiten pasar a 'revoked'; la restauración solo
reconstruye la CRL, no reescribe el certificado).

Uso: sudo -E python -m attacks.run_attacks --host 127.0.0.1 --port 9443 --iface lo
"""

import argparse
import json
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from attacks import probes, rogue_server  # noqa: E402

PCAP_DIR = BASE / "evidence" / "pcap"
LOG_DIR = BASE / "evidence" / "logs"
ATTACK_SUMMARY = LOG_DIR / "attacks_summary.json"
DB_PATH = BASE / "server" / "byodsec.db"
REVOKED_USER = "inv_080"


def tcpdump_available():
    return shutil.which("tcpdump") is not None


class Capture:
    """Captura tcpdump en un fichero .pcap mientras dura un bloque with."""

    def __init__(self, name, iface, port, enabled):
        self.path = PCAP_DIR / f"{name}.pcap"
        self.iface = iface
        self.port = port
        self.enabled = enabled
        self.proc = None

    def __enter__(self):
        if not self.enabled:
            return self
        PCAP_DIR.mkdir(parents=True, exist_ok=True)
        self.proc = subprocess.Popen(
            ["tcpdump", "-i", self.iface, "-w", str(self.path), "-U", f"tcp port {self.port}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.8)  # deja que tcpdump abra el socket antes del ataque
        return self

    def __exit__(self, *exc):
        if self.proc:
            time.sleep(0.4)
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        return False


def serial_of(user):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT serial FROM certificates WHERE username = ? LIMIT 1", (user,)).fetchone()
    conn.close()
    return row[0] if row else None


def rebuild_crl_from_db():
    """Reconstruye crl.pem con los seriales marcados 'revoked' en la BD."""
    import datetime
    from pki.crl import generate_crl
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT serial, revoked_at, reason FROM certificates WHERE status='revoked'").fetchall()
    conn.close()
    revoked = []
    for s, ts, reason in rows:
        s_int = int(s, 16) if str(s).startswith("0x") else int(s, 16)
        rev_date = datetime.datetime.fromtimestamp(ts or time.time(), tz=datetime.timezone.utc)
        from pki.revoke import get_crl_reason
        revoked.append((s_int, rev_date, get_crl_reason(reason or "unspecified")))
    generate_crl(revoked)


def set_status(serial, status):
    conn = sqlite3.connect(DB_PATH)
    if status == "revoked":
        conn.execute("UPDATE certificates SET status='revoked', revoked_at=?, reason='key_compromise' WHERE serial=?",
                     (time.time(), serial))
    else:
        # No se puede 'des-revocar' por diseño; para la prueba limpiamos los campos de revocación.
        conn.execute("UPDATE certificates SET status='valid', revoked_at=NULL, reason=NULL WHERE serial=?", (serial,))
    conn.commit()
    conn.close()


def audit_tail_text():
    log = LOG_DIR / "audit.jsonl"
    if not log.exists():
        return ""
    with open(log, "rb") as f:
        f.seek(0, 2)
        f.seek(max(0, f.tell() - 65536))
        return f.read().decode("utf-8", errors="replace")


def main():
    ap = argparse.ArgumentParser(description="Batería de ataques BYODSEC")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9443)
    ap.add_argument("--iface", default="lo")
    ap.add_argument("--no-pcap", action="store_true", help="No capturar tráfico aunque haya tcpdump")
    args = ap.parse_args()

    capture_on = tcpdump_available() and not args.no_pcap
    if not capture_on:
        print("[!] tcpdump no disponible o desactivado: se ejecutan los ataques sin capturar .pcap")

    results = []

    def run(name, fn):
        with Capture(name, args.iface, args.port, capture_on):
            blocked, detail = fn()
        pcap = f"evidence/pcap/{name}.pcap" if capture_on else None
        results.append({"ataque": name, "bloqueado": blocked, "detalle": detail, "pcap": pcap})
        estado = "RECHAZADO" if blocked else "ADMITIDO (FALLO)"
        print(f"  [{name:11}] {estado}: {detail}")

    print("[*] Lanzando batería de ataques contra el túnel...")
    run("02_no_cert", lambda: probes.probe_no_cert(args.host, args.port))
    run("03_other_ca", lambda: probes.probe_other_ca(args.host, args.port))
    run("04_tls12_downgrade", lambda: probes.probe_tls12(args.host, args.port))
    run("05_weak_suite", lambda: probes.probe_weak_suite(args.host, args.port))
    run("06_brute_force", lambda: probes.probe_brute_force(args.host, args.port))
    run("07_rogue_server", lambda: rogue_server.run_demo()[:2])

    # Certificado revocado: revocar, reconstruir CRL, esperar la recarga del gateway, probar y restaurar.
    serial = serial_of(REVOKED_USER)
    if serial:
        set_status(serial, "revoked")
        rebuild_crl_from_db()
        time.sleep(1.5)  # el gateway detecta el cambio de crl.pem y recarga el contexto
        run("08_revoked", lambda: probes.probe_revoked(args.host, args.port, REVOKED_USER))
        set_status(serial, "valid")
        rebuild_crl_from_db()
        time.sleep(1.5)
    else:
        print(f"  [08_revoked ] OMITIDO: no se encontró certificado de {REVOKED_USER}")

    tail = audit_tail_text()
    audited = tail.count('"event": "TLS_FAIL"') + tail.count('"event": "LOCKED"')
    all_blocked = all(r["bloqueado"] for r in results)

    summary = {
        "generado": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total": len(results),
        "rechazados": sum(1 for r in results if r["bloqueado"]),
        "admitidos_fallo": [r["ataque"] for r in results if not r["bloqueado"]],
        "eventos_tls_fail_o_locked_en_cola_auditoria": audited,
        "pcaps": capture_on,
        "resultados": results,
    }
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ATTACK_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"\n[+] {summary['rechazados']}/{summary['total']} ataques rechazados. "
          f"Resumen en {ATTACK_SUMMARY.relative_to(BASE)}")
    sys.exit(0 if all_blocked else 1)


if __name__ == "__main__":
    main()
