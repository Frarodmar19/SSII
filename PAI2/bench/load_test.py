"""
bench/load_test.py - Prueba de carga de sesiones concurrentes (Obj.3 / RS3)
Proyecto: PAI-2 BYODSEC (Rol C)

Cada cliente simulado recorre el flujo completo del enunciado:
  conexión (+ handshake TLS 1.3 mTLS en modo tls) -> LOGIN -> espera a que
  TODAS las sesiones estén abiertas a la vez -> M mensajes MSG -> LOGOUT.

La barrera garantiza que las N sesiones coexisten en el servidor, que es lo que
pide RS3 ("300 sesiones concurrentes"), y no solo N conexiones escalonadas.

Uso:
  python -m bench.load_test --mode tls   --clients 300 --msgs 20
  python -m bench.load_test --mode plain --clients 300 --msgs 20 --port 9080
  python -m bench.load_test --mode tls --scale 50,100,200,300,500 --server-pid <pid>
"""

import argparse
import asyncio
import csv
import json
import os
import ssl
import statistics
import struct
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

CA_PEM = BASE_DIR / "pki" / "ca" / "ca.pem"
CLIENTS_DIR = BASE_DIR / "pki" / "clients"
DEFAULT_PASSWORD = "PasswordSegura2026!"
OUT_DIR = BASE_DIR / "evidence" / "bench"


def seeded_users():
    """Usuarios precargados (RF5) ordenados: pdi_*, pas_*, inv_*."""
    users = sorted(p.name for p in CLIENTS_DIR.iterdir() if (p / "client.pem").exists() and (p / "client.key").exists())
    if not users:
        raise SystemExit("No hay usuarios precargados: ejecuta antes `python -m seed.seed_users`.")
    return users


# Un contexto por usuario se reutiliza entre rondas; cargar 300 claves P-384 cuesta tiempo.
_CTX_CACHE = {}


def client_context(user: str) -> ssl.SSLContext:
    ctx = _CTX_CACHE.get(user)
    if ctx is None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_verify_locations(cafile=str(CA_PEM))
        ctx.load_cert_chain(str(CLIENTS_DIR / user / "client.pem"), str(CLIENTS_DIR / user / "client.key"))
        _CTX_CACHE[user] = ctx
    return ctx


async def send(writer, obj):
    payload = json.dumps(obj).encode()
    writer.write(struct.pack("!I", len(payload)) + payload)
    await writer.drain()


async def recv(reader):
    (length,) = struct.unpack("!I", await reader.readexactly(4))
    return json.loads(await reader.readexactly(length))


async def one_session(i, user, args, all_logged_in, logged_counter, total):
    """Devuelve un dict con las métricas de una sesión."""
    r = {"client": i, "user": user, "ok": False, "error": "", "connect_ms": None,
         "login_ms": None, "rtt_ms": [], "session_ms": None, "cipher": "", "version": ""}
    t0 = time.perf_counter()
    writer = None
    try:
        if args.mode == "tls":
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(args.host, args.port, ssl=client_context(user),
                                        server_hostname=args.sni, ssl_handshake_timeout=args.timeout),
                args.timeout)
            sslobj = writer.get_extra_info("ssl_object")
            r["cipher"], r["version"] = sslobj.cipher()[0], sslobj.version()
        else:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(args.host, args.port), args.timeout)
        t1 = time.perf_counter()
        r["connect_ms"] = (t1 - t0) * 1000

        await send(writer, {"action": "LOGIN", "username": user, "password": DEFAULT_PASSWORD})
        resp = await asyncio.wait_for(recv(reader), args.timeout)
        t2 = time.perf_counter()
        r["login_ms"] = (t2 - t1) * 1000
        if resp.get("status") != "ok":
            raise RuntimeError(f"LOGIN {resp.get('code')}")
        sid = resp["session_id"]
    except Exception as e:  # noqa: BLE001 - se registra cualquier fallo de la sesión
        r["error"] = f"{type(e).__name__}: {e}"[:200]
        logged_counter[0] += 1
        if logged_counter[0] >= total:
            all_logged_in.set()
        if writer:
            writer.close()
        return r

    # Barrera: nadie envía mensajes hasta que todas las sesiones están abiertas.
    logged_counter[0] += 1
    if logged_counter[0] >= total:
        all_logged_in.set()
    await all_logged_in.wait()

    try:
        body = "x" * args.payload
        for _ in range(args.msgs):
            ts = time.perf_counter()
            await send(writer, {"action": "MSG", "session_id": sid, "body": body})
            resp = await asyncio.wait_for(recv(reader), args.timeout)
            if resp.get("status") != "ok":
                raise RuntimeError(f"MSG {resp.get('code')}")
            r["rtt_ms"].append((time.perf_counter() - ts) * 1000)
        await send(writer, {"action": "LOGOUT", "session_id": sid})
        await asyncio.wait_for(recv(reader), args.timeout)
        r["ok"] = True
    except Exception as e:  # noqa: BLE001
        r["error"] = f"{type(e).__name__}: {e}"[:200]
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 5)
        except Exception:  # noqa: BLE001 - el cierre no afecta a la medida
            pass
    r["session_ms"] = (time.perf_counter() - t0) * 1000
    return r


def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * p / 100
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


async def sample_server(pid, stop, samples):
    """Muestrea CPU y RSS del proceso servidor cada 200 ms."""
    try:
        import psutil
        proc = psutil.Process(pid)
        proc.cpu_percent(None)
    except Exception:  # noqa: BLE001 - sin psutil o sin pid, no hay muestreo
        return
    while not stop.is_set():
        await asyncio.sleep(0.2)
        try:
            samples.append((proc.cpu_percent(None), proc.memory_info().rss / 2**20))
        except Exception:  # noqa: BLE001
            return


async def run_round(n, args):
    users = seeded_users()
    # Se precargan los contextos fuera del tiempo medido.
    if args.mode == "tls":
        for i in range(n):
            client_context(users[i % len(users)])

    all_logged_in = asyncio.Event()
    counter = [0]
    stop = asyncio.Event()
    samples = []
    sampler = asyncio.create_task(sample_server(args.server_pid, stop, samples)) if args.server_pid else None

    t0 = time.perf_counter()
    results = await asyncio.gather(*[
        one_session(i, users[i % len(users)], args, all_logged_in, counter, n) for i in range(n)
    ])
    wall = time.perf_counter() - t0
    stop.set()
    if sampler:
        await sampler

    ok = [r for r in results if r["ok"]]
    rtts = [x for r in ok for x in r["rtt_ms"]]
    msg_phase = [sum(r["rtt_ms"]) for r in ok]
    summary = {
        "mode": args.mode, "clients": n, "msgs_per_client": args.msgs, "payload_bytes": args.payload,
        "ok": len(ok), "failed": n - len(ok), "wall_s": round(wall, 3),
        "connect_ms_p50": pct([r["connect_ms"] for r in ok], 50),
        "connect_ms_p95": pct([r["connect_ms"] for r in ok], 95),
        "login_ms_p50": pct([r["login_ms"] for r in ok], 50),
        "login_ms_p95": pct([r["login_ms"] for r in ok], 95),
        "rtt_ms_p50": pct(rtts, 50), "rtt_ms_p95": pct(rtts, 95), "rtt_ms_p99": pct(rtts, 99),
        "msgs_total": len(rtts),
        "throughput_msg_s": round(len(rtts) / (max(msg_phase) / 1000), 1) if msg_phase and max(msg_phase) else None,
        "srv_cpu_avg": round(statistics.mean(s[0] for s in samples), 1) if samples else None,
        "srv_cpu_max": round(max(s[0] for s in samples), 1) if samples else None,
        "srv_rss_max_mb": round(max(s[1] for s in samples), 1) if samples else None,
        "cipher": next((r["cipher"] for r in ok if r["cipher"]), ""),
        "errors": sorted({r["error"] for r in results if r["error"]})[:5],
    }
    for k, v in list(summary.items()):
        if isinstance(v, float):
            summary[k] = round(v, 2)
    return summary, results


def main():
    ap = argparse.ArgumentParser(description="Prueba de carga BYODSEC")
    ap.add_argument("--mode", choices=["tls", "plain"], default="tls")
    ap.add_argument("--host", default=os.environ.get("GATEWAY_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--sni", default="localhost", help="Nombre esperado en el certificado del servidor")
    ap.add_argument("--clients", type=int, default=300)
    ap.add_argument("--scale", default="", help="Lista de tamaños, p. ej. 50,100,200,300,500")
    ap.add_argument("--msgs", type=int, default=20)
    ap.add_argument("--payload", type=int, default=256, help="Bytes del cuerpo de cada MSG")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--server-pid", type=int, default=None)
    ap.add_argument("--tag", default="", help="Sufijo para los ficheros de salida")
    args = ap.parse_args()
    if args.port is None:
        args.port = 9443 if args.mode == "tls" else 9080

    sizes = [int(x) for x in args.scale.split(",")] if args.scale else [args.clients]
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tag = f"_{args.tag}" if args.tag else ""
    summaries = []
    for n in sizes:
        summary, results = asyncio.run(run_round(n, args))
        summaries.append(summary)
        print(json.dumps(summary, ensure_ascii=False))
        with open(OUT_DIR / f"sessions_{args.mode}_{n}{tag}.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["client", "user", "ok", "connect_ms", "login_ms", "rtt_p50_ms", "session_ms", "cipher", "error"])
            for r in results:
                w.writerow([r["client"], r["user"], r["ok"], r["connect_ms"], r["login_ms"],
                            pct(r["rtt_ms"], 50), r["session_ms"], r["cipher"], r["error"]])
        time.sleep(1)  # deja que el servidor cierre sockets entre rondas

    out = OUT_DIR / f"summary_{args.mode}{tag}.json"
    out.write_text(json.dumps(summaries, indent=2, ensure_ascii=False))
    print(f"[+] Resumen guardado en {out.relative_to(BASE_DIR)}")
    failed = sum(s["failed"] for s in summaries)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
