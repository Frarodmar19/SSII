"""
bench/plot.py - Gráficas de la comparativa TLS 1.3 + mTLS frente a TCP en claro (RS3)
Proyecto: PAI-2 BYODSEC (Rol C)

Lee evidence/bench/summary_tls.json y summary_plain.json (salida de load_test.py)
y genera las figuras PNG del informe en evidence/charts/.

Uso: python -m bench.plot
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

BASE = Path(__file__).resolve().parent.parent
BENCH = BASE / "evidence" / "bench"
CHARTS = BASE / "evidence" / "charts"

TLS_C, PLAIN_C = "#2a78d6", "#eb6834"   # categóricos 1 y 2 (paleta validada para daltonismo)
INK, MUTED, GRID = "#1f1f1e", "#6b6a64", "#e4e3de"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 9.5, "axes.edgecolor": MUTED,
    "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED,
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True,
    "figure.dpi": 160, "savefig.bbox": "tight",
})


def load(mode):
    return json.loads((BENCH / f"summary_{mode}.json").read_text())


def panel(ax, tls, plain, p50, p95, title, unit="ms", log=False):
    for rows, color, name in ((tls, TLS_C, "TLS 1.3 + mTLS"), (plain, PLAIN_C, "TCP en claro")):
        x = [r["clients"] for r in rows]
        mid = [r[p50] for r in rows]
        ax.plot(x, mid, color=color, lw=2, marker="o", ms=5, label=name, zorder=3)
        if p95:
            hi = [r[p95] for r in rows]
            ax.fill_between(x, mid, hi, color=color, alpha=0.14, lw=0, zorder=2)
        ax.annotate(f"{mid[-1]:,.0f}".replace(",", "."), (x[-1], mid[-1]), xytext=(6, 0),
                    textcoords="offset points", va="center", fontsize=8.5, color=INK)
    ax.set_title(title, loc="left", fontsize=10.5, color=INK, fontweight="bold")
    ax.set_xlabel("Sesiones concurrentes")
    ax.set_ylabel(unit)
    ax.set_xticks([r["clients"] for r in tls])
    ax.axvline(300, color=MUTED, lw=0.8, ls="--", zorder=1)
    if log:
        ax.set_yscale("log")
    ax.set_xlim(right=max(r["clients"] for r in tls) * 1.12)


def main():
    CHARTS.mkdir(parents=True, exist_ok=True)
    tls, plain = load("tls"), load("plain")

    fig, axes = plt.subplots(2, 2, figsize=(9.2, 6.4))
    panel(axes[0][0], tls, plain, "connect_ms_p50", "connect_ms_p95",
          "Conexión + handshake (p50, banda hasta p95)", log=True)
    panel(axes[0][1], tls, plain, "login_ms_p50", "login_ms_p95",
          "LOGIN con scrypt (p50, banda hasta p95)")
    panel(axes[1][0], tls, plain, "rtt_ms_p50", "rtt_ms_p95",
          "RTT de MSG (p50, banda hasta p95)")
    panel(axes[1][1], tls, plain, "srv_rss_max_mb", None,
          "Memoria máxima del servidor", unit="MiB")
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(0.5, 1.03))
    fig.suptitle("")
    fig.tight_layout(h_pad=2.2)
    fig.savefig(CHARTS / "escalado_tls_vs_claro.png")
    plt.close(fig)

    # Coste de TLS a 300 sesiones (el punto que pide RS3)
    t = next(r for r in tls if r["clients"] == 300)
    p = next(r for r in plain if r["clients"] == 300)
    metrics = [("Handshake p50", "connect_ms_p50"), ("Login p50", "login_ms_p50"),
               ("RTT MSG p50", "rtt_ms_p50"), ("Sesión completa\n(tiempo total, s)", "wall_s")]
    fig, axes = plt.subplots(1, 4, figsize=(9.2, 2.6))
    for ax, (label, key) in zip(axes, metrics):
        vals = [p[key], t[key]]
        bars = ax.bar(["Claro", "TLS"], vals, color=[PLAIN_C, TLS_C], width=0.6, zorder=3)
        for b, v in zip(bars, vals):
            ax.annotate(f"{v:,.1f}".replace(",", "X").replace(".", ",").replace("X", "."),
                        (b.get_x() + b.get_width() / 2, v), xytext=(0, 3),
                        textcoords="offset points", ha="center", fontsize=8.5, color=INK)
        ax.set_title(label, fontsize=9.5, color=INK, loc="left")
        ax.set_ylim(0, max(vals) * 1.25)
        ax.grid(axis="x", visible=False)
    axes[0].set_ylabel("ms")
    fig.tight_layout()
    fig.savefig(CHARTS / "coste_tls_300.png")
    plt.close(fig)

    # Antes / después de sacar scrypt del bucle asyncio (misma máquina, 300 sesiones TLS)
    before_path = BENCH / "summary_tls_before_fix.json"
    if before_path.exists():
        b = json.loads(before_path.read_text())[0]
        metrics = [("Handshake p95 (ms)", "connect_ms_p95"), ("Login p95 (ms)", "login_ms_p95"),
                   ("Tiempo total (s)", "wall_s")]
        fig, axes = plt.subplots(1, 3, figsize=(8.2, 2.6))
        for ax, (label, key) in zip(axes, metrics):
            vals = [b[key], t[key]]
            bars = ax.bar(["Antes", "Después"], vals, color=["#9a9992", TLS_C], width=0.6, zorder=3)
            for bar, v in zip(bars, vals):
                ax.annotate(f"{v:,.1f}".replace(",", "X").replace(".", ",").replace("X", "."),
                            (bar.get_x() + bar.get_width() / 2, v), xytext=(0, 3),
                            textcoords="offset points", ha="center", fontsize=8.5, color=INK)
            ax.set_title(label, fontsize=9.5, color=INK, loc="left")
            ax.set_ylim(0, max(vals) * 1.25)
            ax.grid(axis="x", visible=False)
        fig.tight_layout()
        fig.savefig(CHARTS / "antes_despues_scrypt_hilo.png")
        plt.close(fig)

    print(f"[+] Gráficas guardadas en {CHARTS.relative_to(BASE)}")


if __name__ == "__main__":
    main()
