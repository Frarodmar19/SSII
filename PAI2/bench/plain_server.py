"""
bench/plain_server.py - Línea base SIN TLS para la comparativa de rendimiento (RS3)
Proyecto: PAI-2 BYODSEC (Rol C)

Ejecuta exactamente la misma lógica de aplicación que el gateway (tramas, LOGIN con
scrypt, MSG, LOGOUT, auditoría) pero sobre TCP en claro. Así la diferencia medida
frente al puerto 9443 es solo el coste de TLS 1.3 + mTLS.

También sirve de "antes" en la auditoría de tráfico: en su captura .pcap se leen
usuario y contraseña (evidence/pcap/01_plain_login.pcap).

NO desplegar: es solo para medidas y demostraciones.

Uso: python -m bench.plain_server            (puerto 9080)
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.gateway import handle_gateway_connection  # noqa: E402

PORT = int(os.environ.get("PLAIN_PORT", "9080"))
BIND = os.environ.get("GATEWAY_BIND", "0.0.0.0")


async def main():
    server = await asyncio.start_server(handle_gateway_connection, BIND, PORT, backlog=1024)
    print(f"[*] Servidor de referencia en claro (sin TLS) escuchando en {BIND}:{PORT}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
