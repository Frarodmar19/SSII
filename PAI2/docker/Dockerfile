# PAI-2 BYODSEC - imagen común para gateway, clientes, bench y ataques (Rol C)
FROM python:3.12-slim

# tcpdump para el contenedor sniffer; openssl para pruebas de política TLS
RUN apt-get update && apt-get install -y --no-install-recommends \
        tcpdump openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencias Python (solo cryptography, matplotlib y psutil; el resto es stdlib)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Código del proyecto
COPY . .

# RS2: OpenSSL debe cargar la política de suites TLS 1.3 antes de que Python importe ssl
ENV OPENSSL_CONF=/app/server/openssl.cnf \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

# Deja constancia de las versiones en el arranque (traza de entorno reproducible)
RUN python -c "import ssl, sys; print('Python', sys.version.split()[0], '/', ssl.OPENSSL_VERSION)"

CMD ["python", "server/gateway.py"]
