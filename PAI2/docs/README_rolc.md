# Rol C — Cómo reproducir las evidencias

Requisitos: Python 3.11+, `cryptography`, `psutil`, `matplotlib`, `pytest`, y
`tcpdump` (solo para capturar `.pcap`). Todo desde la carpeta `PAI2/`.

## 1. Preparar PKI y usuarios (lo hace el Rol A)

```bash
python -c "from pki.ca import generate_ca; generate_ca(force=True)"
python -c "from pki.issue import issue_server_cert; issue_server_cert()"
python -c "from pki.crl import generate_crl; generate_crl([])"
python -m seed.seed_users          # 300 usuarios PDI/PAS/INV con certificado
```

## 2. Arrancar los servidores

```bash
# El gateway exige que OPENSSL_CONF esté puesto ANTES de importar ssl (RS2);
# gateway.py ya lo fija solo, pero en shell conviene exportarlo:
export OPENSSL_CONF=$PWD/server/openssl.cnf
python server/gateway.py            # puertos 8443 (enrol) y 9443 (mTLS)
python -m bench.plain_server        # referencia en claro, puerto 9080
```

## 3. Prueba de carga y gráficas (RS3)

```bash
# 300 sesiones concurrentes sobre el túnel
python -m bench.load_test --mode tls --clients 300 --msgs 20 --server-pid <PID_gateway>
# escalado y comparativa
python -m bench.load_test --mode plain --scale 50,100,200,300,500 --server-pid <PID_plain>
python -m bench.load_test --mode tls   --scale 50,100,200,300,500 --server-pid <PID_gateway>
python -m bench.plot                 # genera evidence/charts/*.png
```

## 4. Capturas y ataques (RS4, extra +10%)

```bash
# Confidencialidad: credenciales en claro vs túnel (necesita ambos servidores)
sudo -E python -m attacks.capture_plain_vs_tunnel --iface lo

# Batería de ataques contra el gateway (cada uno debe ser RECHAZADO)
sudo -E python -m attacks.run_attacks --host 127.0.0.1 --port 9443 --iface lo

# Verificar la integridad de la auditoría
python -m server.verify_audit
```

## 5. Pruebas automáticas

```bash
pytest -q                            # 16 pruebas, incluidas las de ataques
```

## 6. Todo en Docker (reproducible)

```bash
cd docker
docker compose run --rm ca-init
docker compose up -d gateway sniffer
docker compose run --rm bench
docker compose run --rm attacker
docker compose --profile plain up -d plain-server
```

Las evidencias quedan en `evidence/` (`bench/`, `charts/`, `pcap/`, `logs/`).
