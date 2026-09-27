import hashlib
import hmac
import json
import secrets
import time
import requests

BASE_URL = "http://127.0.0.1:8080"


def firmar(session_key_hex, nonce, timestamp, payload):
    """Calcula el digest HMAC-SHA256 sobre el mensaje canónico."""
    clave_bytes = bytes.fromhex(session_key_hex)
    payload_canonico = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    mensaje = f"{nonce}{timestamp}{payload_canonico}".encode("utf-8")
    return hmac.new(clave_bytes, mensaje, hashlib.sha256).hexdigest()


def main():
    print("=== 1. AUTENTICACIÓN (ROL A) ===")
    login_resp = requests.post(
        f"{BASE_URL}/login",
        json={"username": "alice", "password": "PasswordAlice123!"}
    )

    if login_resp.status_code != 200:
        print(f"Error en login: {login_resp.status_code} - {login_resp.text}")
        return

    data = login_resp.json()
    token = data["session_token"]
    session_key = data["session_key"]
    iban_alice = data["iban"]
    print(f"Login exitoso.")
    print(f"Token: {token}")
    print(f"Session Key: {session_key}\n")

    # Datos base para la transferencia
    payload = {
        "origin_iban": iban_alice,
        "destination_iban": "ES1221000418450200055678",
        "amount": 25.50,
        "concept": "Cena de ayer"
    }

    # Metadatos para la petición legítima
    nonce_legitimo = secrets.token_hex(16)
    timestamp_legitimo = int(time.time())
    firma_legitima = firmar(session_key, nonce_legitimo, timestamp_legitimo, payload)

    headers_legitimos = {
        "X-Session-Token": token,
        "X-Signature": firma_legitima,
        "X-Nonce": nonce_legitimo,
        "X-Timestamp": str(timestamp_legitimo),
        "Content-Type": "application/json"
    }

    print("=== 2. PRUEBA TRANSFERENCIA LEGÍTIMA ===")
    r1 = requests.post(f"{BASE_URL}/transfer", headers=headers_legitimos, json=payload)
    print(f"Status: {r1.status_code} (Esperado: 200)")
    print(f"Respuesta: {r1.json()}\n")

    print("=== 3. PRUEBA MAN-IN-THE-MIDDLE (MITM - ALTERACIÓN DE DATOS) ===")
    # Generamos un nonce nuevo para aislar la prueba de integridad del control anti-replay
    nonce_mitm = secrets.token_hex(16)
    timestamp_mitm = int(time.time())
    firma_original = firmar(session_key, nonce_mitm, timestamp_mitm, payload)

    headers_mitm = {
        "X-Session-Token": token,
        "X-Signature": firma_original,
        "X-Nonce": nonce_mitm,
        "X-Timestamp": str(timestamp_mitm),
        "Content-Type": "application/json"
    }

    # El atacante altera el payload en tránsito pero no tiene la clave simétrica para firmar
    payload_alterado = payload.copy()
    payload_alterado["amount"] = 500.00
    r2 = requests.post(f"{BASE_URL}/transfer", headers=headers_mitm, json=payload_alterado)
    print(f"Status: {r2.status_code} (Esperado: 401)")
    print(f"Respuesta: {r2.json()}\n")

    print("=== 4. PRUEBA ATAQUE REPLAY (REUTILIZACIÓN DE NONCE) ===")
    # Reenviamos exactamente la petición legítima inicial con el mismo nonce
    r3 = requests.post(f"{BASE_URL}/transfer", headers=headers_legitimos, json=payload)
    print(f"Status: {r3.status_code} (Esperado: 400)")
    print(f"Respuesta: {r3.json()}\n")


if __name__ == "__main__":
    main()