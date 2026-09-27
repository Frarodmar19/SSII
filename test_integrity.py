import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine, SessionLocal
from app.models import User, ActiveSession
from app.security import hash_password, firmar_mensaje
import time
import secrets

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    db.query(ActiveSession).delete()
    db.query(User).filter(User.username == "test_user").delete()

    user = User(
        username="test_user",
        password_hash=hash_password("Pass123!"),
        iban="ES0000000000000000000001",
        failed_attempts=0
    )
    db.add(user)
    
    session = ActiveSession(
        token="token_test_123",
        username="test_user",
        session_key=secrets.token_hex(32)
    )
    db.add(session)
    db.commit()
    
    key = session.session_key
    db.close()
    
    yield {"token": "token_test_123", "key": key}


def test_transferencia_exitosa(setup_db):
    token = setup_db["token"]
    key = setup_db["key"]
    nonce = secrets.token_hex(16)
    timestamp = int(time.time())
    payload = {
        "origin_iban": "ES0000000000000000000001",
        "destination_iban": "ES0000000000000000000002",
        "amount": 100.0,
        "concept": "Test unitario"
    }
    signature = firmar_mensaje(key, nonce, timestamp, payload)

    response = client.post(
        "/transfer",
        headers={
            "X-Session-Token": token,
            "X-Signature": signature,
            "X-Nonce": nonce,
            "X-Timestamp": str(timestamp)
        },
        json=payload
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"


def test_fallo_mitm_payload_alterado(setup_db):
    token = setup_db["token"]
    key = setup_db["key"]
    nonce = secrets.token_hex(16)
    timestamp = int(time.time())
    payload = {
        "origin_iban": "ES0000000000000000000001",
        "destination_iban": "ES0000000000000000000002",
        "amount": 100.0,
        "concept": "Test unitario"
    }
    signature = firmar_mensaje(key, nonce, timestamp, payload)

    payload["amount"] = 9999.0  # Manipulación en tránsito

    response = client.post(
        "/transfer",
        headers={
            "X-Session-Token": token,
            "X-Signature": signature,
            "X-Nonce": nonce,
            "X-Timestamp": str(timestamp)
        },
        json=payload
    )
    assert response.status_code == 401


def test_fallo_replay_attack(setup_db):
    token = setup_db["token"]
    key = setup_db["key"]
    nonce = secrets.token_hex(16)
    timestamp = int(time.time())
    payload = {
        "origin_iban": "ES0000000000000000000001",
        "destination_iban": "ES0000000000000000000002",
        "amount": 50.0,
        "concept": "Pago único"
    }
    signature = firmar_mensaje(key, nonce, timestamp, payload)
    headers = {
        "X-Session-Token": token,
        "X-Signature": signature,
        "X-Nonce": nonce,
        "X-Timestamp": str(timestamp)
    }

    # Primera petición: correcta
    r1 = client.post("/transfer", headers=headers, json=payload)
    assert r1.status_code == 200

    # Segunda petición idéntica con el mismo nonce: bloqueo por Replay
    r2 = client.post("/transfer", headers=headers, json=payload)
    assert r2.status_code == 400
    assert "Replay" in r2.json()["detail"]