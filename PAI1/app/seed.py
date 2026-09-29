from datetime import datetime
import time

from app.database import Base, SessionLocal, engine
from app.models import User, Transfer
from app.security import hash_password

# Crear tablas si no existen
Base.metadata.create_all(bind=engine)


def seed_users():
    db = SessionLocal()

    if db.query(User).count() > 0:
        print("La base de datos ya contiene usuarios.")
        db.close()
        return

    users_data = [
        {
            "username": "alice",
            "password": "PasswordAlice123!",
            "iban": "ES9121000418450200051234",
        },
        {
            "username": "bob",
            "password": "PasswordBob123!",
            "iban": "ES1221000418450200055678",
        },
        {
            "username": "charlie",
            "password": "PasswordCharlie123!",
            "iban": "ES0021000418450200059999",
        },
    ]

    for u in users_data:
        hashed_pwd = hash_password(u["password"])
        user = User(
            username=u["username"], password_hash=hashed_pwd, iban=u["iban"]
        )
        db.add(user)

    db.commit()
    db.close()
    print("Base de datos precargada con exito (alice, bob, charlie).")


# ==============================================================================
# ROL B: DATOS SEMILLA PARA TRANSFERENCIAS BANCARIAS (RF2)
# ==============================================================================
TRANSFERS_SEED = [
    {
        "origin_iban": "ES9121000418450200051234",      # Alice
        "destination_iban": "ES1221000418450200055678", # Bob
        "amount": 50.00,
        "concept": "Transferencia inicial de prueba",
        "timestamp": int(time.time()),
    }
]


def seed_transfers():
    """Inserta transferencias de prueba para Rol B si la tabla esta vacia."""
    db = SessionLocal()

    if db.query(Transfer).count() > 0:
        print("La tabla de transferencias ya contiene datos de prueba.")
        db.close()
        return

    for t in TRANSFERS_SEED:
        transferencia = Transfer(
            origin_iban=t["origin_iban"],
            destination_iban=t["destination_iban"],
            amount=t["amount"],
            concept=t["concept"],
            timestamp=t["timestamp"],
            created_at=datetime.utcnow(),
        )
        db.add(transferencia)

    db.commit()
    db.close()
    print("Transferencias de prueba de Rol B insertadas correctamente.")


def seed_database():
    seed_users()
    seed_transfers()


if __name__ == "__main__":
    seed_database()
