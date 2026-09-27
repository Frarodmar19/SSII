from datetime import datetime
import time
from app.database import Base, SessionLocal, engine
from app.models import Transfer

# Asegurar tablas en BD
Base.metadata.create_all(bind=engine)

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
    """Inserta transferencias de prueba para Rol B si la tabla está vacía."""
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


if __name__ == "__main__":
    seed_transfers()