from app.database import Base, SessionLocal, engine
from app.models import User
from app.security import hash_password

#ROL A: Script base de datos e inserta usuario de prueba

# Crear tablas si no existen
Base.metadata.create_all(bind=engine)


def seed_database():
    db = SessionLocal()

    # Verificar si ya existen usuarios
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
    print("Base de datos precargada con éxito (alice, bob, charlie).")


if __name__ == "__main__":
    seed_database()