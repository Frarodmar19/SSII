# ROL A: Congiduración del motor de la base de datos de SQLite y la sesión de SQLAlchemy
# (engine, SessionLocal, Base)
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Base de datos SQLite local
SQLALCHEMY_DATABASE_URL = "sqlite:///./secbank.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# Dependencia para obtener la sesión de BD en cada request
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()