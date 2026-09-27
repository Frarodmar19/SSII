from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String
from app.database import Base


class User(Base):
    __tablename__ = "users"

    username = Column(String, primary_key=True, index=True)
    password_hash = Column(String, nullable=False)
    iban = Column(String, nullable=False, unique=True)

    # RS1.b: Control de intentos fallidos y bloqueo temporal
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)


class ActiveSession(Base):
    __tablename__ = "active_sessions"

    token = Column(String, primary_key=True, index=True)
    username = Column(String, nullable=False)
    session_key = Column(String, nullable=False)  # Clave de 256 bits en hex
    created_at = Column(DateTime, default=datetime.utcnow)