from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String
from app.database import Base

#ROL A


#Modelo User: estructura de la tabla de ususarios 
class User(Base):
    __tablename__ = "users"

    username = Column(String, primary_key=True, index=True)
    password_hash = Column(String, nullable=False)
    iban = Column(String, nullable=False, unique=True)

    # RS1.b: Control de intentos fallidos y bloqueo temporal
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

# Modelo AtiveSession: estrucutra para almacenar las sesiones activas
class ActiveSession(Base):
    __tablename__ = "active_sessions"

    token = Column(String, primary_key=True, index=True)
    username = Column(String, nullable=False)
    session_key = Column(String, nullable=False)  # Clave simetrica de 256 bits en hex
    created_at = Column(DateTime, default=datetime.utcnow)
    
    
# ROL B: MODELOS DE INTEGRIDAD, ANTI-REPLAY Y TRANSFERENCIAS (RF2 / RS2 / RS3)

class ProcessedNonce(Base):
    """
    RS3: Almacenamiento persistente de números de un solo uso (nonces).
    Evita ataques de repetición (Replay Attacks). Todo nonce procesado se
    registra aquí como clave primaria para impedir su reutilización.
    Los registros caducados fuera de la ventana de 30 segundos son purgados.
    """
    __tablename__ = "processed_nonces"

    # Nonce aleatorio de 128 bits (32 caracteres hex) recibido en la cabecera X-Nonce
    nonce = Column(String, primary_key=True, index=True)

    # Marca de tiempo de recepción para facilitar la purga periódica de nonces expirados
    created_at = Column(DateTime, default=datetime.utcnow)


class Transfer(Base):
    """
    RF2: Registro de transferencias bancarias procesadas con éxito.
    Solo se insertan registros tras superar todas las validaciones de Rol B:
    firma HMAC-SHA256 legítima, timestamp vigente y nonce no repetido.
    """
    __tablename__ = "transfers"

    # Identificador autoincremental de la operación bancaria
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Cuenta de origen del dinero
    origin_iban = Column(String, nullable=False)

    # Cuenta de destino del dinero
    destination_iban = Column(String, nullable=False)

    # Cantidad transferida
    amount = Column(Float, nullable=False)

    # Concepto descriptivo de la operación
    concept = Column(String, nullable=True)

    # Timestamp de emisión en formato epoch entero reportado en la petición
    timestamp = Column(Integer, nullable=False)

    # Fecha y hora exacta de inserción en la base de datos local
    created_at = Column(DateTime, default=datetime.utcnow)   