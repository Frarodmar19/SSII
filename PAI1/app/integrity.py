import time
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ActiveSession, ProcessedNonce
from app.security import verificar_firma

# Ventana de validez máxima para la marca temporal (en segundos)
VENTANA_TIEMPO_SEGUNDOS = 30


async def verificar_transferencia_firmada(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    RS2 / RS3 / RS4: Middleware de integridad bancaria.
    Valida:
    1. Presencia de cabeceras de seguridad.
    2. Timestamp numérico y dentro de la ventana de tolerancia (+-30s).
    3. Validez de la sesión y obtención de la clave simétrica K.
    4. Unicidad del Nonce para prevenir ataques de repetición (Replay Attacks).
    5. Verificación de la firma HMAC-SHA256 sobre el JSON canónico en tiempo constante.
    """
    token = request.headers.get("x-session-token")
    signature = request.headers.get("x-signature")
    nonce = request.headers.get("x-nonce")
    timestamp_raw = request.headers.get("x-timestamp")

    # 1. Comprobar cabeceras obligatorias
    if not token or not signature or not nonce or not timestamp_raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Faltan cabeceras requeridas (X-Session-Token, X-Signature, X-Nonce, X-Timestamp).",
        )

    # 2. Validar formato numérico del timestamp
    try:
        timestamp = int(timestamp_raw)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Timestamp debe ser un número entero (epoch Unix).",
        )

    # Validar ventana de frescura temporal (+-30 segundos)
    ahora_epoch = time.time()
    if abs(ahora_epoch - timestamp) > VENTANA_TIEMPO_SEGUNDOS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Timestamp fuera de la ventana permitida (30 segundos).",
        )

    # 3. Comprobar sesión activa y recuperar clave de 256 bits
    session = (
        db.query(ActiveSession)
        .filter(ActiveSession.token == token)
        .first()
    )
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión no válida, expirada o cerrada.",
        )

    # 4. Control Anti-Replay: Comprobar si el nonce ya ha sido registrado
    nonce_existente = (
        db.query(ProcessedNonce)
        .filter(ProcessedNonce.nonce == nonce)
        .first()
    )
    if nonce_existente:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ataque Replay detectado: Este nonce ya ha sido procesado.",
        )

    # 5. Obtener payload JSON del cuerpo
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cuerpo de la petición vacío o JSON malformado.",
        )

    # 6. Verificación criptográfica HMAC-SHA256 en tiempo constante (RS2 / RS4)
    session_key_bytes = bytes.fromhex(session.session_key)
    es_valida = verificar_firma(
        session_key_bytes, nonce, timestamp, payload, signature
    )

    if not es_valida:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Fallo de integridad: La firma HMAC no coincide o el mensaje fue alterado.",
        )

    # Si todo es correcto, registramos el nonce para evitar reutilizaciones
    db.add(ProcessedNonce(nonce=nonce))

    # Limpieza periódica de nonces más antiguos que la ventana de expiración
    limite_antiguedad = datetime.utcnow() - timedelta(seconds=VENTANA_TIEMPO_SEGUNDOS)
    db.query(ProcessedNonce).filter(ProcessedNonce.created_at < limite_antiguedad).delete()

    db.commit()

    # Retorna los datos limpios al endpoint de transferencias
    return {"payload": payload, "username": session.username}