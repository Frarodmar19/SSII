import time
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.integrity import verificar_transferencia_firmada
from app.models import Transfer
from app.schemas import TransferResponse

router = APIRouter(tags=["Rol B - Transferencias"])


@router.post("/transfer", response_model=TransferResponse)
def transferir(
    datos_verificados=Depends(verificar_transferencia_firmada),
    db: Session = Depends(get_db)):
    """
    RF2: Solo se ejecuta si el middleware valida la firma HMAC,
    el timestamp dentro de ventana, el token y el nonce unico.
    """
    payload = datos_verificados["payload"]

    nueva_transferencia = Transfer(
        origin_iban=payload.get("origin_iban"),
        destination_iban=payload.get("destination_iban"),
        amount=float(payload.get("amount", 0.0)),
        concept=payload.get("concept", ""),
        timestamp=int(time.time())
    )
    db.add(nueva_transferencia)
    db.commit()
    db.refresh(nueva_transferencia)

    return {
        "status": "success",
        "mensaje": "Transferencia realizada con exito.",
        "transfer_id": nueva_transferencia.id,
        "datos": payload
    }