from typing import Optional
from pydantic import BaseModel


class UserRegister(BaseModel):
    username: str
    password: str
    iban: str


class UserLogin(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    message: str
    session_token: str
    session_key: str  # Clave de 256 bits para el Rol B
    iban: str


class UserResponse(BaseModel):
    username: str
    iban: str

    class Config:
        from_attributes = True
        
# ROL B: Esquemas para Transferencias (RF2)

class TransferRequest(BaseModel):
    origin_iban: str
    destination_iban: str
    amount: float
    concept: Optional[str] = None


class TransferResponse(BaseModel):
    status: str
    mensaje: str
    transfer_id: int
    datos: TransferRequest        