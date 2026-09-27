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