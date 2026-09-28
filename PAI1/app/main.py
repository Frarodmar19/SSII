from datetime import datetime, timedelta
from fastapi import Depends, FastAPI, HTTPException, Header, status
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app.models import ActiveSession, User
from app.schemas import LoginResponse, UserLogin, UserRegister, UserResponse
from app.security import (
    DUMMY_HASH,
    generate_session_key_256bit,
    generate_session_token,
    hash_password,
    verify_password,
)

# Importar el router independiente de Rol B
from app.transfers import router as transfers_router

# Crear las tablas en la base de datos
Base.metadata.create_all(bind=engine)

app = FastAPI(title="SecBank API - PAI-1 IntegriDos", docs_url="/docs")


@app.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """RF1.a / RF1.c: Registro de usuario con verificación de duplicados y hash Argon2id."""
    # Verificar si el usuario ya existe
    existing_user = (
        db.query(User).filter(User.username == user_data.username).first()
    )
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El nombre de usuario ya está registrado.",
        )

    # Verificar si el IBAN ya existe
    existing_iban = (
        db.query(User).filter(User.iban == user_data.iban).first()
    )
    if existing_iban:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El IBAN introducido ya está asociado a otra cuenta.",
        )

    # Hashear contraseña con Argon2id + salt
    hashed_pwd = hash_password(user_data.password)

    new_user = User(
        username=user_data.username,
        password_hash=hashed_pwd,
        iban=user_data.iban,
        failed_attempts=0,
        locked_until=None,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/login", response_model=LoginResponse)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """RF1.d / RS1.b: Login con verificación Argon2id, mitigación de timing attacks y Rate Limiting."""
    user = (
        db.query(User).filter(User.username == credentials.username).first()
    )

    # 1. Protección contra usuarios inexistentes (Timing Attack Mitigation)
    target_hash = user.password_hash if user else DUMMY_HASH

    # 2. Comprobar si la cuenta está bloqueada temporalmente (RS1.b)
    if user and user.locked_until:
        if datetime.utcnow() < user.locked_until:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Cuenta bloqueada temporalmente tras superarse el número máximo de intentos. Inténtelo más tarde.",
            )
        else:
            # El tiempo de bloqueo ha expirado -> Resetear bloqueo
            user.locked_until = None
            user.failed_attempts = 0
            db.commit()

    # 3. Verificación de la contraseña
    is_valid = verify_password(target_hash, credentials.password)

    if not user or not is_valid:
        if user:
            user.failed_attempts += 1
            # Si alcanza 5 fallos, bloquear durante 60 segundos
            if user.failed_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(seconds=60)
            db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas.",
        )

    # Login correcto: Resetear el contador de intentos fallidos
    user.failed_attempts = 0
    user.locked_until = None

    # Generar token de sesión y Clave de Sesión de 256 bits
    token = generate_session_token()
    session_key = generate_session_key_256bit()

    active_session = ActiveSession(
        token=token, username=user.username, session_key=session_key
    )
    db.add(active_session)
    db.commit()

    return LoginResponse(
        message="Login exitoso",
        session_token=token,
        session_key=session_key,
        iban=user.iban,
    )


@app.post("/logout")
def logout(
    x_session_token: str = Header(..., alias="X-Session-Token"),
    db: Session = Depends(get_db),
):
    """RF1.b / RF1.d: Cierre de sesión e invalidación del token/clave activa."""
    session = (
        db.query(ActiveSession)
        .filter(ActiveSession.token == x_session_token)
        .first()
    )
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión no válida o ya cerrada.",
        )

    db.delete(session)
    db.commit()
    return {"message": "Sesión cerrada correctamente."}


# INTEGRACIÓN ROL B (Modular vía APIRouter)

app.include_router(transfers_router)


if __name__ == "__main__":
    import uvicorn
    # Puerto 8080 en HTTP plano (sin TLS)
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)