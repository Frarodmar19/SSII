# Contrato de Mensaje y Transacciones - SecBank (PAI-1)

## 1. Clave de Sesión
Al realizar un login exitoso (`POST /login`), el servidor devuelve:
- `session_token`: Identificador de sesión.
- `session_key`: Clave secreta de 256 bits (32 bytes en hex) generada con `secrets.token_hex(32)`.

## 2. Payload de Transacción (JSON)
```json
{
  "sender_iban": "ES9121000418450200051234",
  "receiver_iban": "ES1221000418450200055678",
  "amount": 150.50,
  "concept": "Pago de prueba"
}

---

### **PASO 2: IMPLEMENTACIÓN DEL CÓDIGO (FASES 1, 2 Y 3)**

#### 2.1. Configuración de Base de Datos (`app/database.py`)
Configura la conexión a SQLite con SQLAlchemy:

```python
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