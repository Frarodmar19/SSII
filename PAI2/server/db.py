"""
server/db.py - Esquema de Base de Datos SQLite y Triggers de Inmutabilidad
Proyecto: PAI-2 BYODSEC (Rol A)
"""

import sqlite3
from pathlib import Path

DB_PATH = Path("server/byodsec.db")


def get_db_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Retorna una conexión a SQLite configurada con claves foráneas activas."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Path = DB_PATH):
    """Crea las tablas y los triggers de inmutabilidad si no existen."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # 1. Tabla de usuarios
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            role TEXT CHECK(role IN ('PDI', 'PAS', 'INV')),
            pwd_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            locked_until REAL DEFAULT 0,
            created_at REAL NOT NULL
        );
    """)

    # 2. Tabla de certificados emitidos
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            serial TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            fingerprint_sha256 TEXT NOT NULL,
            pubkey_pem TEXT NOT NULL,
            not_before REAL NOT NULL,
            not_after REAL NOT NULL,
            status TEXT CHECK(status IN ('valid', 'revoked')) DEFAULT 'valid',
            revoked_at REAL,
            reason TEXT,
            FOREIGN KEY(username) REFERENCES users(username)
        );
    """)

    # 3. Triggers de inmutabilidad (RF1): Abortan UPDATE en campos de identidad/criptografía
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_cert_identity_update
        BEFORE UPDATE OF serial, username, pubkey_pem, fingerprint_sha256 ON certificates
        BEGIN
            SELECT RAISE(ABORT, 'Inmutabilidad violada: No se permite modificar los datos del certificado.');
        END;
    """)

    # 4. Trigger de inmutabilidad (RF1): Aborta DELETE en la tabla de certificados
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_cert_delete
        BEFORE DELETE ON certificates
        BEGIN
            SELECT RAISE(ABORT, 'Inmutabilidad violada: No se permite eliminar registros de certificados.');
        END;
    """)

    conn.commit()
    conn.close()
    print(f"[+] Base de datos y triggers inicializados en: {db_path}")


if __name__ == "__main__":
    init_db()