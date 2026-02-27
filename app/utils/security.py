import random
import string
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import JWTError, jwt
from app.config import settings

# Configuraciones del hash de la contraseña
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Hash de la contraseña
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Verificar contraseña con el hash
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# Generar codigo unico de 6 digitos verificando que no exista en la BD
def generar_codigo_unico(conn) -> str:
    while True:
        codigo = str(random.randint(100000, 999999))
        if not codigo_existe_en_bd(conn, codigo):
            return codigo


# Verificar si el codigo ya existe en la BD solo con codigos vigentes
def codigo_existe_en_bd(conn, codigo: str) -> bool:
    cursor = conn.cursor()
    cursor.execute(
        "SELECT codigo_auth_hash FROM children WHERE code_expires_at > NOW()"
    )
    registros = cursor.fetchall()
    cursor.close()

    for registro in registros:
        if pwd_context.verify(codigo, registro["codigo_auth_hash"]):
            return True
    return False


# Hashear el codigo para guardarlo en la BD
def hash_codigo(codigo: str) -> str:
    return pwd_context.hash(codigo)


# Verificar codigo del hijo y retornar su id si es valido
def verificar_codigo_hijo(conn, codigo: str):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, codigo_auth_hash FROM children WHERE code_expires_at > NOW()"
    )
    registros = cursor.fetchall()
    cursor.close()

    for registro in registros:
        if pwd_context.verify(codigo, registro["codigo_auth_hash"]):
            return registro["id"]
    return None


# Crear token JWT
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt

# Decodificar y verificar JWT
def verify_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        return payload
    except JWTError:
        return None
