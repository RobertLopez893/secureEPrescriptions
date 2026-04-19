from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from src.core.config import settings

# tokenUrl es solo documental para /docs; el login real es /api/v1/auth/login
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

# Se usa bcrypt directo (no passlib) porque passlib 1.7.4 es incompatible
# con bcrypt >= 4.1: rompe al inspeccionar bcrypt.__about__ y dispara
# ValueError al detectar su "wrap bug". bcrypt directo funciona con toda
# la serie 4.x/5.x.
#
# bcrypt acepta como máximo 72 bytes: truncamos explícitamente para no
# propagar el ValueError si alguien envía una contraseña más larga. En la
# práctica bcrypt ignora los bytes a partir del 72 de todas formas.
_BCRYPT_MAX_BYTES = 72


def _encode(password: str) -> bytes:
    return password.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(_encode(plain_password), hashed_password.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(_encode(password), bcrypt.gensalt()).decode("utf-8")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


@dataclass(frozen=True)
class CurrentUser:
    """Vista liviana del JWT: lo justo para autorizar consultas."""
    id: int
    correo: str
    role: str  # "Medico" | "Paciente" | "Farmaceutico" | "Administrador"


def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> CurrentUser:
    """
    Dependencia FastAPI que valida el JWT emitido por /auth/login y devuelve
    un CurrentUser. Lanza 401 si el token falta, es inválido o expiró.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Se requiere autenticación.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("id")
    correo = payload.get("sub")
    role = payload.get("role")
    if user_id is None or role is None or correo is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token mal formado.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return CurrentUser(id=int(user_id), correo=str(correo), role=str(role))
