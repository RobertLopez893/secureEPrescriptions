from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from src.core.config import settings

# Configuración para el hasheo de contraseñas con bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# tokenUrl es solo documental para /docs; el login real es /api/v1/auth/login
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

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
