from datetime import timedelta
from typing import Union

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from src.core.config import settings
from src.core import security
from src.database.database import get_session
from src.database.models import Usuario, Administrador
from src.api_gateway import schemas

router = APIRouter()

def authenticate_user(session: Session, correo: str, contrasena: str) -> Union[Usuario, Administrador, None]:
    """
    Busca un usuario o administrador por correo y verifica su contraseña.
    """
    # Primero busca en la tabla de usuarios generales (médico, paciente, etc.)
    user = session.exec(select(Usuario).where(Usuario.correo == correo)).first()
    if user and security.verify_password(contrasena, user.contrasena):
        return user

    # Si no, busca en la tabla de administradores
    admin = session.exec(select(Administrador).where(Administrador.correo == correo)).first()
    if admin and security.verify_password(contrasena, admin.contrasena):
        return admin

    return None


@router.post("/login", response_model=schemas.Token)
def login_for_access_token(
    *,
    session: Session = Depends(get_session),
    login_data: schemas.LoginRequest
):
    """
    Endpoint de login para todos los roles. Devuelve un JWT si las credenciales son válidas.
    """
    user_or_admin = authenticate_user(session=session, correo=login_data.correo, contrasena=login_data.contrasena)

    if not user_or_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Correo o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Determinar el rol y el ID para el payload del token
    if isinstance(user_or_admin, Usuario):
        session.refresh(user_or_admin, ["rol"]) # Aseguramos que la relación de rol esté cargada
        role_name = user_or_admin.rol.nombre
        user_id = user_or_admin.id_usuario
    else: # Es un Administrador
        role_name = "Administrador"
        user_id = user_or_admin.id_admin

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user_or_admin.correo, "role": role_name, "id": user_id},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}
