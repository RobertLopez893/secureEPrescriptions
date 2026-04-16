from pydantic import BaseModel
from datetime import datetime, date
from typing import Optional

class RecetaCreate(BaseModel):
    """
    Schema para recibir los datos de una nueva receta desde el frontend.
    Los campos criptográficos se reciben como strings (Base64) y se convertirán a bytes en el backend.
    """
    id_medico: int
    id_paciente: int
    expira_en: datetime

    # Campos criptográficos (en formato Base64)
    capsula: str
    iv: str
    dek_medico: str
    dek_paciente: str
    dek_farmaceutico: str


class RecetaPublic(BaseModel):
    id_receta: int
    estado: str
    creada_en: datetime


class UserInfo(BaseModel):
    nombre_completo: str

class RecetaDetailPublic(RecetaPublic):
    expira_en: datetime
    medico: UserInfo
    paciente: UserInfo


class LoginRequest(BaseModel):
    correo: str
    contrasena: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

# --- Schemas de Creación de Usuarios ---

class UsuarioPublic(BaseModel):
    id_usuario: int
    correo: str
    nombre: str
    paterno: str
    rol_nombre: str

class PacienteCreate(BaseModel):
    # Datos del usuario base
    nombre: str
    paterno: str
    materno: Optional[str] = None
    correo: str
    contrasena: str
    id_clinica: Optional[int] = None
    # Datos del perfil de paciente
    curp: str
    nacimiento: date
    sexo: str
    tel_emergencia: str

class MedicoCreate(BaseModel):
    # Datos del usuario base
    nombre: str
    paterno: str
    materno: Optional[str] = None
    correo: str
    contrasena: str
    id_clinica: int # Requerido para médicos
    # Datos del perfil de médico
    cedula: str
    especialidad: str
    universidad: str
