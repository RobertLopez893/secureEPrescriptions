from pydantic import BaseModel
from datetime import datetime, date
from typing import List, Optional


class AccesoCreate(BaseModel):
    rol: str           # "paciente" | "farmaceutico" | "doctor"
    wrappedKey: str    # DEK envuelta en hex
    nonce: str         # Nonce del KeyWrap en hex

class RecetaCreate(BaseModel):
    id_medico: int
    id_paciente: int
    expira_en: datetime
    capsula_cifrada: str   # Ciphertext hex
    iv_aes_gcm: str        # Nonce AES-GCM hex
    accesos: List[AccesoCreate]


class AccesoPublic(BaseModel):
    rol: str
    wrappedKey: str
    nonce: str

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


class RecetaCriptoPublic(BaseModel):
    id_receta: int
    capsula_cifrada: str
    iv_aes_gcm: str
    accesos: List[AccesoPublic]
    estado: str

class RecetaSellarRequest(BaseModel):
    id_farmaceutico: int
    capsula_cifrada: str
    iv_aes_gcm: str
    accesos: List[AccesoCreate]


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
