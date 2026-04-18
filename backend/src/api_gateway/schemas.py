from pydantic import BaseModel
from datetime import datetime, date
from typing import List, Optional


class AccesoCreate(BaseModel):
    rol: str           # "paciente" | "farmaceutico" | "doctor"
    wrappedKey: str    # DEK envuelta en hex
    nonce: str         # Nonce del KeyWrap en hex

class RecetaCreate(BaseModel):
    # id_medico es ignorado salvo para rol Administrador: el backend toma
    # el id_medico del JWT del emisor. Queda opcional para permitir que
    # tooling administrativo emita recetas a nombre de otros.
    id_medico: Optional[int] = None
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
    # id_farmaceutico viene del JWT del farmacéutico que sella.
    # Opcional aquí solo para el camino de Administrador.
    id_farmaceutico: Optional[int] = None
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

class FarmaceuticoCreate(BaseModel):
    # Datos del usuario base
    nombre: str
    paterno: str
    materno: Optional[str] = None
    correo: str
    contrasena: str
    id_clinica: Optional[int] = None
    # Datos del perfil de farmacéutico
    licencia: str
    turno: str  # "Matutino" | "Vespertino" | "Nocturno"


# --- Schemas de Clinica ---

class ClinicaCreate(BaseModel):
    nombre: str
    clues: str
    calle: str
    colonia: str
    municipio: str
    estado: str
    cp: str
    tipo: str  # "Centro Medico" | "Hospital"

class ClinicaPublic(BaseModel):
    id_clinica: int
    nombre: str
    clues: str
    municipio: str
    estado: str
    tipo: str
