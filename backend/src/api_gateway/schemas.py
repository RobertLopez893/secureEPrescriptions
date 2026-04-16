from pydantic import BaseModel
from datetime import datetime

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
