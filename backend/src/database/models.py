from typing import List, Optional
from datetime import datetime, date
from sqlmodel import Field, SQLModel, Relationship

# ==========================================
# 1. INFRAESTRUCTURA
# ==========================================
class Clinica(SQLModel, table=True):
    __tablename__ = "clinicas"
    
    id_clinica: Optional[int] = Field(default=None, primary_key=True)
    nombre: str = Field(index=True)
    clues: str = Field(unique=True) # Clave oficial de la secretaría
    
    calle: str
    colonia: str = Field(index=True)
    municipio: str = Field(index=True)
    estado: str = Field(index=True)
    cp: str
    tipo: str # (Centro Medico, Hospital)

    usuarios: List["Usuario"] = Relationship(back_populates="clinica")


# ==========================================
# 2. IDENTIDAD CENTRAL
# ==========================================
class Rol(SQLModel, table=True):
    __tablename__ = "roles"
    
    id_rol: Optional[int] = Field(default=None, primary_key=True)
    nombre: str = Field(index=True, unique=True) # Medico, Paciente, Farmaceutico
    
    usuarios: List["Usuario"] = Relationship(back_populates="rol")


class Usuario(SQLModel, table=True):
    __tablename__ = "usuarios"
    
    id_usuario: Optional[int] = Field(default=None, primary_key=True)
    id_rol: int = Field(foreign_key="roles.id_rol")
    id_clinica: Optional[int] = Field(default=None, foreign_key="clinicas.id_clinica")
    
    nombre: str
    paterno: str
    materno: Optional[str] = None
    correo: str = Field(unique=True, index=True)
    contrasena: str
    
    activo: bool = Field(default=True)
    creado_en: datetime = Field(default_factory=datetime.utcnow)

    # Relaciones
    rol: Rol = Relationship(back_populates="usuarios")
    clinica: Optional[Clinica] = Relationship(back_populates="usuarios")
    
    paciente: Optional["Paciente"] = Relationship(back_populates="usuario")
    medico: Optional["Medico"] = Relationship(back_populates="usuario")
    farmaceutico: Optional["Farmaceutico"] = Relationship(back_populates="usuario")
    llaves: List["Llave"] = Relationship(back_populates="usuario")


# ==========================================
# 3. PERFILES 
# ==========================================
class Paciente(SQLModel, table=True):
    __tablename__ = "pacientes"
    
    id_usuario: int = Field(foreign_key="usuarios.id_usuario", primary_key=True)
    
    curp: str = Field(unique=True, index=True)
    nacimiento: date
    sexo: str 
    tel_emergencia: str
    
    usuario: Usuario = Relationship(back_populates="paciente")


class Medico(SQLModel, table=True):
    __tablename__ = "medicos"
    
    id_usuario: int = Field(foreign_key="usuarios.id_usuario", primary_key=True)
    
    cedula: str = Field(unique=True, index=True)
    especialidad: str = Field(default="General")
    universidad: str
    
    usuario: Usuario = Relationship(back_populates="medico")


class Farmaceutico(SQLModel, table=True):
    __tablename__ = "farmaceuticos"
    
    id_usuario: int = Field(foreign_key="usuarios.id_usuario", primary_key=True)
    
    licencia: str = Field(unique=True)
    turno: str # Matutino, Vespertino, Nocturno
    
    usuario: Usuario = Relationship(back_populates="farmaceutico")


# ==========================================
# 4. ADMINISTRADOR AISLADO
# ==========================================
class Administrador(SQLModel, table=True):
    __tablename__ = "administradores"
    
    id_admin: Optional[int] = Field(default=None, primary_key=True)
    nombre: str
    correo: str = Field(unique=True, index=True)
    contrasena: str
    
    activo: bool = Field(default=True)
    creado_en: datetime = Field(default_factory=datetime.utcnow)


# ==========================================
# 5. CRIPTOGRAFÍA
# ==========================================
class Llave(SQLModel, table=True):
    __tablename__ = "llaves"
    
    id_llave: Optional[int] = Field(default=None, primary_key=True)
    id_usuario: int = Field(foreign_key="usuarios.id_usuario")
    
    llave_publica: str 
    activo: bool = Field(default=True)
    creado_en: datetime = Field(default_factory=datetime.utcnow)

    usuario: Usuario = Relationship(back_populates="llaves")


class Receta(SQLModel, table=True):
    __tablename__ = "recetas"
    
    id_receta: Optional[int] = Field(default=None, primary_key=True)
    id_medico: int = Field(foreign_key="usuarios.id_usuario", index=True)
    id_paciente: int = Field(foreign_key="usuarios.id_usuario", index=True)

    capsula: bytes # JSON cifrado
    iv: bytes # Vector de inicialización
    
    dek_medico: bytes
    dek_paciente: bytes
    dek_farmaceutico: bytes

    estado: str = Field(default="activa")
    creada_en: datetime = Field(default_factory=datetime.utcnow)
    expira_en: datetime