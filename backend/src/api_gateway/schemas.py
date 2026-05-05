from pydantic import BaseModel, field_validator
from datetime import datetime, date
from typing import List, Optional


# ---------------------------------------------------------------------------
# Helpers de validación hex — item 19 del hardening.
# El backend guarda el material criptográfico como texto hexadecimal dentro
# de la columna JSON `accesos` y en los campos `capsula_cifrada` / `iv_aes_gcm`
# de recetas. Si dejamos pasar basura (emojis, SQL, binario crudo), rompemos
# el contrato con el frontend y nos exponemos a payloads maliciosos en la BD.
# Estos validadores rechazan todo lo que no sea hex puro y, cuando aplica,
# imponen la longitud exacta que dicta el protocolo.
# ---------------------------------------------------------------------------
_MAX_HEX_LEN_GENERIC = 8192        # tope defensivo para capsulas cifradas
_P256_PUBKEY_LEN_HEX = 130         # 04 + X(32B) + Y(32B) en hex
_P256_SIG_LEN_HEX    = 128         # r(32B) || s(32B) en hex
_AES_GCM_NONCE_HEX   = 24          # 12 bytes recomendados por NIST


def _assert_hex(value: str, *, field: str, min_len: int = 2, max_len: int = _MAX_HEX_LEN_GENERIC) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field}: debe ser string hex")
    v = value.strip()
    if len(v) < min_len or len(v) > max_len:
        raise ValueError(f"{field}: longitud fuera de rango ({len(v)} chars)")
    if len(v) % 2 != 0:
        raise ValueError(f"{field}: longitud hex debe ser par")
    try:
        int(v, 16)
    except ValueError:
        raise ValueError(f"{field}: contiene caracteres no hex")
    return v


def _assert_hex_exact(value: str, *, field: str, length: int) -> str:
    v = _assert_hex(value, field=field, min_len=length, max_len=length)
    if len(v) != length:
        raise ValueError(f"{field}: debe tener exactamente {length} caracteres hex")
    return v


class AccesoCreate(BaseModel):
    rol: str           # "paciente" | "farmaceutico" | "doctor"
    wrappedKey: str    # DEK envuelta en hex
    ephemeral_pub_hex: str         # Llave pública ephemeral en hex

    @field_validator("rol")
    @classmethod
    def _v_rol(cls, v: str) -> str:
        v = (v or "").strip()
        # Aceptamos los tres roles clínicos en minúsculas o mayúsculas.
        allowed = {"paciente", "medico", "médico", "doctor", "farmaceutico", "farmacéutico"}
        if v.lower() not in allowed:
            raise ValueError("rol no reconocido en acceso criptográfico")
        return v

    @field_validator("wrappedKey")
    @classmethod
    def _v_wrapped(cls, v: str) -> str:
        # La DEK envuelta no tiene longitud fija (depende del tamaño del
        # payload interno), pero debe ser hex par y caber bajo el tope.
        return _assert_hex(v, field="wrappedKey", min_len=2, max_len=_MAX_HEX_LEN_GENERIC)

    @field_validator("ephemeral_pub_hex")
    @classmethod
    def _v_ephemeral(cls, v: str) -> str:
        return _assert_hex_exact(v, field="ephemeral_pub_hex", length=_P256_PUBKEY_LEN_HEX)

class RecetaCreate(BaseModel):
    folio: str
    id_medico: int
    id_paciente: int
    id_farmaceutico: int

    capsula_cifrada: str   # Ciphertext hex
    nonce: str        # Nonce AES-GCM hex
    accesos: List[AccesoCreate]
    
    creada_en: datetime 
    expira_en: datetime
    
    @field_validator("capsula_cifrada")
    @classmethod
    def _v_capsula(cls, v: str) -> str:
        return _assert_hex(v, field="capsula_cifrada", min_len=2, max_len=_MAX_HEX_LEN_GENERIC)

    @field_validator("nonce")
    @classmethod
    def _v_nonce(cls, v: str) -> str:
        return _assert_hex_exact(v, field="nonce", length=_AES_GCM_NONCE_HEX)



class AccesoPublic(BaseModel):
    rol: str
    wrappedKey: str
    ephemeral_pub_hex: str

class RecetaPublic(BaseModel):
    id_receta: int
    folio: str
    estado: str
    creada_en: datetime
    expira_en: datetime


class UserInfo(BaseModel):
    nombre_completo: str

class RecetaDetailPublic(RecetaPublic):
    # Ids para que los clientes puedan resolver llaves públicas o enlazar
    # con las vistas del emisor/paciente sin llamar al endpoint de cripto.
    folio: str
    id_medico: int
    id_paciente: int
    id_farmaceutico: int
    medico: UserInfo
    paciente: UserInfo
    farmaceutico: UserInfo
    vencida: bool = False
    


class RecetaCriptoPublic(BaseModel):
    id_receta: int
    folio: str
    # Ids de las partes para que el cliente pueda consultar sus llaves
    # públicas activas vía GET /usuarios/{id}/llave sin una segunda llamada
    # al detalle de la receta.
    id_medico: int
    id_paciente: int
    id_farmaceutico: int
    capsula_cifrada: str
    nonce: str
    accesos: List[AccesoPublic]
    estado: str

class RecetaSellarRequest(BaseModel):
    # id_farmaceutico viene del JWT del farmacéutico que sella.
    # Opcional aquí solo para el camino de Administrador.
    id_farmaceutico: int
    capsula_cifrada: str
    nonce: str
    accesos: List[AccesoCreate]

    @field_validator("capsula_cifrada")
    @classmethod
    def _v_capsula_sellar(cls, v: str) -> str:
        return _assert_hex(v, field="capsula_cifrada", min_len=2, max_len=_MAX_HEX_LEN_GENERIC)

    @field_validator("nonce")
    @classmethod
    def _v_nonce_sellar(cls, v: str) -> str:
        return _assert_hex_exact(v, field="nonce", length=_AES_GCM_NONCE_HEX)


class LoginRequest(BaseModel):
    correo: str
    contrasena: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# --- Schemas de login por tarjeta (challenge / response ECDSA) ---

class AuthChallengeRequest(BaseModel):
    """
    Primer paso del login por tarjeta. El cliente identifica al usuario
    con su identificador de rol:
      - Paciente     -> CURP
      - Medico       -> cedula profesional
      - Farmaceutico -> licencia
    El backend responde con un nonce aleatorio de 32 bytes y su TTL.
    """
    rol: str            # "Paciente" | "Medico" | "Farmaceutico"
    identificador: str  # CURP / cedula / licencia (según rol)

class AuthChallengeResponse(BaseModel):
    # Nonce hex (64 chars, 32 bytes aleatorios) que el cliente debe firmar
    # con la llave privada derivada de su tarjeta.
    nonce_hex: str
    # Epoch UTC en segundos cuando el nonce deja de ser aceptado.
    expira_unix: int

class AuthVerifyRequest(BaseModel):
    """
    Segundo paso: el cliente envía el identificador (igual que en el
    challenge), el nonce que recibió y la firma ECDSA P-256 del mismo
    en formato compacto r||s (128 chars hex).
    """
    rol: str
    identificador: str
    nonce_hex: str
    firma_hex: str

    @field_validator("nonce_hex")
    @classmethod
    def _v_nonce_hex(cls, v: str) -> str:
        # 32 bytes aleatorios => 64 chars hex. Tolerante a mayúsculas.
        return _assert_hex_exact(v, field="nonce_hex", length=64)

    @field_validator("firma_hex")
    @classmethod
    def _v_firma_hex(cls, v: str) -> str:
        return _assert_hex_exact(v, field="firma_hex", length=_P256_SIG_LEN_HEX)

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
    # Llave pública P-256 (uncompressed hex, 130 chars) generada en el cliente
    # al momento del registro. Opcional en la API (flujo legacy sin llave),
    # pero el frontend debería enviarla siempre para el flujo criptográfico.
    llave_publica: Optional[str] = None

    @field_validator("llave_publica")
    @classmethod
    def _v_llave_pub(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        out = _assert_hex_exact(v, field="llave_publica", length=_P256_PUBKEY_LEN_HEX)
        if not out.lower().startswith("04"):
            raise ValueError("llave_publica: debe ser P-256 uncompressed (prefijo 04)")
        return out

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
    llave_publica: Optional[str] = None

    @field_validator("llave_publica")
    @classmethod
    def _v_llave_pub(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        out = _assert_hex_exact(v, field="llave_publica", length=_P256_PUBKEY_LEN_HEX)
        if not out.lower().startswith("04"):
            raise ValueError("llave_publica: debe ser P-256 uncompressed (prefijo 04)")
        return out

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
    llave_publica: Optional[str] = None

    @field_validator("llave_publica")
    @classmethod
    def _v_llave_pub(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        out = _assert_hex_exact(v, field="llave_publica", length=_P256_PUBKEY_LEN_HEX)
        if not out.lower().startswith("04"):
            raise ValueError("llave_publica: debe ser P-256 uncompressed (prefijo 04)")
        return out


# --- Schemas de Llaves públicas ---

class LlavePublicaIn(BaseModel):
    """Payload para registrar/rotar la llave pública del usuario autenticado."""
    llave_publica: str 
    responsabilidad: str # 'recetas', 'acceso', etc.

    @field_validator("llave_publica")
    @classmethod
    def _v_llave_publica(cls, v: str) -> str:
        v = _assert_hex_exact(v, field="llave_publica", length=_P256_PUBKEY_LEN_HEX)
        # P-256 uncompressed SEC1 siempre comienza con el byte 0x04.
        if not v.lower().startswith("04"):
            raise ValueError("llave_publica: debe ser P-256 uncompressed (prefijo 04)")
        return v

class LlavePublicaOut(BaseModel):
    id_usuario: int
    llave_publica: str
    responsabilidad: str # 'recetas', 'acceso', etc.


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
