import os
import secrets
import hashlib
import hmac
from datetime import date
from sqlmodel import Session, select

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.database import models
from src.core import security

# ── Derivación de llaves demo ────────────────────────────────────────────
_HKDF_SALT = b"rxpro-2026:cardkey-salt:v1"
_HKDF_INFO_RECIPES = b"rxpro-v1:p256:recipes_key"
_HKDF_INFO_SIGN = b"rxpro-v1:p256:signing_key"
_P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    prev = b""
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        okm += prev
        counter += 1
    return okm[:length]

def _pub_hex_from_seed_hex(seed_hex: str, _hkdf_info: bytes) -> str:
    seed = bytes.fromhex(seed_hex.strip().lower())
    if len(seed) != 32:
        raise ValueError("La semilla debe ser exactamente 32 bytes.")
    for counter in range(256):
        info = _hkdf_info + bytes([counter])
        raw = _hkdf_sha256(seed, _HKDF_SALT, info, 32)
        scalar = int.from_bytes(raw, "big")
        if 0 < scalar < _P256_N:
            priv = ec.derive_private_key(scalar, ec.SECP256R1())
            pub_bytes = priv.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )
            return pub_bytes.hex()
    raise RuntimeError("No se pudo derivar un escalar válido desde la semilla.")

def _resolve_demo_seed(env_var: str, label: str) -> str:
    raw = (os.getenv(env_var) or "").strip().lower()
    if len(raw) == 64 and all(c in "0123456789abcdef" for c in raw):
        return raw
    generated = secrets.token_hex(32)
    print(f"⚠ Semilla demo generada para {label}: {generated}")
    print(f"  Guarda en tu .env como {env_var}={generated} si quieres persistirla.")
    return generated

def _ensure_roles(session: Session) -> None:
    rol_check = session.exec(select(models.Rol)).first()
    if not rol_check:
        print("Creando roles iniciales...")
        for nombre in ("Medico", "Paciente", "Farmaceutico"):
            session.add(models.Rol(nombre=nombre))
        session.commit()
        print("Roles creados.")

def _get_rol(session: Session, nombre: str) -> models.Rol:
    rol = session.exec(select(models.Rol).where(models.Rol.nombre == nombre)).first()
    if not rol:
        raise RuntimeError(f"Rol '{nombre}' no encontrado al sembrar datos demo.")
    return rol

def _seed_demo_data(session: Session) -> None:
    if os.getenv("APP_ENV", "development").lower() != "development":
        return
    if session.exec(select(models.Usuario)).first():
        return  

    print("Sembrando datos demo (APP_ENV=development)...")

    clinica = session.exec(
        select(models.Clinica).where(models.Clinica.clues == "DEMO0000001")
    ).first()
    if clinica is None:
        clinica = models.Clinica(
            nombre="Clínica Demo RxFlow", clues="DEMO0000001", calle="Av. Ficticia 123",
            colonia="Centro", municipio="Ciudad Demo", estado="CDMX", cp="01000", tipo="Centro Medico",
        )
        session.add(clinica)
        session.commit()
        session.refresh(clinica)

    rol_medico = _get_rol(session, "Medico")
    rol_paciente = _get_rol(session, "Paciente")
    rol_farma = _get_rol(session, "Farmaceutico")

    hashed = security.get_password_hash("demo1234")

    medico_u = models.Usuario(
        id_rol=rol_medico.id_rol, id_clinica=clinica.id_clinica, nombre="Demo", paterno="Médico",
        correo="doctor@rxpro.demo", contrasena=hashed,
        medico=models.Medico(cedula="DEMO-MED-0001", especialidad="General", universidad="Universidad Demo"),
    )
    paciente_u = models.Usuario(
        id_rol=rol_paciente.id_rol, id_clinica=clinica.id_clinica, nombre="Demo", paterno="Paciente",
        correo="paciente@rxpro.demo", contrasena=hashed,
        paciente=models.Paciente(curp="DEMO000101HDFXXX01", nacimiento=date(2000, 1, 1), sexo="O", tel_emergencia="5555555555"),
    )
    farma_u = models.Usuario(
        id_rol=rol_farma.id_rol, id_clinica=clinica.id_clinica, nombre="Demo", paterno="Farmacéutico",
        correo="farma@rxpro.demo", contrasena=hashed,
        farmaceutico=models.Farmaceutico(licencia="DEMO-FARM-0001", turno="Matutino"),
    )

    session.add_all([medico_u, paciente_u, farma_u])
    session.commit()
    for u in (medico_u, paciente_u, farma_u):
        session.refresh(u)

    seed_medico    = _resolve_demo_seed("DEMO_SEED_MEDICO", "médico")
    seed_paciente  = _resolve_demo_seed("DEMO_SEED_PACIENTE",    "paciente")
    seed_farma     = _resolve_demo_seed("DEMO_SEED_FARMACEUTICO","farmacéutico")

    print(f"QR demo para Médico: rxpro://card/v1/medico/{medico_u.medico.cedula}/{seed_medico}")
    print(f"QR demo para Paciente: rxpro://card/v1/paciente/{paciente_u.paciente.curp}/{seed_paciente}")
    print(f"QR demo para Farmacéutico: rxpro://card/v1/farmaceutico/{farma_u.farmaceutico.licencia}/{seed_farma}")

    session.add_all([
        models.Llave(id_usuario=medico_u.id_usuario, llave_publica=_pub_hex_from_seed_hex(seed_medico, _HKDF_INFO_RECIPES), activo=True, responsabilidad="recetas"),
        models.Llave(id_usuario=paciente_u.id_usuario, llave_publica=_pub_hex_from_seed_hex(seed_paciente, _HKDF_INFO_RECIPES), activo=True, responsabilidad="recetas"),
        models.Llave(id_usuario=farma_u.id_usuario, llave_publica=_pub_hex_from_seed_hex(seed_farma, _HKDF_INFO_RECIPES), activo=True, responsabilidad="recetas"),
        models.Llave(id_usuario=medico_u.id_usuario, llave_publica=_pub_hex_from_seed_hex(seed_medico, _HKDF_INFO_SIGN), activo=True, responsabilidad="firmas"),
        models.Llave(id_usuario=paciente_u.id_usuario, llave_publica=_pub_hex_from_seed_hex(seed_paciente, _HKDF_INFO_SIGN), activo=True, responsabilidad="firmas"),
        models.Llave(id_usuario=farma_u.id_usuario, llave_publica=_pub_hex_from_seed_hex(seed_farma, _HKDF_INFO_SIGN), activo=True, responsabilidad="firmas"),
    ])
    session.commit()

    if not session.exec(select(models.Administrador)).first():
        session.add(models.Administrador(
            nombre="Admin Demo", correo="admin@rxpro.demo", contrasena=security.get_password_hash("admin1234"),
        ))
        session.commit()

    print("Usuarios demo creados y llaves públicas registradas.")

def create_initial_data(session: Session):
    """Crea los datos iniciales (roles + demo data opcional)."""
    _ensure_roles(session)
    _seed_demo_data(session)