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

    medico_u = models.Usuario(
        id_rol=rol_medico.id_rol, id_clinica=clinica.id_clinica, nombre="Demo", paterno="Médico",
        correo="doctor@rxpro.demo",
        medico=models.Medico(cedula="DEMO-MED-0001", especialidad="General", universidad="Universidad Demo"),
    )
    paciente_u = models.Usuario(
        id_rol=rol_paciente.id_rol, id_clinica=clinica.id_clinica, nombre="Demo", paterno="Paciente",
        correo="paciente@rxpro.demo",
        paciente=models.Paciente(curp="DEMO000101HDFXXX01", nacimiento=date(2000, 1, 1), sexo="O", tel_emergencia="5555555555"),
    )
    farma_u = models.Usuario(
        id_rol=rol_farma.id_rol, id_clinica=clinica.id_clinica, nombre="Demo", paterno="Farmacéutico",
        correo="farma@rxpro.demo",
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

    _seed_batch_users(session, clinica, rol_medico, rol_paciente)

    print("Usuarios demo creados y llaves públicas registradas.")


def _stable_seed(tag: str) -> str:
    """Semilla de 32 bytes (64 hex) determinista y estable entre reinicios,
    sin necesidad de declarar una variable de entorno por usuario."""
    return hashlib.sha256(f"rxpro-batch-v1:{tag}".encode()).hexdigest()


def _registrar_llaves(session: Session, id_usuario: int, seed_hex: str) -> None:
    """Registra las dos llaves públicas que el sistema espera para cualquier
    usuario: 'recetas' (cifrado E2E) y 'firmas' (autoría / login por tarjeta)."""
    session.add_all([
        models.Llave(id_usuario=id_usuario, llave_publica=_pub_hex_from_seed_hex(seed_hex, _HKDF_INFO_RECIPES), activo=True, responsabilidad="recetas"),
        models.Llave(id_usuario=id_usuario, llave_publica=_pub_hex_from_seed_hex(seed_hex, _HKDF_INFO_SIGN), activo=True, responsabilidad="firmas"),
    ])


def _seed_batch_users(session, clinica, rol_medico, rol_paciente) -> None:
    """Crea un lote de 5 pacientes + 3 médicos en la clínica demo para poder
    probar el flujo completo de inmediato. Reutiliza el ÚNICO farmacéutico
    demo (la clínica no puede tener más de uno: ver _resolve_jefe_farmaceutico).
    Las semillas son deterministas, así que los QR no cambian entre reinicios."""
    print("Sembrando lote de prueba (5 pacientes + 3 médicos)...")
    qr_lines: list[str] = []

    for n in range(1, 6):
        curp = f"PAC{n:02d}000101HDFXXX0{n}"
        seed = _stable_seed(f"paciente:{n}")
        u = models.Usuario(
            id_rol=rol_paciente.id_rol, id_clinica=clinica.id_clinica,
            nombre=f"Paciente{n}", paterno="Demo", correo=f"paciente{n}@rxpro.demo",
            paciente=models.Paciente(
                curp=curp, nacimiento=date(2000, 1, 1),
                sexo="O", tel_emergencia="5555555555",
            ),
        )
        session.add(u)
        session.commit()
        session.refresh(u)
        _registrar_llaves(session, u.id_usuario, seed)
        qr_lines.append(f"  Paciente{n} (id={u.id_usuario}, CURP {curp}): rxpro://card/v1/paciente/{curp}/{seed}")

    for n in range(1, 4):
        cedula = f"DEMO-MED-100{n}"
        seed = _stable_seed(f"medico:{n}")
        u = models.Usuario(
            id_rol=rol_medico.id_rol, id_clinica=clinica.id_clinica,
            nombre=f"Doctor{n}", paterno="Demo", correo=f"doctor{n}@rxpro.demo",
            medico=models.Medico(
                cedula=cedula, especialidad="General",
                universidad="Universidad Demo",
            ),
        )
        session.add(u)
        session.commit()
        session.refresh(u)
        _registrar_llaves(session, u.id_usuario, seed)
        qr_lines.append(f"  Doctor{n} (id={u.id_usuario}, céd. {cedula}): rxpro://card/v1/medico/{cedula}/{seed}")

    session.commit()
    print("Lote de prueba creado. QR de login por tarjeta:")
    for line in qr_lines:
        print(line)

_SPEC_ESPECIALIDADES = [
    "Cardiología", "Neurología", "Pediatría", "Ginecología", "Oncología",
    "Dermatología", "Endocrinología", "Gastroenterología", "Hematología",
    "Nefrología", "Neumología", "Oftalmología", "Otorrinolaringología",
    "Psiquiatría", "Reumatología", "Traumatología", "Urología", "Anestesiología",
    "Radiología", "Medicina Interna", "Cirugía General", "Geriatría",
    "Infectología", "Alergología", "Medicina Familiar",
]

_SPEC_TURNOS = ["Matutino", "Vespertino", "Nocturno"]


def _get_or_create_clinica(
    session: Session, *, clues: str, nombre: str, tipo: str,
    calle: str, colonia: str, municipio: str, estado: str, cp: str,
) -> models.Clinica:
    existing = session.exec(select(models.Clinica).where(models.Clinica.clues == clues)).first()
    if existing:
        return existing
    c = models.Clinica(
        nombre=nombre, clues=clues, tipo=tipo,
        calle=calle, colonia=colonia, municipio=municipio, estado=estado, cp=cp,
    )
    session.add(c)
    session.commit()
    session.refresh(c)
    return c


def _crear_medico_spec(
    session: Session, *, clinica: models.Clinica, rol_medico: models.Rol,
    hashed: str, tag: str, nombre: str, paterno: str, correo: str,
    cedula: str, especialidad: str,
) -> None:
    if session.exec(select(models.Usuario).where(models.Usuario.correo == correo)).first():
        return
    seed = _stable_seed(tag)
    u = models.Usuario(
        id_rol=rol_medico.id_rol, id_clinica=clinica.id_clinica,
        nombre=nombre, paterno=paterno, correo=correo, contrasena=hashed,
        medico=models.Medico(cedula=cedula, especialidad=especialidad, universidad="UNAM"),
    )
    session.add(u)
    session.commit()
    session.refresh(u)
    _registrar_llaves(session, u.id_usuario, seed)
    session.commit()


def _crear_jefe_farmacia(
    session: Session, *, farmacia: models.Clinica, rol_farma: models.Rol,
    hashed: str, tag: str, nombre: str, correo: str, licencia: str, turno: str,
) -> None:
    if session.exec(select(models.Usuario).where(models.Usuario.correo == correo)).first():
        return
    seed = _stable_seed(tag)
    u = models.Usuario(
        id_rol=rol_farma.id_rol, id_clinica=farmacia.id_clinica,
        nombre=nombre, paterno="Jefe", correo=correo, contrasena=hashed,
        farmaceutico=models.Farmaceutico(licencia=licencia, turno=turno),
    )
    session.add(u)
    session.commit()
    session.refresh(u)
    _registrar_llaves(session, u.id_usuario, seed)
    session.commit()


def _seed_spec_data(session: Session) -> None:
    """Siembra la infraestructura descrita en el enunciado:
    - 2 centros médicos con 20 médicos cada uno
    - 1 hospital con 300 médicos de distintas especialidades
    - 3 farmacias, cada una con su jefe farmacéutico

    Idempotente: si las clínicas con CLUES SPEC-* ya existen, no recrea
    nada. Solo corre en APP_ENV=development."""
    if os.getenv("APP_ENV", "development").lower() != "development":
        return

    marker = session.exec(
        select(models.Clinica).where(models.Clinica.clues == "SPEC-HOSP-01")
    ).first()
    if marker:
        return

    print("Sembrando infraestructura del enunciado (2 centros + 1 hospital + 3 farmacias)...")

    rol_medico = _get_rol(session, "Medico")
    rol_farma = _get_rol(session, "Farmaceutico")
    hashed = security.get_password_hash("demo1234")

    centros = [
        _get_or_create_clinica(
            session, clues="SPEC-MED-01", nombre="Centro Médico Norte", tipo="Centro Medico",
            calle="Av. Norte 100", colonia="Norte", municipio="Ciudad Demo", estado="CDMX", cp="01100",
        ),
        _get_or_create_clinica(
            session, clues="SPEC-MED-02", nombre="Centro Médico Sur", tipo="Centro Medico",
            calle="Av. Sur 200", colonia="Sur", municipio="Ciudad Demo", estado="CDMX", cp="01200",
        ),
    ]

    hospital = _get_or_create_clinica(
        session, clues="SPEC-HOSP-01", nombre="Hospital General Demo", tipo="Hospital",
        calle="Av. Central 1", colonia="Centro", municipio="Ciudad Demo", estado="CDMX", cp="01000",
    )

    farmacias = [
        _get_or_create_clinica(
            session, clues="SPEC-FARM-01", nombre="Farmacia San Rafael", tipo="Farmacia",
            calle="Calle 1", colonia="Centro", municipio="Ciudad Demo", estado="CDMX", cp="01000",
        ),
        _get_or_create_clinica(
            session, clues="SPEC-FARM-02", nombre="Farmacia La Salud", tipo="Farmacia",
            calle="Calle 2", colonia="Norte", municipio="Ciudad Demo", estado="CDMX", cp="01100",
        ),
        _get_or_create_clinica(
            session, clues="SPEC-FARM-03", nombre="Farmacia del Pueblo", tipo="Farmacia",
            calle="Calle 3", colonia="Sur", municipio="Ciudad Demo", estado="CDMX", cp="01200",
        ),
    ]

    # 20 médicos por centro médico
    for ci, centro in enumerate(centros, start=1):
        for n in range(1, 21):
            _crear_medico_spec(
                session, clinica=centro, rol_medico=rol_medico, hashed=hashed,
                tag=f"spec-med:centro{ci}:{n}",
                nombre=f"Médico{n}", paterno=f"Centro{ci}",
                correo=f"medico.centro{ci}.{n}@rxpro.demo",
                cedula=f"SPEC-CM{ci}-{n:03d}",
                especialidad="Medicina General",
            )

    # 300 médicos en el hospital, distribuyendo especialidades
    for n in range(1, 301):
        especialidad = _SPEC_ESPECIALIDADES[(n - 1) % len(_SPEC_ESPECIALIDADES)]
        _crear_medico_spec(
            session, clinica=hospital, rol_medico=rol_medico, hashed=hashed,
            tag=f"spec-med:hospital:{n}",
            nombre=f"Médico{n}", paterno="Hospital",
            correo=f"medico.hospital.{n}@rxpro.demo",
            cedula=f"SPEC-HOSP-{n:04d}",
            especialidad=especialidad,
        )

    # 1 jefe farmacéutico por farmacia
    for fi, farmacia in enumerate(farmacias, start=1):
        _crear_jefe_farmacia(
            session, farmacia=farmacia, rol_farma=rol_farma, hashed=hashed,
            tag=f"spec-farma:jefe{fi}",
            nombre=f"Jefe{fi}",
            correo=f"jefe.farmacia{fi}@rxpro.demo",
            licencia=f"SPEC-FARM-{fi:02d}-JEFE",
            turno=_SPEC_TURNOS[(fi - 1) % len(_SPEC_TURNOS)],
        )

    session.commit()
    print("Infraestructura del enunciado lista: 2 centros (20 médicos c/u), "
          "1 hospital (300 médicos), 3 farmacias con jefe.")


def create_initial_data(session: Session):
    """Crea los datos iniciales (roles + demo data opcional + infraestructura spec)."""
    _ensure_roles(session)
    _seed_demo_data(session)
    _seed_spec_data(session)