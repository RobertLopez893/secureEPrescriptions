import os
import secrets
import hashlib
import hmac
from datetime import date
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlmodel import SQLModel, Session, select

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Importamos el motor de conexión
from src.database.database import engine

# IMPORTANTE: Debes importar todos los modelos aquí para que SQLModel los registre
# en su Metadata antes de ejecutar create_all()
from src.database import models
from src.core import security
from src.api_gateway.routers import recetas, auth, usuarios, clinicas


# ── Derivación de llaves demo ────────────────────────────────────────────
# El backend no necesita (ni debe) conocer llaves privadas. Lo único que
# requiere para sembrar los usuarios demo es su llave pública, derivada de
# la semilla de la tarjeta QR.
#
# La derivación aquí es equivalente a la del frontend
# (`frontend/src/crypto/seedDerivation.ts`): HKDF-SHA256 sobre la semilla
# con los mismos salt/info/counter. Debe mantenerse en sincronía.
_HKDF_SALT = b"rxpro-2026:cardkey-salt:v1"
_HKDF_INFO = b"rxpro-v1:p256:identity-key"
# Orden del subgrupo de P-256 (NIST FIPS 186-4, D.1.2.3).
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


def _pub_hex_from_seed_hex(seed_hex: str) -> str:
    """Deriva la llave pública P-256 (uncompressed hex, 130 chars) desde una
    semilla hex de 32 bytes siguiendo el mismo HKDF que el frontend."""
    seed = bytes.fromhex(seed_hex.strip().lower())
    if len(seed) != 32:
        raise ValueError("La semilla debe ser exactamente 32 bytes.")
    for counter in range(256):
        info = _HKDF_INFO + bytes([counter])
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
    """Devuelve la semilla demo para `label`:

    - Si `env_var` está definida con 64 hex chars, se usa esa (permite que
      los QRs demo sean estables entre reinicios).
    - Si no, se genera una aleatoria y se imprime con un banner al stdout
      para que el operador pueda regenerar los QRs demo. En ese caso las
      seeds cambian en cada arranque — solo útil en ejecuciones de dev.
    """
    raw = (os.getenv(env_var) or "").strip().lower()
    if len(raw) == 64 and all(c in "0123456789abcdef" for c in raw):
        return raw
    generated = secrets.token_hex(32)
    print(f"⚠ Semilla demo generada para {label}: {generated}")
    print(f"  Guarda en tu .env como {env_var}={generated} si quieres persistirla.")
    return generated

def _ensure_roles(session: Session) -> None:
    """Crea los roles base si no existen."""
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
    """
    Siembra una clínica + un usuario por rol cuando APP_ENV=development.
    Credenciales conocidas para poder probar el login QR de punta a punta.

    Es idempotente a nivel de cada entidad: si un arranque anterior creó
    la clínica pero murió antes de crear los usuarios (p.ej. el bug de
    passlib/bcrypt), este método reusa lo existente en vez de chocar con
    los UNIQUE de `clues`/correos.
    """
    if os.getenv("APP_ENV", "development").lower() != "development":
        return
    if session.exec(select(models.Usuario)).first():
        return  # ya hay usuarios, no tocamos nada

    print("Sembrando datos demo (APP_ENV=development)...")

    # Clínica demo: select-or-create por CLUES (único).
    clinica = session.exec(
        select(models.Clinica).where(models.Clinica.clues == "DEMO0000001")
    ).first()
    if clinica is None:
        clinica = models.Clinica(
            nombre="Clínica Demo RxFlow",
            clues="DEMO0000001",
            calle="Av. Ficticia 123",
            colonia="Centro",
            municipio="Ciudad Demo",
            estado="CDMX",
            cp="01000",
            tipo="Centro Medico",
        )
        session.add(clinica)
        session.commit()
        session.refresh(clinica)

    rol_medico = _get_rol(session, "Medico")
    rol_paciente = _get_rol(session, "Paciente")
    rol_farma = _get_rol(session, "Farmaceutico")

    hashed = security.get_password_hash("demo1234")

    # Médico demo
    medico_u = models.Usuario(
        id_rol=rol_medico.id_rol,
        id_clinica=clinica.id_clinica,
        nombre="Demo",
        paterno="Médico",
        correo="doctor@rxpro.demo",
        contrasena=hashed,
        medico=models.Medico(
            cedula="DEMO-MED-0001",
            especialidad="General",
            universidad="Universidad Demo",
        ),
    )
    # Paciente demo
    paciente_u = models.Usuario(
        id_rol=rol_paciente.id_rol,
        id_clinica=clinica.id_clinica,
        nombre="Demo",
        paterno="Paciente",
        correo="paciente@rxpro.demo",
        contrasena=hashed,
        paciente=models.Paciente(
            curp="DEMO000101HDFXXX01",
            nacimiento=date(2000, 1, 1),
            sexo="O",
            tel_emergencia="5555555555",
        ),
    )
    # Farmacéutico demo
    farma_u = models.Usuario(
        id_rol=rol_farma.id_rol,
        id_clinica=clinica.id_clinica,
        nombre="Demo",
        paterno="Farmacéutico",
        correo="farma@rxpro.demo",
        contrasena=hashed,
        farmaceutico=models.Farmaceutico(
            licencia="DEMO-FARM-0001",
            turno="Matutino",
        ),
    )

    session.add(medico_u)
    session.add(paciente_u)
    session.add(farma_u)
    session.commit()

    # Refrescamos para conocer los ids reales asignados por la BD
    session.refresh(medico_u)
    session.refresh(paciente_u)
    session.refresh(farma_u)

    # Sembramos las llaves públicas derivadas de las semillas demo. Las
    # semillas se toman de variables de entorno si están presentes; si no,
    # se generan aleatorias y se imprimen al stdout para que el operador
    # pueda regenerar los QRs demo. Las privadas nunca viven en el backend.
    seed_medico    = _resolve_demo_seed("DEMO_SEED_MEDICO",      "médico")
    seed_paciente  = _resolve_demo_seed("DEMO_SEED_PACIENTE",    "paciente")
    seed_farma     = _resolve_demo_seed("DEMO_SEED_FARMACEUTICO","farmacéutico")

    session.add(models.Llave(
        id_usuario=medico_u.id_usuario,
        llave_publica=_pub_hex_from_seed_hex(seed_medico),
        activo=True,
    ))
    session.add(models.Llave(
        id_usuario=paciente_u.id_usuario,
        llave_publica=_pub_hex_from_seed_hex(seed_paciente),
        activo=True,
    ))
    session.add(models.Llave(
        id_usuario=farma_u.id_usuario,
        llave_publica=_pub_hex_from_seed_hex(seed_farma),
        activo=True,
    ))
    session.commit()

    # Admin demo (correo + contraseña). Es el único rol que entra por
    # la vía legacy; desde su panel /admin emite tarjetas QR para los
    # demás usuarios.
    if not session.exec(select(models.Administrador)).first():
        session.add(models.Administrador(
            nombre="Admin Demo",
            correo="admin@rxpro.demo",
            contrasena=security.get_password_hash("admin1234"),
        ))
        session.commit()

    print("Usuarios demo creados:")
    print("  - admin@rxpro.demo    / admin1234  (ingresa por /admin/login)")
    print("  - doctor@rxpro.demo   / demo1234")
    print("  - paciente@rxpro.demo / demo1234")
    print("  - farma@rxpro.demo    / demo1234")
    print("Llaves públicas demo registradas (P-256) para los 3 usuarios clínicos.")


def create_initial_data(session: Session):
    """Crea los datos iniciales (roles + demo data opcional)."""
    _ensure_roles(session)
    _seed_demo_data(session)

def _warn_if_multiworker() -> None:
    """El cache de retos en auth.py vive en memoria del proceso y NO se
    comparte entre workers. Con >1 worker los login por tarjeta fallan y
    queda expuesto a replay parciales. Aborta con warning al stdout si
    detectamos un entorno multi-worker. Migrar a Redis para levantar esta
    restricción."""
    raw = os.getenv("WEB_CONCURRENCY") or os.getenv("UVICORN_WORKERS") or os.getenv("GUNICORN_WORKERS")
    try:
        workers = int(raw) if raw else 1
    except ValueError:
        workers = 1
    if workers > 1:
        print(
            "⚠  WEB_CONCURRENCY/workers > 1 detectado. El cache de challenges "
            "de login-por-tarjeta NO se comparte entre workers. Corre con "
            "--workers 1 hasta mover los retos a Redis o BD."
        )


def _wait_for_db(max_attempts: int = 30, delay_seconds: float = 1.0) -> None:
    """Espera a que postgres acepte conexiones antes de crear tablas.

    docker-compose ya declara `depends_on: db: service_healthy`, pero si
    alguien corre el backend fuera de compose (o la BD se reinicia en
    caliente) necesitamos tolerar unos segundos de arranque.
    """
    from sqlalchemy.exc import OperationalError
    import time

    for attempt in range(1, max_attempts + 1):
        try:
            with engine.connect() as conn:
                conn.exec_driver_sql("SELECT 1")
            return
        except OperationalError as exc:
            if attempt == max_attempts:
                raise
            print(
                f"[startup] DB aún no responde (intento {attempt}/{max_attempts}): {exc.orig}. "
                f"Reintento en {delay_seconds:.1f}s..."
            )
            time.sleep(delay_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Lógica de Inicio (Startup) ---
    print("Esperando a que la base de datos acepte conexiones...")
    _wait_for_db()
    print("Verificando y creando tablas de la base de datos...")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        create_initial_data(session)
    _warn_if_multiworker()
    print("Base de datos sincronizada.")

    yield  # Aquí es donde el servidor "vive" y acepta peticiones

    # --- Lógica de Cierre (Shutdown) ---
    print("Cerrando recursos...")

# Inicialización de la App con el ciclo de vida (Lifespan)
app = FastAPI(
    title="Secure E-Prescription API",
    description="Backend Zero-Knowledge para recetas médicas seguras",
    version="1.0.0",
    lifespan=lifespan
)

# Configuración de CORS (Permite que Astro se comunique con la API).
# CORS_ORIGINS es una lista separada por comas tomada del .env. Si no se
# define, usamos los defaults de desarrollo (Astro local, Vite, Docker).
_default_origins = ",".join([
    "http://localhost:4321",
    "http://127.0.0.1:4321",
    "http://localhost:80",
    "http://localhost",
])
_origins_env = os.getenv("CORS_ORIGINS", _default_origins)
_origins = [o.strip() for o in _origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"], # Permite GET, POST, PUT, DELETE, etc.
    allow_headers=["*"], # Permite todos los headers (incluyendo Authorization para JWT)
)

@app.get("/")
async def root():
    return {
        "message": "Bienvenido a Secure E-Prescription API",
        "docs": "/docs",
        "status": "online"
    }

# Incluimos el router de recetas en nuestra aplicación principal (el Gateway)
app.include_router(recetas.router, prefix="/api/v1", tags=["Recetas"])
# Incluimos el router de autenticación
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Autenticación"])
# Incluimos el router de usuarios
app.include_router(usuarios.router, prefix="/api/v1", tags=["Usuarios"])
# Incluimos el router de clínicas (necesario para registrar médicos)
app.include_router(clinicas.router, prefix="/api/v1", tags=["Clínicas"])
