import os
from datetime import date
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlmodel import SQLModel, Session, select

# Importamos el motor de conexión
from src.database.database import engine

# IMPORTANTE: Debes importar todos los modelos aquí para que SQLModel los registre
# en su Metadata antes de ejecutar create_all()
from src.database import models
from src.core import security
from src.api_gateway.routers import recetas, auth, usuarios, clinicas

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
    Se ejecuta solo si NO existen usuarios aún (idempotente por primera corrida).
    """
    if os.getenv("APP_ENV", "development").lower() != "development":
        return
    if session.exec(select(models.Usuario)).first():
        return  # ya hay usuarios, no tocamos nada

    print("Sembrando datos demo (APP_ENV=development)...")

    # 1 clínica demo
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
    print("Usuarios demo creados:")
    print("  - doctor@rxpro.demo   / demo1234")
    print("  - paciente@rxpro.demo / demo1234")
    print("  - farma@rxpro.demo    / demo1234")


def create_initial_data(session: Session):
    """Crea los datos iniciales (roles + demo data opcional)."""
    _ensure_roles(session)
    _seed_demo_data(session)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Lógica de Inicio (Startup) ---
    print("Verificando y creando tablas de la base de datos...")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        create_initial_data(session)
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
