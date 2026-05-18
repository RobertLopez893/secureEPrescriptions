import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlmodel import Session
# Importamos el motor de conexión
from src.database.database import engine
from src.database.seed_demo import create_initial_data
from src.core.config import settings


def _run_migrations() -> None:
    """Lleva el esquema a `head` con Alembic en lugar de create_all.

    create_all NO altera tablas existentes: añadir/renombrar columnas
    (lo que hizo el PR #8) sobre una BD ya creada quedaba silenciosamente
    sin aplicar. Las migraciones versionadas sí lo hacen y son
    reproducibles entre entornos.
    """
    from alembic import command
    from alembic.config import Config

    backend_dir = Path(__file__).resolve().parents[2]
    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "migrations"))
    command.upgrade(cfg, "head")

from src.api_gateway.routers import recetas, auth, usuarios, clinicas



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
    # En tests, conftest.py maneja su propio engine in-memory y crea el
    # esquema con create_all en una fixture; no debemos tocar la BD aquí.
    if settings.APP_ENV.strip().lower() == "test":
        yield
        return

    print("Esperando a que la base de datos acepte conexiones...")
    _wait_for_db()
    print("Aplicando migraciones (alembic upgrade head)...")
    _run_migrations()
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
