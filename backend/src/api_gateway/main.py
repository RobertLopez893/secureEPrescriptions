from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlmodel import SQLModel, Session, select

# Importamos el motor de conexión
from src.database.database import engine

# IMPORTANTE: Debes importar todos los modelos aquí para que SQLModel los registre 
# en su Metadata antes de ejecutar create_all()
from src.database import models
from src.api_gateway.routers import recetas, auth, usuarios

def create_initial_data(session: Session):
    """Crea los datos iniciales (como los roles) si no existen."""
    # Verificar si los roles ya existen
    rol_check = session.exec(select(models.Rol)).first()
    if not rol_check:
        print("Creando roles iniciales...")
        roles = [
            models.Rol(nombre="Medico"),
            models.Rol(nombre="Paciente"),
            models.Rol(nombre="Farmaceutico"),
        ]
        for rol in roles:
            session.add(rol)
        session.commit()
        print("Roles creados.")

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

# Configuración de CORS (Permite que Astro se comunique con la API)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4321", "http://127.0.0.1:4321"], # Puerto por defecto de Astro
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
