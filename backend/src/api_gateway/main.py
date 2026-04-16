from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlmodel import SQLModel

# Importamos el motor de conexión
from src.database.database import engine

# IMPORTANTE: Debes importar todos los modelos aquí para que SQLModel los registre 
# en su Metadata antes de ejecutar create_all()
from src.database import models
from src.api_gateway.routers import recetas, auth

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Lógica de Inicio (Startup) ---
    print("Verificando y creando tablas de la base de datos...")
    # SQLModel.metadata contiene la definición de todas las clases con 'table=True' 
    # que hayan sido importadas en este archivo.
    SQLModel.metadata.create_all(engine)
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
