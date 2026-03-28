from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# 1. Crear la aplicación principal de FastAPI
app = FastAPI(
    title="Secure E-Prescriptions API",
    description="API Gateway para el sistema de recetas médicas seguras",
    version="1.0.0"
)

# 2. Configurar CORS (Crucial para conectar el Frontend y el Backend)
# Esto permite que tu frontend en Astro (localhost:4321) haga peticiones al backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ⚠️ En producción, cambia "*" por ["http://localhost:3000", "tu-dominio.com"]
    allow_credentials=True,
    allow_methods=["*"],  # Permite todos los métodos (GET, POST, PUT, DELETE)
    allow_headers=["*"],  # Permite todos los headers
)

# 3. Crear un Endpoint (Ruta) de inicio
@app.get("/")
def read_root():
    return {
        "status": "success",
        "message": "¡El backend de Secure E-Prescriptions está funcionando correctamente! 🚀"
    }

# 4. Crear un Endpoint de prueba para la salud del servidor (Health check)
@app.get("/health")
def health_check():
    return {"status": "ok", "db_connection": "Pendiente de configurar"}