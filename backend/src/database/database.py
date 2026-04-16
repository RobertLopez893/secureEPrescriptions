import os
from sqlmodel import create_engine, Session

# ==========================================
# CONFIGURACIÓN DE LA CONEXIÓN
# ==========================================
# En producción, NUNCA pongas las credenciales directo en el código.
# Aquí usamos os.getenv para leerlas de un archivo .env, con un valor por defecto para desarrollo local.
# Formato: postgresql://usuario:contraseña@servidor:puerto/nombre_bd



DATABASE_URL = os.getenv("DATABASE_URL")

# ==========================================
# CREACIÓN DEL MOTOR (ENGINE)
# ==========================================
# El motor es la fábrica de conexiones de tu aplicación. 
# Solo se crea una vez al iniciar FastAPI.
# echo=True hace que SQLAlchemy imprima en la consola todas las consultas SQL que ejecuta (muy útil en desarrollo).

engine = create_engine(DATABASE_URL, echo=True)

# ==========================================
# INYECCIÓN DE DEPENDENCIAS (FastAPI)
# ==========================================
def get_session():
    """
    Esta función es un 'Dependency Provider' para FastAPI.
    Garantiza que cada vez que un endpoint (ej. Crear Receta) necesite la base de datos,
    se abra una sesión limpia y, al terminar, se cierre automáticamente.
    """
    with Session(engine) as session:
        yield session