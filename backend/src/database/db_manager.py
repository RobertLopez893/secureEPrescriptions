import os
import psycopg2
from psycopg2 import Error

# Para cargar variables de entorno desde un archivo .env (opcional, si lo usas)
# from dotenv import load_dotenv
# load_dotenv()

def get_db_connection():
    """
    Establece y devuelve una conexión a la base de datos PostgreSQL.
    Las credenciales se obtienen de variables de entorno.
    """
    try:
        connection = psycopg2.connect(
            user=os.getenv("DB_USER", "app_user_default"), # Valor por defecto para desarrollo
            password=os.getenv("DB_PASSWORD", "password_default"), # Valor por defecto para desarrollo
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "5432"),
            database=os.getenv("DB_NAME", "e_prescriptions_db_default") # Valor por defecto para desarrollo
        )
        return connection
    except Error as e:
        print(f"Error al conectar a PostgreSQL: {e}")
        return None

def create_tables():
    """
    Crea las tablas necesarias en la base de datos si no existen.
    """
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            # Tabla para almacenar las recetas cifradas
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS encrypted_prescriptions (
                    id SERIAL PRIMARY KEY,
                    prescription_id VARCHAR(255) UNIQUE NOT NULL,
                    encrypted_data BYTEA NOT NULL, -- Almacena los blobs ininteligibles
                    signature TEXT NOT NULL,       -- Almacena la firma de la receta
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
            print("Tabla 'encrypted_prescriptions' creada o ya existente.")
        except Error as e:
            print(f"Error al crear tablas: {e}")
        finally:
            if conn:
                cursor.close()
                conn.close()
