Aquí tienes la versión final y completa de tu `README.md`. He incluido el diagrama de árbol con la ubicación exacta del archivo de variables de entorno (`.env`) y una sección detallada sobre qué debe contener.

---

# Secure E-Prescriptions

Sistema de gestión de recetas médicas electrónicas con cifrado en el lado del cliente y arquitectura de microservicios.

## 📂 Estructura del Proyecto

```text
secureEPrescriptions/
├── .env                      # Variable de entornoW
├── Diagrams/                 # Documentación técnica (C4 Model)
├── backend/                  # API REST (FastAPI)
│   ├── src/
│   │   ├── api_gateway/      # Punto de entrada (main.py)
│   │   ├── database/         # Configuración de PostgreSQL
│   │   ├── kms/              # Gestión de llaves públicas (RF-02)
│   │   └── secure_channel/   # Intercambio de llaves ECDH
│   └── requirements.txt      # Dependencias de Python
├── frontend/                 # Aplicación Web (Astro)
│   ├── src/
│   │   ├── pages/            # Rutas (Médico, Paciente, Farmacia)
│   │   └── utils/            # Lógica de cifrado (Noble Curves)
│   └── package.json          # Dependencias de Node.js
└── docker-compose.yml        # Orquestación de contenedores
```

## ⚙️ Configuración de Variables de Entorno

Crea un archivo llamado `.env` en la **raíz del proyecto** (donde está el `docker-compose.yml`) con el siguiente contenido:

```env
# Configuración de Base de Datos
POSTGRES_USER=tu_usuario
POSTGRES_PASSWORD=tu_password
POSTGRES_DB=secure_rx_db

# Configuración de Aplicación
APP_ENV=development
FRONTEND_PORT=4321
```

---

## 🚀 Guía de Ejecución

### Opción 1: Docker (Recomendado)
Levanta todos los servicios automáticamente:
```bash
docker-compose up --build
```

### Opción 2: Ejecución Local (Sin Docker)

#### 1. Base de Datos (PostgreSQL)
* Levanta Postgres en el puerto `5432`.
* Crea la base de datos definida en tu `.env`.

#### 2. Backend (FastAPI) - Git Bash
1. Entra a la carpeta: `cd backend`
2. Crea el entorno virtual: `python -m venv venv`
3. **Activa: `source venv/Scripts/activate`**
4. Instala dependencias: `pip install -r requirements.txt`
5. Inicia el servidor: 
   ```bash
   uvicorn src.api_gateway.main:app --reload --port 8000
   ```

#### 3. Frontend (Astro)
1. Entra a la carpeta: `cd frontend`
2. Instala dependencias: `npm install`
3. Inicia el desarrollo: `npm run dev`
   * Acceso: `http://localhost:4321`

---

## 🛠️ Tecnologías Principales
* **Criptografía:** `@noble/curves` para intercambio de llaves y firmas.
* **Backend:** FastAPI (Python).
* **Frontend:** Astro & TailwindCSS.
