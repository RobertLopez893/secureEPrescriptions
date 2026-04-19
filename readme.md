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
# --- Base de datos ---
POSTGRES_USER=tu_usuario
POSTGRES_PASSWORD=tu_password
POSTGRES_DB=secure_rx_db

# --- Entorno ---
APP_ENV=development           # development | production

# --- Puertos del frontend ---
FRONTEND_PORT=4321            # Puerto expuesto al host
FRONTEND_INTERNAL_PORT=4321   # Puerto dentro del contenedor (Astro dev server)

# --- Conexión frontend ↔ backend ---
# URL pública de la API que el navegador consumirá desde el cliente Astro.
PUBLIC_API_URL=http://localhost:8000

# --- CORS del backend ---
# Orígenes autorizados separados por coma. Debe incluir la URL real que
# sirve el frontend (incluyendo el puerto). Si haces despliegue a un
# dominio público, añádelo aquí (https://midominio.mx).
CORS_ORIGINS=http://localhost:4321,http://127.0.0.1:4321
```

> Para desarrollo local hay una plantilla en `frontend/.env.example`
> que sólo contiene `PUBLIC_API_URL`; cópiala a `frontend/.env` si
> ejecutas Astro fuera de Docker.

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
   * El repo incluye un `.npmrc` con `legacy-peer-deps=true` porque
     `@astrojs/tailwind@5` todavía declara peer-deps sobre Astro 3/4/5 y
     nosotros ya estamos en Astro 6. La integración funciona igual; el
     flag sólo evita que npm aborte la instalación.
3. Inicia el desarrollo: `npm run dev`
   * Acceso: `http://localhost:4321`
4. Corre los tests unitarios (opcional): `npm test`

### 🌐 CORS

El backend lee `CORS_ORIGINS` (coma-separado) al arrancar y sólo permite
esos orígenes. Para desarrollo local los valores por defecto son
`http://localhost:4321` y `http://127.0.0.1:4321`. Si cambias el puerto
del frontend, despliegas a un dominio público o abres Astro desde otra
máquina en la red, **tienes que añadir esa URL exacta** (incluyendo
esquema y puerto) a la lista antes de reiniciar el backend — si no, el
navegador bloqueará cada `fetch` con un error de CORS y el banner rojo
"BACKEND NO RESPONDE" del frontend se quedará encendido.

---

## 🛠️ Tecnologías Principales
* **Criptografía:** `@noble/curves` para intercambio de llaves y firmas.
* **Backend:** FastAPI (Python).
* **Frontend:** Astro & TailwindCSS.

---

## 🔌 Integración Frontend ↔ Backend

El cliente Astro consume los endpoints de FastAPI mediante el módulo
`frontend/src/utils/api.ts`. Todas las rutas viven bajo el prefijo
`/api/v1` y son expuestas por `src/api_gateway/main.py`.

| Flujo               | Método | Endpoint                            | Pantalla(s)                          |
|---------------------|--------|-------------------------------------|--------------------------------------|
| Login unificado     | POST   | `/api/v1/auth/login`                | `/doctor`, `/patient`                |
| Registrar paciente  | POST   | `/api/v1/usuarios/pacientes`        | (script de seeding / admin)          |
| Registrar médico    | POST   | `/api/v1/usuarios/medicos`          | (script de seeding / admin)          |
| Emitir receta       | POST   | `/api/v1/recetas`                   | `/doctor/sign`                       |
| Info pública receta | GET    | `/api/v1/recetas/{id}`              | `/patient/dashboard`, `/patient/detail` |
| Cápsula cifrada     | GET    | `/api/v1/recetas/{id}/cripto`       | `/patient/detail`, `/pharmacy/verify`|
| Sellar dispensación | PUT    | `/api/v1/recetas/{id}/sellar`       | `/pharmacy/seal`                     |

El JWT se persiste en `sessionStorage` bajo la clave `rxpro_token` y se
inyecta automáticamente como `Authorization: Bearer ...` en todas las
peticiones salientes. La llave privada del usuario **nunca** sale del
navegador: el cliente firma y descifra en memoria con `@noble/curves` y
`@noble/ciphers` antes de enviar el blob opaco al backend.
