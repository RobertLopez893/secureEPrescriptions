Esta es la documentación técnica formal para tu módulo `api_gateway`. Este `README.md` está diseñado para servir como referencia central para cualquier desarrollador que trabaje en tu sistema.

---

# API Gateway - Secure E-Prescriptions

El `api_gateway` es la capa de entrada de la arquitectura. Su responsabilidad principal es actuar como **punto de terminación de peticiones**, validar la integridad de los datos criptográficos antes de que lleguen a la lógica de negocio y gestionar la autenticación (JWT) y autorización (RBAC).

## Estructura de Archivos

```text
api_gateway/
├── main.py              # Punto de entrada; configura CORS, middlewares y rutas.
├── schemas.py           # Contratos de datos (Pydantic) y validadores criptográficos.
├── README.md            # Documentación del módulo.
└── routers/
    ├── auth.py          # Autenticación: Legacy (pass) y Tarjeta (ECDSA).
    ├── clinicas.py      # CRUD de centros de salud.
    ├── recetas.py       # Lógica de emisión, lectura y sellado de recetas.
    └── usuarios.py      # Gestión de usuarios, roles y llaves públicas.
```

---

## Descripción de Archivos

### `schemas.py`
Define los modelos de validación Pydantic. 
* **Característica crítica:** Implementa validadores personalizados (`_assert_hex`, `_assert_hex_exact`) para asegurar que todo material criptográfico (llaves públicas, nonces, cápsulas cifradas) sea **hexadecimal puro**, tenga la longitud correcta (ej. 130 caracteres para llaves P-256) y prevenga inyecciones de payloads maliciosos.

### `routers/auth.py`
Implementa autenticación de dos vías:
* **Legacy:** `/auth/login` (email/pass) con protección contra fuerza bruta mediante *Rate Limiting* en memoria.
* **Tarjeta:** `/auth/challenge` y `/auth/verify`. Utiliza firma digital ECDSA P-256. El backend emite un nonce aleatorio (32 bytes) que el cliente debe firmar; si la firma es válida, emite el JWT.

### `routers/usuarios.py`
Maneja el ciclo de vida del usuario:
* Alta de pacientes, médicos y farmacéuticos (protegido por `_require_admin`).
* Gestión de llaves públicas (PKI): Permite rotación de llaves, desactivando automáticamente las llaves obsoletas asociadas a una responsabilidad específica.

### `routers/recetas.py`
El corazón del sistema.
* **Emisión:** Solo médicos/admin. Valida la autoría mediante la llave pública antes de guardar.
* **Visibilidad:** Controla que solo el dueño (paciente), emisor (médico) o dispensador (farmacéutico) pueda acceder a los datos.
* **Sellado:** Operación atómica que marca la receta como "surtida" y re-encripta la información.

---

## Referencia de Endpoints

### Autenticación (`/auth`)
| Endpoint | Método | Auth | Entrada (Body) | Descripción |
| :--- | :--- | :--- | :--- | :--- |
| `/login` | POST | N/A | `LoginRequest` (email, pass) | Login admin/bootstrap. Devuelve JWT. |
| `/challenge` | POST | N/A | `AuthChallengeRequest` | Solicita nonce para login por tarjeta. |
| `/verify` | POST | N/A | `AuthVerifyRequest` | Envía firma ECDSA para validar tarjeta. |

### Usuarios (`/usuarios`)
| Endpoint | Método | Auth | Entrada | Descripción |
| :--- | :--- | :--- | :--- | :--- |
| `/usuarios/pacientes` | POST | Admin | `PacienteCreate` | Registro de paciente. |
| `/usuarios/medicos` | POST | Admin | `MedicoCreate` | Registro de médico. |
| `/usuarios/farmaceuticos`| POST | Admin | `FarmaceuticoCreate` | Registro de farmacéutico. |
| `/{id}/llave` | POST | Admin | `LlavePublicaIn` | Registra/rota llave P-256. |
| `/{id}/llave` | GET | Auth | N/A | Consulta llave pública de usuario. |

### Recetas (`/recetas`)
| Endpoint | Método | Auth | Entrada | Descripción |
| :--- | :--- | :--- | :--- | :--- |
| `/recetas` | POST | Medico | `RecetaCreate` | Emisión de nueva receta. |
| `/recetas` | GET | Auth | QueryParams | Listado filtrado (según rol). |
| `/recetas/{id}` | GET | Auth | N/A | Datos públicos/vencimiento. |
| `/recetas/{id}/cripto` | GET | Auth | N/A | **Crítico:** Obtiene datos para descifrado local. |
| `/recetas/{id}/sellar` | PUT | Farma | `RecetaSellarRequest` | Proceso de dispensado. |

### Clínicas (`/clinicas`)
| Endpoint | Método | Auth | Entrada | Descripción |
| :--- | :--- | :--- | :--- | :--- |
| `/clinicas` | POST | Admin | `ClinicaCreate` | Alta de nueva unidad médica. |
| `/clinicas` | GET | Auth | N/A | Listado de clínicas registradas. |

---

## Notas de Implementación
* **Validación:** Todos los endpoints que reciben `capsula_cifrada`, `nonce` o `ephemeral_pub_hex` disparan automáticamente los validadores en `schemas.py` que garantizan el formato hexadecimal estricto antes de que la petición llegue a la lógica de negocio.
* **Seguridad:** Los endpoints de usuario y recetas implementan guardas (`_require_admin`, `_authorize_view_receta`) que validan el rol extraído del token JWT en cada llamada.