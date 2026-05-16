# Diccionario de Datos: Estructura Completa del Sistema

Este documento detalla la estructura de la base de datos y la organización de los archivos del núcleo del sistema.

## 1. Infraestructura y Configuración

### Tabla: `clinicas`
| Campo | Tipo | Restricción | Descripción |
| :--- | :--- | :--- | :--- |
| **`id_clinica`** | `int` | PK | Identificador único de la clínica. |
| **`nombre`** | `str` | Index | Nombre de la institución médica. |
| **`clues`** | `str` | Unique | Clave oficial de la Secretaría de Salud. |
| **`calle`** | `str` | - | Dirección física: Calle y número. |
| **`colonia`** | `str` | Index | Ubicación por colonia. |
| **`municipio`** | `str` | Index | Ubicación por municipio. |
| **`estado`** | `str` | Index | Ubicación por estado. |
| **`cp`** | `str` | - | Código Postal. |
| **`tipo`** | `str` | - | Categoría de la institución (Centro Médico, Hospital). |

### Tabla: `roles`
| Campo | Tipo | Restricción | Descripción |
| :--- | :--- | :--- | :--- |
| **`id_rol`** | `int` | PK | Identificador único del rol. |
| **`nombre`** | `str` | Unique, Index | Nombre del rol: Medico, Paciente o Farmaceutico. |

---

## 2. Usuarios y Perfiles (Identidad)

### Tabla: `usuarios`
| Campo | Tipo | Restricción | Descripción |
| :--- | :--- | :--- | :--- |
| **`id_usuario`** | `int` | PK | ID único global del usuario. |
| **`id_rol`** | `int` | FK (`roles`) | Referencia al rol del usuario. |
| **`id_clinica`** | `int` | FK (`clinicas`) | Clínica a la que pertenece (opcional). |
| **`nombre`** | `str` | - | Nombre(s) del usuario. |
| **`paterno`** | `str` | - | Apellido paterno. |
| **`materno`** | `str` | - | Apellido materno (opcional). |
| **`correo`** | `str` | Unique, Index | Dirección de correo electrónico y login. |
| **`contrasena`** | `str` | - | Hash de la contraseña del usuario. |
| **`activo`** | `bool` | Default: `True` | Estado de vigencia de la cuenta. |
| **`creado_en`** | `datetime`| Default: `now` | Marca de tiempo del registro. |

### Perfiles Específicos (Relación 1:1 con `usuarios`)
| Tabla | FK | Campos Específicos | Descripción |
| :--- | :--- | :--- | :--- |
| **`pacientes`** | `id_usuario` | `curp`, `nacimiento`, `sexo`, `tel_emergencia` | Información médica y de contacto del paciente. |
| **`medicos`** | `id_usuario` | `cedula`, `especialidad`, `universidad` | Credenciales profesionales del médico. |
| **`farmaceuticos`**| `id_usuario` | `licencia`, `turno` | Datos de acreditación y horario del farmacéutico. |

---

## 3. Criptografía y Recetas Médicas

### Tabla: `llaves`
| Campo | Tipo | Restricción | Descripción |
| :--- | :--- | :--- | :--- |
| **`id_llave`** | `int` | PK | Identificador único de la llave. |
| **`id_usuario`** | `int` | FK (`usuarios`) | Propietario de la llave pública. |
| **`llave_publica`**| `str` | - | Cadena de la llave para procesos de cifrado. |
| **`activo`** | `bool` | Default: `True` | Indica si la llave es válida para uso actual. |
| **`creado_en`** | `datetime`| Default: `now` | Fecha de generación de la llave. |
| **`responsabilidad`**| `str` | Default: `general` | Propósito de la llave (ej. "recetas", "firmas"). |

### Tabla: `recetas`
| Campo | Tipo | Restricción | Descripción |
| :--- | :--- | :--- | :--- |
| **`id_receta`** | `int` | PK | Identificador interno de la transacción. |
| **`folio`** | `str` | Unique, Index | Folio público único de la receta médica. |
| **`id_medico`** | `int` | FK (`usuarios`), Index | Médico que emite la prescripción. |
| **`id_paciente`** | `int` | FK (`usuarios`), Index | Paciente asignado a la receta. |
| **`id_farmaceutico`**| `int` | FK (`usuarios`), Index | Farmacéutico involucrado en el surtido. |
| **`capsula_cifrada`**| `str` | - | Contenido JSON cifrado en formato hexadecimal. |
| **`nonce`** | `str` | - | Valor único (hex) para el cifrado AES-GCM. |
| **`accesos`** | `JSON` | Default: `[]` | Lista de accesos cifrados para distintos roles. |
| **`estado`** | `str` | Default: `activa`| Estatus de la receta (ej. activa, surtida, cancelada). |
| **`creada_en`** | `datetime`| Default: `now` | Fecha y hora de emisión. |
| **`expira_en`** | `datetime`| - | Fecha límite de validez legal. |

---

## 4. Administración Independiente

### Tabla: `administradores`
| Campo | Tipo | Restricción | Descripción |
| :--- | :--- | :--- | :--- |
| **`id_admin`** | `int` | PK | Identificador único del administrador. |
| **`nombre`** | `str` | - | Nombre completo del administrador. |
| **`correo`** | `str` | Unique, Index | Correo electrónico de acceso administrativo. |
| **`contrasena`** | `str` | - | Hash de la contraseña administrativa. |
| **`activo`** | `bool` | Default: `True` | Estatus operativo de la cuenta. |
| **`creado_en`** | `datetime`| Default: `now` | Fecha de creación del perfil. |

---

## 5. Descripción de Archivos del Sistema

Los siguientes archivos se encuentran en el directorio raíz del módulo de base de datos y gestionan la lógica de persistencia:

### `models.py`
Define el esquema de la base de datos mediante clases de `SQLModel`. Establece las tablas, sus campos, tipos de datos y las relaciones lógicas entre entidades (como `Relationship` para vincular usuarios con sus perfiles médicos o de paciente).

### `database.py`
Configura el motor de base de datos (`engine`) utilizando la variable de entorno `DATABASE_URL`. Proporciona la función `get_session()`, la cual actúa como un generador para proveer sesiones de base de datos a la aplicación de forma controlada.

### `seed_demo.py`
Script de utilidad para la inicialización de datos. Sus funciones principales incluyen:
* **Creación de Roles**: Asegura que los roles básicos existan en el sistema.
* **Generación de Datos Demo**: En entornos de desarrollo, crea usuarios de prueba, clínicas y administradores.
* **Lógica Criptográfica**: Implementa la derivación de llaves públicas a partir de semillas (seeds) y genera URIs de ejemplo para la integración con dispositivos móviles.