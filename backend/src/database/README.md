Tienes razón, me faltaron algunos atributos importantes de infraestructura (dirección) y metadatos (fechas y estatus) que incluiste en tu código. Aquí tienes la versión corregida y completa en tablas:

---

# Diccionario de Datos: Estructura Completa del Sistema

## 1. Infraestructura y Configuración

### Tabla: `clinicas`
| Campo | Tipo | Restricción | Descripción |
| :--- | :--- | :--- | :--- |
| **`id_clinica`** | `int` | PK | Identificador único. |
| **`nombre`** | `str` | Index | Nombre de la institución. |
| **`clues`** | `str` | Unique | Clave oficial (Secretaría de Salud). |
| **`calle`** | `str` | - | Dirección física. |
| **`colonia`** | `str` | Index | Ubicación por colonia. |
| **`municipio`** | `str` | Index | Ubicación por municipio. |
| **`estado`** | `str` | Index | Ubicación por estado. |
| **`cp`** | `str` | - | Código Postal. |
| **`tipo`** | `str` | - | (Centro Medico, Hospital). |

### Tabla: `roles`
| Campo | Tipo | Restricción | Descripción |
| :--- | :--- | :--- | :--- |
| **`id_rol`** | `int` | PK | ID del rol. |
| **`nombre`** | `str` | Unique, Index | Medico, Paciente o Farmaceutico. |

---

## 2. Usuarios y Perfiles (Identidad)

### Tabla: `usuarios`
| Campo | Tipo | Restricción | Descripción |
| :--- | :--- | :--- | :--- |
| **`id_usuario`** | `int` | PK | ID único de usuario. |
| **`id_rol`** | `int` | FK (`roles`) | Rol del usuario. |
| **`id_clinica`** | `int` | FK (`clinicas`) | Clínica asignada (opcional). |
| **`nombre`** | `str` | - | Nombre(s). |
| **`paterno`** | `str` | - | Apellido paterno. |
| **`materno`** | `str` | - | Apellido materno (opcional). |
| **`correo`** | `str` | Unique, Index | Email de login. |
| **`contrasena`** | `str` | - | Password (hasheado). |
| **`activo`** | `bool` | Default: `True` | Estado de la cuenta. |
| **`creado_en`** | `datetime`| Default: `now` | Fecha de registro. |

### Perfiles Específicos (Relación 1:1 con `usuarios`)
| Tabla | FK | Campos Específicos |
| :--- | :--- | :--- |
| **`pacientes`** | `id_usuario` | `curp` (Unique), `nacimiento`, `sexo`, `tel_emergencia` |
| **`medicos`** | `id_usuario` | `cedula` (Unique), `especialidad`, `universidad` |
| **`farmaceuticos`**| `id_usuario` | `licencia` (Unique), `turno` |

---

## 3. Criptografía y Recetas Médicas

### Tabla: `llaves`
| Campo | Tipo | Restricción | Descripción |
| :--- | :--- | :--- | :--- |
| **`id_llave`** | `int` | PK | ID de la llave. |
| **`id_usuario`** | `int` | FK (`usuarios`) | Dueño de la llave pública. |
| **`llave_publica`**| `str` | - | String de la llave para cifrado asimétrico. |
| **`activo`** | `bool` | Default: `True` | Si la llave está vigente. |
| **`creado_en`** | `datetime`| Default: `now` | Fecha de generación. |

### Tabla: `recetas`
| Campo | Tipo | Restricción | Descripción |
| :--- | :--- | :--- | :--- |
| **`id_receta`** | `int` | PK | ID de la transacción. |
| **`id_medico`** | `int` | FK (`usuarios`) | Médico que prescribe. |
| **`id_paciente`** | `int` | FK (`usuarios`) | Paciente que recibe. |
| **`capsula`** | `bytes` | - | **Payload JSON cifrado.** |
| **`iv`** | `bytes` | - | Vector de inicialización (AES). |
| **`dek_medico`** | `bytes` | - | Llave simétrica cifrada para el Médico. |
| **`dek_paciente`**| `bytes` | - | Llave simétrica cifrada para el Paciente. |
| **`dek_farmaceutico`**| `bytes`| - | Llave simétrica cifrada para el Farmacéutico. |
| **`estado`** | `str` | Default: `activa`| Estatus actual de la receta. |
| **`creada_en`** | `datetime`| Default: `now` | Fecha de emisión. |
| **`expira_en`** | `datetime`| - | Fecha límite de validez. |

---

## 4. Administración Independiente

### Tabla: `administradores`
| Campo | Tipo | Restricción | Descripción |
| :--- | :--- | :--- | :--- |
| **`id_admin`** | `int` | PK | ID de administrador. |
| **`nombre`** | `str` | - | Nombre completo. |
| **`correo`** | `str` | Unique, Index | Email administrativo. |
| **`contrasena`** | `str` | - | Password (hasheado). |
| **`activo`** | `bool` | Default: `True` | Estatus de la cuenta. |
| **`creado_en`** | `datetime`| Default: `now` | Fecha de creación. |