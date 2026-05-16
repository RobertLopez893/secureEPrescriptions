# Módulo `core`: Núcleo de Seguridad y Configuración

Este directorio (`/core`) contiene la base arquitectónica de la aplicación. Aquí no hay lógica de negocio (como crear usuarios o guardar recetas), sino las **herramientas fundamentales** que el resto de la aplicación utiliza para funcionar de manera segura. 

El módulo se divide en tres archivos principales: configuración del entorno, autenticación web (JWT/Contraseñas) y criptografía avanzada (Curvas Elípticas).

---

## 1. `config.py` - Gestión de Entorno y Secretos

Este archivo es el responsable de cargar las variables de entorno (como tu `.env`) y asegurarse de que el servidor no arranque si la configuración de seguridad es deficiente.

### ¿Qué hace específicamente?
Utiliza la librería `pydantic_settings`, que lee tu archivo `.env` o las variables de tu sistema operativo y las convierte en la clase `Settings`. 

* **`APP_ENV`**: Define si estás en modo `"development"` (desarrollo) o `"production"` (producción).
* **`SECRET_KEY`**: Es la llave maestra del servidor. Se usa para firmar los tokens de sesión (JWT). Si alguien descubre esta llave, puede falsificar sesiones y entrar como cualquier usuario.
* **El Validador (`_check_production_secret`)**: Esta es la pieza más importante. Es un "guardia de seguridad" que se ejecuta automáticamente (`@model_validator(mode="after")`) justo cuando la aplicación arranca. 
  * **Si estás en desarrollo:** Te permite usar la llave de ejemplo (`_DEMO_SECRET`) para que programar sea fácil y rápido.
  * **Si estás en producción:** Revisa si la `SECRET_KEY` está vacía o si sigues usando la llave de ejemplo. Si es así, **crashea la aplicación a propósito** (`raise SystemExit(1)`). Esto es un diseño *Fail-Fast* (fallar rápido); es preferible que el servidor no encienda a que encienda con una vulnerabilidad crítica.

---

## 2. `security.py` - Autenticación y Control de Acceso (JWT)

Este archivo maneja cómo los usuarios inician sesión, cómo se guardan sus contraseñas y cómo la aplicación recuerda quiénes son mientras navegan (mediante Tokens JWT).

### ¿Qué hace específicamente?

* **Hasheo de contraseñas con `bcrypt` directo:**
  * En lugar de usar la librería estándar `passlib`, aquí se usa `bcrypt` directamente. Como explica el comentario, `passlib` está abandonada y rompe cuando se combina con versiones modernas de `bcrypt`.
  * **La regla de los 72 bytes:** `bcrypt` por diseño ignora cualquier contraseña que tenga más de 72 caracteres. El método `_encode` corta silenciosamente cualquier contraseña en el byte 72 para evitar que la librería arroje errores (ValueErrors) si un usuario introduce un texto gigantesco.
  * `get_password_hash`: Toma una contraseña en texto plano y la convierte en un hash irreversible.
  * `verify_password`: Compara una contraseña ingresada con el hash guardado en la base de datos.

* **Creación de Tokens (`create_access_token`):**
  * Cuando un usuario hace login exitosamente, esta función crea un JSON Web Token (JWT). Empaqueta los datos del usuario (como su `id`, `rol` y `correo`), le pone una fecha de expiración (1 hora por defecto) y lo **firma digitalmente** usando la `SECRET_KEY` que viene de `config.py`.

* **Protección de Rutas (`get_current_user`):**
  * Es una *Dependencia* de FastAPI. Se coloca en las rutas que requieren que el usuario esté logueado.
  * Captura el token que envía el frontend, verifica que la firma sea válida y que no haya expirado. Si todo está bien, extrae los datos y devuelve un objeto ligero llamado `CurrentUser`. Si el token fue alterado o expiró, rechaza la petición con un error HTTP 401 (No Autorizado).

---

## 3. `crypto_utils.py` - Criptografía Asimétrica (Curvas Elípticas)

A diferencia de `security.py` (que protege la sesión web del usuario), este archivo maneja **criptografía asimétrica** (llaves públicas y privadas), específicamente para firmas digitales usando la curva elíptica P-256 (`SECP256R1`). 

Esto se usa cuando los usuarios firman algo físicamente (como recetas) o inician sesión mediante una tarjeta inteligente o llave criptográfica, en lugar de una contraseña.

### ¿Qué hace específicamente?

* **`verify_p256_ecdsa(pub_hex, message, sig_compact_hex)`:**
  * **El propósito:** Verifica matemáticamente que un mensaje (ej. el contenido de una receta o un reto de login) fue firmado por la persona dueña de una Llave Pública específica.
  * **Los parámetros:**
    1. `pub_hex`: La llave pública del usuario (formato hexadecimal, 130 caracteres, empezando con `04` que significa "descomprimida").
    2. `message`: El mensaje original en bytes.
    3. `sig_compact_hex`: La firma que generó el usuario (64 bytes).
  * **La magia:** La función separa la firma compacta en sus dos componentes matemáticos (`r` y `s`), la convierte al formato estándar (DER), carga la llave pública y ejecuta `pub.verify()`. Si la criptografía coincide, devuelve `True`. Si algo falla (la firma es falsa, la llave está mal formateada), captura el error y devuelve silenciosamente `False`. Jamás interrumpe el servidor con excepciones.

* **`is_valid_p256_pub_hex(pub_hex)`:**
  * Es una función de "Sanity Check" (comprobación de cordura) barata y rápida. 
  * Antes de intentar hacer operaciones matemáticas pesadas con una llave pública, verifica si cumple con el formato básico: que sea un texto, que tenga exactamente 130 caracteres, que empiece con "04" y que sea un hexadecimal válido. Esto evita que datos corruptos lleguen al motor criptográfico.

---

## Resumen de su interacción

1. Cuando levantas el servidor, **`config.py`** se asegura de que haya una llave secreta robusta.
2. Si un usuario inicia sesión con correo y contraseña, **`security.py`** verifica la contraseña, pide a `config.py` la llave secreta, y genera un pasaporte (JWT) para el usuario.
3. Si un usuario realiza una acción avanzada (como firmar una receta médica electrónica o hacer login con tarjeta), el sistema usa **`crypto_utils.py`** para verificar las firmas matemáticas de sus llaves asimétricas.