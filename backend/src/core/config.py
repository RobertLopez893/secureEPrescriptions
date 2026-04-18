"""Configuración global del backend.

En desarrollo se permite un SECRET_KEY de ejemplo para que el proyecto
arranque sin fricción. En producción (APP_ENV=production) se aborta el
arranque si SECRET_KEY está vacío o es el valor demo — así nunca se
firman JWTs con una clave conocida en entornos reales.
"""

import os
import sys

from pydantic_settings import BaseSettings


# Valor de ejemplo; mismo que va en backend/.env.example. Si queda este
# literal cargado en prod, lo tomamos como "no configurado".
_DEMO_SECRET = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"


class Settings(BaseSettings):
    # Para producción, genera una clave segura con: openssl rand -hex 32
    SECRET_KEY: str = _DEMO_SECRET
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60  # El token durará 1 hora

    class Config:
        env_file = ".env"


settings = Settings()


def _is_production() -> bool:
    return os.getenv("APP_ENV", "development").strip().lower() == "production"


# Guardia de arranque: en producción la clave debe venir del entorno y no
# puede ser la de ejemplo. Abortamos temprano — vale más un crash claro
# que un JWT firmado con una llave pública.
if _is_production():
    key = (settings.SECRET_KEY or "").strip()
    if not key or key == _DEMO_SECRET:
        sys.stderr.write(
            "\n[config] ABORT: APP_ENV=production pero SECRET_KEY está vacío "
            "o es el valor de ejemplo. Genera uno con `openssl rand -hex 32` "
            "y expórtalo como variable de entorno antes de arrancar.\n"
        )
        raise SystemExit(1)
