import sys
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEMO_SECRET = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"

class Settings(BaseSettings):
    # Añadimos APP_ENV aquí para que Pydantic lo cargue del .env o del OS
    APP_ENV: str = "development"
    
    SECRET_KEY: str = _DEMO_SECRET
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Este validador se ejecuta automáticamente al instanciar la clase
    @model_validator(mode="after")
    def _check_production_secret(self) -> "Settings":
        if self.APP_ENV.strip().lower() == "production":
            key = (self.SECRET_KEY or "").strip()
            if not key or key == _DEMO_SECRET:
                sys.stderr.write(
                    "\n[config] ABORT: APP_ENV=production pero SECRET_KEY está vacío "
                    "o es el valor de ejemplo. Genera uno con `openssl rand -hex 32` "
                    "y colócalo en tu entorno antes de arrancar.\n"
                )
                raise SystemExit(1)
        return self

# Al instanciar, validará todo automáticamente
settings = Settings()