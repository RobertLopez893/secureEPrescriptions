from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Para producción, genera una clave segura con: openssl rand -hex 32
    SECRET_KEY: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 # El token durará 1 hora

    class Config:
        env_file = ".env"

settings = Settings()
