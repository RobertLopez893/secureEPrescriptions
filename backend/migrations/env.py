"""Entorno de Alembic.

Toma la URL de conexión de DATABASE_URL (la misma variable que usa la
app en src/database/database.py) con fallback a sqlite local, para que
`alembic upgrade head` funcione idéntico dentro de docker-compose y en
una máquina de desarrollo sin Postgres.

target_metadata = SQLModel.metadata: importamos los modelos para que
todas las tablas queden registradas y `--autogenerate` pueda comparar.
"""
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool
from sqlmodel import SQLModel
from alembic import context

# backend/ al sys.path para poder importar `src.*` igual que la app.
sys.path.append(str(Path(__file__).resolve().parents[1]))

# Importar los modelos POBLA SQLModel.metadata (efecto de import).
from src.database import models  # noqa: E402,F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Misma fuente de verdad que la app; fallback a sqlite para dev sin docker.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./alembic_dev.db")
config.set_main_option("sqlalchemy.url", DATABASE_URL)

target_metadata = SQLModel.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        render_as_batch=DATABASE_URL.startswith("sqlite"),
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            # batch mode: sqlite no soporta ALTER nativo (rename/altercol).
            render_as_batch=DATABASE_URL.startswith("sqlite"),
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
