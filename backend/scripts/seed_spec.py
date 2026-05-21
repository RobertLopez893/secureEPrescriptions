"""Script CLI para sembrar manualmente la infraestructura del enunciado
(2 centros médicos × 20 médicos, 1 hospital × 300 médicos, 3 farmacias
con jefe farmacéutico). Idempotente: se puede correr varias veces sin
duplicar registros.

Uso típico (con los contenedores ya levantados):

    docker compose exec backend python -m scripts.seed_spec

Solo ver el conteo, sin sembrar:

    docker compose exec backend python -m scripts.seed_spec --stats

O localmente (con DATABASE_URL apuntando a la BD correcta):

    cd backend
    python -m scripts.seed_spec
"""
from __future__ import annotations

import argparse
import os
import sys

from sqlmodel import SQLModel, Session, select, func

from src.database.database import engine
from src.database import models, seed_demo


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Seeder manual de infraestructura spec.")
    p.add_argument(
        "--force-dev",
        action="store_true",
        help="Forzar APP_ENV=development durante esta corrida (los seeders "
             "exigen development).",
    )
    p.add_argument(
        "--only-spec",
        action="store_true",
        help="Sembrar solo la infraestructura del enunciado (2 centros + "
             "1 hospital + 3 farmacias). Omite el bloque demo (usuarios "
             "doctor@/paciente@/farma@).",
    )
    p.add_argument(
        "--create-tables",
        action="store_true",
        help="Ejecutar create_all antes de sembrar (útil si la BD está "
             "vacía y no levantaste el backend todavía).",
    )
    p.add_argument(
        "--stats",
        action="store_true",
        help="Solo imprime el conteo de clínicas/médicos/pacientes/"
             "farmacéuticos y termina, sin sembrar nada.",
    )
    return p.parse_args()


def _print_stats(session: Session) -> None:
    """Imprime el conteo agregado y por tipo de clínica."""
    # Conteo de clínicas por tipo
    filas_tipo = session.exec(
        select(models.Clinica.tipo, func.count(models.Clinica.id_clinica))
        .group_by(models.Clinica.tipo)
    ).all()
    total_clinicas = sum(n for _, n in filas_tipo)

    # Conteo por rol (médico/paciente/farmacéutico)
    filas_rol = session.exec(
        select(models.Rol.nombre, func.count(models.Usuario.id_usuario))
        .join(models.Usuario, models.Usuario.id_rol == models.Rol.id_rol, isouter=True)
        .group_by(models.Rol.nombre)
    ).all()
    conteo_rol = {nombre: n for nombre, n in filas_rol}

    total_usuarios = session.exec(select(func.count(models.Usuario.id_usuario))).one()
    total_admins = session.exec(select(func.count(models.Administrador.id_admin))).one()
    total_llaves = session.exec(select(func.count(models.Llave.id_llave))).one()
    total_recetas = session.exec(select(func.count(models.Receta.id_receta))).one()

    print("")
    print("== Conteo actual en la BD ==")
    print(f"  Clínicas totales: {total_clinicas}")
    for tipo, n in sorted(filas_tipo):
        print(f"    - {tipo}: {n}")
    print(f"  Usuarios totales: {total_usuarios}")
    print(f"    - Médicos:       {conteo_rol.get('Medico', 0)}")
    print(f"    - Pacientes:     {conteo_rol.get('Paciente', 0)}")
    print(f"    - Farmacéuticos: {conteo_rol.get('Farmaceutico', 0)}")
    print(f"  Administradores: {total_admins}")
    print(f"  Llaves públicas: {total_llaves}")
    print(f"  Recetas:         {total_recetas}")
    print("")


def main() -> int:
    args = _parse_args()

    if args.stats:
        with Session(engine) as session:
            _print_stats(session)
        return 0

    if args.force_dev:
        os.environ["APP_ENV"] = "development"

    if os.getenv("APP_ENV", "development").lower() != "development":
        print("APP_ENV no es 'development'. Usa --force-dev para forzarlo.",
              file=sys.stderr)
        return 2

    if args.create_tables:
        print("Creando tablas (SQLModel.metadata.create_all)...")
        SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        seed_demo._ensure_roles(session)
        if not args.only_spec:
            seed_demo._seed_demo_data(session)
        seed_demo._seed_spec_data(session)
        _print_stats(session)

    print("OK. Seed manual completado.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
