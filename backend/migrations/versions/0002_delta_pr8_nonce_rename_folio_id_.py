"""delta PR8: nonce rename, folio, id_farmaceutico NOT NULL, responsabilidad, tz

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-16 21:24:44.336256

Esta migración reconstruye el delta que el PR #8 (UpdateCripto, Andy/Emiliano)
metió a `main` *sin* migración. Autogenerada por Alembic y luego ajustada
a mano para que sea SEGURA CON DATOS EXISTENTES:

  * iv_aes_gcm -> nonce  : RENOMBRADO (no drop+add) para no perder el
                           nonce AES-GCM de recetas ya emitidas.
  * llaves.responsabilidad: agregada con server_default 'general' para
                           que las filas viejas tengan valor.
  * recetas.folio        : agregada nullable, backfill determinista
                           'LEGACY-<id_receta>', índice UNIQUE, luego
                           NOT NULL.
  * recetas.id_farmaceutico nullable -> NOT NULL: ver WARNING abajo.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision: str = '0002'
down_revision: Union[str, None] = '0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- llaves.responsabilidad: server_default para filas preexistentes ---
    with op.batch_alter_table('llaves', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            'responsabilidad',
            sqlmodel.sql.sqltypes.AutoString(),
            nullable=False,
            server_default='general',
        ))

    # --- recetas: rename + folio + id_farmaceutico ---
    with op.batch_alter_table('recetas', schema=None) as batch_op:
        # RENAME real: preserva el nonce de recetas ya emitidas.
        batch_op.alter_column(
            'iv_aes_gcm',
            new_column_name='nonce',
            existing_type=sa.VARCHAR(),
            existing_nullable=False,
        )
        # folio: primero nullable para poder backfillear filas viejas.
        batch_op.add_column(sa.Column(
            'folio', sqlmodel.sql.sqltypes.AutoString(), nullable=True))

    # Backfill determinista y único de folio para recetas históricas.
    op.execute(
        "UPDATE recetas SET folio = 'LEGACY-' || id_receta WHERE folio IS NULL"
    )

    with op.batch_alter_table('recetas', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_recetas_folio'), ['folio'], unique=True)
        batch_op.alter_column(
            'folio',
            existing_type=sqlmodel.sql.sqltypes.AutoString(),
            nullable=False,
        )
        # WARNING (cambio semántico heredado del PR #8): antes una receta
        # podía existir SIN farmacéutico (se asignaba al sellar). Ahora
        # id_farmaceutico es obligatorio desde la emisión. Si la DB tiene
        # recetas con id_farmaceutico NULL, este ALTER FALLA a propósito:
        # no hay un farmacéutico válido que inventar. La decisión correcta
        # (backfill vs. rediseño) la tiene que tomar el equipo con Andy,
        # no esta migración. Discutido en la revisión de la rama.
        batch_op.alter_column(
            'id_farmaceutico',
            existing_type=sa.INTEGER(),
            nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table('recetas', schema=None) as batch_op:
        batch_op.alter_column(
            'id_farmaceutico',
            existing_type=sa.INTEGER(),
            nullable=True,
        )
        batch_op.drop_index(batch_op.f('ix_recetas_folio'))
        batch_op.drop_column('folio')
        # Revertir el rename.
        batch_op.alter_column(
            'nonce',
            new_column_name='iv_aes_gcm',
            existing_type=sa.VARCHAR(),
            existing_nullable=False,
        )

    with op.batch_alter_table('llaves', schema=None) as batch_op:
        batch_op.drop_column('responsabilidad')
