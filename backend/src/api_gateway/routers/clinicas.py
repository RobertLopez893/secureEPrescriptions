from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select, func

from src.core.security import CurrentUser, get_current_user
from src.database.database import get_session
from src.database.models import Clinica, Usuario, Rol
from src.api_gateway import schemas

router = APIRouter()


@router.post("/clinicas", response_model=schemas.ClinicaPublic, status_code=status.HTTP_201_CREATED)
def crear_clinica(
    *,
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
    clinica_in: schemas.ClinicaCreate,
):
    """Registra una nueva clínica/hospital. Solo Admin."""
    if current_user.role != "Administrador":
        raise HTTPException(
            status_code=403,
            detail="Solo un Administrador puede dar de alta clínicas.",
        )
    if session.exec(select(Clinica).where(Clinica.clues == clinica_in.clues)).first():
        raise HTTPException(status_code=400, detail="Ya existe una clínica con esa CLUES.")

    db_clinica = Clinica(**clinica_in.model_dump())
    session.add(db_clinica)
    session.commit()
    session.refresh(db_clinica)
    return schemas.ClinicaPublic(**db_clinica.model_dump())


@router.get("/clinicas", response_model=List[schemas.ClinicaPublic])
def listar_clinicas(*, session: Session = Depends(get_session)):
    """Devuelve la lista de clínicas registradas (necesaria al registrar médicos)."""
    rows = session.exec(select(Clinica)).all()
    return [schemas.ClinicaPublic(**c.model_dump()) for c in rows]


@router.get("/stats")
def estadisticas_publicas(*, session: Session = Depends(get_session)):
    """Conteo público (no requiere auth) de clínicas por tipo y usuarios
    por rol. Lo consume el landing para mostrar el tamaño de la red."""
    filas_tipo = session.exec(
        select(Clinica.tipo, func.count(Clinica.id_clinica)).group_by(Clinica.tipo)
    ).all()
    por_tipo = {tipo: n for tipo, n in filas_tipo}

    filas_rol = session.exec(
        select(Rol.nombre, func.count(Usuario.id_usuario))
        .join(Usuario, Usuario.id_rol == Rol.id_rol, isouter=True)
        .group_by(Rol.nombre)
    ).all()
    por_rol = {nombre: n for nombre, n in filas_rol}

    centros = por_tipo.get("Centro Medico", 0)
    hospitales = por_tipo.get("Hospital", 0)
    farmacias = por_tipo.get("Farmacia", 0)

    return {
        "clinicas": {
            "total": sum(por_tipo.values()),
            "centros_medicos": centros,
            "hospitales": hospitales,
            "farmacias": farmacias,
            # Suma "instituciones de salud" (centros + hospitales) por si
            # el front quiere un solo número.
            "instituciones_salud": centros + hospitales,
        },
        "usuarios": {
            "medicos": por_rol.get("Medico", 0),
            "pacientes": por_rol.get("Paciente", 0),
            "farmaceuticos": por_rol.get("Farmaceutico", 0),
        },
    }
