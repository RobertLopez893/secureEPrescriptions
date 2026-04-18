from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from src.database.database import get_session
from src.database.models import Clinica
from src.api_gateway import schemas

router = APIRouter()


@router.post("/clinicas", response_model=schemas.ClinicaPublic, status_code=status.HTTP_201_CREATED)
def crear_clinica(*, session: Session = Depends(get_session), clinica_in: schemas.ClinicaCreate):
    """Registra una nueva clínica/hospital."""
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
