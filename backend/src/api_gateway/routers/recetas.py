from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from src.database.database import get_session
from src.database.models import Receta, Usuario
from src.api_gateway import schemas

router = APIRouter()

@router.post("/recetas", response_model=schemas.RecetaPublic, status_code=201)
def emitir_receta(
    *,
    session: Session = Depends(get_session),
    receta_in: schemas.RecetaCreate
):
    db_receta = Receta(
        id_medico=receta_in.id_medico,
        id_paciente=receta_in.id_paciente,
        expira_en=receta_in.expira_en,
        capsula_cifrada=receta_in.capsula_cifrada,
        iv_aes_gcm=receta_in.iv_aes_gcm,
        accesos=[a.model_dump() for a in receta_in.accesos],
    )
    session.add(db_receta)
    session.commit()
    session.refresh(db_receta)
    return db_receta


@router.get("/recetas/{id_receta}", response_model=schemas.RecetaDetailPublic)
def obtener_info_publica_receta(
    *,
    session: Session = Depends(get_session),
    id_receta: int
):
    receta = session.get(Receta, id_receta)
    if not receta:
        raise HTTPException(status_code=404, detail="Receta no encontrada")

    medico = session.get(Usuario, receta.id_medico)
    paciente = session.get(Usuario, receta.id_paciente)

    if not medico or not paciente:
        raise HTTPException(status_code=404, detail="No se encontró la información del médico o paciente asociado.")

    return schemas.RecetaDetailPublic(
        id_receta=receta.id_receta,
        estado=receta.estado,
        creada_en=receta.creada_en,
        expira_en=receta.expira_en,
        medico=schemas.UserInfo(nombre_completo=f"{medico.nombre} {medico.paterno}"),
        paciente=schemas.UserInfo(nombre_completo=f"{paciente.nombre} {paciente.paterno}")
    )


@router.get("/recetas/{id_receta}/cripto", response_model=schemas.RecetaCriptoPublic)
def obtener_cripto_receta(
    *,
    session: Session = Depends(get_session),
    id_receta: int
):
    """Devuelve la cápsula cifrada y los accesos para desencriptar en el frontend."""
    receta = session.get(Receta, id_receta)
    if not receta:
        raise HTTPException(status_code=404, detail="Receta no encontrada")

    return schemas.RecetaCriptoPublic(
        id_receta=receta.id_receta,
        capsula_cifrada=receta.capsula_cifrada,
        iv_aes_gcm=receta.iv_aes_gcm,
        accesos=[schemas.AccesoPublic(**a) for a in receta.accesos],
        estado=receta.estado,
    )


@router.put("/recetas/{id_receta}/sellar", response_model=schemas.RecetaPublic)
def sellar_receta(
    *,
    session: Session = Depends(get_session),
    id_receta: int,
    sello_in: schemas.RecetaSellarRequest
):
    """Actualiza la receta después del sellado por la farmacia."""
    receta = session.get(Receta, id_receta)
    if not receta:
        raise HTTPException(status_code=404, detail="Receta no encontrada")

    if receta.estado != "activa":
        raise HTTPException(status_code=400, detail="La receta ya fue surtida o está inactiva.")

    receta.capsula_cifrada = sello_in.capsula_cifrada
    receta.iv_aes_gcm = sello_in.iv_aes_gcm
    receta.accesos = [a.model_dump() for a in sello_in.accesos]
    receta.id_farmaceutico = sello_in.id_farmaceutico
    receta.estado = "surtida"

    session.add(receta)
    session.commit()
    session.refresh(receta)
    return receta
