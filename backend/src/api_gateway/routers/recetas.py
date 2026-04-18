from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from src.database.database import get_session
from src.database.models import Receta, Usuario
from src.api_gateway import schemas

router = APIRouter()


@router.get("/recetas", response_model=List[schemas.RecetaDetailPublic])
def listar_recetas(
    *,
    session: Session = Depends(get_session),
    id_paciente: Optional[int] = Query(
        default=None,
        description="Filtra recetas por el id_usuario del paciente dueño.",
    ),
    id_medico: Optional[int] = Query(
        default=None,
        description="Filtra recetas emitidas por un médico (id_usuario).",
    ),
    estado: Optional[str] = Query(
        default=None,
        description="Filtra por estado ('activa' o 'surtida').",
    ),
    limit: int = Query(default=50, ge=1, le=200),
):
    """Devuelve las recetas que cumplen con los filtros dados, ordenadas
    de la más reciente a la más antigua. Se requiere al menos un filtro
    (id_paciente o id_medico) para evitar listados globales abiertos."""
    if id_paciente is None and id_medico is None:
        raise HTTPException(
            status_code=400,
            detail="Proporciona id_paciente o id_medico para filtrar.",
        )

    stmt = select(Receta)
    if id_paciente is not None:
        stmt = stmt.where(Receta.id_paciente == id_paciente)
    if id_medico is not None:
        stmt = stmt.where(Receta.id_medico == id_medico)
    if estado is not None:
        stmt = stmt.where(Receta.estado == estado)
    stmt = stmt.order_by(Receta.creada_en.desc()).limit(limit)

    recetas = session.exec(stmt).all()

    # Precargamos los usuarios que aparecen para evitar N+1 consultas.
    ids_usuarios = {r.id_medico for r in recetas} | {r.id_paciente for r in recetas}
    usuarios = {}
    if ids_usuarios:
        for u in session.exec(select(Usuario).where(Usuario.id_usuario.in_(ids_usuarios))).all():
            usuarios[u.id_usuario] = u

    out: List[schemas.RecetaDetailPublic] = []
    for r in recetas:
        medico = usuarios.get(r.id_medico)
        paciente = usuarios.get(r.id_paciente)
        if not medico or not paciente:
            # Omitimos las recetas cuyas referencias de usuario ya no existen
            # para no romper la respuesta completa.
            continue
        out.append(
            schemas.RecetaDetailPublic(
                id_receta=r.id_receta,
                estado=r.estado,
                creada_en=r.creada_en,
                expira_en=r.expira_en,
                medico=schemas.UserInfo(nombre_completo=f"{medico.nombre} {medico.paterno}"),
                paciente=schemas.UserInfo(nombre_completo=f"{paciente.nombre} {paciente.paterno}"),
            )
        )
    return out

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
