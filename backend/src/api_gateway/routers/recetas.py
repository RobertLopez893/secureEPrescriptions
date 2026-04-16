import base64
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from src.database.database import get_session
from src.database.models import Receta, Usuario
from src.api_gateway import schemas

router = APIRouter()

@router.post("/recetas", response_model=RecetaPublic, status_code=201)
def emitir_receta(
    *,
    session: Session = Depends(get_session),
    receta_in: schemas.RecetaCreate
):
    """
    Endpoint para que un médico emita una nueva receta.
    Recibe los datos y el paquete criptográfico desde el frontend.
    """
    try:
        # Decodificar los datos de Base64 a bytes antes de guardarlos
        db_receta = Receta.model_validate(
            receta_in,
            update={
                "capsula": base64.b64decode(receta_in.capsula),
                "iv": base64.b64decode(receta_in.iv),
                "dek_medico": base64.b64decode(receta_in.dek_medico),
                "dek_paciente": base64.b64decode(receta_in.dek_paciente),
                "dek_farmaceutico": base64.b64decode(receta_in.dek_farmaceutico),
            }
        )
        session.add(db_receta)
        session.commit()
        session.refresh(db_receta)
        return db_receta
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al procesar la receta: {e}")


@router.get("/recetas/{id_receta}", response_model=schemas.RecetaDetailPublic)
def obtener_info_publica_receta(
    *,
    session: Session = Depends(get_session),
    id_receta: int
):
    """
    Endpoint público para verificación por QR.
    Devuelve información no sensible de la receta para que el farmacéutico verifique.
    """
    # 1. Obtener la receta por su ID
    receta = session.get(Receta, id_receta)
    if not receta:
        raise HTTPException(status_code=404, detail="Receta no encontrada")

    # 2. Obtener la información del médico y del paciente usando los IDs de la receta
    medico = session.get(Usuario, receta.id_medico)
    paciente = session.get(Usuario, receta.id_paciente)

    if not medico or not paciente:
        raise HTTPException(status_code=404, detail="No se encontró la información del médico o paciente asociado.")

    # 3. Construir y devolver la respuesta pública
    return schemas.RecetaDetailPublic(
        id_receta=receta.id_receta,
        estado=receta.estado,
        creada_en=receta.creada_en,
        expira_en=receta.expira_en,
        medico=schemas.UserInfo(nombre_completo=f"{medico.nombre} {medico.paterno}"),
        paciente=schemas.UserInfo(nombre_completo=f"{paciente.nombre} {paciente.paterno}")
    )
