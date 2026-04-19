from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from src.core.crypto_utils import verify_p256_ecdsa
from src.core.security import CurrentUser, get_current_user
from src.database.database import get_session
from src.database.models import Llave, Receta, Usuario
from src.api_gateway import schemas


def _is_vencida(expira_en: datetime, now_utc: datetime) -> bool:
    """Una receta está vencida si su expira_en ya pasó. Los datetime naive
    se asumen UTC (mismo criterio que al firmar el envelope)."""
    dt = expira_en if expira_en.tzinfo else expira_en.replace(tzinfo=timezone.utc)
    return dt < now_utc

router = APIRouter()


# ---------------------------------------------------------------------------
# Envelope signature helpers
# ---------------------------------------------------------------------------
def _envelope_message(
    id_medico: int,
    id_paciente: int,
    capsula_cifrada: str,
    iv_aes_gcm: str,
    expira_en: datetime,
) -> bytes:
    """Construye el mensaje canónico que el médico firma con su llave
    privada para probar autoría de la cápsula cifrada. El formato es una
    concatenación simple separada por '\\n' para evitar ambigüedades entre
    canónicos JSON de JS y Python:

        <id_medico>\\n<id_paciente>\\n<capsula_cifrada>\\n<iv_aes_gcm>\\n<expira_unix>

    `expira_unix` es segundos enteros desde epoch UTC. Si el datetime es
    naive, lo asumimos UTC."""
    dt = expira_en if expira_en.tzinfo else expira_en.replace(tzinfo=timezone.utc)
    expira_unix = int(dt.timestamp())
    return (
        f"{id_medico}\n{id_paciente}\n{capsula_cifrada}\n{iv_aes_gcm}\n{expira_unix}"
    ).encode("utf-8")


def _get_active_public_key(session: Session, id_usuario: int) -> Optional[str]:
    """Devuelve la llave pública activa (hex) de un usuario o None."""
    llave = session.exec(
        select(Llave)
        .where(Llave.id_usuario == id_usuario, Llave.activo == True)
        .order_by(Llave.creado_en.desc())
    ).first()
    return llave.llave_publica if llave else None


@router.get("/recetas", response_model=List[schemas.RecetaDetailPublic])
def listar_recetas(
    *,
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
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
        description=(
            "Filtra por estado: 'activa', 'surtida' o 'expirada'. "
            "'expirada' es derivado (expira_en < now()) y excluye surtidas."
        ),
    ),
    limit: int = Query(default=50, ge=1, le=200),
):
    """Devuelve las recetas que cumplen con los filtros dados, ordenadas
    de la más reciente a la más antigua. Se requiere al menos un filtro
    (id_paciente o id_medico) para evitar listados globales abiertos.

    Autorización: el filtro debe coincidir con el usuario autenticado,
    salvo que sea Administrador o Farmaceutico (que debe dispensar y ver
    recetas asignadas a pacientes)."""
    if id_paciente is None and id_medico is None:
        raise HTTPException(
            status_code=400,
            detail="Proporciona id_paciente o id_medico para filtrar.",
        )

    # Reglas mínimas de autorización por rol:
    # - Paciente: solo su propio id_paciente.
    # - Medico:   solo su propio id_medico.
    # - Farmaceutico / Administrador: cualquier filtro válido.
    role = current_user.role
    if role == "Paciente":
        if id_paciente is None or id_paciente != current_user.id:
            raise HTTPException(status_code=403, detail="Solo puedes consultar tus propias recetas.")
    elif role == "Medico":
        if id_medico is None or id_medico != current_user.id:
            raise HTTPException(status_code=403, detail="Solo puedes consultar recetas emitidas por ti.")
    elif role not in ("Farmaceutico", "Administrador"):
        raise HTTPException(status_code=403, detail=f"Rol '{role}' no autorizado para este recurso.")

    now_utc = datetime.now(timezone.utc)

    stmt = select(Receta)
    if id_paciente is not None:
        stmt = stmt.where(Receta.id_paciente == id_paciente)
    if id_medico is not None:
        stmt = stmt.where(Receta.id_medico == id_medico)
    if estado is not None:
        if estado == "expirada":
            # "Expirada" es derivado: se excluyen surtidas y se filtran
            # por expira_en < ahora en naive UTC (match del tipo en BD).
            stmt = stmt.where(
                Receta.estado != "surtida",
                Receta.expira_en < now_utc.replace(tzinfo=None),
            )
        else:
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
                id_medico=r.id_medico,
                id_paciente=r.id_paciente,
                medico=schemas.UserInfo(nombre_completo=f"{medico.nombre} {medico.paterno}"),
                paciente=schemas.UserInfo(nombre_completo=f"{paciente.nombre} {paciente.paterno}"),
                vencida=_is_vencida(r.expira_en, now_utc) and r.estado != "surtida",
            )
        )
    return out

def _authorize_view_receta(receta: Receta, current_user: CurrentUser) -> None:
    """
    Reglas de visibilidad de una receta específica (por id):
      - Paciente: solo si es su dueño.
      - Medico:   solo si la emitió él.
      - Farmaceutico: siempre (necesita dispensar).
      - Administrador: siempre.
    Lanza 403 si el usuario autenticado no cumple.
    """
    role = current_user.role
    if role == "Paciente" and receta.id_paciente != current_user.id:
        raise HTTPException(status_code=403, detail="No puedes ver recetas de otro paciente.")
    if role == "Medico" and receta.id_medico != current_user.id:
        raise HTTPException(status_code=403, detail="No puedes ver recetas emitidas por otro médico.")
    if role not in ("Paciente", "Medico", "Farmaceutico", "Administrador"):
        raise HTTPException(status_code=403, detail=f"Rol '{role}' no autorizado para este recurso.")


@router.post("/recetas", response_model=schemas.RecetaPublic, status_code=201)
def emitir_receta(
    *,
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
    receta_in: schemas.RecetaCreate,
):
    """Emite una nueva receta. Solo médicos (o admin) pueden hacerlo.
    El `id_medico` se toma siempre del token para evitar suplantación:
    un cliente comprometido no puede firmar a nombre de otro doctor."""
    if current_user.role not in ("Medico", "Administrador"):
        raise HTTPException(
            status_code=403,
            detail=f"El rol '{current_user.role}' no puede emitir recetas.",
        )

    # Si es médico, el id_medico del body se ignora y se usa el del token.
    # Admin sí puede especificar cualquier id_medico (útil para tooling).
    id_medico = current_user.id if current_user.role == "Medico" else receta_in.id_medico
    if id_medico is None:
        raise HTTPException(
            status_code=400,
            detail="Falta el id_medico emisor (Administrador debe especificarlo).",
        )

    # Validamos que el paciente existe (evitamos referencias rotas en la BD).
    if not session.get(Usuario, receta_in.id_paciente):
        raise HTTPException(status_code=404, detail="Paciente no encontrado.")

    # ── Verificación ECDSA de autoría ────────────────────────────────────
    # El médico firma el "envelope" (metadatos + blobs opacos) con su
    # llave privada. El backend verifica con la llave pública registrada
    # sin necesidad de conocer el contenido real de la receta.
    pub_hex = _get_active_public_key(session, id_medico)
    if not pub_hex:
        raise HTTPException(
            status_code=400,
            detail=(
                f"El médico {id_medico} no tiene llave pública registrada. "
                "Registra una con PUT /usuarios/me/llave antes de emitir recetas."
            ),
        )
    envelope_msg = _envelope_message(
        id_medico=id_medico,
        id_paciente=receta_in.id_paciente,
        capsula_cifrada=receta_in.capsula_cifrada,
        iv_aes_gcm=receta_in.iv_aes_gcm,
        expira_en=receta_in.expira_en,
    )
    if not verify_p256_ecdsa(pub_hex, envelope_msg, receta_in.firma_envelope):
        raise HTTPException(
            status_code=400,
            detail="Firma de autoría inválida: la cápsula no pudo verificarse contra la llave pública del médico.",
        )

    db_receta = Receta(
        id_medico=id_medico,
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
    current_user: CurrentUser = Depends(get_current_user),
    id_receta: int,
):
    receta = session.get(Receta, id_receta)
    if not receta:
        raise HTTPException(status_code=404, detail="Receta no encontrada")

    _authorize_view_receta(receta, current_user)

    medico = session.get(Usuario, receta.id_medico)
    paciente = session.get(Usuario, receta.id_paciente)

    if not medico or not paciente:
        raise HTTPException(status_code=404, detail="No se encontró la información del médico o paciente asociado.")

    now_utc = datetime.now(timezone.utc)
    return schemas.RecetaDetailPublic(
        id_receta=receta.id_receta,
        estado=receta.estado,
        creada_en=receta.creada_en,
        expira_en=receta.expira_en,
        id_medico=receta.id_medico,
        id_paciente=receta.id_paciente,
        medico=schemas.UserInfo(nombre_completo=f"{medico.nombre} {medico.paterno}"),
        paciente=schemas.UserInfo(nombre_completo=f"{paciente.nombre} {paciente.paterno}"),
        vencida=_is_vencida(receta.expira_en, now_utc) and receta.estado != "surtida",
    )


@router.get("/recetas/{id_receta}/cripto", response_model=schemas.RecetaCriptoPublic)
def obtener_cripto_receta(
    *,
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
    id_receta: int,
):
    """Devuelve la cápsula cifrada y los accesos para desencriptar en el frontend.
    Aplica la misma política que GET /recetas/{id}: paciente dueño, médico
    emisor, farmacéutico (para dispensar) o administrador."""
    receta = session.get(Receta, id_receta)
    if not receta:
        raise HTTPException(status_code=404, detail="Receta no encontrada")

    _authorize_view_receta(receta, current_user)

    return schemas.RecetaCriptoPublic(
        id_receta=receta.id_receta,
        id_medico=receta.id_medico,
        id_paciente=receta.id_paciente,
        capsula_cifrada=receta.capsula_cifrada,
        iv_aes_gcm=receta.iv_aes_gcm,
        accesos=[schemas.AccesoPublic(**a) for a in receta.accesos],
        estado=receta.estado,
    )


@router.put("/recetas/{id_receta}/sellar", response_model=schemas.RecetaPublic)
def sellar_receta(
    *,
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
    id_receta: int,
    sello_in: schemas.RecetaSellarRequest,
):
    """Actualiza la receta después del sellado por la farmacia.
    Solo farmacéuticos (o admin) pueden ejecutar esta operación y el
    `id_farmaceutico` grabado en la receta proviene del token, no del body."""
    if current_user.role not in ("Farmaceutico", "Administrador"):
        raise HTTPException(
            status_code=403,
            detail=f"El rol '{current_user.role}' no puede sellar recetas.",
        )

    receta = session.get(Receta, id_receta)
    if not receta:
        raise HTTPException(status_code=404, detail="Receta no encontrada")

    if receta.estado != "activa":
        raise HTTPException(status_code=400, detail="La receta ya fue surtida o está inactiva.")

    now_utc = datetime.now(timezone.utc)
    if _is_vencida(receta.expira_en, now_utc):
        raise HTTPException(
            status_code=400,
            detail="La receta está vencida y no puede dispensarse.",
        )

    id_farma = current_user.id if current_user.role == "Farmaceutico" else sello_in.id_farmaceutico

    receta.capsula_cifrada = sello_in.capsula_cifrada
    receta.iv_aes_gcm = sello_in.iv_aes_gcm
    receta.accesos = [a.model_dump() for a in sello_in.accesos]
    receta.id_farmaceutico = id_farma
    receta.estado = "surtida"

    session.add(receta)
    session.commit()
    session.refresh(receta)
    return receta
