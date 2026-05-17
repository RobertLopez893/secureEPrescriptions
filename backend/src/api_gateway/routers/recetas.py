from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from src.core.crypto_utils import verify_p256_ecdsa
from src.core.security import CurrentUser, get_current_user
from src.database.database import get_session
from src.database.models import Llave, Receta, Rol, Usuario
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

def _get_active_public_key(session: Session, id_usuario: int) -> Optional[str]:
    """Devuelve la llave pública activa (hex) de un usuario o None."""
    llave = session.exec(
        select(Llave)
        .where(Llave.id_usuario == id_usuario, Llave.activo == True)
        .order_by(Llave.creado_en.desc())
    ).first()
    return llave.llave_publica if llave else None


def _get_signing_public_key(session: Session, id_usuario: int) -> Optional[str]:
    """Llave pública de FIRMA (responsabilidad='firmas') activa de un
    usuario. Es la contraparte de la llave 'sign' que deriva el frontend;
    el directorio de llaves separa cifrado ('recetas') de autoría
    ('firmas'). Mismo criterio que usa el login por tarjeta en auth.py,
    para no mantener dos convenciones de verificación distintas."""
    llave = session.exec(
        select(Llave)
        .where(
            Llave.id_usuario == id_usuario,
            Llave.activo == True,
            Llave.responsabilidad == "firmas",
        )
        .order_by(Llave.creado_en.desc())
    ).first()
    return llave.llave_publica if llave else None


def _envelope_message(
    *,
    id_medico: int,
    id_paciente: int,
    id_farmaceutico: int,
    folio: str,
    capsula_cifrada: str,
    nonce: str,
    creada_en: datetime,
    expira_en: datetime,
) -> bytes:
    """Mensaje canónico que el médico firma para probar autoría de la
    cápsula, SIN que el backend vea el contenido en claro.

    Concatenación separada por '\\n' (no JSON, para evitar ambigüedades
    de canónico entre JS y Python). El frontend construye exactamente la
    misma cadena y firma con `p256.sign(bytes, priv, {prehash:true})`;
    el backend verifica con `verify_p256_ecdsa` (ECDSA SHA-256) — la
    misma convención ya probada en el login por tarjeta.

        <id_medico>\\n<id_paciente>\\n<id_farmaceutico>\\n<folio>
        \\n<capsula_cifrada>\\n<nonce>\\n<creada_unix>\\n<expira_unix>

    Se incluyen `id_farmaceutico` y `folio` a propósito: así la firma
    también ata la receta a SU farmacéutico destino y folio; cambiarlos
    (página manipulada, JWT robado) invalida la firma.

    Los datetime naive se asumen UTC (mismo criterio que `_is_vencida`).
    """
    def _unix(dt: datetime) -> int:
        d = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        return int(d.timestamp())

    return (
        f"{id_medico}\n{id_paciente}\n{id_farmaceutico}\n{folio}\n"
        f"{capsula_cifrada}\n{nonce}\n{_unix(creada_en)}\n{_unix(expira_en)}"
    ).encode("utf-8")


def _resolve_jefe_farmaceutico(session: Session, id_clinica: Optional[int]) -> Usuario:
    """Resuelve el ÚNICO farmacéutico jefe de una clínica.

    El modelo de Andy asume 1 farmacéutico jefe por hospital, pero el
    esquema permite varios usuarios Farmaceutico por clínica. Tratamos
    ese "1" como invariante duro: 0 o >1 es un estado de datos inválido y
    abortamos en vez de adivinar (decidido con el equipo). La
    auto-asignación cierra el agujero de que el cliente eligiera el
    id_farmaceutico a mano.
    """
    if id_clinica is None:
        raise HTTPException(
            status_code=409,
            detail="El médico emisor no tiene clínica asignada; no se puede "
                   "resolver el farmacéutico jefe.",
        )
    farmaceuticos = session.exec(
        select(Usuario)
        .join(Rol, Usuario.id_rol == Rol.id_rol)
        .where(Rol.nombre == "Farmaceutico", Usuario.id_clinica == id_clinica)
    ).all()
    if len(farmaceuticos) == 0:
        raise HTTPException(
            status_code=409,
            detail=f"La clínica {id_clinica} no tiene un farmacéutico jefe "
                   "registrado.",
        )
    if len(farmaceuticos) > 1:
        raise HTTPException(
            status_code=409,
            detail=f"La clínica {id_clinica} tiene {len(farmaceuticos)} "
                   "farmacéuticos; el modelo exige exactamente 1 jefe. "
                   "Corrige los datos antes de emitir.",
        )
    return farmaceuticos[0]


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
    folio: Optional[str]= Query(
        default=None,
        description=(
            "Filtra recetas por su Folio.",
        )
    ),
    limit: int = Query(default=50, ge=1, le=200),
):
    """Devuelve las recetas que cumplen con los filtros dados, ordenadas
    de la más reciente a la más antigua. Se requiere al menos un filtro
    (id_paciente o id_medico) para evitar listados globales abiertos.

    Autorización: el filtro debe coincidir con el usuario autenticado,
    salvo que sea Administrador o Farmaceutico (que debe dispensar y ver
    recetas asignadas a pacientes)."""
    #if id_paciente is None and id_medico is None :
    #    raise HTTPException(
    #        status_code=400,
    #        detail="Proporciona id_paciente o id_medico para filtrar.",
    #    )

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
    if folio is not None:
        stmt = stmt.where(Receta.folio.icontains(folio))
        print(folio)

    stmt = stmt.order_by(Receta.id_receta.desc()).limit(limit)

    recetas = session.exec(stmt).all()
    print(recetas)
    # Precargamos los usuarios que aparecen para evitar N+1 consultas.
    ids_usuarios = {r.id_medico for r in recetas} | {r.id_paciente for r in recetas} | {r.id_farmaceutico for r in recetas}
    usuarios = {}
    if ids_usuarios:
        for u in session.exec(select(Usuario).where(Usuario.id_usuario.in_(ids_usuarios))).all():
            usuarios[u.id_usuario] = u

    out: List[schemas.RecetaDetailPublic] = []
    for r in recetas:
        medico = usuarios.get(r.id_medico)
        paciente = usuarios.get(r.id_paciente)
        farmaceutico = usuarios.get(r.id_farmaceutico)

        if not medico or not paciente or not farmaceutico:
            # Omitimos las recetas cuyas referencias de usuario ya no existen
            # para no romper la respuesta completa.
            continue
        out.append(
            schemas.RecetaDetailPublic(
                folio=r.folio,
                id_receta=r.id_receta,
                estado=r.estado,
                creada_en=r.creada_en,
                expira_en=r.expira_en,
                id_medico=r.id_medico,
                id_paciente=r.id_paciente,
                id_farmaceutico=r.id_farmaceutico,
                medico=schemas.UserInfo(nombre_completo=f"{medico.nombre} {medico.paterno}"),
                paciente=schemas.UserInfo(nombre_completo=f"{paciente.nombre} {paciente.paterno}"),
                farmaceutico=schemas.UserInfo(nombre_completo=f"{farmaceutico.nombre} {farmaceutico.paterno}"),
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

    medico = session.get(Usuario, id_medico)
    if not medico:
        raise HTTPException(status_code=404, detail="Médico emisor no encontrado.")

    # --- Auto-asignación: el farmacéutico jefe lo decide el SERVIDOR a
    # partir de la clínica del médico, no el cliente. Aunque la página
    # esté manipulada y mande otro id_farmaceutico, aquí se rechaza si no
    # coincide con el jefe resuelto. Sin esto, la firma del envelope solo
    # certificaría un valor que el atacante eligió.
    jefe = _resolve_jefe_farmaceutico(session, medico.id_clinica)
    if receta_in.id_farmaceutico != jefe.id_usuario:
        raise HTTPException(
            status_code=400,
            detail=(
                f"id_farmaceutico inválido: la clínica del médico tiene como "
                f"farmacéutico jefe al usuario {jefe.id_usuario}, no al "
                f"{receta_in.id_farmaceutico}."
            ),
        )

    # --- Verificación ECDSA de autoría sobre el envelope opaco ---
    # Reintroduce el control que el PR #8 eliminó: sin firma válida del
    # médico (verificada contra su llave pública de FIRMAS registrada) no
    # se emite. El backend nunca descifra la cápsula.
    pub_firma = _get_signing_public_key(session, id_medico)
    if not pub_firma:
        raise HTTPException(
            status_code=400,
            detail=(
                f"El médico {id_medico} no tiene llave pública de firmas "
                "registrada; no se puede verificar la autoría de la receta."
            ),
        )
    envelope_msg = _envelope_message(
        id_medico=id_medico,
        id_paciente=receta_in.id_paciente,
        id_farmaceutico=receta_in.id_farmaceutico,
        folio=receta_in.folio,
        capsula_cifrada=receta_in.capsula_cifrada,
        nonce=receta_in.nonce,
        creada_en=receta_in.creada_en,
        expira_en=receta_in.expira_en,
    )
    if not verify_p256_ecdsa(pub_firma, envelope_msg, receta_in.firma_envelope):
        raise HTTPException(
            status_code=400,
            detail="Firma de autoría inválida: el envelope no verifica "
                   "contra la llave pública del médico.",
        )

    db_receta = Receta(
        folio=receta_in.folio,
        id_medico=id_medico,
        id_paciente=receta_in.id_paciente,
        id_farmaceutico=receta_in.id_farmaceutico,
        creada_en=receta_in.creada_en,
        expira_en=receta_in.expira_en,
        capsula_cifrada=receta_in.capsula_cifrada,
        nonce=receta_in.nonce,
        accesos=[a.model_dump() for a in receta_in.accesos],
    )
    session.add(db_receta)
    session.commit()
    session.refresh(db_receta)
    return db_receta


@router.get(
    "/recetas/farmaceutico-jefe",
    response_model=schemas.FarmaceuticoJefePublic,
)
def resolver_farmaceutico_jefe(
    *,
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Devuelve el farmacéutico jefe de la clínica del médico autenticado.

    Sustituye al `DEMO_FARMACEUTICO_ID` hardcodeado en el frontend: el
    cliente ya no inventa a quién va dirigida la receta, lo resuelve el
    servidor desde el JWT. Declarada ANTES de `/recetas/{id_receta}` para
    que la ruta literal gane sobre la paramétrica.
    """
    if current_user.role not in ("Medico", "Administrador"):
        raise HTTPException(
            status_code=403,
            detail=f"El rol '{current_user.role}' no puede resolver el "
                   "farmacéutico jefe.",
        )
    medico = session.get(Usuario, current_user.id)
    if not medico:
        raise HTTPException(status_code=404, detail="Médico no encontrado.")
    jefe = _resolve_jefe_farmaceutico(session, medico.id_clinica)
    return schemas.FarmaceuticoJefePublic(
        id_farmaceutico=jefe.id_usuario,
        id_clinica=jefe.id_clinica,
        nombre_completo=f"{jefe.nombre} {jefe.paterno}",
    )


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
        folio=receta.folio,
        estado=receta.estado,
        creada_en=receta.creada_en,
        expira_en=receta.expira_en,
        id_medico=receta.id_medico,
        id_paciente=receta.id_paciente,
        id_farmaceutico=receta.id_farmaceutico,
        medico=schemas.UserInfo(nombre_completo=f"{medico.nombre} {medico.paterno}"),
        paciente=schemas.UserInfo(nombre_completo=f"{paciente.nombre} {paciente.paterno}"),
        farmaceutico=schemas.UserInfo(nombre_completo=f"{session.get(Usuario, receta.id_farmaceutico).nombre} {session.get(Usuario, receta.id_farmaceutico).paterno}"),
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
        folio=receta.folio,
        id_receta=receta.id_receta,
        id_medico=receta.id_medico,
        id_paciente=receta.id_paciente,
        id_farmaceutico=receta.id_farmaceutico,
        capsula_cifrada=receta.capsula_cifrada,
        nonce=receta.nonce,
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

    # El farmacéutico destino quedó ATADO en la emisión (jefe de la
    # clínica del médico) y la firma del envelope lo certifica. Aquí solo
    # se verifica que quien sella sea ese mismo farmacéutico: un
    # Farmaceutico no puede surtir —ni apropiarse— una receta dirigida a
    # otra farmacia. NO se reasigna `id_farmaceutico`: dejar que el sello
    # lo sobrescribiera anulaba la auto-asignación hecha al emitir.
    if (
        current_user.role == "Farmaceutico"
        and current_user.id != receta.id_farmaceutico
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "Esta receta está dirigida a otro farmacéutico "
                f"(id {receta.id_farmaceutico}); no puedes surtirla."
            ),
        )

    receta.capsula_cifrada = sello_in.capsula_cifrada
    receta.nonce = sello_in.nonce
    receta.accesos = [a.model_dump() for a in sello_in.accesos]
    receta.estado = "surtida"

    session.add(receta)
    session.commit()
    session.refresh(receta)
    return receta
