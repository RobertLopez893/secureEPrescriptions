from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from src.database.database import get_session
from src.database.models import Usuario, Paciente, Medico, Farmaceutico, Rol, Llave
from src.core import security
from src.core.security import CurrentUser, get_current_user
from src.api_gateway import schemas

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_rol_by_name(session: Session, nombre_rol: str) -> Rol:
    """Obtiene un rol por su nombre o lanza un error si no existe."""
    rol = session.exec(select(Rol).where(Rol.nombre == nombre_rol)).first()
    if not rol:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"El rol '{nombre_rol}' no está configurado en la base de datos."
        )
    return rol


def _validate_p256_pub_hex(llave: str) -> str:
    """
    Valida que la llave pública sea P-256 uncompressed en hex:
      - 130 chars hex (65 bytes)
      - empieza por '04'
    Devuelve el hex en minúsculas si es válido; lanza HTTP 400 si no.
    """
    l = (llave or "").strip().lower()
    if len(l) != 130 or not l.startswith("04"):
        raise HTTPException(
            status_code=400,
            detail="Formato de llave pública inválido (se espera P-256 uncompressed hex, 130 chars, empezando por 04).",
        )
    try:
        bytes.fromhex(l)
    except ValueError:
        raise HTTPException(status_code=400, detail="La llave pública no es hex válido.")
    return l


def _set_active_key(session: Session, id_usuario: int, llave_publica: str) -> Llave:
    """
    Desactiva las llaves anteriores del usuario y registra una nueva como activa.
    No hace commit (el caller decide cuándo flushear).
    """
    llave_hex = _validate_p256_pub_hex(llave_publica)
    previas = session.exec(
        select(Llave).where(Llave.id_usuario == id_usuario, Llave.activo == True)
    ).all()
    for k in previas:
        k.activo = False
        session.add(k)
    nueva = Llave(id_usuario=id_usuario, llave_publica=llave_hex, activo=True)
    session.add(nueva)
    return nueva

def _require_admin(current_user: CurrentUser) -> None:
    """Guard común: los POST de alta de usuarios y clínicas solo pueden
    ser ejecutados por un Administrador autenticado."""
    if current_user.role != "Administrador":
        raise HTTPException(
            status_code=403,
            detail="Solo un Administrador puede dar de alta usuarios o clínicas.",
        )


@router.post("/usuarios/pacientes", response_model=schemas.UsuarioPublic, status_code=status.HTTP_201_CREATED)
def registrar_paciente(
    *,
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
    paciente_in: schemas.PacienteCreate,
):
    """Registra un nuevo usuario con el rol de Paciente. Solo Admin."""
    _require_admin(current_user)
    if session.exec(select(Usuario).where(Usuario.correo == paciente_in.correo)).first():
        raise HTTPException(status_code=400, detail="El correo ya está registrado.")

    rol_paciente = get_rol_by_name(session, "Paciente")

    perfil_paciente = Paciente(
        curp=paciente_in.curp, nacimiento=paciente_in.nacimiento,
        sexo=paciente_in.sexo, tel_emergencia=paciente_in.tel_emergencia,
    )

    usuario_data = paciente_in.model_dump(
        exclude={"curp", "nacimiento", "sexo", "tel_emergencia", "contrasena", "llave_publica"}
    )
    db_usuario = Usuario(
        **usuario_data,
        contrasena=security.get_password_hash(paciente_in.contrasena),
        id_rol=rol_paciente.id_rol,
        paciente=perfil_paciente # Asigna el perfil directamente
    )

    session.add(db_usuario)
    session.commit()
    session.refresh(db_usuario)

    # Si el cliente envió su llave pública al registrarse, la guardamos
    # como activa para este usuario.
    if paciente_in.llave_publica:
        _set_active_key(session, db_usuario.id_usuario, paciente_in.llave_publica)
        session.commit()
        session.refresh(db_usuario)

    return schemas.UsuarioPublic(
        **db_usuario.model_dump(), rol_nombre=db_usuario.rol.nombre
    )

@router.post("/usuarios/medicos", response_model=schemas.UsuarioPublic, status_code=status.HTTP_201_CREATED)
def registrar_medico(
    *,
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
    medico_in: schemas.MedicoCreate,
):
    """Registra un nuevo usuario con el rol de Médico. Solo Admin."""
    _require_admin(current_user)
    if session.exec(select(Usuario).where(Usuario.correo == medico_in.correo)).first():
        raise HTTPException(status_code=400, detail="El correo ya está registrado.")

    rol_medico = get_rol_by_name(session, "Medico")

    perfil_medico = Medico(
        cedula=medico_in.cedula, especialidad=medico_in.especialidad,
        universidad=medico_in.universidad,
    )

    usuario_data = medico_in.model_dump(
        exclude={"cedula", "especialidad", "universidad", "contrasena", "llave_publica"}
    )
    db_usuario = Usuario(
        **usuario_data,
        contrasena=security.get_password_hash(medico_in.contrasena),
        id_rol=rol_medico.id_rol,
        medico=perfil_medico
    )

    session.add(db_usuario)
    session.commit()
    session.refresh(db_usuario)

    if medico_in.llave_publica:
        _set_active_key(session, db_usuario.id_usuario, medico_in.llave_publica)
        session.commit()
        session.refresh(db_usuario)

    return schemas.UsuarioPublic(
        **db_usuario.model_dump(), rol_nombre=db_usuario.rol.nombre
    )


@router.post("/usuarios/farmaceuticos", response_model=schemas.UsuarioPublic, status_code=status.HTTP_201_CREATED)
def registrar_farmaceutico(
    *,
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
    farma_in: schemas.FarmaceuticoCreate,
):
    """Registra un nuevo usuario con el rol de Farmacéutico. Solo Admin."""
    _require_admin(current_user)
    if session.exec(select(Usuario).where(Usuario.correo == farma_in.correo)).first():
        raise HTTPException(status_code=400, detail="El correo ya está registrado.")

    rol_farma = get_rol_by_name(session, "Farmaceutico")

    perfil_farma = Farmaceutico(
        licencia=farma_in.licencia,
        turno=farma_in.turno,
    )

    usuario_data = farma_in.model_dump(
        exclude={"licencia", "turno", "contrasena", "llave_publica"}
    )
    db_usuario = Usuario(
        **usuario_data,
        contrasena=security.get_password_hash(farma_in.contrasena),
        id_rol=rol_farma.id_rol,
        farmaceutico=perfil_farma,
    )

    session.add(db_usuario)
    session.commit()
    session.refresh(db_usuario)

    if farma_in.llave_publica:
        _set_active_key(session, db_usuario.id_usuario, farma_in.llave_publica)
        session.commit()
        session.refresh(db_usuario)

    return schemas.UsuarioPublic(
        **db_usuario.model_dump(), rol_nombre=db_usuario.rol.nombre
    )


# ---------------------------------------------------------------------------
# Llaves públicas por usuario
# ---------------------------------------------------------------------------
@router.put("/usuarios/me/llave", response_model=schemas.LlavePublicaOut)
def registrar_mi_llave_publica(
    *,
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
    body: schemas.LlavePublicaIn,
):
    """Registra o rota la llave pública del usuario autenticado.

    Administrador no gestiona llaves propias (usa los flujos médicos/paciente/
    farmacéutico desde sus respectivos perfiles)."""
    if current_user.role not in ("Medico", "Paciente", "Farmaceutico"):
        raise HTTPException(
            status_code=403,
            detail=f"El rol '{current_user.role}' no gestiona llaves públicas propias.",
        )
    # Aseguramos que el usuario aún existe en BD.
    u = session.get(Usuario, current_user.id)
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    nueva = _set_active_key(session, current_user.id, body.llave_publica)
    session.commit()
    session.refresh(nueva)
    return schemas.LlavePublicaOut(
        id_usuario=current_user.id, llave_publica=nueva.llave_publica
    )


@router.get("/usuarios/{id_usuario}/llave", response_model=schemas.LlavePublicaOut)
def obtener_llave_publica(
    *,
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
    id_usuario: int,
):
    """Devuelve la llave pública activa de un usuario.

    Cualquier usuario autenticado puede consultar la llave pública de otro
    (las llaves públicas son, por definición, públicas dentro del directorio
    del sistema). Lanza 404 si el usuario no tiene llave registrada."""
    # Forzamos que esté autenticado (get_current_user ya lo hace).
    llave = session.exec(
        select(Llave)
        .where(Llave.id_usuario == id_usuario, Llave.activo == True)
        .order_by(Llave.creado_en.desc())
    ).first()
    if not llave:
        raise HTTPException(
            status_code=404,
            detail=f"El usuario {id_usuario} no tiene llave pública registrada.",
        )
    return schemas.LlavePublicaOut(
        id_usuario=id_usuario, llave_publica=llave.llave_publica
    )
