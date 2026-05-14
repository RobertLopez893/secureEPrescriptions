from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlmodel import Session, select
from typing import Optional
from src.database.database import get_session
from src.database.models import Usuario, Paciente, Medico, Farmaceutico, Rol, Llave
from src.core import security
from src.core.security import CurrentUser, get_current_user
from src.api_gateway import schemas
from typing import List

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


def _set_active_key(session: Session, id_usuario: int, llave_publica: str, responsabilidad: str = "general") -> Llave:
    """Desactiva las llaves anteriores y registra la nueva como activa."""
    llaves_viejas = session.exec(
        select(Llave).where(Llave.id_usuario == id_usuario, Llave.responsabilidad == responsabilidad, Llave.activo == True)
    ).all()
    for obj in llaves_viejas:
        obj.activo = False
        session.add(obj)

    nueva = Llave(
        id_usuario=id_usuario, 
        llave_publica=llave_publica,
        responsabilidad=responsabilidad 
    )
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
@router.get("/usuarios/pacientes/{id_usuario}", response_model=schemas.PacientePublic)
def obtener_paciente_por_id(
    *,
    id_usuario: int,
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Obtiene el detalle completo de un paciente usando su ID directo."""
    usuario = session.get(Usuario, id_usuario)
    
    if not usuario or not usuario.paciente:
        raise HTTPException(status_code=404, detail="Paciente no encontrado con este ID")
    
    return schemas.PacientePublic(
        id_usuario=usuario.id_usuario,
        nombre=usuario.nombre,
        paterno=usuario.paterno,
        materno=usuario.materno,
        curp=usuario.paciente.curp,
        nacimiento=usuario.paciente.nacimiento,
        sexo=usuario.paciente.sexo,
        tel_emergencia=usuario.paciente.tel_emergencia
    )

@router.get("/usuarios/pacientes", response_model=schemas.PacientePublic)
def buscar_paciente_por_curp(
    *,
    curp: str = Query(..., description="CURP del paciente a buscar"),
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Obtiene un paciente filtrando por su CURP (Estándar REST)."""
    paciente = session.exec(select(Paciente).where(Paciente.curp == curp)).first()
    if not paciente:
        raise HTTPException(status_code=404, detail="Paciente no encontrado con este CURP")
    
    usuario = session.get(Usuario, paciente.id_usuario)
    return schemas.PacientePublic(
        id_usuario=usuario.id_usuario,
        nombre=usuario.nombre,
        paterno=usuario.paterno,
        materno=usuario.materno,
        curp=paciente.curp,
        nacimiento=paciente.nacimiento,
        sexo=paciente.sexo,
        tel_emergencia=paciente.tel_emergencia
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
@router.post("/usuarios/{id_usuario}/llave", response_model=List[schemas.LlavePublicaOut])
def registrar_llave_publicas(
    *,
    id_usuario: int,
    llaves_in: List[schemas.LlavePublicaIn],
    session: Session = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Registra o rota una lista de llaves públicas del usuario autenticado,
    asignando a cada una su respectiva responsabilidad.

    Verificación de seguridad: Si al menos una de las llaves públicas en la 
    lista ya se encuentra registrada previamente en la base de datos, se rechaza
    la petición completa para evitar colisiones o reutilización de material criptográfico."""
    _require_admin(current_user)
    
    # Aseguramos que el usuario aún existe en BD.
    u = session.get(Usuario, id_usuario)
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    if not llaves_in:
        raise HTTPException(status_code=400, detail="La lista de llaves no puede estar vacía.")

    # 1. Extraer todas las secuencias hex de las llaves que se desean registrar
    cadenas_llaves = [item.llave_publica for item in llaves_in]

    # 2. Verificar si alguna ya existe previamente en toda la tabla Llave
    llaves_duplicadas = session.exec(
        select(Llave).where(Llave.llave_publica.in_(cadenas_llaves))
    ).all()

    if llaves_duplicadas:
        raise HTTPException(
            status_code=400,
            detail="Operación rechazada: Al menos una de las llaves públicas proporcionadas ya está registrada previamente en el sistema."
        )

    # 3. Proceder con el registro asignando la responsabilidad correspondiente
    llaves_creadas = []
    for item in llaves_in:
        nueva = _set_active_key(
            session=session, 
            id_usuario=id_usuario, 
            llave_publica=item.llave_publica, 
            responsabilidad=item.responsabilidad
        )
        llaves_creadas.append(nueva)

    session.commit()

    # 4. Refrescar y construir la respuesta de salida
    for llave in llaves_creadas:
        session.refresh(llave)

    return [
        schemas.LlavePublicaOut(
            id_usuario=id_usuario,
            llave_publica=llave.llave_publica,
            responsabilidad=llave.responsabilidad
        )
        for llave in llaves_creadas
    ]


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
        id_usuario=id_usuario, llave_publica=llave.llave_publica, responsabilidad=llave.responsabilidad
    )
