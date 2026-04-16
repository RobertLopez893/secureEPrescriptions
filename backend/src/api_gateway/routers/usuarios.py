from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from src.database.database import get_session
from src.database.models import Usuario, Paciente, Medico, Rol
from src.core import security
from src.api_gateway import schemas

router = APIRouter()

def get_rol_by_name(session: Session, nombre_rol: str) -> Rol:
    """Obtiene un rol por su nombre o lanza un error si no existe."""
    rol = session.exec(select(Rol).where(Rol.nombre == nombre_rol)).first()
    if not rol:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"El rol '{nombre_rol}' no está configurado en la base de datos."
        )
    return rol

@router.post("/usuarios/pacientes", response_model=schemas.UsuarioPublic, status_code=status.HTTP_201_CREATED)
def registrar_paciente(*, session: Session = Depends(get_session), paciente_in: schemas.PacienteCreate):
    """Registra un nuevo usuario con el rol de Paciente."""
    if session.exec(select(Usuario).where(Usuario.correo == paciente_in.correo)).first():
        raise HTTPException(status_code=400, detail="El correo ya está registrado.")

    rol_paciente = get_rol_by_name(session, "Paciente")

    # SQLModel es inteligente: crea el perfil y lo asigna al usuario
    perfil_paciente = Paciente.model_validate(paciente_in)
    
    usuario_data = paciente_in.model_dump(exclude={"curp", "nacimiento", "sexo", "tel_emergencia"})
    db_usuario = Usuario(
        **usuario_data,
        contrasena=security.get_password_hash(paciente_in.contrasena),
        id_rol=rol_paciente.id_rol,
        paciente=perfil_paciente # Asigna el perfil directamente
    )

    session.add(db_usuario)
    session.commit()
    session.refresh(db_usuario)
    
    return schemas.UsuarioPublic(
        **db_usuario.model_dump(), rol_nombre=db_usuario.rol.nombre
    )

@router.post("/usuarios/medicos", response_model=schemas.UsuarioPublic, status_code=status.HTTP_201_CREATED)
def registrar_medico(*, session: Session = Depends(get_session), medico_in: schemas.MedicoCreate):
    """Registra un nuevo usuario con el rol de Médico."""
    if session.exec(select(Usuario).where(Usuario.correo == medico_in.correo)).first():
        raise HTTPException(status_code=400, detail="El correo ya está registrado.")

    rol_medico = get_rol_by_name(session, "Medico")

    perfil_medico = Medico.model_validate(medico_in)
    
    usuario_data = medico_in.model_dump(exclude={"cedula", "especialidad", "universidad"})
    db_usuario = Usuario(
        **usuario_data,
        contrasena=security.get_password_hash(medico_in.contrasena),
        id_rol=rol_medico.id_rol,
        medico=perfil_medico
    )

    session.add(db_usuario)
    session.commit()
    session.refresh(db_usuario)

    return schemas.UsuarioPublic(
        **db_usuario.model_dump(), rol_nombre=db_usuario.rol.nombre
    )
