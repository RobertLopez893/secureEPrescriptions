"""
Fixtures compartidas para todos los tests del backend.
Usa SQLite in-memory para no depender de PostgreSQL.
"""
import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine, select
from sqlmodel.pool import StaticPool

from src.api_gateway.main import app
from src.database.database import get_session
from src.database.models import Rol, Usuario, Clinica
from src.core.security import get_password_hash


@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        # Crear roles iniciales
        for nombre in ("Medico", "Paciente", "Farmaceutico"):
            session.add(Rol(nombre=nombre))
        # Crear clínica de prueba
        session.add(Clinica(
            nombre="Clínica Test", clues="CLUES001",
            calle="Calle 1", colonia="Centro", municipio="Mun",
            estado="Estado", cp="12345", tipo="Centro Medico",
        ))
        session.commit()
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


# --- Helpers para crear datos de prueba ---

@pytest.fixture
def roles(session: Session) -> dict[str, int]:
    """Retorna un dict {nombre_rol: id_rol}."""
    result = {}
    for rol in session.exec(select(Rol)).all():
        result[rol.nombre] = rol.id_rol
    return result


@pytest.fixture
def medico_registrado(client: TestClient) -> dict:
    """Registra un médico y retorna los datos de respuesta."""
    resp = client.post("/api/v1/usuarios/medicos", json={
        "nombre": "Juan", "paterno": "Pérez", "materno": "López",
        "correo": "doctor@test.com", "contrasena": "password123",
        "id_clinica": 1,
        "cedula": "CED-001", "especialidad": "General", "universidad": "UNAM",
    })
    assert resp.status_code == 201
    return resp.json()


@pytest.fixture
def paciente_registrado(client: TestClient) -> dict:
    """Registra un paciente y retorna los datos de respuesta."""
    resp = client.post("/api/v1/usuarios/pacientes", json={
        "nombre": "María", "paterno": "García", "materno": "Ruiz",
        "correo": "paciente@test.com", "contrasena": "password123",
        "curp": "GARM900101HDFRRL01", "nacimiento": "1990-01-01",
        "sexo": "F", "tel_emergencia": "5512345678",
    })
    assert resp.status_code == 201
    return resp.json()


@pytest.fixture
def token_medico(client: TestClient, medico_registrado: dict) -> str:
    """Login como médico y retorna el JWT."""
    resp = client.post("/api/v1/auth/login", json={
        "correo": "doctor@test.com", "contrasena": "password123",
    })
    assert resp.status_code == 200
    return resp.json()["access_token"]
