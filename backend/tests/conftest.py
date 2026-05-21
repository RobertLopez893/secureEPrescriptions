import os
import pytest, bcrypt
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine
from sqlmodel.pool import StaticPool

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["APP_ENV"] = "test"


from src.api_gateway.main import app
from src.database.database import get_session
from src.database.models import Rol, Clinica, Administrador
from src.core.security import get_password_hash


# --- 1. Base de Datos In-Memory ---
@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        # Pre-poblar catálogos
        for nombre in ("Medico", "Paciente", "Farmaceutico"):
            session.add(Rol(nombre=nombre))
        session.add(Clinica(
            nombre="Clínica Central", clues="CLUES001", calle="Av. X", 
            colonia="Centro", municipio="Mun", estado="Est", cp="12345", tipo="Hospital"
        ))
        # Crear un Administrador Maestro real
        session.add(Administrador(
            nombre="Super Admin", correo="admin@test.com", contrasena=get_password_hash("admin123")
        ))
        session.commit()
        yield session

# --- 2. Cliente HTTP con Override SOLO de BD ---
@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session
    app.dependency_overrides[get_session] = get_session_override
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()

# --- 3. Generadores de Tokens (Login Real) ---
@pytest.fixture
def admin_headers(client):
    """Hace login como admin y retorna los headers con el JWT."""
    resp = client.post("/api/v1/auth/login", json={"correo": "admin@test.com", "contrasena": "admin123"})
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}

@pytest.fixture
def base_users(client, admin_headers):
    """Crea un usuario de cada rol en la BD para usarlos en los tests."""
    p = client.post("/api/v1/usuarios/pacientes", headers=admin_headers, json={
        "nombre": "Ana", "paterno": "Paz", "correo": "paciente@test.com", "contrasena": "pass",
        "curp": "PAZA900101HDFRRL01", "nacimiento": "1990-01-01", "sexo": "F", "tel_emergencia": "123"
    }).json()
    
    m = client.post("/api/v1/usuarios/medicos", headers=admin_headers, json={
        "nombre": "Dr. Juan", "paterno": "Med", "correo": "medico@test.com", "contrasena": "pass",
        "id_clinica": 1, "cedula": "CED-123", "especialidad": "General", "universidad": "UNAM"
    }).json()
    
    f = client.post("/api/v1/usuarios/farmaceuticos", headers=admin_headers, json={
        "nombre": "Far. Luis", "paterno": "Pild", "correo": "farma@test.com", "contrasena": "pass",
        "id_clinica": 1, "licencia": "LIC-123", "turno": "Matutino"
    }).json()

    # Registrar llaves válidas para que puedan operar criptografía (130 chars hex)
    llave_base = "04" + ("a" * 128)
    for user_id in (p["id_usuario"], m["id_usuario"], f["id_usuario"]):
        client.post(f"/api/v1/usuarios/{user_id}/llave", headers=admin_headers,
                    json={"llave_publica": llave_base, "responsabilidad": "firmas"})

    # El médico necesita una llave de FIRMAS *real*: tras el PR #8 la
    # emisión vuelve a verificar la firma ECDSA del envelope. Generamos
    # un par P-256 de verdad, sobrescribimos su llave pública 'firmas' y
    # exponemos la privada para que los tests firmen igual que el front.
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat,
    )
    medico_priv = ec.generate_private_key(ec.SECP256R1())
    medico_pub_hex = medico_priv.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    ).hex()
    client.post(
        f"/api/v1/usuarios/{m['id_usuario']}/llave",
        headers=admin_headers,
        json={"llave_publica": medico_pub_hex, "responsabilidad": "firmas"},
    )

    return {
        "paciente": p,
        "medico": m,
        "farmaceutico": f,
        "medico_priv": medico_priv,
    }

def _get_headers_for_card(client, rol, identificador):
    """Obtiene un JWT de usuario clínico vía /auth/challenge + /auth/verify
    con la verificación ECDSA mockeada (los tests no firman con curva real;
    eso ya se ejercita en test_auth.TestLoginSmartCard)."""
    with patch("src.api_gateway.routers.auth.verify_p256_ecdsa", return_value=True):
        nonce = client.post(
            "/api/v1/auth/challenge",
            json={"rol": rol, "identificador": identificador},
        ).json()["nonce_hex"]
        token = client.post(
            "/api/v1/auth/verify",
            json={"rol": rol, "identificador": identificador, "nonce_hex": nonce, "firma_hex": "b" * 128},
        ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def paciente_headers(client, base_users): return _get_headers_for_card(client, "Paciente", "PAZA900101HDFRRL01")

@pytest.fixture
def medico_headers(client, base_users): return _get_headers_for_card(client, "Medico", "CED-123")

@pytest.fixture
def farmaceutico_headers(client, base_users): return _get_headers_for_card(client, "Farmaceutico", "LIC-123")

@pytest.fixture(autouse=True)
def reduce_bcrypt_rounds():
    """
    Fuerza a bcrypt a usar siempre 4 rondas (el mínimo) durante las pruebas 
    sin importar lo que diga el código de la aplicación.
    """
    original_gensalt = bcrypt.gensalt
    # Interceptamos la llamada y forzamos rounds=4
    with patch("bcrypt.gensalt", lambda rounds=12, prefix=b"2b": original_gensalt(4, prefix)):
        yield