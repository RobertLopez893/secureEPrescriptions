"""Tests para el endpoint de autenticación /api/v1/auth/login"""
from jose import jwt
from src.core.config import settings


class TestLogin:
    def test_login_medico_exitoso(self, client, medico_registrado):
        resp = client.post("/api/v1/auth/login", json={
            "correo": "doctor@test.com",
            "contrasena": "password123",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_paciente_exitoso(self, client, paciente_registrado):
        resp = client.post("/api/v1/auth/login", json={
            "correo": "paciente@test.com",
            "contrasena": "password123",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_login_contrasena_incorrecta(self, client, medico_registrado):
        resp = client.post("/api/v1/auth/login", json={
            "correo": "doctor@test.com",
            "contrasena": "wrong_password",
        })
        assert resp.status_code == 401
        assert "incorrectos" in resp.json()["detail"]

    def test_login_correo_inexistente(self, client):
        resp = client.post("/api/v1/auth/login", json={
            "correo": "noexiste@test.com",
            "contrasena": "password123",
        })
        assert resp.status_code == 401

    def test_jwt_contiene_claims_correctos(self, client, medico_registrado):
        resp = client.post("/api/v1/auth/login", json={
            "correo": "doctor@test.com",
            "contrasena": "password123",
        })
        token = resp.json()["access_token"]
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert payload["sub"] == "doctor@test.com"
        assert payload["role"] == "Medico"
        assert "id" in payload
        assert "exp" in payload

    def test_jwt_paciente_tiene_rol_paciente(self, client, paciente_registrado):
        resp = client.post("/api/v1/auth/login", json={
            "correo": "paciente@test.com",
            "contrasena": "password123",
        })
        token = resp.json()["access_token"]
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["role"] == "Paciente"
