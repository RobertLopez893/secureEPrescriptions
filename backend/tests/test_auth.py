import pytest
from jose import jwt
from unittest.mock import patch
from src.core.config import settings

class TestLoginLegacy:
    """Pruebas para el endpoint /api/v1/auth/login (Correo + Contraseña)"""

    def test_login_admin_exitoso(self, client):
        # El administrador maestro se crea en el session_fixture de conftest.py
        resp = client.post("/api/v1/auth/login", json={
            "correo": "admin@test.com",
            "contrasena": "admin123",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_medico_exitoso(self, client, base_users):
        resp = client.post("/api/v1/auth/login", json={
            "correo": "medico@test.com",
            "contrasena": "pass",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_login_paciente_exitoso(self, client, base_users):
        resp = client.post("/api/v1/auth/login", json={
            "correo": "paciente@test.com",
            "contrasena": "pass",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_login_farmaceutico_exitoso(self, client, base_users):
        resp = client.post("/api/v1/auth/login", json={
            "correo": "farma@test.com",
            "contrasena": "pass",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_login_contrasena_incorrecta(self, client, base_users):
        resp = client.post("/api/v1/auth/login", json={
            "correo": "medico@test.com",
            "contrasena": "wrong_password",
        })
        assert resp.status_code == 401
        assert "incorrectos" in resp.json()["detail"].lower()

    def test_login_correo_inexistente(self, client):
        resp = client.post("/api/v1/auth/login", json={
            "correo": "noexiste@test.com",
            "contrasena": "password123",
        })
        assert resp.status_code == 401

    @pytest.mark.parametrize("correo, rol_esperado", [
        ("admin@test.com", "Administrador"),
        ("medico@test.com", "Medico"),
        ("paciente@test.com", "Paciente"),
        ("farma@test.com", "Farmaceutico"),
    ])
    def test_jwt_contiene_claims_correctos(self, client, base_users, correo, rol_esperado):
        # Usamos contraseñas distintas dependiendo de si es admin o clínico
        password = "admin123" if rol_esperado == "Administrador" else "pass"
        
        resp = client.post("/api/v1/auth/login", json={
            "correo": correo,
            "contrasena": password,
        })
        token = resp.json()["access_token"]
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert payload["sub"] == correo
        assert payload["role"] == rol_esperado
        assert "id" in payload
        assert "exp" in payload

    def test_rate_limit_fuerza_bruta(self, client, base_users):
        """Prueba que después de 5 intentos fallidos, el API bloquee con 429"""
        # 5 intentos fallidos
        for _ in range(5):
            resp = client.post("/api/v1/auth/login", json={
                "correo": "medico@test.com",
                "contrasena": "INTENTO_FALLIDO"
            })
            assert resp.status_code in (401, 429)
        
        # El 6to intento (incluso si tiene la contraseña correcta) debe ser bloqueado por Rate Limit
        resp_bloqueado = client.post("/api/v1/auth/login", json={
            "correo": "medico@test.com",
            "contrasena": "pass"
        })
        assert resp_bloqueado.status_code == 429
        assert "Demasiados intentos" in resp_bloqueado.json()["detail"]


class TestLoginSmartCard:
    """Pruebas para los endpoints de tarjeta /api/v1/auth/challenge y /verify"""

    def test_challenge_verify_medico_exitoso(self, client, base_users):
        # 1. Pedir Reto (Nonce) usando la Cédula del médico
        resp_challenge = client.post("/api/v1/auth/challenge", json={
            "rol": "Medico", 
            "identificador": "CED-123"
        })
        assert resp_challenge.status_code == 200
        data_challenge = resp_challenge.json()
        assert "nonce_hex" in data_challenge
        nonce = data_challenge["nonce_hex"]

        # 2. Verificar Reto
        # Simulamos que la firma criptográfica es válida (para no firmar con curvas elípticas en Python aquí)
        with patch("src.api_gateway.routers.auth.verify_p256_ecdsa", return_value=True):
            resp_verify = client.post("/api/v1/auth/verify", json={
                "rol": "Medico", 
                "identificador": "CED-123", 
                "nonce_hex": nonce, 
                "firma_hex": "b" * 128  # Firma mockeada de 128 chars
            })
            assert resp_verify.status_code == 200
            data_verify = resp_verify.json()
            assert "access_token" in data_verify
            
            # Verificamos que el JWT entregado por la tarjeta es de Médico
            token = data_verify["access_token"]
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            assert payload["role"] == "Medico"

    def test_challenge_verify_paciente_exitoso(self, client, base_users):
        resp_challenge = client.post("/api/v1/auth/challenge", json={"rol": "Paciente", "identificador": "PAZA900101HDFRRL01"})
        assert resp_challenge.status_code == 200
        nonce = resp_challenge.json()["nonce_hex"]

        with patch("src.api_gateway.routers.auth.verify_p256_ecdsa", return_value=True):
            resp_verify = client.post("/api/v1/auth/verify", json={
                "rol": "Paciente", "identificador": "PAZA900101HDFRRL01", "nonce_hex": nonce, "firma_hex": "b" * 128
            })
            assert resp_verify.status_code == 200

    def test_challenge_identificador_invalido(self, client, base_users):
        # Intentar pedir challenge para una cédula que no existe
        resp = client.post("/api/v1/auth/challenge", json={
            "rol": "Medico", 
            "identificador": "CED-INVENTADA"
        })
        assert resp.status_code == 404

    def test_challenge_rol_incorrecto(self, client, base_users):
        # Intentar pedir challenge pasando una CURP pero diciendo que es Medico
        resp = client.post("/api/v1/auth/challenge", json={
            "rol": "Medico", 
            "identificador": "PAZA900101HDFRRL01"
        })
        assert resp.status_code == 404 # Falla porque la búsqueda en la tabla Medico no lo encuentra

    def test_verify_firma_criptografica_invalida(self, client, base_users):
        # 1. Pedir Reto
        resp_challenge = client.post("/api/v1/auth/challenge", json={"rol": "Farmaceutico", "identificador": "LIC-123"})
        nonce = resp_challenge.json()["nonce_hex"]

        # 2. Verificar Reto devolviendo FALSE en la verificación ECDSA
        with patch("src.api_gateway.routers.auth.verify_p256_ecdsa", return_value=False):
            resp_verify = client.post("/api/v1/auth/verify", json={
                "rol": "Farmaceutico", 
                "identificador": "LIC-123", 
                "nonce_hex": nonce, 
                "firma_hex": "c" * 128
            })
            assert resp_verify.status_code == 401
            assert "Firma inválida" in resp_verify.json()["detail"]