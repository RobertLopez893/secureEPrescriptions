"""Tests para los endpoints de registro de usuarios /api/v1/usuarios/*"""


class TestRegistroPaciente:
    PACIENTE_DATA = {
        "nombre": "Ana", "paterno": "López", "materno": "Sánchez",
        "correo": "ana@test.com", "contrasena": "securepass",
        "curp": "LOSA950515MDFRNN01", "nacimiento": "1995-05-15",
        "sexo": "F", "tel_emergencia": "5598765432",
    }

    def test_registro_exitoso(self, client):
        resp = client.post("/api/v1/usuarios/pacientes", json=self.PACIENTE_DATA)
        assert resp.status_code == 201
        data = resp.json()
        assert data["correo"] == "ana@test.com"
        assert data["nombre"] == "Ana"
        assert data["rol_nombre"] == "Paciente"
        assert "id_usuario" in data

    def test_correo_duplicado_rechazado(self, client):
        client.post("/api/v1/usuarios/pacientes", json=self.PACIENTE_DATA)
        resp = client.post("/api/v1/usuarios/pacientes", json=self.PACIENTE_DATA)
        assert resp.status_code == 400
        assert "registrado" in resp.json()["detail"]

    def test_campos_requeridos(self, client):
        resp = client.post("/api/v1/usuarios/pacientes", json={
            "nombre": "Ana", "paterno": "López",
        })
        assert resp.status_code == 422


class TestRegistroMedico:
    MEDICO_DATA = {
        "nombre": "Carlos", "paterno": "Hernández",
        "correo": "carlos@test.com", "contrasena": "securepass",
        "id_clinica": 1,
        "cedula": "CED-100", "especialidad": "Cardiología", "universidad": "IPN",
    }

    def test_registro_exitoso(self, client):
        resp = client.post("/api/v1/usuarios/medicos", json=self.MEDICO_DATA)
        assert resp.status_code == 201
        data = resp.json()
        assert data["correo"] == "carlos@test.com"
        assert data["rol_nombre"] == "Medico"

    def test_correo_duplicado_rechazado(self, client):
        client.post("/api/v1/usuarios/medicos", json=self.MEDICO_DATA)
        resp = client.post("/api/v1/usuarios/medicos", json=self.MEDICO_DATA)
        assert resp.status_code == 400

    def test_campos_requeridos(self, client):
        resp = client.post("/api/v1/usuarios/medicos", json={
            "nombre": "Carlos",
        })
        assert resp.status_code == 422
