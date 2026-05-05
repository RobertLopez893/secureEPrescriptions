import pytest

class TestRegistroPaciente:
    PACIENTE_DATA = {
        "nombre": "Carlos", "paterno": "Gómez", "correo": "nuevo_paciente@test.com",
        "contrasena": "pass123", "curp": "GOMC900101HDFRRL01",
        "nacimiento": "1990-01-01", "sexo": "M", "tel_emergencia": "5551234567"
    }

    def test_registro_exitoso(self, client, admin_headers):
        # INYECTAMOS admin_headers PARA QUE EL SERVIDOR NOS DEJE PASAR
        resp = client.post("/api/v1/usuarios/pacientes", headers=admin_headers, json=self.PACIENTE_DATA)
        assert resp.status_code == 201
        assert resp.json()["correo"] == self.PACIENTE_DATA["correo"]

    def test_correo_duplicado_rechazado(self, client, admin_headers, base_users):
        # Intentamos registrar usando el correo de la paciente "Ana" que ya existe en base_users
        payload = self.PACIENTE_DATA.copy()
        payload["correo"] = base_users["paciente"]["correo"]
        
        resp = client.post("/api/v1/usuarios/pacientes", headers=admin_headers, json=payload)
        assert resp.status_code == 400
        assert "registrado" in resp.json()["detail"].lower()

    def test_campos_requeridos(self, client, admin_headers):
        # Enviamos un JSON incompleto (falta CURP, correo, etc.)
        resp = client.post("/api/v1/usuarios/pacientes", headers=admin_headers, json={"nombre": "Ana"})
        assert resp.status_code == 422 # Pydantic debe rechazarlo


class TestRegistroMedico:
    MEDICO_DATA = {
        "nombre": "Roberto", "paterno": "Díaz", "correo": "nuevo_medico@test.com",
        "contrasena": "pass123", "id_clinica": 1, "cedula": "CED-999",
        "especialidad": "Cardiología", "universidad": "UNAM"
    }

    def test_registro_exitoso(self, client, admin_headers):
        resp = client.post("/api/v1/usuarios/medicos", headers=admin_headers, json=self.MEDICO_DATA)
        assert resp.status_code == 201

    def test_correo_duplicado_rechazado(self, client, admin_headers, base_users):
        payload = self.MEDICO_DATA.copy()
        payload["correo"] = base_users["medico"]["correo"] # Correo repetido
        
        resp = client.post("/api/v1/usuarios/medicos", headers=admin_headers, json=payload)
        assert resp.status_code == 400

    def test_campos_requeridos(self, client, admin_headers):
        resp = client.post("/api/v1/usuarios/medicos", headers=admin_headers, json={"nombre": "Carlos"})
        assert resp.status_code == 422


class TestGestionLlaves:
    # Una llave de 130 caracteres hexadecimales que comienza con "04"
    LLAVE_VALIDA = "04" + ("f" * 128)

    def test_registrar_llave_admin(self, client, admin_headers, base_users):
        id_medico = base_users["medico"]["id_usuario"]
        
        resp = client.post(
            f"/api/v1/usuarios/{id_medico}/llave",
            headers=admin_headers,
            json={"llave_publica": self.LLAVE_VALIDA, "responsabilidad": "recetas"}
        )
        assert resp.status_code == 200
        assert resp.json()["llave_publica"] == self.LLAVE_VALIDA

    def test_rechazo_llave_invalida(self, client, admin_headers, base_users):
        id_medico = base_users["medico"]["id_usuario"]
        # Esta llave falla porque empieza con "03" en lugar de "04"
        llave_invalida = "03" + ("f" * 128) 
        
        resp = client.post(
            f"/api/v1/usuarios/{id_medico}/llave",
            headers=admin_headers,
            json={"llave_publica": llave_invalida, "responsabilidad": "recetas"}
        )
        assert resp.status_code == 422 # Pydantic la bloquea por seguridad

    def test_consultar_llave_por_responsabilidad(self, client, medico_headers, base_users):
        # El médico consulta la llave del paciente
        id_paciente = base_users["paciente"]["id_usuario"]
        
        resp = client.get(
            f"/api/v1/usuarios/{id_paciente}/llave?responsabilidad=firmas",
            headers=medico_headers # Usamos el token del médico
        )
        assert resp.status_code == 200
        assert resp.json()["llave_publica"].startswith("04")

    def test_consultar_llave_inexistente(self, client, medico_headers):
        # Consultar la llave de un usuario ID 999 que no existe
        resp = client.get("/api/v1/usuarios/999/llave", headers=medico_headers)
        assert resp.status_code == 404