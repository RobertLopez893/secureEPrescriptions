import pytest

class TestClinicas:
    CLINICA_DATA = {
        "nombre": "Hospital San José",
        "clues": "HSJ0001",
        "calle": "Av. Principal 123",
        "colonia": "Centro",
        "municipio": "Ecatepec",
        "estado": "EdoMex",
        "cp": "55000",
        "tipo": "Hospital"
    }

    def test_crear_clinica_como_admin_exitoso(self, client, admin_headers):
        resp = client.post("/api/v1/clinicas", headers=admin_headers, json=self.CLINICA_DATA)
        assert resp.status_code == 201
        assert resp.json()["clues"] == self.CLINICA_DATA["clues"]

    def test_crear_clinica_duplicada_falla(self, client, admin_headers):
        # La creamos la primera vez
        client.post("/api/v1/clinicas", headers=admin_headers, json=self.CLINICA_DATA)
        # La segunda vez debe rebotar por CLUES duplicada
        resp = client.post("/api/v1/clinicas", headers=admin_headers, json=self.CLINICA_DATA)
        assert resp.status_code == 400
        assert "Ya existe" in resp.json()["detail"]

    def test_medico_no_puede_crear_clinica(self, client, medico_headers):
        # Intentamos usar el token del médico en lugar del admin
        resp = client.post("/api/v1/clinicas", headers=medico_headers, json={
            "nombre": "Clinica Ilegal", "clues": "ILEGAL01", "calle": "X", 
            "colonia": "Y", "municipio": "Z", "estado": "W", "cp": "111", "tipo": "Clinica"
        })
        assert resp.status_code == 403
        assert "Solo un Administrador" in resp.json()["detail"]

    def test_listar_clinicas(self, client, paciente_headers, admin_headers):
        # Creamos una clínica
        client.post("/api/v1/clinicas", headers=admin_headers, json=self.CLINICA_DATA)
        
        # Cualquier usuario logueado (ej. paciente) puede ver el listado
        resp = client.get("/api/v1/clinicas", headers=paciente_headers)
        assert resp.status_code == 200
        assert len(resp.json()) >= 1