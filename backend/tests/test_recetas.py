"""Tests para los endpoints de recetas /api/v1/recetas/*"""
from datetime import datetime, timedelta


ACCESOS_MOCK = [
    {"rol": "paciente", "wrappedKey": "aa" * 48, "nonce": "bb" * 12},
    {"rol": "farmaceutico", "wrappedKey": "cc" * 48, "nonce": "dd" * 12},
    {"rol": "doctor", "wrappedKey": "ee" * 48, "nonce": "ff" * 12},
]


def make_receta_payload(id_medico: int, id_paciente: int) -> dict:
    return {
        "id_medico": id_medico,
        "id_paciente": id_paciente,
        "expira_en": (datetime.utcnow() + timedelta(days=7)).isoformat(),
        "capsula_cifrada": "ab" * 64,
        "iv_aes_gcm": "cd" * 12,
        "accesos": ACCESOS_MOCK,
    }


class TestEmitirReceta:
    def test_emitir_receta_exitosa(self, client, medico_registrado, paciente_registrado):
        payload = make_receta_payload(
            medico_registrado["id_usuario"],
            paciente_registrado["id_usuario"],
        )
        resp = client.post("/api/v1/recetas", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["estado"] == "activa"
        assert "id_receta" in data
        assert "creada_en" in data

    def test_emitir_multiples_recetas(self, client, medico_registrado, paciente_registrado):
        payload = make_receta_payload(
            medico_registrado["id_usuario"],
            paciente_registrado["id_usuario"],
        )
        r1 = client.post("/api/v1/recetas", json=payload)
        r2 = client.post("/api/v1/recetas", json=payload)
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert r1.json()["id_receta"] != r2.json()["id_receta"]


class TestObtenerReceta:
    def test_obtener_info_publica(self, client, medico_registrado, paciente_registrado):
        payload = make_receta_payload(
            medico_registrado["id_usuario"],
            paciente_registrado["id_usuario"],
        )
        create_resp = client.post("/api/v1/recetas", json=payload)
        id_receta = create_resp.json()["id_receta"]

        resp = client.get(f"/api/v1/recetas/{id_receta}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id_receta"] == id_receta
        assert data["estado"] == "activa"
        assert "medico" in data
        assert "paciente" in data
        assert data["medico"]["nombre_completo"] == "Juan Pérez"
        assert data["paciente"]["nombre_completo"] == "María García"

    def test_receta_no_encontrada(self, client):
        resp = client.get("/api/v1/recetas/99999")
        assert resp.status_code == 404


class TestObtenerCripto:
    def test_obtener_datos_cripto(self, client, medico_registrado, paciente_registrado):
        payload = make_receta_payload(
            medico_registrado["id_usuario"],
            paciente_registrado["id_usuario"],
        )
        create_resp = client.post("/api/v1/recetas", json=payload)
        id_receta = create_resp.json()["id_receta"]

        resp = client.get(f"/api/v1/recetas/{id_receta}/cripto")
        assert resp.status_code == 200
        data = resp.json()
        assert data["capsula_cifrada"] == "ab" * 64
        assert data["iv_aes_gcm"] == "cd" * 12
        assert len(data["accesos"]) == 3
        roles = [a["rol"] for a in data["accesos"]]
        assert "paciente" in roles
        assert "farmaceutico" in roles
        assert "doctor" in roles

    def test_cripto_receta_no_encontrada(self, client):
        resp = client.get("/api/v1/recetas/99999/cripto")
        assert resp.status_code == 404


class TestSellarReceta:
    def test_sellar_exitoso(self, client, medico_registrado, paciente_registrado):
        # Crear receta
        payload = make_receta_payload(
            medico_registrado["id_usuario"],
            paciente_registrado["id_usuario"],
        )
        create_resp = client.post("/api/v1/recetas", json=payload)
        id_receta = create_resp.json()["id_receta"]

        # Sellar
        sello_payload = {
            "id_farmaceutico": medico_registrado["id_usuario"],  # reusamos por simplicidad
            "capsula_cifrada": "ff" * 64,
            "iv_aes_gcm": "ee" * 12,
            "accesos": [
                {"rol": "paciente", "wrappedKey": "11" * 48, "nonce": "22" * 12},
                {"rol": "doctor", "wrappedKey": "33" * 48, "nonce": "44" * 12},
            ],
        }
        resp = client.put(f"/api/v1/recetas/{id_receta}/sellar", json=sello_payload)
        assert resp.status_code == 200
        assert resp.json()["estado"] == "surtida"

    def test_no_sellar_receta_ya_surtida(self, client, medico_registrado, paciente_registrado):
        payload = make_receta_payload(
            medico_registrado["id_usuario"],
            paciente_registrado["id_usuario"],
        )
        create_resp = client.post("/api/v1/recetas", json=payload)
        id_receta = create_resp.json()["id_receta"]

        sello_payload = {
            "id_farmaceutico": medico_registrado["id_usuario"],
            "capsula_cifrada": "ff" * 64,
            "iv_aes_gcm": "ee" * 12,
            "accesos": [
                {"rol": "paciente", "wrappedKey": "11" * 48, "nonce": "22" * 12},
            ],
        }
        # Primer sellado
        client.put(f"/api/v1/recetas/{id_receta}/sellar", json=sello_payload)
        # Segundo sellado: debe fallar
        resp = client.put(f"/api/v1/recetas/{id_receta}/sellar", json=sello_payload)
        assert resp.status_code == 400
        assert "surtida" in resp.json()["detail"]

    def test_sellar_receta_no_encontrada(self, client):
        sello_payload = {
            "id_farmaceutico": 1,
            "capsula_cifrada": "ff" * 64,
            "iv_aes_gcm": "ee" * 12,
            "accesos": [],
        }
        resp = client.put("/api/v1/recetas/99999/sellar", json=sello_payload)
        assert resp.status_code == 404
