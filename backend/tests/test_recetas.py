import uuid
from datetime import datetime, timedelta, timezone
import pytest

# --- Helper para generar recetas válidas ---
def _payload_receta(id_m, id_p, id_f):
    now = datetime.now(timezone.utc)
    return {
        "folio": f"REC-{uuid.uuid4().hex[:8].upper()}",
        "id_medico": id_m,
        "id_paciente": id_p,
        "id_farmaceutico": id_f,
        "creada_en": now.isoformat(),
        "expira_en": (now + timedelta(days=7)).isoformat(),
        "capsula_cifrada": "ff" * 32, # 64 chars hex
        "nonce": "aa" * 12,          # 24 chars hex
        "accesos": [
            {"rol": "paciente", "wrappedKey": "11"*48, "ephemeral_pub_hex": "04" + "b"*128},
            {"rol": "doctor", "wrappedKey": "22"*48, "ephemeral_pub_hex": "04" + "c"*128},
            {"rol": "farmaceutico", "wrappedKey": "33"*48, "ephemeral_pub_hex": "04" + "d"*128}
        ]
    }

class TestEmitirReceta:
    def test_emitir_receta_exitosa(self, client, base_users, medico_headers):
        payload = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"])
        
        # Debemos enviar los headers del médico para que el backend nos deje emitir
        resp = client.post("/api/v1/recetas", headers=medico_headers, json=payload)
        assert resp.status_code == 201
        assert "id_receta" in resp.json()

    def test_emitir_multiples_recetas(self, client, base_users, medico_headers):
        # Al usar _payload_receta, el UUID hace que el folio no choque
        p1 = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"])
        p2 = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"])
        
        assert client.post("/api/v1/recetas", headers=medico_headers, json=p1).status_code == 201
        assert client.post("/api/v1/recetas", headers=medico_headers, json=p2).status_code == 201


class TestObtenerReceta:
    def test_obtener_info_publica(self, client, base_users, medico_headers):
        payload = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"])
        creada = client.post("/api/v1/recetas", headers=medico_headers, json=payload).json()
        
        resp = client.get(f"/api/v1/recetas/{creada['id_receta']}", headers=medico_headers)
        assert resp.status_code == 200
        assert resp.json()["folio"] == payload["folio"]

    def test_receta_no_encontrada(self, client, medico_headers):
        # Inyectamos medico_headers para pasar la puerta (401) y probar que de 404
        resp = client.get("/api/v1/recetas/99999", headers=medico_headers)
        assert resp.status_code == 404


class TestObtenerCripto:
    def test_obtener_datos_cripto(self, client, base_users, medico_headers):
        payload = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"])
        creada = client.post("/api/v1/recetas", headers=medico_headers, json=payload).json()
        
        resp = client.get(f"/api/v1/recetas/{creada['id_receta']}/cripto", headers=medico_headers)
        assert resp.status_code == 200
        assert "capsula_cifrada" in resp.json()

    def test_cripto_receta_no_encontrada(self, client, medico_headers):
        resp = client.get("/api/v1/recetas/99999/cripto", headers=medico_headers)
        assert resp.status_code == 404


class TestSellarReceta:
    def test_sellar_exitoso(self, client, base_users, medico_headers, farmaceutico_headers):
        # 1. El médico emite
        payload = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"])
        creada = client.post("/api/v1/recetas", headers=medico_headers, json=payload).json()
        
        # 2. El farmacéutico sella
        sello_payload = {
            "id_farmaceutico": base_users["farmaceutico"]["id_usuario"],
            "capsula_cifrada": "ee" * 32,
            "nonce": "dd" * 12,
            "accesos": []
        }
        resp = client.put(f"/api/v1/recetas/{creada['id_receta']}/sellar", headers=farmaceutico_headers, json=sello_payload)
        assert resp.status_code == 200
        assert resp.json()["estado"] == "surtida"

    def test_no_sellar_receta_ya_surtida(self, client, base_users, medico_headers, farmaceutico_headers):
        payload = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"])
        creada = client.post("/api/v1/recetas", headers=medico_headers, json=payload).json()
        
        sello_payload = {
            "id_farmaceutico": base_users["farmaceutico"]["id_usuario"],
            "capsula_cifrada": "ee" * 32,
            "nonce": "dd" * 12,
            "accesos": []
        }
        # Surtimos una vez (debe funcionar)
        client.put(f"/api/v1/recetas/{creada['id_receta']}/sellar", headers=farmaceutico_headers, json=sello_payload)
        
        # Intentamos surtir por SEGUNDA vez la misma receta (debe fallar)
        resp2 = client.put(f"/api/v1/recetas/{creada['id_receta']}/sellar", headers=farmaceutico_headers, json=sello_payload)
        assert resp2.status_code == 400

    def test_sellar_receta_no_encontrada(self, client, farmaceutico_headers):
        sello_payload = {
            "id_farmaceutico": 1,
            "capsula_cifrada": "ff" * 32,
            "nonce": "ee" * 12,
            "accesos": [],
        }
        # Pasamos farmaceutico_headers para evitar el 401
        resp = client.put("/api/v1/recetas/99999/sellar", headers=farmaceutico_headers, json=sello_payload)
        assert resp.status_code == 404