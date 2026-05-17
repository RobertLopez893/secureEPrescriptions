import uuid
from datetime import datetime, timedelta, timezone
import pytest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def _unix(dt: datetime) -> int:
    d = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return int(d.timestamp())


def _firmar_envelope(priv, *, id_m, id_p, id_f, folio, capsula, nonce,
                      creada, expira) -> str:
    """Reproduce byte a byte el `_envelope_message` del backend y lo
    firma con ECDSA P-256/SHA-256, devolviendo la firma compacta r||s
    en hex (lo que el frontend manda como firma_envelope)."""
    msg = (
        f"{id_m}\n{id_p}\n{id_f}\n{folio}\n"
        f"{capsula}\n{nonce}\n{_unix(creada)}\n{_unix(expira)}"
    ).encode("utf-8")
    der = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


# --- Helper para generar recetas válidas (con firma de envelope) ---
def _payload_receta(id_m, id_p, id_f, priv=None):
    now = datetime.now(timezone.utc)
    expira = now + timedelta(days=7)
    folio = f"REC-{uuid.uuid4().hex[:8].upper()}"
    capsula = "ff" * 32   # 64 chars hex
    nonce = "aa" * 12      # 24 chars hex
    payload = {
        "folio": folio,
        "id_medico": id_m,
        "id_paciente": id_p,
        "id_farmaceutico": id_f,
        "creada_en": now.isoformat(),
        "expira_en": expira.isoformat(),
        "capsula_cifrada": capsula,
        "nonce": nonce,
        "accesos": [
            {"rol": "paciente", "wrappedKey": "11"*48, "ephemeral_pub_hex": "04" + "b"*128},
            {"rol": "doctor", "wrappedKey": "22"*48, "ephemeral_pub_hex": "04" + "c"*128},
            {"rol": "farmaceutico", "wrappedKey": "33"*48, "ephemeral_pub_hex": "04" + "d"*128}
        ],
        # Firma placeholder (128 hex) válida de formato pero no de cripto;
        # se reemplaza abajo si se pasa la llave privada del médico.
        "firma_envelope": "00" * 64,
    }
    if priv is not None:
        payload["firma_envelope"] = _firmar_envelope(
            priv, id_m=id_m, id_p=id_p, id_f=id_f, folio=folio,
            capsula=capsula, nonce=nonce, creada=now, expira=expira,
        )
    return payload

class TestEmitirReceta:
    def test_emitir_receta_exitosa(self, client, base_users, medico_headers):
        payload = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"], base_users["medico_priv"])
        
        # Debemos enviar los headers del médico para que el backend nos deje emitir
        resp = client.post("/api/v1/recetas", headers=medico_headers, json=payload)
        assert resp.status_code == 201
        assert "id_receta" in resp.json()

    def test_emitir_multiples_recetas(self, client, base_users, medico_headers):
        # Al usar _payload_receta, el UUID hace que el folio no choque
        p1 = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"], base_users["medico_priv"])
        p2 = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"], base_users["medico_priv"])
        
        assert client.post("/api/v1/recetas", headers=medico_headers, json=p1).status_code == 201
        assert client.post("/api/v1/recetas", headers=medico_headers, json=p2).status_code == 201


class TestObtenerReceta:
    def test_obtener_info_publica(self, client, base_users, medico_headers):
        payload = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"], base_users["medico_priv"])
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
        payload = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"], base_users["medico_priv"])
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
        payload = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"], base_users["medico_priv"])
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
        payload = _payload_receta(base_users["medico"]["id_usuario"], base_users["paciente"]["id_usuario"], base_users["farmaceutico"]["id_usuario"], base_users["medico_priv"])
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

class TestEmitirRecetaSeguridad:
    """Regresión reintroducida tras el PR #8: firma de envelope + jefe."""

    def test_firma_envelope_invalida_rechaza(self, client, base_users, medico_headers):
        # Sin la llave privada => firma placeholder 00*64: jefe OK pero la
        # verificación ECDSA debe fallar.
        payload = _payload_receta(
            base_users["medico"]["id_usuario"],
            base_users["paciente"]["id_usuario"],
            base_users["farmaceutico"]["id_usuario"],
        )
        resp = client.post("/api/v1/recetas", headers=medico_headers, json=payload)
        assert resp.status_code == 400
        assert "Firma de autoría inválida" in resp.json()["detail"]

    def test_id_farmaceutico_distinto_del_jefe_rechaza(self, client, base_users, medico_headers):
        # id_farmaceutico que no es el jefe de la clínica del médico.
        payload = _payload_receta(
            base_users["medico"]["id_usuario"],
            base_users["paciente"]["id_usuario"],
            base_users["paciente"]["id_usuario"],  # NO es el farmacéutico jefe
            base_users["medico_priv"],
        )
        resp = client.post("/api/v1/recetas", headers=medico_headers, json=payload)
        assert resp.status_code == 400
        assert "id_farmaceutico inválido" in resp.json()["detail"]

    def test_clinica_con_mas_de_un_farmaceutico_aborta(self, client, base_users, admin_headers, medico_headers):
        # Segundo farmacéutico en la MISMA clínica (id 1) -> invariante roto.
        client.post("/api/v1/usuarios/farmaceuticos", headers=admin_headers, json={
            "nombre": "Far. Dos", "paterno": "Extra", "correo": "farma2@test.com",
            "contrasena": "pass", "id_clinica": 1, "licencia": "LIC-999", "turno": "Vespertino",
        })
        payload = _payload_receta(
            base_users["medico"]["id_usuario"],
            base_users["paciente"]["id_usuario"],
            base_users["farmaceutico"]["id_usuario"],
            base_users["medico_priv"],
        )
        resp = client.post("/api/v1/recetas", headers=medico_headers, json=payload)
        assert resp.status_code == 409
        assert "exactamente 1 jefe" in resp.json()["detail"]

    def test_clinica_sin_farmaceutico_aborta(self, client, base_users, admin_headers):
        # Médico en una clínica nueva SIN farmacéutico -> 409 al resolver.
        cli = client.post("/api/v1/clinicas", headers=admin_headers, json={
            "nombre": "Clínica Sola", "clues": "SOLA0001", "calle": "X",
            "colonia": "Y", "municipio": "Z", "estado": "W", "cp": "111", "tipo": "Hospital",
        }).json()
        client.post("/api/v1/usuarios/medicos", headers=admin_headers, json={
            "nombre": "Dr. Solo", "paterno": "Med", "correo": "solo@test.com",
            "contrasena": "pass", "id_clinica": cli["id_clinica"], "cedula": "CED-SOLO",
            "especialidad": "General", "universidad": "UNAM",
        })
        token = client.post("/api/v1/auth/login", json={
            "correo": "solo@test.com", "contrasena": "pass"
        }).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        payload = _payload_receta(99, base_users["paciente"]["id_usuario"], 99)
        resp = client.post("/api/v1/recetas", headers=headers, json=payload)
        assert resp.status_code == 409
        assert "no tiene un farmacéutico jefe" in resp.json()["detail"]

    def test_emitir_receta_firma_valida_exitosa(self, client, base_users, medico_headers):
        payload = _payload_receta(
            base_users["medico"]["id_usuario"],
            base_users["paciente"]["id_usuario"],
            base_users["farmaceutico"]["id_usuario"],
            base_users["medico_priv"],
        )
        resp = client.post("/api/v1/recetas", headers=medico_headers, json=payload)
        assert resp.status_code == 201, resp.text

    def test_resolver_farmaceutico_jefe_endpoint(self, client, base_users, medico_headers):
        resp = client.get("/api/v1/recetas/farmaceutico-jefe", headers=medico_headers)
        assert resp.status_code == 200
        assert resp.json()["id_farmaceutico"] == base_users["farmaceutico"]["id_usuario"]

    def test_otro_farmaceutico_no_puede_surtir_receta_ajena(self, client, base_users, admin_headers, medico_headers):
        # Receta emitida -> atada al farmacéutico jefe de la clínica 1.
        payload = _payload_receta(
            base_users["medico"]["id_usuario"],
            base_users["paciente"]["id_usuario"],
            base_users["farmaceutico"]["id_usuario"],
            base_users["medico_priv"],
        )
        creada = client.post("/api/v1/recetas", headers=medico_headers, json=payload).json()

        # Otro farmacéutico, en OTRA clínica (no rompe el invariante de clínica 1).
        cli2 = client.post("/api/v1/clinicas", headers=admin_headers, json={
            "nombre": "Otra Clínica", "clues": "OTRA0001", "calle": "X",
            "colonia": "Y", "municipio": "Z", "estado": "W", "cp": "222", "tipo": "Hospital",
        }).json()
        client.post("/api/v1/usuarios/farmaceuticos", headers=admin_headers, json={
            "nombre": "Far. Ajeno", "paterno": "Otro", "correo": "ajeno@test.com",
            "contrasena": "pass", "id_clinica": cli2["id_clinica"],
            "licencia": "LIC-AJENO", "turno": "Nocturno",
        })
        token = client.post("/api/v1/auth/login", json={
            "correo": "ajeno@test.com", "contrasena": "pass"
        }).json()["access_token"]
        ajeno_headers = {"Authorization": f"Bearer {token}"}

        sello = {
            "id_farmaceutico": 999,
            "capsula_cifrada": "ee" * 32, "nonce": "dd" * 12, "accesos": [],
        }
        resp = client.put(
            f"/api/v1/recetas/{creada['id_receta']}/sellar",
            headers=ajeno_headers, json=sello,
        )
        assert resp.status_code == 403
        assert "dirigida a otro farmacéutico" in resp.json()["detail"]
