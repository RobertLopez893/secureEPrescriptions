"""Tests para las utilidades de seguridad (hashing, JWT)."""
from datetime import timedelta
from jose import jwt

from src.core.security import verify_password, get_password_hash, create_access_token
from src.core.config import settings


class TestPasswordHashing:
    def test_hash_y_verificar(self):
        plain = "mi_password_seguro"
        hashed = get_password_hash(plain)
        assert hashed != plain
        assert verify_password(plain, hashed)

    def test_password_incorrecto(self):
        hashed = get_password_hash("password_real")
        assert not verify_password("password_falso", hashed)

    def test_hashes_diferentes_para_mismo_password(self):
        h1 = get_password_hash("same_password")
        h2 = get_password_hash("same_password")
        assert h1 != h2  # bcrypt usa salt aleatorio


class TestJWT:
    def test_crear_y_decodificar_token(self):
        data = {"sub": "test@test.com", "role": "Medico", "id": 1}
        token = create_access_token(data)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["sub"] == "test@test.com"
        assert payload["role"] == "Medico"
        assert payload["id"] == 1

    def test_token_tiene_expiracion(self):
        token = create_access_token({"sub": "test@test.com"})
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert "exp" in payload
        assert "iat" in payload

    def test_custom_expiracion(self):
        token = create_access_token(
            {"sub": "test@test.com"},
            expires_delta=timedelta(minutes=5),
        )
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["exp"] - payload["iat"] == 300  # 5 minutos

    def test_token_invalido_con_clave_incorrecta(self):
        token = create_access_token({"sub": "test@test.com"})
        try:
            jwt.decode(token, "clave_incorrecta", algorithms=[settings.ALGORITHM])
            assert False, "Debería haber fallado"
        except Exception:
            pass
