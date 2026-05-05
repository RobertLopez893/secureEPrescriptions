"""
Autenticación de la API.

Este módulo expone dos caminos de login coexistiendo:

1) Legacy: correo + contraseña vía /auth/login (POST) — lo usan los
   administradores y sirve como bootstrap hasta que haya tarjetas.
2) Tarjeta: /auth/challenge + /auth/verify (POST) — el cliente deriva
   su llave privada P-256 desde la semilla guardada en la tarjeta QR y
   prueba posesión firmando un nonce aleatorio emitido por el servidor.

El camino de tarjeta nunca expone la semilla al backend: solo se
intercambia el identificador de rol (CURP/cédula/licencia), el nonce y
la firma. La llave pública viva en la tabla `llaves` y se consulta por
`id_usuario` una vez que la identidad queda resuelta.
"""
from datetime import datetime, timedelta, timezone
from secrets import token_hex
from threading import Lock
from typing import Dict, Tuple, Union

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import Session, select

from src.core.config import settings
from src.core import security
from src.core.crypto_utils import verify_p256_ecdsa
from src.database.database import get_session
from src.database.models import (
    Administrador,
    Farmaceutico,
    Llave,
    Medico,
    Paciente,
    Usuario,
)
from src.api_gateway import schemas

router = APIRouter()


# ---------------------------------------------------------------------------
# Rate limit de /login (anti brute-force)
# ---------------------------------------------------------------------------
# Ventana deslizante en memoria: por cada (IP, correo) registramos los
# timestamps de los intentos fallidos recientes. Si superan el umbral
# dentro de la ventana, devolvemos 429 sin tocar bcrypt (bcrypt es caro
# y es justo ese costo el que hace atractivo un DoS).
#
# Esto es un mitigante, no una defensa completa: para producción real
# conviene mover el estado a Redis y añadir CAPTCHA tras varios 429.
_LOGIN_ATTEMPT_WINDOW_SECONDS = 60
_LOGIN_ATTEMPT_MAX = 5
_login_attempts: Dict[str, list] = {}
_login_attempts_lock = Lock()


def _rate_limit_key(request: Request, correo: str) -> str:
    # Cliente directo o detrás de proxy (X-Forwarded-For first hop).
    ip = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if not ip:
        ip = request.client.host if request.client else "unknown"
    return f"{ip}|{(correo or '').strip().lower()}"


def _login_rate_limit_check(request: Request, correo: str) -> None:
    """Aborta con 429 si hay demasiados intentos fallidos recientes."""
    key = _rate_limit_key(request, correo)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=_LOGIN_ATTEMPT_WINDOW_SECONDS)
    with _login_attempts_lock:
        attempts = [t for t in _login_attempts.get(key, []) if t > cutoff]
        _login_attempts[key] = attempts
        if len(attempts) >= _LOGIN_ATTEMPT_MAX:
            retry_in = int((attempts[0] + timedelta(seconds=_LOGIN_ATTEMPT_WINDOW_SECONDS) - now).total_seconds())
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Demasiados intentos fallidos. Intenta de nuevo en "
                    f"{max(retry_in, 1)} segundos."
                ),
                headers={"Retry-After": str(max(retry_in, 1))},
            )


def _login_rate_limit_record_failure(request: Request, correo: str) -> None:
    key = _rate_limit_key(request, correo)
    now = datetime.now(timezone.utc)
    with _login_attempts_lock:
        _login_attempts.setdefault(key, []).append(now)


def _login_rate_limit_clear(request: Request, correo: str) -> None:
    key = _rate_limit_key(request, correo)
    with _login_attempts_lock:
        _login_attempts.pop(key, None)


# ---------------------------------------------------------------------------
# Login legacy (correo + contraseña)
# ---------------------------------------------------------------------------
def authenticate_user(session: Session, correo: str, contrasena: str) -> Union[Usuario, Administrador, None]:
    """
    Busca un usuario o administrador por correo y verifica su contraseña.
    """
    # Primero busca en la tabla de usuarios generales (médico, paciente, etc.)
    user = session.exec(select(Usuario).where(Usuario.correo == correo)).first()
    if user and security.verify_password(contrasena, user.contrasena):
        return user

    # Si no, busca en la tabla de administradores
    admin = session.exec(select(Administrador).where(Administrador.correo == correo)).first()
    if admin and security.verify_password(contrasena, admin.contrasena):
        return admin

    return None


def _issue_token(correo: str, role_name: str, user_id: int) -> dict:
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": correo, "role": role_name, "id": user_id},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/login", response_model=schemas.Token)
def login_for_access_token(
    *,
    request: Request,
    session: Session = Depends(get_session),
    login_data: schemas.LoginRequest
):
    """
    Endpoint de login por correo + contraseña. Se mantiene para el
    administrador y para el bootstrap inicial. Los usuarios clínicos
    (médico, paciente, farmacéutico) deberían preferir /auth/challenge +
    /auth/verify con su tarjeta.
    """
    # Rate limit ANTES de tocar bcrypt: evita que un atacante convierta
    # cada intento en ~100 ms de CPU del servidor.
    _login_rate_limit_check(request, login_data.correo)

    user_or_admin = authenticate_user(session=session, correo=login_data.correo, contrasena=login_data.contrasena)

    if not user_or_admin:
        _login_rate_limit_record_failure(request, login_data.correo)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Correo o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Login OK → limpiamos los fallos recientes de esta combinación.
    _login_rate_limit_clear(request, login_data.correo)

    # Determinar el rol y el ID para el payload del token
    if isinstance(user_or_admin, Usuario):
        session.refresh(user_or_admin, ["rol"]) # Aseguramos que la relación de rol esté cargada
        role_name = user_or_admin.rol.nombre
        user_id = user_or_admin.id_usuario
    else: # Es un Administrador
        role_name = "Administrador"
        user_id = user_or_admin.id_admin

    return _issue_token(user_or_admin.correo, role_name, user_id)


# ---------------------------------------------------------------------------
# Login por tarjeta (challenge / response ECDSA P-256)
# ---------------------------------------------------------------------------
# IMPORTANTE: el cache de retos vive en memoria del proceso, así que esta
# implementación solo es segura si el backend corre con UN ÚNICO worker
# (uvicorn/gunicorn con --workers 1). Con más workers:
#   - El challenge emitido en el worker A no existe en el worker B, así
#     que el verify contra B siempre falla → login roto.
#   - Peor: un atacante que intercepte una firma podría intentar replay
#     contra otro worker sin que éste haya visto el nonce, pero como
#     tampoco puede canjearlo (no lo conoce), solo hay DoS, no bypass.
# Para producción se debe mover a Redis (con TTL nativo) o a una tabla
# `auth_challenges` con índice único y limpieza periódica. Mientras tanto,
# `main.py` emite un warning al arranque si se detecta WEB_CONCURRENCY>1.
_CHALLENGE_TTL_SECONDS = 120
_challenge_cache: Dict[Tuple[str, str], Tuple[str, datetime]] = {}
_challenge_lock = Lock()


def _normalize(rol: str, identificador: str) -> Tuple[str, str]:
    """Normaliza rol e identificador para la clave del cache y la búsqueda."""
    r = (rol or "").strip().capitalize()
    i = (identificador or "").strip().upper()
    return (r, i)


def _prune_expired(now: datetime) -> None:
    """Elimina del cache cualquier nonce ya expirado. Se ejecuta barato
    dentro del lock porque en el prototipo son pocas entradas."""
    dead = [k for k, (_, exp) in _challenge_cache.items() if exp < now]
    for k in dead:
        _challenge_cache.pop(k, None)


def _resolve_usuario_por_identificador(
    session: Session, rol: str, identificador: str
) -> Usuario:
    """
    Resuelve el Usuario correspondiente a (rol, identificador).
    Los identificadores por rol son:
      - Paciente     -> Paciente.curp
      - Medico       -> Medico.cedula
      - Farmaceutico -> Farmaceutico.licencia
    Lanza 404 si no se encuentra. Para Administrador lanza 400 (no usa
    este flujo; el admin entra por /auth/login).
    """
    if rol == "Paciente":
        perfil = session.exec(select(Paciente).where(Paciente.curp == identificador)).first()
    elif rol == "Medico":
        perfil = session.exec(select(Medico).where(Medico.cedula == identificador)).first()
    elif rol == "Farmaceutico":
        perfil = session.exec(select(Farmaceutico).where(Farmaceutico.licencia == identificador)).first()
    else:
        raise HTTPException(
            status_code=400,
            detail=(
                f"El rol '{rol}' no soporta login por tarjeta. "
                "Usa /auth/login con correo y contraseña."
            ),
        )
    if not perfil:
        raise HTTPException(status_code=404, detail="Identificador no registrado.")
    usuario = session.get(Usuario, perfil.id_usuario)
    if not usuario or not usuario.activo:
        raise HTTPException(status_code=404, detail="Usuario no encontrado o inactivo.")
    # Doble check de rol contra la tabla roles
    session.refresh(usuario, ["rol"])
    if usuario.rol.nombre != rol:
        raise HTTPException(
            status_code=400,
            detail=(
                f"El identificador corresponde al rol '{usuario.rol.nombre}', "
                f"no a '{rol}'."
            ),
        )
    return usuario


@router.post("/challenge", response_model=schemas.AuthChallengeResponse)
def auth_challenge(
    *,
    session: Session = Depends(get_session),
    body: schemas.AuthChallengeRequest,
):
    """
    Emite un nonce de 32 bytes que el cliente debe firmar con la llave
    privada derivada de su tarjeta. El nonce queda ligado al par
    (rol, identificador) durante 120 segundos. Antes de emitirlo
    confirmamos que existe un usuario con ese identificador y que tiene
    una llave pública registrada — de lo contrario firmar no serviría
    de nada.
    """
    rol, identificador = _normalize(body.rol, body.identificador)
    usuario = _resolve_usuario_por_identificador(session, rol, identificador)

    llave = session.exec(
        select(Llave)
        .where(Llave.id_usuario == usuario.id_usuario, Llave.activo == True, Llave.responsabilidad == "firmas")
        .order_by(Llave.creado_en.desc())
    ).first()
    if not llave:
        raise HTTPException(
            status_code=400,
            detail="El usuario no tiene llave pública registrada.",
        )

    now = datetime.now(timezone.utc)
    nonce = token_hex(32)  # 32 bytes aleatorios en hex = 64 chars
    expira = now + timedelta(seconds=_CHALLENGE_TTL_SECONDS)

    with _challenge_lock:
        _prune_expired(now)
        _challenge_cache[(rol, identificador)] = (nonce, expira)

    return schemas.AuthChallengeResponse(
        nonce_hex=nonce,
        expira_unix=int(expira.timestamp()),
    )


@router.post("/verify", response_model=schemas.Token)
def auth_verify(
    *,
    session: Session = Depends(get_session),
    body: schemas.AuthVerifyRequest,
):
    """
    Verifica la firma del nonce con la llave pública activa del usuario
    identificado. Si pasa, emite JWT igual que /auth/login. El nonce se
    consume en el primer uso (no se permite replay).
    """
    rol, identificador = _normalize(body.rol, body.identificador)

    # 1) Recuperar y consumir el nonce emitido
    now = datetime.now(timezone.utc)
    with _challenge_lock:
        _prune_expired(now)
        entry = _challenge_cache.pop((rol, identificador), None)

    if not entry:
        raise HTTPException(
            status_code=401,
            detail="No hay reto vigente para este identificador. Pide uno nuevo.",
        )
    cached_nonce, expira = entry
    if cached_nonce != body.nonce_hex.strip().lower():
        raise HTTPException(status_code=401, detail="El nonce no coincide con el emitido.")
    if expira < now:
        raise HTTPException(status_code=401, detail="El reto expiró. Pide uno nuevo.")

    # 2) Resolver el usuario y su llave pública activa
    usuario = _resolve_usuario_por_identificador(session, rol, identificador)
    llave = session.exec(
        select(Llave)
        .where(Llave.id_usuario == usuario.id_usuario, Llave.activo == True, Llave.responsabilidad == "firmas")
        .order_by(Llave.creado_en.desc())
    ).first()
    if not llave:
        raise HTTPException(status_code=400, detail="El usuario no tiene llave pública registrada.")

    # 3) Verificar la firma ECDSA P-256 sobre el nonce en bytes
    try:
        nonce_bytes = bytes.fromhex(cached_nonce)
    except ValueError:
        # No debería pasar porque el nonce lo generamos nosotros.
        raise HTTPException(status_code=500, detail="Nonce interno corrupto.")

    if not verify_p256_ecdsa(llave.llave_publica, nonce_bytes, body.firma_hex.strip().lower()):
        raise HTTPException(status_code=401, detail="Firma inválida.")

    # 4) Emitir JWT
    session.refresh(usuario, ["rol"])
    return _issue_token(usuario.correo, usuario.rol.nombre, usuario.id_usuario)
