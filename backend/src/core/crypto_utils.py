"""
Helpers compartidos de criptografía de servidor.

Estos helpers se usan tanto para verificar la firma "envelope" sobre una
cápsula de receta (en recetas.py) como para verificar la firma de un
reto en el login por tarjeta (en auth.py). Se mantienen aquí para no
duplicar lógica y para tener un único punto de cambio si se rota la curva.
"""
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils


def verify_p256_ecdsa(pub_hex: str, message: bytes, sig_compact_hex: str) -> bool:
    """
    Verifica una firma ECDSA P-256 en formato compacto r||s (64 bytes, 128 hex)
    contra un mensaje y una llave pública uncompressed hex (65 bytes, 130 hex).
    Devuelve True si la firma es válida, False en cualquier error. Nunca lanza.
    """
    try:
        pub_bytes = bytes.fromhex(pub_hex)
        if len(pub_bytes) != 65 or pub_bytes[0] != 0x04:
            return False
        pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), pub_bytes
        )
        sig_bytes = bytes.fromhex(sig_compact_hex)
        if len(sig_bytes) != 64:
            return False
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")
        der = ec_utils.encode_dss_signature(r, s)
        pub.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
    except Exception:
        return False


def is_valid_p256_pub_hex(pub_hex: str) -> bool:
    """Valida barato el formato de llave pública P-256 uncompressed (130 hex, '04')."""
    if not isinstance(pub_hex, str):
        return False
    s = pub_hex.strip().lower()
    if len(s) != 130 or not s.startswith("04"):
        return False
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False
