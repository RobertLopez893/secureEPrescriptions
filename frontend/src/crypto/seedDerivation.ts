/**
 * Derivación determinista de llaves ECDSA P-256 a partir de la semilla
 * guardada en la tarjeta QR del usuario.
 *
 * Diseño (simple y suficiente para un prototipo):
 *   - La tarjeta lleva 32 bytes aleatorios (64 hex) como "semilla".
 *   - Se aplica HKDF-SHA256 con un `salt` y un `info` fijos para obtener
 *     32 bytes de material determinista.
 *   - Ese material se interpreta como escalar privado de la curva P-256.
 *     Si cayera fuera del rango [1, n-1] (probabilidad ~2^-128) se
 *     reintentaría con una nueva ronda de HKDF — en la práctica no pasa.
 *   - La llave pública se obtiene con @noble/curves `p256.getPublicKey`.
 *
 * No se guarda la semilla en BD; el backend solo recibe la pública
 * derivada al momento de registrar al usuario.
 */

import { p256 } from '@noble/curves/nist.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'

// Constantes de dominio: no deben cambiar una vez emitidas tarjetas, si
// no las llaves derivadas dejan de reproducirse. Versionar con 'v1'.
const HKDF_SALT = utf8ToBytes('rxpro-2026:cardkey-salt:v1')
const HKDF_INFO_RECIPES = utf8ToBytes('rxpro-v1:p256:recipes_key')
const HKDF_INFO_SIGN = utf8ToBytes('rxpro-v1:p256:signing_key')
const HKDF_INFO_SEAL = utf8ToBytes('rxpro-v1:p256:sealing_key')

// Orden del subgrupo de P-256 (n). Un escalar privado válido está en
// el intervalo [1, n-1]. Fuente: NIST FIPS 186-4, D.1.2.3.
const P256_N = BigInt(
  '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'
)

export interface DerivedKeys {
  /** Hex del escalar privado P-256 (64 chars). */
  privateKeyHex: string
  /** Hex de la llave pública uncompressed P-256 (130 chars, empieza con 04). */
  publicKeyHex: string
}

function scalarFromBytes(bytes: Uint8Array): bigint {
  let n = 0n
  for (const b of bytes) n = (n << 8n) | BigInt(b)
  return n
}

function bigIntToHex(n: bigint): string {
  let h = n.toString(16)
  if (h.length < 64) h = '0'.repeat(64 - h.length) + h
  return h
}

/**
 * Deriva el par (priv, pub) de forma determinista a partir de una
 * semilla hex de 32 bytes (64 chars). Throws si la semilla no tiene
 * ese tamaño.
 */
export function deriveKeysFromSeed(seedHex: string, typekey: 'recipes' | 'sign' | 'seal'): DerivedKeys {
  const clean = (seedHex || '').trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error('La semilla debe ser exactamente 64 chars hex (32 bytes).')
  }
  const seed = hexToBytes(clean)

  // HKDF-SHA256 → 32 bytes. Reintentamos con un counter si cayera fuera
  // de rango (pragmáticamente no ocurre).
  let counter = 0
  // Reservamos 2 slots en el array para permitir reintentos extremos.
  // eslint-disable-next-line no-constant-condition

  const hkdf_info = typekey === 'recipes' ? HKDF_INFO_RECIPES : typekey === 'sign' ? HKDF_INFO_SIGN : HKDF_INFO_SEAL
  while (true) {
    const info = new Uint8Array(hkdf_info.length + 1)
    info.set(hkdf_info, 0)
    info[hkdf_info.length] = counter & 0xff
    const raw = hkdf(sha256, seed, HKDF_SALT, info, 32)
    const scalar = scalarFromBytes(raw)
    if (scalar > 0n && scalar < P256_N) {
      const privateKeyHex = bigIntToHex(scalar)
      const pubBytes = p256.getPublicKey(hexToBytes(privateKeyHex), false) // uncompressed
      return { privateKeyHex, publicKeyHex: bytesToHex(pubBytes) }
    }
    counter += 1
    if (counter > 255) {
      throw new Error('No se pudo derivar un escalar válido (caso imposible en la práctica).')
    }
  }
}

/** Genera una semilla aleatoria de 32 bytes (64 chars hex). */
export function generateCardSeed(): string {
  const buf = new Uint8Array(32)
  crypto.getRandomValues(buf)
  return bytesToHex(buf)
}
