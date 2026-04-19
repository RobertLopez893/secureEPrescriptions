/**
 * Acceso a las llaves derivadas del usuario actualmente logueado.
 *
 * Se basa en la semilla (seedHex) guardada en sessionStorage al momento
 * del login con tarjeta (ver authFlow.ts). Si no hay semilla persistida
 * (por ejemplo, sesión abierta con correo+contraseña, o sesión antigua
 * antes de esta feature), se devuelve null y las páginas que necesiten
 * firmar/descifrar deben mostrar un error claro o re-pedir el QR.
 */

import { deriveKeysFromSeed } from '../crypto/seedDerivation.ts'
import { getUserSeed } from './api.ts'

export interface UserKeys {
  privateKeyHex: string
  publicKeyHex: string
}

/**
 * Devuelve el par derivado del usuario logueado, o null si no hay semilla
 * persistida. No lanza: la ausencia de semilla es un estado esperado
 * (sesión por credenciales, logout, etc.).
 */
export function getUserKeys(): UserKeys | null {
  const seed = getUserSeed()
  if (!seed) return null
  try {
    return deriveKeysFromSeed(seed)
  } catch {
    return null
  }
}

/** Shortcut: llave privada hex del usuario logueado, o null. */
export function getUserPrivKeyHex(): string | null {
  return getUserKeys()?.privateKeyHex ?? null
}

/** Shortcut: llave pública hex del usuario logueado, o null. */
export function getUserPublicKeyHex(): string | null {
  return getUserKeys()?.publicKeyHex ?? null
}
