/**
 * Acceso a las llaves derivadas del usuario actualmente logueado.
 *
 * Se basa en la semilla (seedHex) guardada en sessionStorage al momento
 * del login con tarjeta (ver authFlow.ts). Si no hay semilla persistida
 * (por ejemplo, sesión abierta con correo+contraseña, o sesión antigua
 * antes de esta feature), se devuelve null y las páginas que necesiten
 * firmar/descifrar deben mostrar un error claro o re-pedir el QR.
 */

import { deriveKeysFromSeed, type DerivedKeys} from '../crypto/seedDerivation.ts'
import { getUserSeed } from './api.ts'

type responsabilidad = 'sign' | 'recipes' | 'seal'
export interface UserKeys {
  SymetricKeys: Array<{
    responsabilidad: responsabilidad
    DerivedKeys: DerivedKeys
  }>
  AsymetricKeys: Array<{
    responsabilidad: responsabilidad
    KeyHex: string
  }>
}

/**
 * Devuelve el par derivado del usuario logueado, o null si no hay semilla
 * persistida. No lanza: la ausencia de semilla es un estado esperado
 * (sesión por credenciales, logout, etc.).
*/

export function getUserKeys(rol: 'paciente' | 'medico' | 'farmaceutico'): UserKeys | null {
  const seed = getUserSeed()
  if (!seed) return null
  if(!rol) return null
  try {
    const sign = deriveKeysFromSeed(seed, "sign")
    const recipes = deriveKeysFromSeed(seed, "recipes")
    const result: UserKeys = {
      SymetricKeys: [{
        responsabilidad: "sign",
        DerivedKeys: sign
      },
      {
        responsabilidad: "recipes",
        DerivedKeys: recipes
      }],
      AsymetricKeys: []
    }
    if(rol === 'farmaceutico') {
      const seal = deriveKeysFromSeed(seed, "seal").privateKeyHex
      result.AsymetricKeys.push({
        responsabilidad: "seal",
        KeyHex: seal
      })
    }
    return result
    
  } catch {
    return null
  }
}

/** Shortcut: llave privada hex del usuario logueado, o null. */
export function getUserPrivKeyHex(rol: 'paciente' | 'medico' | 'farmaceutico', responsabilidad: responsabilidad): string | null {
  const userKeys = getUserKeys(rol)
  if (!userKeys) return null
  const symkey = userKeys.SymetricKeys.find(k => k.responsabilidad === responsabilidad)?.DerivedKeys.privateKeyHex
  const asymKey = userKeys.AsymetricKeys.find(k => k.responsabilidad === responsabilidad)?.KeyHex
  const key = symkey ? symkey : asymKey
  return key ? key : null
}

/** Shortcut: llave pública hex del usuario logueado, o null. */
export function getUserPublicKeyHex(rol: 'paciente' | 'medico' | 'farmaceutico', responsabilidad: responsabilidad): string | null {
  const userKeys = getUserKeys(rol)
  if (!userKeys) return null
  const key = userKeys.SymetricKeys.find(k => k.responsabilidad === responsabilidad)?.DerivedKeys.publicKeyHex
  return key ? key : null
}
