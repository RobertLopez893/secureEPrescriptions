/**
 * Flujo de login por tarjeta (challenge/response ECDSA P-256).
 *
 * Pide un nonce al backend, deriva la llave privada desde la semilla,
 * firma el nonce, y envía la firma para obtener un JWT + sesión.
 *
 * La semilla nunca sale del cliente.
 */

import { p256 } from '@noble/curves/nist.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

import { deriveKeysFromSeed } from '../crypto/seedDerivation.ts'
import { Api, decodeJwtPayload, saveSession, type SessionData } from './api.ts'
import type { CardPayload } from './cardQr.ts'

/**
 * Ejecuta el flujo completo: challenge → deriva → firma → verify →
 * persiste la sesión. Devuelve la sesión resultante o lanza ApiError.
 */
export async function loginWithCard(card: CardPayload): Promise<SessionData> {
  // 1) Pedir reto
  const challenge = await Api.authChallenge({
    rol: card.rol,
    identificador: card.identificador,
  })

  // 2) Derivar llaves desde la semilla
  const { privateKeyHex } = deriveKeysFromSeed(card.seedHex)

  // 3) Firmar SHA-256(nonce_bytes). El backend verifica con
  //    ec.ECDSA(hashes.SHA256()), que aplica SHA-256 al mensaje antes de
  //    verificar — así que el cliente debe hashear antes y pasar el
  //    digest a p256.sign, que NO re-hashea (espera un digest de 32 B).
  const nonceBytes = hexToBytes(challenge.nonce_hex)
  const digest = sha256(nonceBytes)
  const sig: any = p256.sign(digest, hexToBytes(privateKeyHex))
  const compact: Uint8Array =
    typeof sig?.toCompactRawBytes === 'function'
      ? sig.toCompactRawBytes()
      : sig instanceof Uint8Array
        ? sig
        : new Uint8Array(sig)
  const firmaHex = bytesToHex(compact)

  // 4) Verificar en backend → recibimos JWT
  const token = await Api.authVerify({
    rol: card.rol,
    identificador: card.identificador,
    nonce_hex: challenge.nonce_hex,
    firma_hex: firmaHex,
  })

  // 5) Decodificar y persistir sesión (mismo patrón que loginAndPersist)
  const payload = decodeJwtPayload(token.access_token) || {}
  const session: SessionData = {
    id: Number(payload.id),
    correo: String(payload.sub || ''),
    role: String(payload.role || ''),
  }
  saveSession(token.access_token, session)
  return session
}
