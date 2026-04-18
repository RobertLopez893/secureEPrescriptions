/**
 * Formato del QR de la tarjeta de identidad de RxPro.
 *
 *   rxpro://card/v1/<rol>/<identificador>/<semilla_hex64>
 *
 * Ejemplos:
 *   rxpro://card/v1/paciente/GARM850315HDFNDS07/a1b2...ff
 *   rxpro://card/v1/medico/CED-4892103/c0ffee...42
 *   rxpro://card/v1/farmaceutico/LIC-123456/deadbe...ef
 *
 * Los identificadores son los mismos que ya son únicos en la BD:
 *   - paciente     -> CURP
 *   - medico       -> cédula profesional
 *   - farmaceutico -> licencia
 *
 * El `rol` va en minúsculas en el QR (más amigable al escáner), pero el
 * backend lo espera capitalizado ("Paciente"/"Medico"/"Farmaceutico"),
 * así que el decoder normaliza a ese formato.
 */

export type CardRol = 'Paciente' | 'Medico' | 'Farmaceutico'

export interface CardPayload {
  rol: CardRol
  identificador: string
  seedHex: string
}

const PREFIX = 'rxpro://card/v1/'

function normalizeRol(raw: string): CardRol | null {
  const r = (raw || '').trim().toLowerCase()
  if (r === 'paciente') return 'Paciente'
  if (r === 'medico' || r === 'médico') return 'Medico'
  if (r === 'farmaceutico' || r === 'farmacéutico') return 'Farmaceutico'
  return null
}

/** Produce el payload que va dentro del QR imprimible. */
export function encodeCardQr(payload: CardPayload): string {
  const rol = payload.rol.toLowerCase()
  const id = encodeURIComponent(payload.identificador.trim())
  const seed = payload.seedHex.trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(seed)) {
    throw new Error('encodeCardQr: la semilla debe ser 64 hex chars.')
  }
  return `${PREFIX}${rol}/${id}/${seed}`
}

/**
 * Parsea el texto leído por el escáner. Devuelve null si no es una
 * tarjeta RxPro válida (por ejemplo si escanean otro QR cualquiera).
 */
export function parseCardQr(raw: string): CardPayload | null {
  const trimmed = (raw || '').trim()
  if (!trimmed.startsWith(PREFIX)) return null

  const rest = trimmed.slice(PREFIX.length)
  // Dividimos manualmente porque el identificador podría contener '-'
  // pero no esperamos '/' (lo validamos abajo).
  const firstSlash = rest.indexOf('/')
  if (firstSlash < 0) return null
  const rolRaw = rest.slice(0, firstSlash)
  const afterRol = rest.slice(firstSlash + 1)
  const lastSlash = afterRol.lastIndexOf('/')
  if (lastSlash < 0) return null
  const idRaw = afterRol.slice(0, lastSlash)
  const seedRaw = afterRol.slice(lastSlash + 1)

  const rol = normalizeRol(rolRaw)
  if (!rol) return null

  let identificador: string
  try {
    identificador = decodeURIComponent(idRaw).trim().toUpperCase()
  } catch {
    return null
  }
  if (!identificador) return null

  const seedHex = seedRaw.trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(seedHex)) return null

  return { rol, identificador, seedHex }
}
