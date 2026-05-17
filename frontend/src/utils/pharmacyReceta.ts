/**
 * Carga + validación de una receta para el flujo de farmacia.
 *
 * Centraliza la lógica que antes estaba duplicada (y divergente) entre
 * pharmacy/verify.astro y pharmacy/seal.astro. La divergencia era la causa
 * raíz de varios bugs: la firma del médico nunca se comprobaba, seal pedía
 * la llave del médico con la etiqueta equivocada y leía una propiedad
 * inexistente del resultado de descifrado.
 *
 * Reglas de bloqueo (ninguna receta se dispensa si falla alguna):
 *   - YA_SURTIDA       estado === 'surtida'
 *   - VENCIDA          recetaInfo.vencida === true
 *   - NO_ASIGNADA      id_farmaceutico de la receta != farmacéutico logueado
 *   - SIN_LLAVE        no hay llave 'recipes' en la sesión (re-escanear tarjeta)
 *   - DESCIFRADO       el contenedor no se pudo abrir (sin acceso / cápsula alterada)
 *   - FIRMA_INVALIDA   la firma ECDSA del médico no verifica sobre los datos
 *   - YA_SELLADA       el contenedor ya tiene un sello de dispensación
 */
import { Api, getSession } from './api.ts'
import { CryptoEngine } from '../crypto/index.ts'
import { getUserPrivKeyHex } from './userKeys.ts'
import type { RecetaContainer } from '../crypto/interfaces'

export type RecetaErrorCode =
  | 'SIN_SESION'
  | 'YA_SURTIDA'
  | 'VENCIDA'
  | 'NO_ASIGNADA'
  | 'SIN_LLAVE'
  | 'DESCIFRADO'
  | 'FIRMA_INVALIDA'
  | 'YA_SELLADA'

export class RecetaValidationError extends Error {
  code: RecetaErrorCode
  constructor(code: RecetaErrorCode, message: string) {
    super(message)
    this.name = 'RecetaValidationError'
    this.code = code
  }
}

const MENSAJES: Record<RecetaErrorCode, string> = {
  SIN_SESION:     'No hay sesión de farmacéutico activa. Vuelve a iniciar sesión.',
  YA_SURTIDA:     'Esta receta ya fue surtida y no puede dispensarse de nuevo.',
  VENCIDA:        'Esta receta está vencida y no puede dispensarse.',
  NO_ASIGNADA:    'Esta receta no está asignada a este farmacéutico.',
  SIN_LLAVE:      'No hay llave de cifrado en esta sesión. Vuelve a escanear tu tarjeta.',
  DESCIFRADO:     'No se pudo descifrar la cápsula: acceso no autorizado o datos alterados.',
  FIRMA_INVALIDA: 'FIRMA DIGITAL DEL MÉDICO INVÁLIDA · LA RECETA FUE ALTERADA O NO ES AUTÉNTICA.',
  YA_SELLADA:     'El contenedor ya tiene un sello de dispensación.',
}

export function mensajeReceta(code: RecetaErrorCode): string {
  return MENSAJES[code]
}

export interface RecetaValidada {
  recetaInfo: Awaited<ReturnType<typeof Api.obtenerRecetaInfo>>
  payload: Awaited<ReturnType<typeof Api.obtenerRecetaCripto>>
  contenedor: RecetaContainer
}

/**
 * Obtiene, descifra y valida una receta para que el farmacéutico logueado
 * pueda verla/dispensarla. Lanza RecetaValidationError con un código
 * específico ante cualquier condición de bloqueo.
 */
export async function cargarRecetaValidada(idReceta: number): Promise<RecetaValidada> {
  const session = getSession()
  if (!session) throw new RecetaValidationError('SIN_SESION', MENSAJES.SIN_SESION)

  const recetaInfo = await Api.obtenerRecetaInfo(idReceta)

  // --- Compuertas pre-criptográficas (metadata del backend) ---
  if (recetaInfo.estado === 'surtida') {
    throw new RecetaValidationError('YA_SURTIDA', MENSAJES.YA_SURTIDA)
  }
  if (recetaInfo.vencida === true) {
    throw new RecetaValidationError('VENCIDA', MENSAJES.VENCIDA)
  }
  if (recetaInfo.id_farmaceutico !== session.id) {
    throw new RecetaValidationError('NO_ASIGNADA', MENSAJES.NO_ASIGNADA)
  }

  const privRecipes = getUserPrivKeyHex('farmaceutico', 'recipes')
  if (!privRecipes) throw new RecetaValidationError('SIN_LLAVE', MENSAJES.SIN_LLAVE)

  const payload = await Api.obtenerRecetaCripto(idReceta)

  // Llave pública de FIRMA del médico: el backend la almacena con
  // responsabilidad 'firmas' (ver backend/.../recetas.py _llave_publica_firma).
  const docPubFirma = (await Api.obtenerLlavePublica(recetaInfo.id_medico, 'firmas')).llave_publica

  // --- Apertura criptográfica del contenedor ---
  let decrypted: { valido: boolean; contenido: RecetaContainer }
  try {
    decrypted = CryptoEngine.abrirReceta(
      payload,
      'farmaceutico',
      privRecipes,
      docPubFirma,
      'DOC-' + recetaInfo.id_medico,
      'USR-' + recetaInfo.id_paciente,
      'FAR-' + recetaInfo.id_farmaceutico,
      recetaInfo.folio,
    )
  } catch {
    throw new RecetaValidationError('DESCIFRADO', MENSAJES.DESCIFRADO)
  }

  // Compuerta de autenticidad: la firma del médico DEBE verificar.
  if (!decrypted.valido) {
    throw new RecetaValidationError('FIRMA_INVALIDA', MENSAJES.FIRMA_INVALIDA)
  }

  if (decrypted.contenido.sellos) {
    throw new RecetaValidationError('YA_SELLADA', MENSAJES.YA_SELLADA)
  }

  return { recetaInfo, payload, contenedor: decrypted.contenido }
}
