// frontend/src/crypto/contextFactory.ts
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { CRYPTO_VERSION } from './config.ts';

export class CryptoContextFactory {
  
  /**
   * Construye el AAD (Additional Authenticated Data) para AES-GCM.
   * NIST SP 800-38D: Vincula el texto cifrado a sus actores principales.
   */
  static buildAAD(idReceta: string, idMedico: string, idPaciente: string): Uint8Array {
    if (!idReceta || !idMedico || !idPaciente) throw new Error("AAD incompleto");
    return utf8ToBytes(`${idReceta}|${idMedico}|${idPaciente}`);
  }

  /**
   * Construye el ContextInfo (FixedInfo) para HKDF.
   * NIST SP 800-56A: Vincula la derivación de llaves al algoritmo y las llaves públicas.
   */
  static buildHKDFContext(idReceta: string, idReceptor: string): Uint8Array {
    if (!idReceta || !idReceptor) {
      throw new Error("Contexto HKDF incompleto: Faltan IDs de destino.");
    }
    return utf8ToBytes(`${CRYPTO_VERSION.kw}|${idReceta}|${idReceptor}`);
  }

  /**
   * Construye el mensaje estandarizado para el Sello HMAC.
   * Previene la falsificación asegurando el Quién, Qué, Cuándo y Dónde.
   */
  static buildSealMessage(idReceta: string, estado: string, idClinica: string, fechaSurtido: string): string {
    return `${idReceta}|${estado}|${idClinica}|${fechaSurtido}`;
  }
}