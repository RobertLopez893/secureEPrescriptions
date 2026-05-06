// frontend/src/crypto/contextFactory.ts
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { CRYPTO_VERSION } from './config.ts';

export class CryptoContextFactory {
  
  /**
   * Construye el AAD (Additional Authenticated Data) para AES-GCM.
   * NIST SP 800-38D: Vincula el texto cifrado a sus actores principales.
   */
  static buildAAD(folio: string, idMedico: string, idPaciente: string): Uint8Array {
    if (!folio || !idMedico || !idPaciente) throw new Error("AAD incompleto");
    return utf8ToBytes(`${folio}|${idMedico}|${idPaciente}`);
  }

  /**
   * Construye el ContextInfo (FixedInfo) para HKDF.
   * NIST SP 800-56A: Vincula la derivación de llaves al algoritmo y las llaves públicas.
   */
  static buildHKDFContext(folio: string, idReceptor: string): Uint8Array {
    if (!folio || !idReceptor) {
      throw new Error("Contexto HKDF incompleto: Faltan IDs de destino.");
    }
    return utf8ToBytes(`${CRYPTO_VERSION.kw}|${folio}|${idReceptor}`);
  }

  /**
   * Construye el mensaje estandarizado para el Sello HMAC.
   * Previene la falsificación asegurando el Quién, Qué, Cuándo y Dónde.
   */
  // !Refactorizar
  static buildSealMessage(folio: string, estado: string, idClinica: string, fechaSurtido: string): string {
    return `${folio}|${estado}|${idClinica}|${fechaSurtido}`;
  }
}