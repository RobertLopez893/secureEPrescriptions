/**
 * src/crypto/hmac.ts
 * Módulo de Sellado mediante HMAC-SHA256
 */
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

export class HmacModule {
  /**
   * Genera un sello criptográfico para la farmacia.
   * @param dataToSeal Texto que vincula la receta y la fecha.
   * @param secretKeyHex Llave secreta de la farmacia.
   */
  static generateSeal(dataToSeal: string, secretKeyHex: string): string {
    const key = hexToBytes(secretKeyHex);
    const message = utf8ToBytes(dataToSeal);
    const mac = hmac(sha256, key, message);
    return bytesToHex(mac);
  }

  /**
   * Verifica que el sello de la farmacia sea auténtico.
   */
  static verifySeal(dataToSeal: string, sealToVerify: string, secretKeyHex: string): boolean {
    const expectedSeal = this.generateSeal(dataToSeal, secretKeyHex);
    return expectedSeal === sealToVerify;
  }
}