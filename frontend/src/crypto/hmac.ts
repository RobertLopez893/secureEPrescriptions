/**
 * src/crypto/hmac.ts
 * Módulo de Sellado mediante HMAC-SHA256
 */
import { hmac } from '@noble/hashes/hmac.js';
import { appHash } from './config.ts';
import { utf8ToBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

export class HmacModule {
  /**
   * Genera un sello criptográfico para la farmacia.
   * @param dataToSeal Texto que vincula la receta y la fecha.
   * @param secretKeyHex Llave secreta de la farmacia.
   */
  static generateSeal(dataToSeal: string, sealKeyHex: string): string {
    const key = hexToBytes(sealKeyHex);
    const message = utf8ToBytes(dataToSeal);
    const mac = hmac(appHash, key, message);
    return bytesToHex(mac);
  }

  /**
   * Verifica que el sello de la farmacia sea auténtico.
   */
  static verifySeal(dataToSeal: string, sealToVerify: string, sealKeyHex: string): boolean {
    const expectedMac = hexToBytes(this.generateSeal(dataToSeal, sealKeyHex));
    const receivedMac = hexToBytes(sealToVerify);
    
    // Prevenir ataque si el tamaño es diferente
    if (expectedMac.length !== receivedMac.length) return false;
    
    // Comparación de tiempo constante (Constant-time comparison)
    let diff = 0;
    for (let i = 0; i < expectedMac.length; i++) {
        diff |= expectedMac[i] ^ receivedMac[i];
    }
    return diff === 0;
  }
}