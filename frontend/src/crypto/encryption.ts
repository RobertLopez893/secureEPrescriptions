/**
 * src/crypto/encryption.ts
 * Módulo de Cifrado Simétrico AES-256-GCM
 */
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { RecetaContainer } from './interfaces';

export class EncryptionModule {
  /**
   * Cifra el contenedor de la receta (datos + firma).
   * @param container El objeto RecetaContainer completo.
   * @param dek La llave simétrica plana (Uint8Array de 32 bytes).
   */
  static encrypt(container: RecetaContainer, dek: Uint8Array) {
    // Generación de Nonce de 12 bytes (Estándar NIST)
    const nonce = randomBytes(12);
    const aes = gcm(dek, nonce);

    const plaintext = new TextEncoder().encode(JSON.stringify(container));
    const ciphertext = aes.encrypt(plaintext);

    return {
      capsula_cifrada: bytesToHex(ciphertext),
      iv_aes_gcm: bytesToHex(nonce)
    };
  }

  /**
   * Descifra la cápsula para que el paciente o farmacia lean el contenido.
   */
  static decrypt(ciphertextHex: string, ivHex: string, dek: Uint8Array): RecetaContainer {
    const nonce = hexToBytes(ivHex);
    const ciphertext = hexToBytes(ciphertextHex);
    const aes = gcm(dek, nonce);

    const plaintextBytes = aes.decrypt(ciphertext);
    const jsonString = new TextDecoder().decode(plaintextBytes);
    
    return JSON.parse(jsonString) as RecetaContainer;
  }
}