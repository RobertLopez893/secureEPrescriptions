
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { RecetaContainer } from './interfaces';

export class EncryptionModule {

  static encrypt(container: RecetaContainer, dek: Uint8Array) {
    if(dek.length !== 32) throw new Error('DEK debe ser de 32 bytes');
    const nonce = randomBytes(12);
    const aes = gcm(dek, nonce);
    const plaintext = new TextEncoder().encode(JSON.stringify(container));
    const ciphertext = aes.encrypt(plaintext);

    return {
      capsula_cifrada: bytesToHex(ciphertext),
      iv_aes_gcm: bytesToHex(nonce)
    };
  }
  static decrypt(ciphertextHex: string, ivHex: string, dek: Uint8Array): RecetaContainer {
    if(ivHex.length !== 24) throw new Error('IV debe ser de 12 bytes (24 hex)');
    if(dek.length !== 32) throw new Error('DEK debe ser de 32 bytes');
    const aes = gcm(dek, hexToBytes(ivHex));
    const plaintextBytes = aes.decrypt(hexToBytes(ciphertextHex));
    return JSON.parse(new TextDecoder().decode(plaintextBytes)) as RecetaContainer;
  }

}