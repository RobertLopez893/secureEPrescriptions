
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { RecetaContainer } from './interfaces';

export class EncryptionModule {

  static encrypt(container: RecetaContainer, dek: Uint8Array) {
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
    const aes = gcm(dek, hexToBytes(ivHex));
    const plaintextBytes = aes.decrypt(hexToBytes(ciphertextHex));
    return JSON.parse(new TextDecoder().decode(plaintextBytes)) as RecetaContainer;
  }

}