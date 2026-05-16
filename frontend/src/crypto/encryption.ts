
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes, bytesToHex, hexToBytes,utf8ToBytes } from '@noble/hashes/utils.js';
import type { RecetaContainer, RecetaCifrada } from './interfaces';

export class EncryptionModule {

  static encrypt(container: RecetaContainer, dek: Uint8Array, AAD:Uint8Array): RecetaCifrada {
    if(dek.length !== 32) throw new Error('DEK debe ser de 32 bytes');
    const nonce = randomBytes(12);
    const aes = gcm(dek, nonce, AAD);
    const plaintext = new TextEncoder().encode(JSON.stringify(container));
    const ciphertext = aes.encrypt(plaintext);

    return {
      capsula_cifrada: bytesToHex(ciphertext),
      nonce: bytesToHex(nonce),
      accesos: []
    };
  }
  static decrypt(ciphertextHex: string, nonceHex: string, dek: Uint8Array, AAD:Uint8Array): RecetaContainer {
    if(nonceHex.length !== 24) throw new Error('Nonce debe ser de 12 bytes (24 hex)');
    if(dek.length !== 32) throw new Error('DEK debe ser de 32 bytes');
    const aes = gcm(dek, hexToBytes(nonceHex), AAD);
    const plaintextBytes = aes.decrypt(hexToBytes(ciphertextHex));
    return JSON.parse(new TextDecoder().decode(plaintextBytes)) as RecetaContainer;
  }

}