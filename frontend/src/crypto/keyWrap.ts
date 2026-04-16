/**
 * src/crypto/keyWrap.ts
 * Módulo de Envolvimiento de Claves (Key Wrapping) usando ECDH
 */
import { p256 } from '@noble/curves/nist.js';
import { gcm } from '@noble/ciphers/aes.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes, bytesToHex, randomBytes } from '@noble/hashes/utils.js';

export class KeyWrapModule {
  /**
   * Envuelve la DEK para un receptor específico usando su llave pública.
   */
  static wrap(dek: Uint8Array, senderPrivateKeyHex: string, recipientPublicKeyHex: string) {
    // 1. Derivación de secreto compartido (ECDH)
    const sharedSecret = p256.getSharedSecret(hexToBytes(senderPrivateKeyHex), hexToBytes(recipientPublicKeyHex));
    const encryptionKey = sha256(sharedSecret).slice(0, 32); // KEK (Key Encryption Key)

    // 2. Cifrar la DEK con la KEK usando un Nonce dedicado
    const nonce = randomBytes(12);
    const aes = gcm(encryptionKey, nonce);
    const wrapped = aes.encrypt(dek);

    return {
      wrappedKey: bytesToHex(wrapped),
      nonce: bytesToHex(nonce)
    }
    
  }
  static async unwrap(wrappedKeyHex: string, nonceHex: string, myPrivHex: string, theirPubHex: string): Promise<Uint8Array> {
    const sharedSecret = p256.getSharedSecret(hexToBytes(myPrivHex), hexToBytes(theirPubHex));
    const kek = sha256(sharedSecret).slice(0, 32);
    
    const aes = gcm(kek, hexToBytes(nonceHex));
    return aes.decrypt(hexToBytes(wrappedKeyHex));
  }
}