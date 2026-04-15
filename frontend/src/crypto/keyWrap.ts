import { p256 } from '@noble/curves/nist.js';
import { gcm } from '@noble/ciphers/aes.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes, bytesToHex, randomBytes } from '@noble/hashes/utils.js';

export class KeyWrapModule {
  static wrap(dek: Uint8Array, senderPrivateKeyHex: string, recipientPublicKeyHex: string) {
    const sharedSecret = p256.getSharedSecret(hexToBytes(senderPrivateKeyHex), hexToBytes(recipientPublicKeyHex));
    const kek = sha256(sharedSecret);

    const nonce = randomBytes(12);
    const aes = gcm(kek, nonce);
    return {
      wrappedKey: bytesToHex(aes.encrypt(dek)),
      nonce: bytesToHex(nonce)
    };
  }
  static unwrap(wrappedKeyHex: string, nonceHex: string, myPrivHex: string, theirPubHex: string): Uint8Array {
    const sharedSecret = p256.getSharedSecret(hexToBytes(myPrivHex), hexToBytes(theirPubHex));
    const kek = sha256(sharedSecret);
    const aes = gcm(kek, hexToBytes(nonceHex));
    return aes.decrypt(hexToBytes(wrappedKeyHex));
  }
}