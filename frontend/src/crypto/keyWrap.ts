import { aeskw } from '@noble/ciphers/aes.js';
import { appCurve, appHash } from './config.ts';
import { hexToBytes, bytesToHex, randomBytes} from '@noble/hashes/utils.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import type {KeyWrapResult} from './interfaces.ts';

export class KeyWrapModule {

    static wrap(rol: 'paciente' | 'farmaceutico' | 'doctor',dek: Uint8Array, recipientPublicKeyHex: string, contextInfo: Uint8Array): KeyWrapResult {
    // Generamos una llave efímera para este envoltorio
    const ephemeralPriv = randomBytes(32);
    const ephemeralPubHex = bytesToHex(appCurve.getPublicKey(ephemeralPriv, false));

    // Derivamos un KEK usando ECDH + HKDF con la llave efímera y la llave pública del destinatario
    const sharedSecret = appCurve.getSharedSecret(ephemeralPriv, hexToBytes(recipientPublicKeyHex));
    const kek = hkdf(appHash, sharedSecret, new Uint8Array(), contextInfo, 32);
    
    // Envolvemos el DEK usando AES-KW con el KEK derivado
    const kwInstance = aeskw(kek);
    return {
      rol: rol,
      wrappedKey: bytesToHex(kwInstance.encrypt(dek)),
      ephemeral_pub_hex: ephemeralPubHex
    };
  }

  static unwrap(wrappedKeyHex: string,  myPrivHex: string, theirPubHex: string,contextInfo: Uint8Array): Uint8Array 
  {
    const sharedSecret = appCurve.getSharedSecret(hexToBytes(myPrivHex), hexToBytes(theirPubHex));
    const kek = hkdf(appHash, sharedSecret, new Uint8Array(), contextInfo, 32);
    const kwInstance = aeskw(kek);
    return kwInstance.decrypt(hexToBytes(wrappedKeyHex));
  }
}