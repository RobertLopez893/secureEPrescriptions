import { aeskw } from '@noble/ciphers/aes.js';
import { appCurve, appHash, CRYPTO_SIZES, CRYPTO_VERSION } from './config.ts';
import { hexToBytes, bytesToHex, randomBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { hkdf } from '@noble/hashes/hkdf.js';

export class KeyWrapModule {
  /**
   * Envuelve (cifra) una llave simétrica (DEK) para un destinatario específico.
   * Utiliza llaves efímeras para garantizar el Secreto Hacia Adelante (Forward Secrecy).
   * @param dek - La Llave de Encriptación de Datos (Data Encryption Key) de 32 bytes a proteger.
   * @param recipientPublicKeyHex - La llave pública estática del destinatario en formato Hex.
   * @param contextInfo - Información de contexto para amarrar la derivación ( ID de receta | ID de usuario).
   * @returns Un objeto con la llave envuelta y la llave pública efímera necesaria para desenvolverla.
   */


  static wrap(dek: Uint8Array, recipientPublicKeyHex: string,contextInfo: string): { wrappedKey: string; ephemeralPubHex: string } {
    // Generamos una llave efímera para este envoltorio
    const ephemeralPriv = randomBytes(32);
    const ephemeralPubHex = bytesToHex(appCurve.getPublicKey(ephemeralPriv));

    // Derivamos un KEK usando ECDH + HKDF con la llave efímera y la llave pública del destinatario
    const sharedSecret = appCurve.getSharedSecret(ephemeralPriv, hexToBytes(recipientPublicKeyHex));
    const contextInfoBytes = concatBytes( utf8ToBytes(CRYPTO_VERSION.kw),utf8ToBytes(contextInfo)) ;
    const kek = hkdf(appHash, sharedSecret, new Uint8Array(), contextInfoBytes, 32);
    
    // Envolvemos el DEK usando AES-KW con el KEK derivado
    const kwInstance = aeskw(kek);
    return {
      wrappedKey: bytesToHex(kwInstance.encrypt(dek)),
      ephemeralPubHex: ephemeralPubHex
    };
  }

  /**
   * Desenvuelve (descifra) una llave simétrica (DEK) previamente envuelta.
   * @param wrappedKeyHex - La llave envuelta (cifrada) en formato Hex.
   * @param myPrivHex - La llave privada estática del destinatario que está intentando leer.
   * @param theirPubHex - La llave pública efímera del emisor (adjunta en el JSON de la receta).
   * @returns La llave simétrica original (DEK) lista para usarse.
   */

  static unwrap(wrappedKeyHex: string,  myPrivHex: string, theirPubHex: string,contextInfo: string): Uint8Array 
  {
    const sharedSecret = appCurve.getSharedSecret(hexToBytes(myPrivHex), hexToBytes(theirPubHex));
    const contextInfoBytes = concatBytes( utf8ToBytes(CRYPTO_VERSION.kw),utf8ToBytes(contextInfo )) ;
    const kek = hkdf(appHash, sharedSecret, new Uint8Array(), contextInfoBytes, 32);
    const kwInstance = aeskw(kek);
    return kwInstance.decrypt(hexToBytes(wrappedKeyHex));
  }
}