import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { DatosMedicos } from './interfaces';

export class SignatureModule {
    
    static getPublicKey(privateKeyHex: string): string {
        return bytesToHex(p256.getPublicKey(hexToBytes(privateKeyHex)));
    }
    
    static canonicalize(obj: any): string {
        if (typeof obj !== 'object' || obj === null) return JSON.stringify(obj);
        if (Array.isArray(obj)) return '[' + obj.map(SignatureModule.canonicalize).join(',') + ']';
        const sortedKeys = Object.keys(obj).sort();
        const result = sortedKeys.map(key => 
            JSON.stringify(key) + ':' + SignatureModule.canonicalize(obj[key])
        );
        return '{' + result.join(',') + '}';
    }

    static hashData(datos: DatosMedicos): Uint8Array {
        return sha256(utf8ToBytes(this.canonicalize(datos)));
    }

    static sign(datos: DatosMedicos, privateKeyHex: string): string {
        const hash = this.hashData(datos);
        return bytesToHex(p256.sign(hash, hexToBytes(privateKeyHex)))
    }

    static verify(datos: DatosMedicos, signatureHex: string, publicKeyDoctorHex: string): boolean {
        try {
            const hash = this.hashData(datos);
            return p256.verify(hexToBytes(signatureHex), hash, hexToBytes(publicKeyDoctorHex));
        } catch {
            return false; 
        }
    }
}