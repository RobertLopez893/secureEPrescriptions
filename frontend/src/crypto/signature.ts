import { appCurve, appHash } from './config.ts';
import { utf8ToBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { DatosMedicos } from './interfaces';

export class SignatureModule {
    static canonicalize(obj: any): string {
        if (typeof obj !== 'object' || obj === null) return JSON.stringify(obj);
        if (Array.isArray(obj)) return '[' + obj.map(SignatureModule.canonicalize).join(',') + ']';
        const sortedKeys = Object.keys(obj).sort();
        const result = sortedKeys.map(key => 
            JSON.stringify(key) + ':' + SignatureModule.canonicalize(obj[key])
        );
        return '{' + result.join(',') + '}';
    }

    static sign(datos: DatosMedicos, privateKeyHex: string): string {
        const hash = appHash(utf8ToBytes(this.canonicalize(datos)));
        return bytesToHex(appCurve.sign(hash, hexToBytes(privateKeyHex)))
    }

    static verify(datos: DatosMedicos, signatureHex: string, publicKeyDoctorHex: string): boolean {
        try {
            const hash = appHash(utf8ToBytes(this.canonicalize(datos)));
            return appCurve.verify(hexToBytes(signatureHex), hash, hexToBytes(publicKeyDoctorHex));
        } catch {
            return false; 
        }
    }
}