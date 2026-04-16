
// RUTAS CORREGIDAS PARA ASTRO/VITE:
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

import type { DatosMedicos } from './interfaces';

export class SignatureModule {
    
    /**
     * 1. CANONIZACIÓN ESTRICTA
     * Ordena recursivamente las llaves del objeto alfabéticamente.
     * Garantiza que el Hash siempre sea idéntico en el Frontend del Médico y la Farmacia.
     */
    static canonicalize(obj: any): string {
        if (typeof obj !== 'object' || obj === null) {
            return JSON.stringify(obj);
        }
        if (Array.isArray(obj)) {
            return '[' + obj.map(SignatureModule.canonicalize).join(',') + ']';
        }
        
        // Ordenar las llaves alfabéticamente
        const sortedKeys = Object.keys(obj).sort();
        const result = sortedKeys.map(key => {
            return JSON.stringify(key) + ':' + SignatureModule.canonicalize(obj[key]);
        });
        
        return '{' + result.join(',') + '}';
    }

    /**
     * 2. GENERACIÓN DEL HASH INMUTABLE
     * Aplica SHA-256 a los datos médicos canonizados.
     */
    static hashData(datos: DatosMedicos): Uint8Array {
        const jsonString = this.canonicalize(datos);
        return sha256(utf8ToBytes(jsonString));
    }

    /**
     * 3. FIRMA DIGITAL (EMISIÓN)
     * Toma los datos médicos y la llave privada del doctor (en formato Hex)
     * y retorna una firma criptográfica irrepudiable.
     */

    
    static sign(datos: DatosMedicos, privateKeyHex: string): string {
        const hash = this.hashData(datos);
        const signature = p256.sign(hash, hexToBytes(privateKeyHex));
        return (signature as any).toHex();
    }

    /**
     * 4. VERIFICACIÓN (DISPENSACIÓN)
     * La farmacia o el paciente usan este método para asegurar que
     * la receta no fue alterada y realmente pertenece al doctor.
     */
    static verify(datos: DatosMedicos, signatureHex: string, publicKeyDoctorHex: string): boolean {
        try {
            const hash = this.hashData(datos);
            return p256.verify(hexToBytes(signatureHex), hash, hexToBytes(publicKeyDoctorHex));
        } catch (error) {
            // Si la firma está mal formateada o hay un error matemático, es falsa.
            return false; 
        }
    }
}