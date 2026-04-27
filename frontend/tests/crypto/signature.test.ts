// frontend/test/crypto/signature.test.ts
import { describe, it, expect } from 'vitest';
import { SignatureModule } from '../../src/crypto/signature';
import { p256 } from '@noble/curves/nist.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { DatosMedicos } from '../../src/crypto/interfaces';

// Helper para generar llave pública
function getPublicKeyHex(privKeyHex: string): string {
  return bytesToHex(p256.getPublicKey(hexToBytes(privKeyHex), false));
}

const PRIV_KEY = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
const PUB_KEY  = getPublicKeyHex(PRIV_KEY);

function makeDatos(overrides: Partial<DatosMedicos> = {}): DatosMedicos {
  return {
    id_receta: 'REC-001',
    id_medico: 'DOC-001',
    id_paciente: 'PAT-001',
    id_farmaceutico: 'FARM-001',
    fecha_emision: '2026-01-01T00:00:00.000Z',
    fecha_vencimiento: '2026-01-08T00:00:00.000Z',
    medicamentos: [{ nombre: 'Ibuprofeno', forma: 'Tableta', dosis: '400mg', frecuencia: '8h', duracion: '3 días' }],
    ...overrides,
  };
}

describe('SignatureModule', () => {

  describe('canonicalize', () => {
    it('ordena las propiedades alfabéticamente (Mitiga ataques de reordenamiento)', () => {
      const result = SignatureModule.canonicalize({ z: 1, a: 2 });
      expect(result).toBe('{"a":2,"z":1}');
    });

    it('ordena recursivamente objetos anidados en varios niveles', () => {
      const result = SignatureModule.canonicalize({ b: { d: 1, c: 2 }, a: 3 });
      expect(result).toBe('{"a":3,"b":{"c":2,"d":1}}');
    });

    it('preserva los arrays estandarizados sin reordenar sus elementos internos', () => {
      const result = SignatureModule.canonicalize({ items: [3, 1, 2] });
      expect(result).toBe('{"items":[3,1,2]}');
    });

    it('es un proceso 100% determinista: mismo input en distinto orden produce mismo output', () => {
      const obj1 = { a: 1, b: 2 };
      const obj2 = { b: 2, a: 1 };
      expect(SignatureModule.canonicalize(obj1)).toBe(SignatureModule.canonicalize(obj2));
    });

    it('maneja de forma segura valores nulos y tipos primitivos', () => {
      expect(SignatureModule.canonicalize(null)).toBe('null');
      expect(SignatureModule.canonicalize('hello')).toBe('"hello"');
      expect(SignatureModule.canonicalize(42)).toBe('42');
    });
  });

  describe('sign + verify', () => {
    const datos = makeDatos();

    it('firma y verifica exitosamente la autenticidad de los datos médicos', () => {
      const firma = SignatureModule.sign(datos, PRIV_KEY);
      expect(firma).toBeTruthy();
      expect(typeof firma).toBe('string');

      const valido = SignatureModule.verify(datos, firma, PUB_KEY);
      expect(valido).toBe(true);
    });

    it('la firma criptográfica ECDSA es distinta para datos diferentes', () => {
      const firma1 = SignatureModule.sign(datos, PRIV_KEY);
      const firma2 = SignatureModule.sign(makeDatos({ id_receta: 'REC-999' }), PRIV_KEY);
      expect(firma1).not.toBe(firma2);
    });

    it('rechaza la firma si los datos de la receta fueron alterados (Ej. Modificar paciente)', () => {
      const firma = SignatureModule.sign(datos, PRIV_KEY);
      const datosAlterados = makeDatos({ id_paciente: 'PAT-HACKER' });
      expect(SignatureModule.verify(datosAlterados, firma, PUB_KEY)).toBe(false);
    });

    it('rechaza si la cadena hexadecimal de la firma fue interceptada y alterada', () => {
      const firma = SignatureModule.sign(datos, PRIV_KEY);
      const firmaAlterada = firma.slice(0, -2) + 'ff';
      expect(SignatureModule.verify(datos, firmaAlterada, PUB_KEY)).toBe(false);
    });

    it('rechaza si un doctor intenta verificar con la llave pública de OTRO doctor', () => {
      const firma = SignatureModule.sign(datos, PRIV_KEY);
      const otraPriv = 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3';
      const otraPub = getPublicKeyHex(otraPriv);
      expect(SignatureModule.verify(datos, firma, otraPub)).toBe(false);
    });

    it('devuelve false de forma segura si la firma no tiene formato válido', () => {
      expect(SignatureModule.verify(datos, 'texto_aleatorio_no_hexadecimal', PUB_KEY)).toBe(false);
      expect(SignatureModule.verify(datos, '', PUB_KEY)).toBe(false);
    });
  });
});