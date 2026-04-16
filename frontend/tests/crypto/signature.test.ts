import { describe, it, expect } from 'vitest';
import { SignatureModule } from '../../src/crypto/signature';
import type { DatosMedicos } from '../../src/crypto/interfaces';

// Clave privada de prueba (32 bytes hex = 64 caracteres)
const PRIV_KEY = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';

function makeDatos(overrides: Partial<DatosMedicos> = {}): DatosMedicos {
  return {
    id_receta: 'REC-001',
    id_medico: 'DOC-001',
    id_paciente: 'PAT-001',
    fecha_emision: '2026-01-01T00:00:00.000Z',
    fecha_vencimiento: '2026-01-08T00:00:00.000Z',
    medicamentos: [{ nombre: 'Ibuprofeno', forma: 'Tableta', dosis: '400mg', frecuencia: '8h', duracion: '3 días' }],
    ...overrides,
  };
}

describe('SignatureModule', () => {

  describe('getPublicKey', () => {
    it('deriva una clave pública válida desde una privada', () => {
      const pub = SignatureModule.getPublicKey(PRIV_KEY);
      // P-256 compressed: 02|03 + 32 bytes X = 66 hex chars
      expect(pub).toMatch(/^(02|03)[0-9a-f]{64}$/);
    });

    it('la misma privada siempre produce la misma pública', () => {
      const pub1 = SignatureModule.getPublicKey(PRIV_KEY);
      const pub2 = SignatureModule.getPublicKey(PRIV_KEY);
      expect(pub1).toBe(pub2);
    });

    it('claves privadas distintas producen públicas distintas', () => {
      const otherKey = 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3';
      expect(SignatureModule.getPublicKey(PRIV_KEY)).not.toBe(SignatureModule.getPublicKey(otherKey));
    });
  });

  describe('canonicalize', () => {
    it('ordena las llaves alfabéticamente', () => {
      const result = SignatureModule.canonicalize({ z: 1, a: 2 });
      expect(result).toBe('{"a":2,"z":1}');
    });

    it('ordena recursivamente objetos anidados', () => {
      const result = SignatureModule.canonicalize({ b: { d: 1, c: 2 }, a: 3 });
      expect(result).toBe('{"a":3,"b":{"c":2,"d":1}}');
    });

    it('preserva arrays sin reordenar elementos', () => {
      const result = SignatureModule.canonicalize({ items: [3, 1, 2] });
      expect(result).toBe('{"items":[3,1,2]}');
    });

    it('es determinista: mismo input, mismo output', () => {
      const obj = { b: 1, a: [{ d: 2, c: 3 }] };
      expect(SignatureModule.canonicalize(obj)).toBe(SignatureModule.canonicalize(obj));
    });

    it('maneja valores null y primitivos', () => {
      expect(SignatureModule.canonicalize(null)).toBe('null');
      expect(SignatureModule.canonicalize('hello')).toBe('"hello"');
      expect(SignatureModule.canonicalize(42)).toBe('42');
    });
  });

  describe('sign + verify', () => {
    const datos = makeDatos();
    const pubKey = SignatureModule.getPublicKey(PRIV_KEY);

    it('firma y verifica correctamente datos médicos', () => {
      const firma = SignatureModule.sign(datos, PRIV_KEY);
      expect(firma).toBeTruthy();
      expect(typeof firma).toBe('string');

      const valido = SignatureModule.verify(datos, firma, pubKey);
      expect(valido).toBe(true);
    });

    it('la firma es diferente para datos diferentes', () => {
      const firma1 = SignatureModule.sign(datos, PRIV_KEY);
      const firma2 = SignatureModule.sign(makeDatos({ id_receta: 'REC-999' }), PRIV_KEY);
      expect(firma1).not.toBe(firma2);
    });

    it('rechaza si los datos fueron alterados post-firma', () => {
      const firma = SignatureModule.sign(datos, PRIV_KEY);
      const datosAlterados = makeDatos({ id_paciente: 'PAT-HACKER' });
      expect(SignatureModule.verify(datosAlterados, firma, pubKey)).toBe(false);
    });

    it('rechaza si la firma fue alterada', () => {
      const firma = SignatureModule.sign(datos, PRIV_KEY);
      const firmaAlterada = firma.slice(0, -2) + 'ff';
      expect(SignatureModule.verify(datos, firmaAlterada, pubKey)).toBe(false);
    });

    it('rechaza si se verifica con la clave pública incorrecta', () => {
      const firma = SignatureModule.sign(datos, PRIV_KEY);
      const otraPriv = 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3';
      const otraPub = SignatureModule.getPublicKey(otraPriv);
      expect(SignatureModule.verify(datos, firma, otraPub)).toBe(false);
    });

    it('no explota con firma basura, retorna false', () => {
      expect(SignatureModule.verify(datos, 'basura_total', pubKey)).toBe(false);
      expect(SignatureModule.verify(datos, '', pubKey)).toBe(false);
    });
  });
});
