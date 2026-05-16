// frontend/test/crypto/hmac.test.ts
import { describe, it, expect } from 'vitest';
import { HmacModule } from '../../src/crypto/hmac';

const SECRET = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';

describe('HmacModule', () => {

  describe('generateSeal', () => {
    it('genera un sello HMAC-SHA256 en formato hexadecimal (64 caracteres)', () => {
      const seal = HmacModule.generateSeal('REC-001-2026-01-01', SECRET);
      expect(seal).toMatch(/^[0-9a-f]{64}$/);
    });

    it('es determinista: mismos datos de entrada generan el mismo sello', () => {
      const s1 = HmacModule.generateSeal('REC-001-2026-01-01', SECRET);
      const s2 = HmacModule.generateSeal('REC-001-2026-01-01', SECRET);
      expect(s1).toBe(s2);
    });

    it('el sello cambia completamente si el mensaje cambia', () => {
      const s1 = HmacModule.generateSeal('REC-001-2026-01-01', SECRET);
      const s2 = HmacModule.generateSeal('REC-002-2026-01-01', SECRET);
      expect(s1).not.toBe(s2);
    });

    it('el sello cambia completamente si la llave secreta cambia', () => {
      const otherSecret = 'ff'.repeat(32);
      const s1 = HmacModule.generateSeal('REC-001-2026-01-01', SECRET);
      const s2 = HmacModule.generateSeal('REC-001-2026-01-01', otherSecret);
      expect(s1).not.toBe(s2);
    });
  });

  describe('verifySeal', () => {
    it('acepta como válido un sello generado correctamente', () => {
      const seal = HmacModule.generateSeal('REC-001-2026-01-01', SECRET);
      expect(HmacModule.verifySeal('REC-001-2026-01-01', seal, SECRET)).toBe(true);
    });

    it('rechaza el sello si el mensaje (ej. fecha o ID) fue alterado', () => {
      const seal = HmacModule.generateSeal('REC-001-2026-01-01', SECRET);
      expect(HmacModule.verifySeal('REC-001-ALTERADO', seal, SECRET)).toBe(false);
    });

    it('rechaza la verificación si el sello criptográfico fue alterado directamente', () => {
      const seal = HmacModule.generateSeal('REC-001-2026-01-01', SECRET);
      const altered = seal.slice(0, -2) + 'ff';
      expect(HmacModule.verifySeal('REC-001-2026-01-01', altered, SECRET)).toBe(false);
    });

    it('rechaza la verificación si la farmacia usa la llave incorrecta', () => {
      const seal = HmacModule.generateSeal('REC-001-2026-01-01', SECRET);
      const wrongKey = 'ff'.repeat(32);
      expect(HmacModule.verifySeal('REC-001-2026-01-01', seal, wrongKey)).toBe(false);
    });

    it('rechaza rápidamente por longitud inválida (Previene ataques de timing)', () => {
      const shortSeal = 'a1b2c3d4'; // Sello demasiado corto
      expect(HmacModule.verifySeal('REC-001-2026-01-01', shortSeal, SECRET)).toBe(false);
    });
  });
});