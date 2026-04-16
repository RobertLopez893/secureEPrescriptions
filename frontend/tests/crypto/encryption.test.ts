import { describe, it, expect } from 'vitest';
import { EncryptionModule } from '../../src/crypto/encryption';
import { randomBytes } from '@noble/ciphers/utils.js';
import type { RecetaContainer } from '../../src/crypto/interfaces';

function makeContainer(): RecetaContainer {
  return {
    datos: {
      id_receta: 'REC-001',
      id_medico: 'DOC-001',
      id_paciente: 'PAT-001',
      fecha_emision: '2026-01-01T00:00:00.000Z',
      fecha_vencimiento: '2026-01-08T00:00:00.000Z',
      medicamentos: [{ nombre: 'Ibuprofeno', forma: 'Tableta', dosis: '400mg', frecuencia: '8h', duracion: '3 días' }],
    },
    firma_medico: 'abc123deadbeef',
  };
}

describe('EncryptionModule', () => {
  const dek = randomBytes(32);
  const container = makeContainer();

  describe('encrypt', () => {
    it('retorna capsula_cifrada e iv_aes_gcm en hex', () => {
      const result = EncryptionModule.encrypt(container, dek);
      expect(result).toHaveProperty('capsula_cifrada');
      expect(result).toHaveProperty('iv_aes_gcm');
      expect(result.capsula_cifrada).toMatch(/^[0-9a-f]+$/);
      expect(result.iv_aes_gcm).toMatch(/^[0-9a-f]{24}$/); // 12 bytes = 24 hex
    });

    it('genera IV diferente en cada llamada (nonce único)', () => {
      const r1 = EncryptionModule.encrypt(container, dek);
      const r2 = EncryptionModule.encrypt(container, dek);
      expect(r1.iv_aes_gcm).not.toBe(r2.iv_aes_gcm);
    });

    it('genera ciphertext diferente con IV diferente', () => {
      const r1 = EncryptionModule.encrypt(container, dek);
      const r2 = EncryptionModule.encrypt(container, dek);
      expect(r1.capsula_cifrada).not.toBe(r2.capsula_cifrada);
    });
  });

  describe('decrypt', () => {
    it('descifra correctamente lo que se cifró', () => {
      const { capsula_cifrada, iv_aes_gcm } = EncryptionModule.encrypt(container, dek);
      const result = EncryptionModule.decrypt(capsula_cifrada, iv_aes_gcm, dek);
      expect(result).toEqual(container);
    });

    it('preserva todos los campos anidados', () => {
      const containerConSello: RecetaContainer = {
        ...container,
        sellos: { id_clinica: 'FARM-001', fecha_surtido: '2026-01-02T00:00:00.000Z', hmac_sello: 'deadbeef' },
      };
      const { capsula_cifrada, iv_aes_gcm } = EncryptionModule.encrypt(containerConSello, dek);
      const result = EncryptionModule.decrypt(capsula_cifrada, iv_aes_gcm, dek);
      expect(result.sellos).toEqual(containerConSello.sellos);
    });

    it('falla si el ciphertext fue alterado (GCM auth tag)', () => {
      const { capsula_cifrada, iv_aes_gcm } = EncryptionModule.encrypt(container, dek);
      const altered = capsula_cifrada.slice(0, -2) + 'ff';
      expect(() => EncryptionModule.decrypt(altered, iv_aes_gcm, dek)).toThrow();
    });

    it('falla si el IV es incorrecto', () => {
      const { capsula_cifrada } = EncryptionModule.encrypt(container, dek);
      const wrongIv = 'aa'.repeat(12);
      expect(() => EncryptionModule.decrypt(capsula_cifrada, wrongIv, dek)).toThrow();
    });

    it('falla si la DEK es incorrecta', () => {
      const { capsula_cifrada, iv_aes_gcm } = EncryptionModule.encrypt(container, dek);
      const wrongDek = randomBytes(32);
      expect(() => EncryptionModule.decrypt(capsula_cifrada, iv_aes_gcm, wrongDek)).toThrow();
    });
  });
});
