// frontend/test/crypto/keyWrap.test.ts
import { describe, it, expect } from 'vitest';
import { KeyWrapModule } from '../../src/crypto/keyWrap';
import { p256 } from '@noble/curves/nist.js';
import { randomBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// Helper local para generar la llave pública
function getPublicKeyHex(privKeyHex: string): string {
  return bytesToHex(p256.getPublicKey(hexToBytes(privKeyHex), false));
}

const ALICE_PRIV = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
const BOB_PRIV   = 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3';
const ALICE_PUB  = getPublicKeyHex(ALICE_PRIV);
const BOB_PUB    = getPublicKeyHex(BOB_PRIV);

const CONTEXT_INFO = "REC-001-BOB_ID";

describe('KeyWrapModule', () => {
  const dek = randomBytes(32);

  describe('wrap', () => {
    it('retorna wrappedKey y ephemeralPubHex en formato hexadecimal', () => {
      const result = KeyWrapModule.wrap(dek, BOB_PUB, CONTEXT_INFO);
      expect(result).toHaveProperty('wrappedKey');
      expect(result).toHaveProperty('ephemeralPubHex');
      expect(result.wrappedKey).toMatch(/^[0-9a-f]+$/);
      expect(result.ephemeralPubHex).toMatch(/^[0-9a-f]+$/); 
    });

    it('genera una llave pública efímera diferente en cada iteración (Forward Secrecy)', () => {
      const r1 = KeyWrapModule.wrap(dek, BOB_PUB, CONTEXT_INFO);
      const r2 = KeyWrapModule.wrap(dek, BOB_PUB, CONTEXT_INFO);
      expect(r1.ephemeralPubHex).not.toBe(r2.ephemeralPubHex);
      expect(r1.wrappedKey).not.toBe(r2.wrappedKey);
    });
  });

  describe('wrap + unwrap (ECDH + HKDF + AES-KW Roundtrip)', () => {
    it('Alguien cifra la DEK para Bob, Bob descifra exitosamente con su llave privada', () => {
      const { wrappedKey, ephemeralPubHex } = KeyWrapModule.wrap(dek, BOB_PUB, CONTEXT_INFO);
      const recoveredDek = KeyWrapModule.unwrap(wrappedKey, BOB_PRIV, ephemeralPubHex, CONTEXT_INFO);
      expect(bytesToHex(recoveredDek)).toBe(bytesToHex(dek));
    });

    it('Falla si se intenta desenvolver con una llave privada incorrecta (Ej. atacante Eve)', () => {
      const EVE_PRIV = 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4';
      const { wrappedKey, ephemeralPubHex } = KeyWrapModule.wrap(dek, BOB_PUB, CONTEXT_INFO);
      expect(() => KeyWrapModule.unwrap(wrappedKey, EVE_PRIV, ephemeralPubHex, CONTEXT_INFO)).toThrow();
    });

    it('Falla si el contexto (ContextInfo) de HKDF no coincide', () => {
      const { wrappedKey, ephemeralPubHex } = KeyWrapModule.wrap(dek, BOB_PUB, CONTEXT_INFO);
      const WRONG_CONTEXT = "REC-001-ALICE_ID"; 
      expect(() => KeyWrapModule.unwrap(wrappedKey, BOB_PRIV, ephemeralPubHex, WRONG_CONTEXT)).toThrow();
    });

    it('Falla si la llave cifrada (wrappedKey) fue manipulada', () => {
      const { wrappedKey, ephemeralPubHex } = KeyWrapModule.wrap(dek, BOB_PUB, CONTEXT_INFO);
      const alteredWrap = wrappedKey.slice(0, -2) + 'ff';
      expect(() => KeyWrapModule.unwrap(alteredWrap, BOB_PRIV, ephemeralPubHex, CONTEXT_INFO)).toThrow();
    });

    it('Falla si la llave pública efímera del emisor fue alterada', () => {
      const { wrappedKey } = KeyWrapModule.wrap(dek, BOB_PUB, CONTEXT_INFO);
      const fakeEphemeral = ALICE_PUB; // Llave válida pero incorrecta para este intercambio
      expect(() => KeyWrapModule.unwrap(wrappedKey, BOB_PRIV, fakeEphemeral, CONTEXT_INFO)).toThrow();
    });
  });
});