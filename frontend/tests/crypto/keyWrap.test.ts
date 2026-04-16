import { describe, it, expect } from 'vitest';
import { KeyWrapModule } from '../../src/crypto/keyWrap';
import { SignatureModule } from '../../src/crypto/signature';
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js';

const ALICE_PRIV = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
const BOB_PRIV   = 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3';
const ALICE_PUB  = SignatureModule.getPublicKey(ALICE_PRIV);
const BOB_PUB    = SignatureModule.getPublicKey(BOB_PRIV);

describe('KeyWrapModule', () => {
  const dek = randomBytes(32);

  describe('wrap', () => {
    it('retorna wrappedKey y nonce en hex', () => {
      const result = KeyWrapModule.wrap(dek, ALICE_PRIV, BOB_PUB);
      expect(result).toHaveProperty('wrappedKey');
      expect(result).toHaveProperty('nonce');
      expect(result.wrappedKey).toMatch(/^[0-9a-f]+$/);
      expect(result.nonce).toMatch(/^[0-9a-f]{24}$/); // 12 bytes
    });

    it('genera nonce diferente en cada wrap', () => {
      const r1 = KeyWrapModule.wrap(dek, ALICE_PRIV, BOB_PUB);
      const r2 = KeyWrapModule.wrap(dek, ALICE_PRIV, BOB_PUB);
      expect(r1.nonce).not.toBe(r2.nonce);
    });
  });

  describe('wrap + unwrap (ECDH roundtrip)', () => {
    it('Alice wraps para Bob, Bob unwraps correctamente', () => {
      const { wrappedKey, nonce } = KeyWrapModule.wrap(dek, ALICE_PRIV, BOB_PUB);
      const recovered = KeyWrapModule.unwrap(wrappedKey, nonce, BOB_PRIV, ALICE_PUB);
      expect(bytesToHex(recovered)).toBe(bytesToHex(dek));
    });

    it('Bob wraps para Alice, Alice unwraps correctamente', () => {
      const { wrappedKey, nonce } = KeyWrapModule.wrap(dek, BOB_PRIV, ALICE_PUB);
      const recovered = KeyWrapModule.unwrap(wrappedKey, nonce, ALICE_PRIV, BOB_PUB);
      expect(bytesToHex(recovered)).toBe(bytesToHex(dek));
    });

    it('falla si unwrap usa la clave privada incorrecta', () => {
      const EVE_PRIV = 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4';
      const { wrappedKey, nonce } = KeyWrapModule.wrap(dek, ALICE_PRIV, BOB_PUB);
      expect(() => KeyWrapModule.unwrap(wrappedKey, nonce, EVE_PRIV, ALICE_PUB)).toThrow();
    });

    it('falla si la wrappedKey fue alterada', () => {
      const { wrappedKey, nonce } = KeyWrapModule.wrap(dek, ALICE_PRIV, BOB_PUB);
      const altered = wrappedKey.slice(0, -2) + 'ff';
      expect(() => KeyWrapModule.unwrap(altered, nonce, BOB_PRIV, ALICE_PUB)).toThrow();
    });

    it('falla si el nonce fue alterado', () => {
      const { wrappedKey } = KeyWrapModule.wrap(dek, ALICE_PRIV, BOB_PUB);
      const wrongNonce = 'bb'.repeat(12);
      expect(() => KeyWrapModule.unwrap(wrappedKey, wrongNonce, BOB_PRIV, ALICE_PUB)).toThrow();
    });
  });
});
