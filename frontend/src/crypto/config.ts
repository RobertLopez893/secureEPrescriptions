// frontend/src/crypto/config.ts
import { sha3_256 } from '@noble/hashes/sha3.js';
import { p256 } from '@noble/curves/nist.js';

export const appHash = sha3_256;
export const appCurve = p256;

export const CRYPTO_VERSION = {
    hash: "SHA3-256",
    curve: "P-256",
    cipher: "AES-GCM-256",
    kdf: "HKDF",
    kw: "AES-KW-256"
};

export const CRYPTO_SIZES = {
    privateKeyBytes: 32,
    dekBytes: 32,
    gcmNonceBytes: 12
};