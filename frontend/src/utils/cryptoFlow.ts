// src/utils/cryptoFlow.ts
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { utf8ToBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

export function canonicalizeJSON(obj: any): string {
  const sortKeys = (o: any): any => {
    if (o === null || typeof o !== 'object') return o;
    if (Array.isArray(o)) return o.map(sortKeys);
    return Object.keys(o).sort().reduce((acc, key) => {
      acc[key] = sortKeys(o[key]);
      return acc;
    }, {} as any);
  };
  return JSON.stringify(sortKeys(obj));
}

export function signData(canonicalStr: string, privateKeyHex: string) {
  const msgHash = sha256(utf8ToBytes(canonicalStr));
  const signature = p256.sign(msgHash, hexToBytes(privateKeyHex));
  return (signature as any).toHex();
}

export function verifySignature(canonicalStr: string, signatureHex: string, publicKeyHex: string): boolean {
  try {
    const msgHash = sha256(utf8ToBytes(canonicalStr));
    return p256.verify(hexToBytes(signatureHex), msgHash, hexToBytes(publicKeyHex));
  } catch { return false; }
}

export function generateHMAC(canonicalStr: string, keyHex: string): string {
  const mac = hmac(sha256, hexToBytes(keyHex), utf8ToBytes(canonicalStr));
  return bytesToHex(mac);
}

export function verifyHMAC(canonicalStr: string, hmacToVerify: string, keyHex: string): boolean {
  try {
    const generated = generateHMAC(canonicalStr, keyHex);
    return generated === hmacToVerify;
  } catch { return false; }
}

export function getPublicKey(privateKeyHex: string): string {
  return bytesToHex(p256.getPublicKey(hexToBytes(privateKeyHex)));
}