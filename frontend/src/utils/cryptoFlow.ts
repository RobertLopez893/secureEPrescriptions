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

// ── ENVELOPE: firma ECDSA verificada por el backend ────────────────────
// El "envelope" son los metadatos + la cápsula opaca que el servidor puede
// ver. El médico lo firma con su llave privada para probar autoría sin
// revelar el contenido cifrado. El backend verifica esta firma usando la
// llave pública registrada del médico.
//
// Formato canónico (coincide 1:1 con backend _envelope_message):
//   "<id_medico>\n<id_paciente>\n<capsula_cifrada>\n<iv_aes_gcm>\n<expira_unix>"
// donde expira_unix son segundos enteros UTC desde epoch.
export interface EnvelopeFields {
  id_medico: number;
  id_paciente: number;
  capsula_cifrada: string;
  iv_aes_gcm: string;
  expira_iso: string; // ISO 8601, se convierte internamente a unix seconds
}

export function envelopeMessage(fields: EnvelopeFields): string {
  const expiraUnix = Math.floor(new Date(fields.expira_iso).getTime() / 1000);
  return [
    String(fields.id_medico),
    String(fields.id_paciente),
    fields.capsula_cifrada,
    fields.iv_aes_gcm,
    String(expiraUnix),
  ].join('\n');
}

/**
 * Firma el envelope con ECDSA P-256 y devuelve la firma compacta r||s en hex
 * (128 chars) — el formato que el backend espera en RecetaCreate.firma_envelope.
 */
export function signEnvelope(fields: EnvelopeFields, privateKeyHex: string): string {
  const msg = envelopeMessage(fields);
  const hash = sha256(utf8ToBytes(msg));
  const sig: any = p256.sign(hash, hexToBytes(privateKeyHex));
  // noble/curves: .toCompactRawBytes() → 64 bytes r||s
  const compact: Uint8Array = typeof sig?.toCompactRawBytes === 'function'
    ? sig.toCompactRawBytes()
    : (sig instanceof Uint8Array ? sig : new Uint8Array(sig));
  return bytesToHex(compact);
}