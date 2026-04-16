/**
 * src/crypto/seedDerivation.ts
 * Derivación determinista de llave P-256 desde semilla (QR de tarjeta digital)
 *
 * Flujo:
 *   Tarjeta digital → QR → Semilla (32 bytes) → HKDF-SHA256 → Escalar P-256
 *
 * La llave privada NUNCA se persiste — se deriva en memoria cada vez que
 * el paciente escanea su tarjeta. Inspirado en el modelo seed de wallets HD.
 */
import { hkdf }        from '@noble/hashes/hkdf.js';
import { sha256 }      from '@noble/hashes/sha2.js';
import { p256 }        from '@noble/curves/nist.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';

// ── Constantes de dominio (domain separation) ──────────────────────────────
// Cambiarlas invalida todas las llaves derivadas; versionar con cuidado.
const RXPRO_INFO = new TextEncoder().encode('rxpro-v1:p256:patient-identity-key');
const RXPRO_SALT = new TextEncoder().encode('rxpro-2026:cardkey-salt:v1');

// ── Formato del payload QR ─────────────────────────────────────────────────
const QR_PREFIX = 'rxpro://card/v1/';

/** Semilla válida: 64 caracteres hex (= 32 bytes) */
const SEED_REGEX = /^[0-9a-f]{64}$/i;

// ── Tipos ──────────────────────────────────────────────────────────────────
export interface DerivedKeys {
  /** Llave privada P-256 como hex (64 chars). Solo existe en memoria. */
  privateKeyHex: string;
  /** Llave pública P-256 sin comprimir (130 chars hex, prefijo 04). */
  publicKeyHex: string;
  /** Llave pública P-256 comprimida (66 chars hex, prefijo 02/03). */
  publicKeyCompressedHex: string;
}

// ── API pública ────────────────────────────────────────────────────────────

/**
 * Deriva las llaves P-256 de una semilla hex de 32 bytes.
 * Entrada: seedHex obtenida al decodificar el QR de la tarjeta digital.
 *
 * @throws {Error} Si la semilla no tiene el formato esperado.
 */
export function deriveKeysFromSeed(seedHex: string): DerivedKeys {
  if (!SEED_REGEX.test(seedHex)) {
    throw new Error('Semilla inválida: se esperan 64 caracteres hexadecimales.');
  }

  const seedBytes = hexToBytes(seedHex);

  // HKDF-SHA256 → 32 bytes de material de clave
  const keyMaterial = hkdf(sha256, seedBytes, RXPRO_SALT, RXPRO_INFO, 32);

  // Normalizar al escalar del grupo P-256 (mod n, nunca cero)
  const scalar = p256.utils.normPrivateKeyToScalar(keyMaterial);
  const privateKeyHex = scalar.toString(16).padStart(64, '0');

  // Derivar llave pública en ambos formatos
  const pubCompressed   = p256.getPublicKey(scalar, true);
  const pubUncompressed = p256.getPublicKey(scalar, false);

  return {
    privateKeyHex,
    publicKeyHex:           bytesToHex(pubUncompressed),
    publicKeyCompressedHex: bytesToHex(pubCompressed),
  };
}

/**
 * Genera una semilla aleatoria de 32 bytes para emitir una nueva tarjeta digital.
 * Llamar UNA sola vez por paciente; la semilla es su identidad criptográfica.
 */
export function generateCardSeed(): string {
  return bytesToHex(randomBytes(32));
}

/**
 * Codifica la semilla en el formato que se incrusta en el QR de la tarjeta.
 * Formato: rxpro://card/v1/<seedHex64>
 */
export function encodeSeedAsQrPayload(seedHex: string): string {
  if (!SEED_REGEX.test(seedHex)) {
    throw new Error('Semilla inválida al codificar QR.');
  }
  return `${QR_PREFIX}${seedHex.toLowerCase()}`;
}

/**
 * Decodifica el payload leído del QR y extrae la semilla.
 * Devuelve `null` si el payload no tiene el formato esperado.
 */
export function decodeSeedFromQrPayload(payload: string): string | null {
  if (!payload.startsWith(QR_PREFIX)) return null;
  const seed = payload.slice(QR_PREFIX.length);
  if (!SEED_REGEX.test(seed)) return null;
  return seed.toLowerCase();
}
