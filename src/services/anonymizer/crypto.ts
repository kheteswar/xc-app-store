/**
 * WebCrypto helpers for the auto-redaction layer.
 *
 * Design:
 *   - Key derivation: PBKDF2-SHA256(secret, fixed_salt, 100k) → 256-bit AES key.
 *   - Encryption: AES-CBC with a zero IV. This is deterministic — the same
 *     plaintext always produces the same ciphertext under the same key, which
 *     is exactly what we want so a single value (e.g. the same IP) gets the
 *     same placeholder everywhere in the document.
 *   - Determinism is not a flaw here: the threat model is "an adversary holds
 *     the anonymized document but does NOT have the secret." They cannot
 *     decrypt at all. Repeat-detection across rows is fine — Claude needs
 *     placeholder consistency to reason about the doc.
 *   - PKCS#7 padding is handled by WebCrypto.
 *   - Encoding: base32 (RFC 4648, no padding). Uppercase A–Z + 2–7. Avoids
 *     the `=`/`+`/`/` characters that would interact badly with regex
 *     placeholder detection.
 */

const SALT = new TextEncoder().encode('xc-anonymizer-v1');
const ZERO_IV = new Uint8Array(16);
const PBKDF2_ITERATIONS = 100_000;

export async function deriveKey(secret: string): Promise<CryptoKey> {
  if (!secret) throw new Error('Secret is empty');
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: SALT,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function encryptBytes(
  plaintext: Uint8Array,
  key: CryptoKey,
): Promise<Uint8Array> {
  const buf = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: ZERO_IV as BufferSource },
    key,
    plaintext as BufferSource,
  );
  return new Uint8Array(buf);
}

export async function decryptBytes(
  ciphertext: Uint8Array,
  key: CryptoKey,
): Promise<Uint8Array> {
  const buf = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: ZERO_IV as BufferSource },
    key,
    ciphertext as BufferSource,
  );
  return new Uint8Array(buf);
}

// ─── Base32 (RFC 4648, no padding) ──────────────────────────────────────

const B32_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B32_REVERSE: Record<string, number> = {};
for (let i = 0; i < B32_ALPHA.length; i++) B32_REVERSE[B32_ALPHA[i]] = i;

export function base32Encode(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const b of bytes) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32_ALPHA[(buffer >> bits) & 0x1f];
    }
  }
  if (bits > 0) out += B32_ALPHA[(buffer << (5 - bits)) & 0x1f];
  return out;
}

export function base32Decode(str: string): Uint8Array {
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const c of str) {
    const v = B32_REVERSE[c.toUpperCase()];
    if (v === undefined) throw new Error(`Invalid base32 character: ${c}`);
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

// ─── Random secret generator ────────────────────────────────────────────

/**
 * Generate a 32-character random secret using crypto.getRandomValues.
 * Output is base32 of 20 random bytes — printable, copy/pasteable, and
 * has ~100 bits of entropy.
 */
export function generateSecret(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}
