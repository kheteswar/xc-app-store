/**
 * Auto-redaction rules for structured data where building a manual mapping
 * is tedious (IP addresses, UUIDs, …).
 *
 * Round-trip strategy: the original value is *encrypted into the placeholder
 * itself* — `1.2.3.4` → `<<IP:K7VFAB...>>` where the suffix is base32-encoded
 * AES-CBC ciphertext keyed off the user's secret. Deanonymize parses the
 * token, decrypts the ciphertext, and reconstructs the original. No
 * per-value mapping entries needed; only the secret needs to round-trip.
 *
 * Token format: `<<TYPE:BASE32>>` (double angle brackets). Distinct from
 * manual placeholders (`<NAME>`) so detection is unambiguous.
 */

import { base32Decode, base32Encode, decryptBytes, encryptBytes } from './crypto';
import type { AutoConfig, Direction } from './types';

interface AutoRule {
  /** Identifier used in the placeholder token (e.g. "IP"). */
  name: string;
  /** Regex that finds candidate matches in source text. Must be /g flagged. */
  match: RegExp;
  /**
   * Convert a string match to bytes for encryption. Returns null if the
   * match isn't actually a valid value of this type (regex over-matched).
   */
  toBytes: (s: string) => Uint8Array | null;
  /** Convert decrypted bytes back to a string. */
  fromBytes: (b: Uint8Array) => string;
  /** Which AutoConfig flag controls this rule. */
  flag: keyof AutoConfig;
}

// ─── IPv4 ───────────────────────────────────────────────────────────────

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

const ipv4Rule: AutoRule = {
  name: 'IP',
  match: IPV4_RE,
  flag: 'ipv4',
  toBytes(s) {
    const parts = s.split('.');
    if (parts.length !== 4) return null;
    const out = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      const n = Number(parts[i]);
      if (!Number.isInteger(n) || n < 0 || n > 255) return null;
      out[i] = n;
    }
    return out;
  },
  fromBytes(b) {
    if (b.length !== 4) throw new Error('IP must be 4 bytes');
    return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
  },
};

// ─── UUID ───────────────────────────────────────────────────────────────

const UUID_RE = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;

const uuidRule: AutoRule = {
  name: 'UUID',
  match: UUID_RE,
  flag: 'uuid',
  toBytes(s) {
    const hex = s.replace(/-/g, '');
    if (hex.length !== 32) return null;
    const out = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      const byte = parseInt(hex.substr(i * 2, 2), 16);
      if (Number.isNaN(byte)) return null;
      out[i] = byte;
    }
    return out;
  },
  fromBytes(b) {
    if (b.length !== 16) throw new Error('UUID must be 16 bytes');
    const hex = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
    return [
      hex.slice(0, 8),
      hex.slice(8, 12),
      hex.slice(12, 16),
      hex.slice(16, 20),
      hex.slice(20, 32),
    ].join('-');
  },
};

const ALL_RULES: AutoRule[] = [ipv4Rule, uuidRule];

const RULE_BY_NAME: Record<string, AutoRule> = Object.fromEntries(
  ALL_RULES.map((r) => [r.name, r]),
);

/** Catalog of which rule names exist; surfaced to UI for status badges. */
export const AUTO_RULE_LABELS: Record<keyof AutoConfig, string> = {
  ipv4: 'IPv4',
  uuid: 'UUID',
};

export const DEFAULT_AUTO_CONFIG: AutoConfig = {
  ipv4: true,
  uuid: true,
};

function activeRules(cfg: AutoConfig): AutoRule[] {
  return ALL_RULES.filter((r) => cfg[r.flag]);
}

// ─── Token format ───────────────────────────────────────────────────────

/**
 * Detect any auto-token in text. Greedy on cipher chars (base32 alphabet).
 * Capture groups: 1=type name, 2=cipher.
 */
const TOKEN_RE = /<<([A-Z][A-Z0-9]*):([A-Z2-7]+)>>/g;

function makeToken(typeName: string, cipher: Uint8Array): string {
  return `<<${typeName}:${base32Encode(cipher)}>>`;
}

// ─── Public API ─────────────────────────────────────────────────────────

/**
 * Pre-compute a substitution map covering every auto-rule match in `text`.
 * The map is keyed by the original match (anonymize) or the token (deanonymize)
 * so the synchronous OOXML walker can apply substitutions without having to
 * re-await crypto on every text node.
 */
export async function buildAutoSubMap(
  text: string,
  cfg: AutoConfig,
  key: CryptoKey,
  direction: Direction,
): Promise<Map<string, string>> {
  const rules = activeRules(cfg);
  if (rules.length === 0) return new Map();

  if (direction === 'anonymize') {
    return buildAnonymizeMap(text, rules, key);
  }
  return buildDeanonymizeMap(text, key);
}

async function buildAnonymizeMap(
  text: string,
  rules: AutoRule[],
  key: CryptoKey,
): Promise<Map<string, string>> {
  // Collect unique candidates per rule (dedupe so we encrypt once per value).
  const candidates: Array<{ rule: AutoRule; value: string; bytes: Uint8Array }> = [];
  const seen = new Set<string>();
  for (const rule of rules) {
    rule.match.lastIndex = 0;
    for (const m of text.matchAll(rule.match)) {
      const v = m[0];
      const dedupeKey = `${rule.name}:${v}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      const bytes = rule.toBytes(v);
      if (!bytes) continue;
      candidates.push({ rule, value: v, bytes });
    }
  }

  // Encrypt in parallel.
  const ciphers = await Promise.all(
    candidates.map((c) => encryptBytes(c.bytes, key)),
  );

  const map = new Map<string, string>();
  for (let i = 0; i < candidates.length; i++) {
    const { rule, value } = candidates[i];
    map.set(value, makeToken(rule.name, ciphers[i]));
  }
  return map;
}

async function buildDeanonymizeMap(
  text: string,
  key: CryptoKey,
): Promise<Map<string, string>> {
  // Collect unique tokens.
  const seen = new Set<string>();
  const candidates: Array<{ token: string; rule: AutoRule; cipher: Uint8Array }> = [];
  TOKEN_RE.lastIndex = 0;
  for (const m of text.matchAll(TOKEN_RE)) {
    const token = m[0];
    if (seen.has(token)) continue;
    seen.add(token);
    const rule = RULE_BY_NAME[m[1]];
    if (!rule) continue; // unknown type — leave token as-is
    let cipher: Uint8Array;
    try {
      cipher = base32Decode(m[2]);
    } catch {
      continue;
    }
    candidates.push({ token, rule, cipher });
  }

  // Decrypt in parallel; tolerate per-token failures (wrong key, corrupted).
  const results = await Promise.all(
    candidates.map(async ({ token, rule, cipher }) => {
      try {
        const plain = await decryptBytes(cipher, key);
        return { token, value: rule.fromBytes(plain) };
      } catch {
        return null;
      }
    }),
  );

  const map = new Map<string, string>();
  for (const r of results) {
    if (r) map.set(r.token, r.value);
  }
  return map;
}

/**
 * Apply a precomputed substitution map to text. Sorted longest-first so
 * tokens never partially overlap (base32 chars can collide as substrings).
 */
export function applyAutoSubMap(text: string, map: Map<string, string>): string {
  if (map.size === 0) return text;
  const keys = Array.from(map.keys()).sort((a, b) => b.length - a.length);
  let out = text;
  for (const k of keys) {
    if (!out.includes(k)) continue;
    out = out.split(k).join(map.get(k) || k);
  }
  return out;
}

/**
 * Quick presence check used by the UI to warn if a doc contains auto-tokens
 * but the user is trying to deanonymize without a secret set.
 */
export function hasAutoTokens(text: string): boolean {
  TOKEN_RE.lastIndex = 0;
  return TOKEN_RE.test(text);
}
