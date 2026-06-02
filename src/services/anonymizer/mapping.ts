import yaml from 'js-yaml';
import { DEFAULT_AUTO_CONFIG } from './auto-rules';
import { generateSecret } from './crypto';
import type { AutoConfig, MappingEntry, ParsedMapping } from './types';

interface RawEntry {
  real?: unknown;
  placeholder?: unknown;
  word_boundary?: unknown;
  case_sensitive?: unknown;
}

interface RawMapping {
  entries?: RawEntry[];
  secret?: unknown;
  auto?: Record<string, unknown>;
}

/** Parse mapping YAML and return all sections (entries + secret + auto cfg). */
export function parseMappingFull(text: string): ParsedMapping {
  const data = yaml.load(text) as RawMapping | null;
  if (!data || !Array.isArray(data.entries)) {
    throw new Error("Mapping must contain a top-level 'entries:' list");
  }

  const entries: MappingEntry[] = [];
  const seenReal = new Set<string>();
  const seenPlaceholder = new Set<string>();

  data.entries.forEach((item, i) => {
    if (typeof item.real !== 'string' || typeof item.placeholder !== 'string') {
      throw new Error(`Entry ${i} missing string 'real' or 'placeholder'`);
    }
    if (seenReal.has(item.real)) {
      throw new Error(`Duplicate real value: ${JSON.stringify(item.real)}`);
    }
    if (seenPlaceholder.has(item.placeholder)) {
      throw new Error(`Duplicate placeholder: ${JSON.stringify(item.placeholder)}`);
    }
    seenReal.add(item.real);
    seenPlaceholder.add(item.placeholder);
    entries.push({
      real: item.real,
      placeholder: item.placeholder,
      wordBoundary: item.word_boundary === undefined ? true : Boolean(item.word_boundary),
      caseSensitive: Boolean(item.case_sensitive),
    });
  });

  const secret =
    typeof data.secret === 'string' && data.secret.trim().length > 0
      ? data.secret
      : null;

  // Auto config: defaults all on. Per-rule explicit false disables.
  const auto: AutoConfig = { ...DEFAULT_AUTO_CONFIG };
  if (data.auto && typeof data.auto === 'object') {
    for (const k of Object.keys(auto) as Array<keyof AutoConfig>) {
      if (k in data.auto) auto[k] = Boolean(data.auto[k]);
    }
  }

  return { entries, secret, auto };
}

/** Backwards-compatible: returns just the entries. */
export function parseMapping(text: string): MappingEntry[] {
  return parseMappingFull(text).entries;
}

// ─── Secret manipulation in YAML text ───────────────────────────────────

const SECRET_LINE_RE = /^[ \t]*secret[ \t]*:.*$/m;

/**
 * Insert or replace the `secret:` line in a YAML mapping. Preserves the rest
 * of the document (comments, formatting, entries). If the YAML is blank,
 * seeds a fresh skeleton.
 */
export function setSecretInMapping(yamlText: string, secret: string): string {
  const line = `secret: ${JSON.stringify(secret)}`;
  const trimmed = yamlText.trim();
  if (!trimmed) {
    return (
      '# Anonymization mapping. Keep LOCAL — do NOT share or commit.\n' +
      `${line}\n\n` +
      'entries: []\n'
    );
  }
  if (SECRET_LINE_RE.test(yamlText)) {
    return yamlText.replace(SECRET_LINE_RE, line);
  }
  // Insert before `entries:` if found, else prepend.
  const entriesIdx = yamlText.search(/^[ \t]*entries[ \t]*:/m);
  if (entriesIdx >= 0) {
    return yamlText.slice(0, entriesIdx) + `${line}\n\n` + yamlText.slice(entriesIdx);
  }
  return `${line}\n${yamlText}`;
}

/** Generate + insert a fresh secret. Returns the new YAML text. */
export function rotateSecret(yamlText: string): { text: string; secret: string } {
  const secret = generateSecret();
  return { text: setSecretInMapping(yamlText, secret), secret };
}

export const EMPTY_MAPPING = `# Anonymization mapping. Keep LOCAL — do NOT share or commit.
# Run "Scan" on your file, then click "+ Map" on each flagged token to build
# this mapping interactively. Or paste your own YAML below.
#
# To auto-redact IPs and UUIDs (no manual entries needed), click
# "Generate secret" — every IP/UUID gets a deterministic encrypted
# placeholder that round-trips on Deanonymize. The same mapping must be used
# for both directions.

entries: []
`;

export const EXAMPLE_MAPPING = `# Anonymization mapping. Keep LOCAL — do NOT share or commit.
# Tool sorts longest-first automatically.

# Optional: secret enables auto-redaction of structured data (IPs, UUIDs, …).
# Click "Generate secret" in the toolbar to fill this in safely.
# secret: "PASTE-A-RANDOM-STRING-HERE"

# Per-rule on/off. All on by default when secret is set.
# auto:
#   ipv4: true
#   uuid: true

entries:
  - real: "Acme Banking Corporation Singapore"
    placeholder: "<COMPANY-NAME-FULL>"

  - real: "Acme Bank"
    placeholder: "<COMPANY-NAME>"

  - real: "ACME"
    placeholder: "<COMPANY-SHORT>"
    case_sensitive: true

  - real: "acme.com.sg"
    placeholder: "<COMPANY-DOMAIN>"
    word_boundary: false   # match inside emails like alice@acme.com.sg

  - real: "PaymentsGateway"
    placeholder: "<APP-NAME-1>"

  - real: "Mr. Tanaka"
    placeholder: "<STAKEHOLDER-SECURITY-LEAD>"
`;

// ─── Category-driven placeholder suggestions ────────────────────────────

interface CategoryDefaults {
  prefix: string;
  wordBoundary: boolean;
  caseSensitive: boolean;
}

const CATEGORY_DEFAULTS: Record<string, CategoryDefaults> = {
  'IPv4 address':                   { prefix: 'IP',      wordBoundary: true,  caseSensitive: false },
  'Email address':                  { prefix: 'EMAIL',   wordBoundary: true,  caseSensitive: false },
  'Domain name':                    { prefix: 'DOMAIN',  wordBoundary: false, caseSensitive: false },
  'URL':                            { prefix: 'URL',     wordBoundary: false, caseSensitive: false },
  'Capitalized phrase (3+ words)':  { prefix: 'NAME',    wordBoundary: true,  caseSensitive: false },
  'All-caps token (4+ chars)':      { prefix: 'SHORT',   wordBoundary: true,  caseSensitive: true  },
};

const DEFAULT_FALLBACK: CategoryDefaults = {
  prefix: 'TOKEN',
  wordBoundary: true,
  caseSensitive: false,
};

export interface SuggestedEntry {
  real: string;
  placeholder: string;
  wordBoundary: boolean;
  caseSensitive: boolean;
}

/**
 * Pick a sensible default placeholder + flags for a token in a given scan
 * category. Numbers the placeholder to avoid collisions with what's already
 * in the mapping (e.g. <IP-1>, <IP-2>, …).
 */
export function suggestEntry(
  token: string,
  category: string,
  existingPlaceholders: ReadonlySet<string>,
): SuggestedEntry {
  const defaults = CATEGORY_DEFAULTS[category] ?? DEFAULT_FALLBACK;
  let n = 1;
  let placeholder = `<${defaults.prefix}-${n}>`;
  while (existingPlaceholders.has(placeholder)) {
    n += 1;
    placeholder = `<${defaults.prefix}-${n}>`;
  }
  return {
    real: token,
    placeholder,
    wordBoundary: defaults.wordBoundary,
    caseSensitive: defaults.caseSensitive,
  };
}

// ─── YAML appender ──────────────────────────────────────────────────────

/**
 * Format a single mapping entry as a YAML block. Real and placeholder are
 * emitted as JSON-style double-quoted scalars — JSON.stringify produces
 * valid YAML double-quoted strings for any printable string.
 */
function serializeEntry(entry: SuggestedEntry): string {
  const lines = [
    `  - real: ${JSON.stringify(entry.real)}`,
    `    placeholder: ${JSON.stringify(entry.placeholder)}`,
  ];
  if (!entry.wordBoundary) lines.push('    word_boundary: false');
  if (entry.caseSensitive) lines.push('    case_sensitive: true');
  return lines.join('\n');
}

export interface AppendResult {
  text: string;
  error?: string;
}

/**
 * Append a new entry to YAML mapping text. Bootstraps a fresh mapping if
 * the input is blank or has no `entries:` key. Detects duplicate real/
 * placeholder values before writing.
 */
export function appendMappingEntry(
  yamlText: string,
  entry: SuggestedEntry,
): AppendResult {
  const trimmed = yamlText.trim();

  // Detect "fresh start" — empty file, or `entries: []` / missing entries key.
  let existing: MappingEntry[] = [];
  let bootstrap = false;

  if (!trimmed) {
    bootstrap = true;
  } else {
    try {
      existing = parseMapping(yamlText);
    } catch (e) {
      const msg = (e as Error).message;
      // Missing entries list → bootstrap. Anything else is a real error.
      if (msg.includes("'entries'")) {
        bootstrap = true;
      } else {
        return { text: yamlText, error: `Mapping has errors: ${msg}` };
      }
    }
  }

  if (existing.some((e) => e.real === entry.real)) {
    return { text: yamlText, error: `Already mapped: ${JSON.stringify(entry.real)}` };
  }
  if (existing.some((e) => e.placeholder === entry.placeholder)) {
    return { text: yamlText, error: `Placeholder in use: ${JSON.stringify(entry.placeholder)}` };
  }

  const block = serializeEntry(entry);

  if (bootstrap) {
    const header =
      '# Anonymization mapping. Keep LOCAL — do NOT share or commit.\n' +
      'entries:\n';
    return { text: header + block + '\n' };
  }

  // Append after existing content. If the YAML uses `entries: []` syntax,
  // we need to convert it to a block list before appending.
  if (/^\s*entries\s*:\s*\[\s*\]\s*$/m.test(yamlText)) {
    const replaced = yamlText.replace(
      /^(\s*entries\s*:)\s*\[\s*\]\s*$/m,
      '$1\n' + block,
    );
    return { text: replaced.endsWith('\n') ? replaced : replaced + '\n' };
  }

  const cleaned = yamlText.replace(/\s+$/, '');
  return { text: `${cleaned}\n\n${block}\n` };
}
