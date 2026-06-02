import { applyAutoSubMap } from './auto-rules';
import type { Direction, MappingEntry } from './types';

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function buildPattern(entry: MappingEntry): RegExp {
  const escaped = escapeRegex(entry.real);
  const body = entry.wordBoundary ? `\\b${escaped}\\b` : escaped;
  const flags = entry.caseSensitive ? 'g' : 'gi';
  return new RegExp(body, flags);
}

function sortBy<T extends MappingEntry>(entries: T[], field: 'real' | 'placeholder'): T[] {
  return [...entries].sort((a, b) => b[field].length - a[field].length);
}

/**
 * Apply manual mapping rules + (optionally) an auto-sub map computed by
 * auto-rules.buildAutoSubMap(). The auto map keys are pre-encrypted tokens
 * for anonymize, or `<<TYPE:CIPHER>>` tokens for deanonymize.
 */
export function substituteText(
  text: string,
  entries: MappingEntry[],
  direction: Direction,
  autoMap?: Map<string, string>,
): string {
  if (!text) return text;

  if (direction === 'anonymize') {
    let out = text;
    // Manual rules first (longest-first), then auto-redaction sweeps the rest.
    for (const e of sortBy(entries, 'real')) {
      out = out.replace(buildPattern(e), e.placeholder);
    }
    if (autoMap) out = applyAutoSubMap(out, autoMap);
    return out;
  }

  // deanonymize: placeholders are literal, no word boundary, case-sensitive.
  let out = text;
  for (const e of sortBy(entries, 'placeholder')) {
    out = out.split(e.placeholder).join(e.real);
  }
  if (autoMap) out = applyAutoSubMap(out, autoMap);
  return out;
}
