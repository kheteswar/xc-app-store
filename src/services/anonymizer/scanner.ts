import type { MappingEntry, ScanFindings } from './types';
import { buildPattern } from './substitution';

const SUSPICIOUS: Array<[string, RegExp]> = [
  ['IPv4 address', /\b(?:\d{1,3}\.){3}\d{1,3}\b/g],
  ['Email address', /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g],
  ['Domain name', /\b[a-zA-Z0-9-]+\.(?:com|net|org|io|sg|co|jp|in|gov|edu)(?:\.[a-z]{2})?\b/g],
  ['URL', /https?:\/\/[^\s]+/g],
  ['Capitalized phrase (3+ words)', /\b(?:[A-Z][a-z]+\s+){2,}[A-Z][a-z]+\b/g],
  ['All-caps token (4+ chars)', /\b[A-Z]{4,}\b/g],
];

export function scanForLeaks(text: string, entries: MappingEntry[]): ScanFindings {
  // Strip manual placeholders + auto-tokens so neither the placeholder text
  // (COMPANY, DOMAIN) nor the encrypted base32 cipher in <<IP:...>> tokens
  // generates false alarms.
  let stripped = text.replace(/<<[A-Z][A-Z0-9]*:[A-Z2-7]+>>/g, ' ');
  for (const e of entries) {
    stripped = stripped.split(e.placeholder).join(' ');
  }

  // Build the set of tokens already covered by mapping (so they're not flagged).
  const covered = new Set<string>();
  for (const e of entries) {
    const pat = buildPattern(e);
    for (const m of text.matchAll(pat)) {
      covered.add(m[0].toLowerCase());
    }
  }

  const findings: ScanFindings = {};
  for (const [label, pat] of SUSPICIOUS) {
    const matches = new Set<string>();
    for (const m of stripped.matchAll(pat)) {
      const tok = m[0];
      if (!covered.has(tok.toLowerCase())) matches.add(tok);
    }
    if (matches.size > 0) findings[label] = Array.from(matches).sort();
  }
  return findings;
}

export function findResiduals(text: string, entries: MappingEntry[]): string[] {
  const residuals: string[] = [];
  for (const e of entries) {
    if (buildPattern(e).test(text)) residuals.push(e.real);
  }
  return residuals;
}
