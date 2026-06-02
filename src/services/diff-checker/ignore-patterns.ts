import type { IgnorePattern } from './types';

const STORAGE_KEY = 'xc-app-store:diff-checker:patterns';

export const PRESET_PATTERNS: IgnorePattern[] = [
  { id: 'preset-timestamp', name: 'Timestamps (ISO 8601)', pattern: '/\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:?\\d{2})?/g', enabled: false, preset: true },
  { id: 'preset-uuid', name: 'UUIDs', pattern: '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi', enabled: false, preset: true },
  { id: 'preset-ip', name: 'IPv4 addresses', pattern: '/\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b/g', enabled: false, preset: true },
  { id: 'preset-jwt', name: 'JWT tokens', pattern: '/eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+/g', enabled: false, preset: true },
  { id: 'preset-sha256', name: 'SHA-256 / Docker hashes', pattern: '/sha256:[0-9a-f]{64}/g', enabled: false, preset: true },
  { id: 'preset-autoinc', name: 'Auto-increment IDs', pattern: '/\\b[Ii][Dd]\\s*=\\s*\\d+/g', enabled: false, preset: true },
  { id: 'preset-hex', name: 'Hex commit / blob hashes (40 chars)', pattern: '/\\b[0-9a-f]{40}\\b/g', enabled: false, preset: true },
  { id: 'preset-numeric-ts', name: 'Unix timestamps (10/13 digits)', pattern: '/\\b1[0-9]{9}(\\d{3})?\\b/g', enabled: false, preset: true },
];

export function loadPatterns(): IgnorePattern[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [...PRESET_PATTERNS];
    const stored = JSON.parse(raw) as IgnorePattern[];
    const presetIds = new Set(PRESET_PATTERNS.map(p => p.id));
    const merged: IgnorePattern[] = [];
    for (const preset of PRESET_PATTERNS) {
      const existing = stored.find(p => p.id === preset.id);
      merged.push({ ...preset, enabled: existing?.enabled ?? false });
    }
    for (const p of stored) {
      if (!presetIds.has(p.id)) merged.push(p);
    }
    return merged;
  } catch {
    return [...PRESET_PATTERNS];
  }
}

export function savePatterns(patterns: IgnorePattern[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(patterns));
  } catch {
    // localStorage unavailable
  }
}

export function validatePattern(pattern: string): { ok: true } | { ok: false; error: string } {
  try {
    let src = pattern;
    let flags = '';
    const m = src.match(/^\/(.+)\/([a-z]*)$/);
    if (m) { src = m[1]; flags = m[2]; }
    new RegExp(src, flags);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'Invalid regex' };
  }
}

export function testPattern(pattern: string, sample: string): string[] {
  const r = validatePattern(pattern);
  if (!r.ok) return [];
  try {
    let src = pattern;
    let flags = 'g';
    const m = src.match(/^\/(.+)\/([a-z]*)$/);
    if (m) { src = m[1]; flags = m[2].includes('g') ? m[2] : m[2] + 'g'; }
    const regex = new RegExp(src, flags);
    return Array.from(sample.matchAll(regex)).map(x => x[0]);
  } catch {
    return [];
  }
}
