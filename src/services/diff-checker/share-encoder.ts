import LZString from 'lz-string';
import type { DiffOptions, SemanticFormat } from './types';

export interface SharePayload {
  l: string;
  r: string;
  b?: string;
  o: DiffOptions;
  f: SemanticFormat;
}

export function encodeDiffToURL(
  left: string,
  right: string,
  options: DiffOptions,
  format: SemanticFormat,
  base?: string,
): string {
  const payload: SharePayload = { l: left, r: right, o: options, f: format };
  if (base !== undefined) payload.b = base;
  const json = JSON.stringify(payload);
  const compressed = LZString.compressToEncodedURIComponent(json);
  return `${window.location.origin}${window.location.pathname}#diff=${compressed}`;
}

export function decodeDiffFromURL(): SharePayload | null {
  const hash = window.location.hash;
  if (!hash.startsWith('#diff=')) return null;
  try {
    const compressed = hash.slice(6);
    const json = LZString.decompressFromEncodedURIComponent(compressed);
    if (!json) return null;
    return JSON.parse(json) as SharePayload;
  } catch {
    return null;
  }
}

export function estimateURLLength(
  left: string,
  right: string,
  options: DiffOptions,
  format: SemanticFormat,
  base?: string,
): number {
  const url = encodeDiffToURL(left, right, options, format, base);
  return url.length;
}

export function clearURLFragment() {
  if (window.location.hash) {
    history.replaceState(null, '', window.location.pathname + window.location.search);
  }
}
