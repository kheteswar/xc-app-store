import type {
  AutoConfig,
  Direction,
  MappingEntry,
  ParsedMapping,
  ProcessResult,
  SupportedExt,
} from './types';
import { SUPPORTED_EXTS } from './types';
import { extractText, PROCESSORS } from './processors';
import { findResiduals, scanForLeaks } from './scanner';
import { buildAutoSubMap } from './auto-rules';
import { deriveKey } from './crypto';

export type {
  AutoConfig,
  Direction,
  MappingEntry,
  ParsedMapping,
  ProcessResult,
  SupportedExt,
};
export { SUPPORTED_EXTS };
export {
  parseMapping,
  parseMappingFull,
  EXAMPLE_MAPPING,
  EMPTY_MAPPING,
  suggestEntry,
  appendMappingEntry,
  setSecretInMapping,
  rotateSecret,
} from './mapping';
export type { SuggestedEntry, AppendResult } from './mapping';
export { scanForLeaks, findResiduals } from './scanner';
export { extractText } from './processors';
export { generateSecret } from './crypto';
export { hasAutoTokens, AUTO_RULE_LABELS } from './auto-rules';

export function getExtension(filename: string): SupportedExt | null {
  const lower = filename.toLowerCase();
  for (const ext of SUPPORTED_EXTS) {
    if (lower.endsWith(ext)) return ext;
  }
  return null;
}

export function suggestOutputName(filename: string, direction: Direction): string {
  const ext = getExtension(filename);
  if (!ext) return filename;
  const stem = filename.slice(0, -ext.length);
  const suffix = direction === 'anonymize' ? '.anon' : '.deanon';
  // Strip a previous .anon/.deanon suffix to keep round-trips clean.
  const cleaned = stem.replace(/\.(anon|deanon)$/, '');
  return `${cleaned}${suffix}${ext}`;
}

export interface ProcessOptions {
  /** Pass-through for auto-redaction. null/undefined = auto-rules off. */
  secret?: string | null;
  auto?: AutoConfig;
}

/**
 * Anonymize or deanonymize a file end-to-end. After anonymize, runs the
 * leak scan and residual check on the output (mirroring the Python CLI).
 *
 * If `secret` is provided, structured-data auto-rules (IPv4, UUID, …) run
 * after the manual mapping. The auto-substitution map is computed once on
 * the full extracted text, so per-text-node walking remains synchronous.
 */
export async function processFile(
  file: File,
  entries: MappingEntry[],
  direction: Direction,
  options: ProcessOptions = {},
): Promise<ProcessResult> {
  const ext = getExtension(file.name);
  if (!ext) {
    throw new Error(
      `Unsupported file type. Supported: ${SUPPORTED_EXTS.join(', ')}`,
    );
  }

  const buf = await file.arrayBuffer();

  // Build auto-substitution map once if a secret is set.
  let autoMap: Map<string, string> | undefined;
  let autoCounts: Record<string, number> = {};
  if (options.secret) {
    const key = await deriveKey(options.secret);
    const fullText = await extractText(buf, ext);
    autoMap = await buildAutoSubMap(
      fullText,
      options.auto ?? { ipv4: true, uuid: true },
      key,
      direction,
    );
    autoCounts = countMatchesPerType(autoMap, direction);
  }

  const blob = await PROCESSORS[ext](buf, entries, direction, autoMap);
  const filename = suggestOutputName(file.name, direction);

  let residuals: string[] = [];
  let findings = {};
  if (direction === 'anonymize') {
    const outBuf = await blob.arrayBuffer();
    const outText = await extractText(outBuf, ext);
    residuals = findResiduals(outText, entries);
    findings = scanForLeaks(outText, entries);
  }

  return { blob, filename, residuals, findings, autoCounts };
}

/**
 * Group an auto-sub map's values (anonymize) or keys (deanonymize) by
 * placeholder type, e.g. { IP: 7, UUID: 3 }.
 */
function countMatchesPerType(
  map: Map<string, string>,
  direction: Direction,
): Record<string, number> {
  const counts: Record<string, number> = {};
  const tokens = direction === 'anonymize' ? map.values() : map.keys();
  for (const tok of tokens) {
    const m = tok.match(/^<<([A-Z][A-Z0-9]*):/);
    if (!m) continue;
    counts[m[1]] = (counts[m[1]] || 0) + 1;
  }
  return counts;
}
