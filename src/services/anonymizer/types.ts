export interface MappingEntry {
  real: string;
  placeholder: string;
  wordBoundary: boolean;
  caseSensitive: boolean;
}

export type Direction = 'anonymize' | 'deanonymize';

export type ScanFindings = Record<string, string[]>;

export interface AutoConfig {
  ipv4: boolean;
  uuid: boolean;
}

export interface ParsedMapping {
  entries: MappingEntry[];
  /** Secret used to derive the AES key for auto-redaction. null = auto off. */
  secret: string | null;
  /** Per-rule on/off. Defaults to all-on when secret is set. */
  auto: AutoConfig;
}

export interface ProcessResult {
  blob: Blob;
  filename: string;
  residuals: string[];
  findings: ScanFindings;
  /** Count of auto-redacted tokens by type. Empty for deanonymize. */
  autoCounts: Record<string, number>;
}

export type SupportedExt =
  | '.txt'
  | '.docx'
  | '.pptx'
  | '.xlsx'
  | '.csv'
  | '.tsv'
  | '.json'
  | '.xml'
  | '.yaml'
  | '.yml'
  | '.log'
  | '.md'
  | '.html'
  | '.htm'
  | '.ini'
  | '.conf'
  | '.cfg';

export const SUPPORTED_EXTS: SupportedExt[] = [
  '.txt',
  '.docx',
  '.pptx',
  '.xlsx',
  '.csv',
  '.tsv',
  '.json',
  '.xml',
  '.yaml',
  '.yml',
  '.log',
  '.md',
  '.html',
  '.htm',
  '.ini',
  '.conf',
  '.cfg',
];
