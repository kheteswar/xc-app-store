export type DiffAlgorithm = 'myers';
export type ViewMode = 'split' | 'unified';
export type DiffGranularity = 'line' | 'word' | 'character';
export type InputMode = 'text' | 'file' | 'url' | 'github';
export type SemanticFormat = 'none' | 'json' | 'yaml' | 'xml';

export interface CharChange {
  side: 'left' | 'right';
  start: number;
  end: number;
  type: 'insert' | 'delete';
}

export interface DiffLine {
  type: 'equal' | 'insert' | 'delete' | 'replace';
  lineNumLeft?: number;
  lineNumRight?: number;
  leftContent?: string;
  rightContent?: string;
  content: string;
  leftCharChanges?: CharChange[];
  rightCharChanges?: CharChange[];
  isNoise?: boolean;
  isContext?: boolean;
}

export interface DiffHunk {
  id: string;
  lines: DiffLine[];
  leftStart: number;
  leftEnd: number;
  rightStart: number;
  rightEnd: number;
  mergeDecision?: 'left' | 'right' | 'both' | 'skip' | 'manual';
  manualContent?: string;
}

export interface DiffStats {
  additions: number;
  deletions: number;
  hunkCount: number;
  changedLines: number;
  totalLines: number;
  noiseLines: number;
  similarityPercent: number;
}

export interface SemanticChange {
  path: string;
  type: 'added' | 'removed' | 'changed' | 'moved';
  oldValue?: unknown;
  newValue?: unknown;
}

export interface DiffResult {
  hunks: DiffHunk[];
  stats: DiffStats;
  algorithm: DiffAlgorithm;
  format: SemanticFormat;
  semanticChanges?: SemanticChange[];
  parseError?: string;
}

export interface ThreeWayInput {
  base: string;
  left: string;
  right: string;
}

export interface MergeConflict {
  id: string;
  baseStart: number;
  baseEnd: number;
  baseLines: string[];
  leftLines: string[];
  rightLines: string[];
  resolution?: 'left' | 'right' | 'base' | 'manual';
  manualContent?: string;
}

export interface MergeResult {
  resolvedLines: string[];
  segments: MergeSegment[];
  conflicts: MergeConflict[];
  autoResolved: number;
  conflictCount: number;
}

export interface MergeSegment {
  type: 'context' | 'auto-left' | 'auto-right' | 'auto-both' | 'conflict';
  lines: string[];
  conflictId?: string;
}

export interface IgnorePattern {
  id: string;
  name: string;
  pattern: string;
  enabled: boolean;
  preset: boolean;
}

export interface DiffOptions {
  viewMode: ViewMode;
  ignoreWhitespace: boolean;
  ignoreCase: boolean;
  ignoreBlankLines: boolean;
  wrapLines: boolean;
  contextLines: number;
  granularity: DiffGranularity;
  language: string;
  formatCode: boolean;
  activePatterns: string[];
  semanticMode: boolean;
}

export const DEFAULT_DIFF_OPTIONS: DiffOptions = {
  viewMode: 'split',
  ignoreWhitespace: false,
  ignoreCase: false,
  ignoreBlankLines: false,
  wrapLines: false,
  contextLines: 3,
  granularity: 'line',
  language: 'auto',
  formatCode: false,
  activePatterns: [],
  semanticMode: false,
};

export interface DiffSnapshot {
  id: string;
  name: string;
  createdAt: number;
  leftContent: string;
  rightContent: string;
  baseContent?: string;
  options: DiffOptions;
  format: SemanticFormat;
}

export interface GitHubFile {
  filename: string;
  status: 'added' | 'removed' | 'modified' | 'renamed';
  additions: number;
  deletions: number;
  patch?: string;
  rawUrl?: string;
  blobUrl?: string;
  previousFilename?: string;
}

export interface GitHubPRInfo {
  number: number;
  title: string;
  repo: string;
  owner: string;
  files: GitHubFile[];
  baseSha: string;
  headSha: string;
}
