/**
 * FP Analysis Excel Report Generator
 *
 * Generates a professionally-styled Excel workbook using ExcelJS.
 * Each sheet is described declaratively as a list of "blocks" (title / metadata /
 * section / note / table) and a single `renderSheet` renderer applies a consistent
 * slate/blue theme: dark title banners, blue table headers (frozen), zebra-striped
 * data rows, thin borders, and verdict / AI-risk colour grading.
 *
 * This is a styling + library migration from SheetJS (`xlsx`). The DATA in every
 * sheet — values, columns, sheet names, sheet order, and conditional inclusion —
 * is identical to the previous generator.
 */

import ExcelJS from 'exceljs';
import type {
  AnalysisScope,
  AnalysisMode,
  SummaryResult,
  ThreatMeshAnalysisUnit,
  SignatureAnalysisUnit,
  ViolationAnalysisUnit,
  WafExclusionPolicyObject,
  ManualReviewMap,
  ManualReviewVerdict,
} from './types';

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export interface FPExcelReportOptions {
  summary: SummaryResult;
  scopes: AnalysisScope[];
  namespace: string;
  lbName: string;
  mode?: AnalysisMode;
  threatMeshDetails?: ThreatMeshAnalysisUnit[];
  signatureDetails?: SignatureAnalysisUnit[];
  violationDetails?: ViolationAnalysisUnit[];
  exclusionPolicy?: WafExclusionPolicyObject;
  /** Analyst manual confirmations, keyed by signature ID. */
  signatureReviewStatus?: ManualReviewMap;
  /** Analyst manual confirmations, keyed by violation name. */
  violationReviewStatus?: ManualReviewMap;
}

// ═══════════════════════════════════════════════════════════════════
// STYLE PALETTE (ExcelJS ARGB — 8 hex digits, FF alpha prefix)
// ═══════════════════════════════════════════════════════════════════

const FONT = 'Calibri';
const NUM_FMT = '#,##0';

const TITLE_FILL = 'FF0F172A';   // slate-900 banner
const TITLE_FONT = 'FFFFFFFF';
const META_KEY = 'FF1E293B';     // slate-800
const SECTION_FILL = 'FFE2E8F0'; // slate-200
const SECTION_FONT = 'FF1E293B';
const HEADER_FILL = 'FF1E40AF';  // blue-800
const HEADER_FONT = 'FFFFFFFF';
const ZEBRA = 'FFF8FAFC';        // slate-50
const BORDER = 'FFE2E8F0';       // slate-200

const FP_FONT = 'FFB45309';      // amber-700
const FP_FILL = 'FFFEF3C7';      // amber-100
const TP_FONT = 'FF15803D';      // green-700
const TP_FILL = 'FFDCFCE7';      // green-100
const AMBIG_FONT = 'FF64748B';   // slate-500

const RISK_HIGH = 'FFDC2626';    // red-600
const RISK_MED = 'FFD97706';     // amber-600
const RISK_LOW = 'FF15803D';     // green-700

const REC_FILL = 'FFDCFCE7';     // green-100 (recommended)

const solidFill = (argb: string): ExcelJS.Fill => ({ type: 'pattern', pattern: 'solid', fgColor: { argb } });
const THIN: Partial<ExcelJS.Border> = { style: 'thin', color: { argb: BORDER } };
const ALL_BORDERS: Partial<ExcelJS.Borders> = { top: THIN, left: THIN, bottom: THIN, right: THIN };

// ═══════════════════════════════════════════════════════════════════
// DECLARATIVE BLOCK MODEL
// ═══════════════════════════════════════════════════════════════════

type CellVal = string | number;
type Align = 'left' | 'center' | 'right';

/** A per-cell colour override applied on top of zebra striping. */
interface CellGrade { font?: string; fill?: string; bold?: boolean; }

interface TitleBlock { type: 'title'; text: string; }
interface MetaBlock { type: 'meta'; label: string; value: CellVal; }
interface SectionBlock { type: 'section'; text: string; }
interface NoteBlock { type: 'note'; text: string; }
interface SpacerBlock { type: 'spacer'; }
interface TableBlock {
  type: 'table';
  headers: string[];
  rows: CellVal[][];
  /** Optional per-column horizontal alignment override. */
  align?: Align[];
  /** Freeze the rows above + including this table's header (first such table wins). */
  freeze?: boolean;
  /** Per-cell colour grade callback (row, rowIdx, colIdx) → grade. */
  grade?: (row: CellVal[], r: number, c: number) => CellGrade | undefined;
}
type Block = TitleBlock | MetaBlock | SectionBlock | NoteBlock | SpacerBlock | TableBlock;

interface SheetSpec { blocks: Block[]; widths: number[]; }

// Build a per-cell grader from a map of colIdx → grader function.
function gradeByCol(
  map: Record<number, (v: CellVal, row: CellVal[]) => CellGrade | undefined>,
): TableBlock['grade'] {
  return (row, _r, c) => {
    const fn = map[c];
    return fn ? fn(row[c], row) : undefined;
  };
}

function gradeVerdict(v: string): CellGrade | undefined {
  if (!v) return undefined;
  if (v.includes('FP')) return { font: FP_FONT, fill: FP_FILL };
  if (v.includes('TP')) return { font: TP_FONT, fill: TP_FILL };
  if (v.includes('Ambiguous')) return { font: AMBIG_FONT };
  return undefined;
}

function gradeAiRisk(v: string): CellGrade | undefined {
  const s = (v || '').toLowerCase();
  if (s === 'high') return { font: RISK_HIGH, bold: true };
  if (s === 'medium') return { font: RISK_MED, bold: true };
  if (s === 'low' || s.includes('false positive')) return { font: RISK_LOW };
  return undefined;
}

// ═══════════════════════════════════════════════════════════════════
// RENDERER
// ═══════════════════════════════════════════════════════════════════

function renderTable(ws: ExcelJS.Worksheet, b: TableBlock): number {
  const headers = b.headers;
  const ncol = headers.length;
  const dense = ncol >= 8;
  const size = dense ? 9 : 10;
  const numericCol = headers.map((_, c) => b.rows.length > 0 && typeof b.rows[0][c] === 'number');
  const headerAlign = (c: number): Align => b.align?.[c] ?? (numericCol[c] ? 'center' : 'left');
  const dataAlign = (c: number, v: CellVal): Align =>
    typeof v === 'number' ? 'right' : (b.align?.[c] ?? (numericCol[c] ? 'right' : 'left'));

  const headerRow = ws.addRow(headers);
  for (let c = 0; c < ncol; c++) {
    const cell = headerRow.getCell(c + 1);
    cell.font = { name: FONT, bold: true, size, color: { argb: HEADER_FONT } };
    cell.fill = solidFill(HEADER_FILL);
    cell.alignment = { horizontal: headerAlign(c), vertical: 'middle', wrapText: true };
    cell.border = ALL_BORDERS;
  }

  b.rows.forEach((r, ri) => {
    const row = ws.addRow(r);
    const zebra = ri % 2 === 1;
    for (let c = 0; c < ncol; c++) {
      const cell = row.getCell(c + 1);
      const v: CellVal = r[c] ?? '';
      cell.alignment = { horizontal: dataAlign(c, v), vertical: 'middle', wrapText: true };
      if (typeof v === 'number') cell.numFmt = NUM_FMT;
      cell.border = ALL_BORDERS;

      const g = b.grade?.(r, ri, c);
      const fillArgb = g?.fill ?? (zebra ? ZEBRA : undefined);
      if (fillArgb) cell.fill = solidFill(fillArgb);

      const font: Partial<ExcelJS.Font> = { name: FONT, size, bold: !!g?.bold };
      if (g?.font) font.color = { argb: g.font };
      cell.font = font;
    }
  });

  return headerRow.number;
}

function renderSheet(ws: ExcelJS.Worksheet, blocks: Block[], widths: number[]): void {
  const colSpan = Math.max(1, widths.length);
  widths.forEach((w, i) => { ws.getColumn(i + 1).width = w; });
  let freezeRow: number | undefined;

  for (const b of blocks) {
    switch (b.type) {
      case 'spacer':
        ws.addRow([]);
        break;
      case 'title': {
        const row = ws.addRow([b.text]);
        row.height = 26;
        if (colSpan > 1) ws.mergeCells(row.number, 1, row.number, colSpan);
        const cell = row.getCell(1);
        cell.font = { name: FONT, bold: true, size: 14, color: { argb: TITLE_FONT } };
        cell.fill = solidFill(TITLE_FILL);
        cell.alignment = { horizontal: 'left', vertical: 'middle', wrapText: true };
        break;
      }
      case 'section': {
        const row = ws.addRow([b.text]);
        row.height = 18;
        if (colSpan > 1) ws.mergeCells(row.number, 1, row.number, colSpan);
        const cell = row.getCell(1);
        cell.font = { name: FONT, bold: true, size: 10, color: { argb: SECTION_FONT } };
        cell.fill = solidFill(SECTION_FILL);
        cell.alignment = { horizontal: 'left', vertical: 'middle', wrapText: true };
        break;
      }
      case 'note': {
        const row = ws.addRow([b.text]);
        if (colSpan > 1) ws.mergeCells(row.number, 1, row.number, colSpan);
        const cell = row.getCell(1);
        cell.font = { name: FONT, italic: true, size: 9, color: { argb: AMBIG_FONT } };
        cell.alignment = { horizontal: 'left', vertical: 'middle', wrapText: true };
        break;
      }
      case 'meta': {
        const row = ws.addRow([b.label, b.value]);
        const k = row.getCell(1);
        const v = row.getCell(2);
        k.font = { name: FONT, bold: true, size: 10, color: { argb: META_KEY } };
        k.alignment = { horizontal: 'left', vertical: 'middle', wrapText: true };
        v.font = { name: FONT, size: 10 };
        v.alignment = { horizontal: typeof b.value === 'number' ? 'right' : 'left', vertical: 'middle', wrapText: true };
        if (typeof b.value === 'number') v.numFmt = NUM_FMT;
        break;
      }
      case 'table': {
        const headerRowNum = renderTable(ws, b);
        if (b.freeze && freezeRow === undefined) freezeRow = headerRowNum;
        break;
      }
    }
  }

  if (freezeRow !== undefined) ws.views = [{ state: 'frozen', ySplit: freezeRow }];
}

// ═══════════════════════════════════════════════════════════════════
// DATA HELPERS (unchanged from the previous generator)
// ═══════════════════════════════════════════════════════════════════

function topEntries(record: Record<string, number>, count = 5): string {
  return Object.entries(record)
    .sort((a, b) => b[1] - a[1])
    .slice(0, count)
    .map(([k, v]) => `${k} (${v})`)
    .join(', ');
}

function verdictLabel(verdict: string): string {
  switch (verdict) {
    case 'highly_likely_fp': return 'Highly Likely FP';
    case 'likely_fp': return 'Likely FP';
    case 'ambiguous': return 'Ambiguous';
    case 'likely_tp': return 'Likely TP';
    case 'confirmed_tp': return 'Confirmed TP';
    case 'investigate': return 'Investigate';
    default: return verdict;
  }
}

/** Human label for an analyst's manual confirmation (blank when not yet reviewed). */
function manualReviewLabel(verdict: ManualReviewVerdict | undefined): string {
  switch (verdict) {
    case 'confirmed_fp': return 'Manually confirmed FP';
    case 'confirmed_tp': return 'Manually confirmed TP';
    case 'skipped': return 'Reviewed — skipped';
    default: return 'Not reviewed';
  }
}

const aiRiskLabel = (r?: string): string => (r && r !== 'unknown' ? r : '');

/** Compact, readable "Top Paths" cell — cap to 3 paths and truncate long/obfuscated attack strings. */
function topPathsCell(paths: Array<{ path: string; count: number }>): string {
  return paths.slice(0, 3).map(p => `${p.path.length > 48 ? p.path.slice(0, 45) + '…' : p.path} (${p.count})`).join('\n');
}

// ═══════════════════════════════════════════════════════════════════
// SHEET BUILDERS (each returns a declarative SheetSpec)
// ═══════════════════════════════════════════════════════════════════

function buildSummarySheet(opts: FPExcelReportOptions): SheetSpec {
  const blocks: Block[] = [];
  blocks.push({ type: 'title', text: 'FP Analysis Report — Executive Summary' });
  blocks.push({ type: 'spacer' });
  blocks.push({ type: 'meta', label: 'Load Balancer', value: opts.lbName });
  blocks.push({ type: 'meta', label: 'Namespace', value: opts.namespace });
  blocks.push({ type: 'meta', label: 'Scopes', value: opts.scopes.join(', ') });
  blocks.push({ type: 'meta', label: 'Period Start', value: opts.summary.period.start });
  blocks.push({ type: 'meta', label: 'Period End', value: opts.summary.period.end });
  blocks.push({ type: 'meta', label: 'Generated', value: new Date().toISOString() });
  blocks.push({ type: 'spacer' });

  const fp = opts.summary.signatures.filter(s => s.fpVerdict === 'highly_likely_fp' || s.fpVerdict === 'likely_fp').length;
  const tp = opts.summary.signatures.filter(s => s.fpVerdict === 'likely_tp' || s.fpVerdict === 'confirmed_tp').length;
  const metricRows: CellVal[][] = [
    ['Total flagged events', opts.summary.totalEvents],
    ['Malicious bot requests', opts.summary.botAnalysis?.maliciousEvents ?? 0],
    ['Unique Signatures', opts.summary.signatures.length],
    ['Unique Violations', opts.summary.violations.length],
  ];
  if (opts.summary.enforcementMode) metricRows.push(['WAF Enforcement Mode', opts.summary.enforcementMode]);
  metricRows.push(['Signatures: likely false positive', fp]);
  metricRows.push(['Signatures: likely true positive', tp]);
  blocks.push({ type: 'table', headers: ['Metric', 'Value'], rows: metricRows });

  if (opts.summary.wafComparison) {
    blocks.push({ type: 'spacer' });
    blocks.push({ type: 'meta', label: 'AI vs Traditional WAF', value: opts.summary.wafComparison.headline });
  }

  return { blocks, widths: [28, 90] };
}

function buildNextStepsSheet(opts: FPExcelReportOptions): SheetSpec {
  const rec = opts.summary.recommendations!;
  const blocks: Block[] = [];
  blocks.push({ type: 'title', text: 'Recommendations & Next Steps' });
  blocks.push({ type: 'spacer' });
  blocks.push({ type: 'meta', label: 'Goal', value: `Tune out false positives, then move this load balancer ${rec.enforcementMode === 'blocking' ? 'to a verified Blocking state' : 'from Monitoring to Blocking'} with AI-powered WAF protection.` });
  blocks.push({ type: 'meta', label: 'Recommended AI blocking threshold', value: rec.aiBlockingThreshold === 'high_medium' ? 'High + Medium risk' : 'High risk' });
  blocks.push({ type: 'meta', label: 'Reason', value: rec.aiThresholdReason });
  blocks.push({ type: 'spacer' });
  blocks.push({ type: 'table', headers: ['Step', 'Action', 'How to do it'], rows: rec.steps.map(s => [s.num, s.title, s.detail]) });
  blocks.push({ type: 'spacer' });

  if (rec.excludeList.length > 0) {
    blocks.push({ type: 'section', text: `False positives to exclude (${rec.excludeList.length})` });
    blocks.push({
      type: 'table',
      headers: ['Type', 'ID', 'Name', 'Verdict'],
      rows: rec.excludeList.map(e => [e.kind, e.id, e.name, verdictLabel(e.verdict)]),
      grade: gradeByCol({ 3: v => gradeVerdict(String(v)) }),
    });
    blocks.push({ type: 'spacer' });
  }
  if (rec.investigateList.length > 0) {
    blocks.push({ type: 'section', text: `Investigate & manually confirm — do NOT auto-exclude (${rec.investigateList.length})` });
    blocks.push({
      type: 'table',
      headers: ['Type', 'ID', 'Name', 'Why / How to investigate'],
      rows: rec.investigateList.map(e => [e.kind, e.id, e.name, e.reason]),
    });
    blocks.push({ type: 'spacer' });
  }
  if (rec.autoHandledList.length > 0) {
    blocks.push({ type: 'section', text: `Already auto-suppressed by F5 AI — NO exclusion needed (${rec.autoHandledList.length})` });
    blocks.push({
      type: 'table',
      headers: ['Type', 'ID', 'Name'],
      rows: rec.autoHandledList.map(e => [e.kind, e.id, e.name]),
    });
  }

  return { blocks, widths: [10, 46, 110, 22] };
}

function buildBotClassificationSheet(opts: FPExcelReportOptions): SheetSpec {
  const ba = opts.summary.botAnalysis!;
  const cc = ba.classificationCounts;
  const blocks: Block[] = [];
  blocks.push({ type: 'title', text: 'Malicious Bots' });
  if (ba.maliciousEvents === 0) {
    blocks.push({ type: 'note', text: 'No malicious-bot requests were found in this window. (Bots are classified by F5 Bot Signatures; the classification distribution below covers all flagged requests.)' });
  } else {
    blocks.push({ type: 'note', text: 'Malicious bots detected by Bot Signatures. Currently ALLOWED (monitoring) — moving this LB to Blocking will block them.' });
  }
  blocks.push({ type: 'spacer' });
  blocks.push({ type: 'meta', label: 'Recommendation', value: ba.recommendation });
  blocks.push({ type: 'spacer' });
  blocks.push({
    type: 'table',
    headers: ['F5 Bot Defense classification', 'Events', 'Bot Defense action'],
    rows: [
      ['Malicious', cc.malicious, 'Blocked (when enabled)'],
      ['Suspicious', cc.suspicious, 'Allowed / ignored'],
      ['Benign / Good', cc.benign, 'Allowed / ignored'],
      ['Human', cc.human, 'Allowed'],
      ['Unknown', cc.unknown, '—'],
    ],
  });
  blocks.push({ type: 'spacer' });
  blocks.push({ type: 'meta', label: 'Malicious events', value: ba.maliciousEvents });
  blocks.push({ type: 'meta', label: 'Distinct malicious clients', value: `${ba.maliciousIps}${ba.breakdownSampled ? '+ (≥; from sample)' : ba.ipsCapped ? '+ (capped at 500)' : ''}` });
  if (ba.breakdownSampled) {
    blocks.push({ type: 'note', text: `Note: the total above is exact, but the per-client/path breakdown is from a sample of ${(ba.breakdownSampleSize || 0).toLocaleString()} of ${ba.maliciousEvents.toLocaleString()} events (server-side aggregation unavailable on this LB) — so the distinct-client count and per-IP counts are a lower bound, not exact.` });
  }
  blocks.push({ type: 'spacer' });

  blocks.push({ type: 'section', text: `Potential false positives in the Malicious set (${ba.fpRiskFlags.length}) — verify before blocking` });
  blocks.push({
    type: 'table',
    headers: ['Type', 'User-Agent / Bot Name', 'Events'],
    rows: ba.fpRiskFlags.length === 0
      ? [['—', 'None — no known-good bot or real-browser client in the Malicious set', '']]
      : ba.fpRiskFlags.map(f => [f.kind === 'known_good_bot' ? 'Known-good bot' : 'Real browser', f.label, f.count]),
  });
  blocks.push({ type: 'spacer' });

  blocks.push({ type: 'table', headers: ['Top malicious source IPs', 'Events'], rows: ba.topMaliciousIps.map(b => [b.key, b.count]) });
  blocks.push({ type: 'spacer' });

  if (ba.topPaths.length > 0) {
    blocks.push({ type: 'table', headers: ['Paths targeted by malicious bots', 'Events'], rows: ba.topPaths.map(b => [b.key, b.count]) });
    blocks.push({ type: 'spacer' });
  }

  const flagLabels = new Set(ba.fpRiskFlags.map(f => f.label));
  blocks.push({
    type: 'table',
    headers: ['Top user-agents in the Malicious set', 'Events', 'FP risk?'],
    rows: ba.topUserAgents.map(b => [b.key, b.count, flagLabels.has(b.key) ? 'YES — verify' : '']),
  });
  blocks.push({ type: 'spacer' });

  if (ba.topBotNames.length > 0) {
    blocks.push({ type: 'table', headers: ['Top bot names in the Malicious set', 'Events'], rows: ba.topBotNames.map(b => [b.key, b.count]) });
    blocks.push({ type: 'spacer' });
  }

  blocks.push({ type: 'table', headers: ['Top countries (malicious)', 'Events'], rows: ba.topCountries.map(b => [b.key, b.count]) });
  blocks.push({ type: 'spacer' });

  if (ba.topBotTypes.length > 0) {
    blocks.push({ type: 'table', headers: ['Bot type / category (malicious) — bot_info.type', 'Events'], rows: ba.topBotTypes.map(b => [b.key, b.count]) });
    blocks.push({ type: 'spacer' });
  }
  if (ba.topDetectionSources.length > 0) {
    blocks.push({ type: 'table', headers: ['Detection source — incl. bot signatures (malicious) — risk_score_info.source', 'Events'], rows: ba.topDetectionSources.map(b => [b.key, b.count]) });
    blocks.push({ type: 'spacer' });
  }
  if (ba.topAsOrgs.length > 0) {
    blocks.push({ type: 'table', headers: ['Top networks / AS org (malicious) — as_org', 'Events'], rows: ba.topAsOrgs.map(b => [b.key, b.count]) });
    blocks.push({ type: 'spacer' });
  }
  if (ba.reqRiskDist.length > 0) {
    blocks.push({ type: 'table', headers: ['AI req_risk among malicious bots', 'Events'], rows: ba.reqRiskDist.map(b => [b.key, b.count]) });
    blocks.push({ type: 'spacer' });
  }

  // Current handling vs F5 recommendation — the "allowed now → blocked after enforcing" point.
  if (ba.actionDist.length > 0 || ba.recommendationDist.length > 0) {
    blocks.push({ type: 'section', text: 'Current handling vs F5 recommendation' });
    if (ba.actionDist.length > 0) blocks.push({ type: 'table', headers: ['WAF action now — action', 'Events'], rows: ba.actionDist.map(b => [b.key, b.count]) });
    if (ba.recommendationDist.length > 0) blocks.push({ type: 'table', headers: ['F5 AI recommendation — recommended_action', 'Events'], rows: ba.recommendationDist.map(b => [b.key, b.count]) });
    blocks.push({ type: 'note', text: 'Malicious bots are ALLOWED today (monitoring) but F5 recommends BLOCK — switching this LB to Blocking will block them.' });
  }

  return { blocks, widths: [56, 60, 16] };
}

function buildSignaturesSheet(opts: FPExcelReportOptions): SheetSpec {
  const review = opts.signatureReviewStatus || {};
  const headers = [
    'Sig ID', 'Name', 'FP Verdict', 'Manual Review', 'FP Score', 'AI Risk', 'Events',
    'Unique IPs', 'Unique Paths', 'Accuracy', 'Attack Type', 'Auto Suppressed', 'Top Paths',
  ];
  const rows: CellVal[][] = opts.summary.signatures.map(s => [
    s.sigId,
    s.name,
    verdictLabel(s.fpVerdict),
    manualReviewLabel(review[s.sigId]),
    s.fpScore,
    aiRiskLabel(s.aiRisk),
    s.totalEvents,
    s.uniqueIPs,
    s.uniquePaths,
    s.accuracy,
    s.attackType,
    s.autoSuppressed ? 'Yes' : 'No',
    topPathsCell(s.topPaths),
  ]);
  return {
    blocks: [{
      type: 'table',
      headers,
      rows,
      freeze: true,
      grade: gradeByCol({ 2: v => gradeVerdict(String(v)), 5: v => gradeAiRisk(String(v)) }),
    }],
    widths: [15, 38, 16, 20, 9, 9, 9, 11, 12, 15, 22, 14, 50],
  };
}

function buildViolationsSheet(opts: FPExcelReportOptions): SheetSpec {
  const review = opts.violationReviewStatus || {};
  const headers = [
    'Violation Name', 'FP Verdict', 'Manual Review', 'FP Score', 'AI Risk', 'Attack Type',
    'Events', 'Unique Users', 'Unique Paths', 'Top Paths',
  ];
  const rows: CellVal[][] = opts.summary.violations.map(v => [
    v.violationName,
    verdictLabel(v.fpVerdict),
    manualReviewLabel(review[v.violationName]),
    v.fpScore,
    aiRiskLabel(v.aiRisk),
    v.attackType,
    v.totalEvents,
    v.uniqueUsers,
    v.uniquePaths,
    topPathsCell(v.topPaths),
  ]);
  return {
    blocks: [{
      type: 'table',
      headers,
      rows,
      freeze: true,
      grade: gradeByCol({ 1: v => gradeVerdict(String(v)), 4: v => gradeAiRisk(String(v)) }),
    }],
    widths: [40, 16, 20, 9, 9, 22, 9, 12, 12, 50],
  };
}

function buildExclusionRulesSheet(policy: WafExclusionPolicyObject): SheetSpec {
  const headers = [
    'Rule Name', 'Domain', 'Path', 'Methods',
    'Sig Exclusions', 'Violation Exclusions', 'Attack Type Exclusions',
    'Description',
  ];
  const rows: CellVal[][] = policy.spec.waf_exclusion_rules.map(rule => [
    rule.metadata.name,
    rule.any_domain ? 'any' : rule.exact_value || '',
    rule.any_path ? 'any' : rule.path_prefix || rule.path_regex || '',
    rule.methods.join(', ') || 'any',
    rule.app_firewall_detection_control.exclude_signature_contexts
      .map(s => `${s.signature_id} (${s.context}${s.context_name ? ': ' + s.context_name : ''})`)
      .join('\n'),
    rule.app_firewall_detection_control.exclude_violation_contexts
      .map(v => `${v.exclude_violation} (${v.context})`)
      .join('\n'),
    rule.app_firewall_detection_control.exclude_attack_type_contexts
      .map(a => `${a.exclude_attack_type} (${a.context})`)
      .join('\n'),
    rule.metadata.description || '',
  ]);
  return {
    blocks: [
      { type: 'title', text: 'WAF Exclusion Rules — apply ONLY after confirming a false positive' },
      { type: 'note', text: 'These rules are NOT a recommendation to apply them. They are provided ready-to-use ONLY in case you confirm a false positive and decide an exclusion rule is genuinely needed.' },
      { type: 'note', text: 'Before applying ANY rule below: (1) Manually confirm the flagged input is a genuine false positive (benign), not a real attack — review its matching values, the origin response code, and whether other clients trip the same path. (2) Check whether the AI-powered WAF already auto-allows it: if the request\'s req_risk is "false positive" or the signature state is AutoSuppressed, the AI already handles it and NO exclusion rule is needed — skip it.' },
      { type: 'note', text: 'Add a rule only when the false positive is CONFIRMED and the AI-powered WAF does NOT already allow it. Leaving Automatic Attack Signature Tuning ON lets the AI keep suppressing new false positives without manual exclusions.' },
      { type: 'spacer' },
      { type: 'table', headers, rows },
    ],
    widths: [25, 15, 40, 20, 50, 50, 40, 50],
  };
}

function buildThreatMeshSummarySheet(opts: FPExcelReportOptions): SheetSpec {
  const headers = [
    'Source IP', 'Country', 'AS Organization', 'Sec Events', 'Access Log Reqs',
    'Success Rate', 'Avg Req/Hour', 'Paths', 'Description', 'Action',
    'User Agent', 'Attack Types', 'Tenant Count',
    'Quick Verdict', 'Enriched Verdict', 'Enriched Score',
  ];
  const rows: CellVal[][] = opts.summary.threatMeshIPs.map(ip => [
    ip.srcIp,
    ip.country || '',
    ip.asOrg || '',
    ip.eventCount,
    ip.accessLogRequests ?? '',
    ip.successRate != null ? `${(ip.successRate * 100).toFixed(1)}%` : '',
    ip.avgReqPerHour != null ? ip.avgReqPerHour.toFixed(1) : '',
    ip.paths,
    ip.description,
    ip.action || '',
    ip.userAgent || '',
    (ip.attackTypes || []).join(', '),
    ip.tenantCount || 0,
    verdictLabel(ip.quickVerdict),
    ip.enrichedVerdict ? verdictLabel(ip.enrichedVerdict) : '',
    ip.enrichedScore ?? '',
  ]);
  return {
    blocks: [{
      type: 'table',
      headers,
      rows,
      freeze: true,
      grade: gradeByCol({ 13: v => gradeVerdict(String(v)), 14: v => gradeVerdict(String(v)) }),
    }],
    widths: [18, 12, 25, 12, 14, 12, 12, 8, 40, 10, 35, 30, 12, 18, 18, 12],
  };
}

function buildThreatMeshDetailSheet(details: ThreatMeshAnalysisUnit[]): SheetSpec {
  const headers = [
    'Source IP', 'User', 'Country', 'AS Org', 'User Agent',
    'Total Requests on App', 'WAF Events from IP',
    'Description', 'Attack Types', 'Tenant Count', 'Global Events',
    'High Accuracy Sigs', 'TLS Events', 'Malicious Bot Events',
    'Paths Accessed', 'Response Codes',
    'FP Score', 'Verdict', 'Reasons',
    'Suggested Action',
  ];
  const rows: CellVal[][] = details.map(ip => [
    ip.srcIp,
    ip.user || '',
    ip.country || '',
    ip.asOrg || '',
    ip.userAgent || '',
    ip.totalRequestsOnApp || 0,
    ip.wafEventsFromThisIP || 0,
    ip.threatDetails?.description || '',
    (ip.threatDetails?.attackTypes || []).join(', '),
    ip.threatDetails?.tenantCount || 0,
    ip.threatDetails?.events || 0,
    ip.threatDetails?.highAccuracySignatures || 0,
    ip.threatDetails?.tlsCount || 0,
    ip.threatDetails?.maliciousBotEvents || 0,
    ip.pathsAccessed ? topEntries(ip.pathsAccessed, 10) : '',
    ip.rspCodes ? topEntries(ip.rspCodes) : '',
    ip.fpScore,
    verdictLabel(ip.verdict),
    (ip.reasons || []).join('\n'),
    ip.suggestedAction || 'no_action',
  ]);
  return {
    blocks: [{
      type: 'table',
      headers,
      rows,
      freeze: true,
      grade: gradeByCol({ 17: v => gradeVerdict(String(v)) }),
    }],
    widths: [
      18, 20, 12, 25, 35,
      15, 12,
      40, 30, 12, 12,
      15, 12, 15,
      50, 30,
      10, 18, 50,
      18,
    ],
  };
}

function buildPolicyRulesSheet(opts: FPExcelReportOptions): SheetSpec {
  const headers = ['Rule Name', 'Policy Name', 'Total Blocked', 'Unique IPs'];
  const rows: CellVal[][] = opts.summary.policyRules.map(r => [
    r.ruleName,
    r.policyName,
    r.totalBlocked,
    r.uniqueIPs,
  ]);
  return {
    blocks: [{ type: 'table', headers, rows, freeze: true }],
    widths: [30, 30, 15, 12],
  };
}

// Blocking-Mode Comparison — which blocking policy to enable (folded in from the old standalone report).
function buildBlockingComparisonSheet(opts: FPExcelReportOptions): SheetSpec {
  const c = opts.summary.enforcementComparison!;
  const rec = c.policies.find(p => p.policy === c.recommended);
  const blocks: Block[] = [
    { type: 'title', text: 'WAF Blocking-Mode Comparison — which policy to enable for Blocking' },
    { type: 'spacer' },
    { type: 'meta', label: 'Requests analyzed (signatures + violations + malicious bots)', value: c.totalRequests },
    { type: 'meta', label: 'Requests with a real attack', value: c.totalTpRequests },
    { type: 'meta', label: 'All-false-positive requests', value: c.totalFpRequests },
    { type: 'spacer' },
    { type: 'meta', label: 'RECOMMENDED', value: rec?.label || c.recommended },
    { type: 'meta', label: 'Reason', value: c.recommendationReason },
    { type: 'meta', label: 'Legacy-only blocks (AI-High avoids)', value: c.legacyOnlyBlocked },
    { type: 'meta', label: 'AI-High-only blocks (legacy misses)', value: c.aiHighOnlyBlocked },
    { type: 'spacer' },
    {
      type: 'table',
      headers: ['Blocking policy', 'Requests blocked', 'Real-attack blocks', 'FP blocks', 'Ambiguous (review)', 'Attack coverage %', 'Attacks missed', 'Exclusion rules (overhead)', 'Recommended'],
      rows: c.policies.map(p => [
        p.label,
        p.blockedRequests,
        p.tpBlocked,
        p.fpBlocked,
        p.ambiguousBlocked,
        p.attackCoveragePct == null ? 'N/A' : Math.floor(p.attackCoveragePct * 100),
        p.attacksMissed,
        p.exclusionRulesNeeded,
        p.policy === c.recommended ? 'YES' : '',
      ]),
      grade: (row) => (String(row[row.length - 1]) === 'YES' ? { bold: true, fill: REC_FILL } : undefined),
    },
  ];

  // Plain-language findings & reasoning — makes the table self-explanatory.
  if (c.narrative && c.narrative.length > 0) {
    blocks.push({ type: 'spacer' });
    blocks.push({ type: 'section', text: 'Findings & reasoning' });
    for (const line of c.narrative) blocks.push({ type: 'note', text: line });
  }

  // FP-suppression detail — which WAF catches each false positive: traditional (signature state =
  // AutoSuppressed) vs AI (req_risk = "false positive"), with a verdict for which engine caught it.
  const fpSupp = opts.summary.wafComparison?.fpSuppression;
  if (fpSupp && fpSupp.length > 0) {
    blocks.push({ type: 'spacer' });
    blocks.push({ type: 'section', text: 'False-positive suppression — which WAF catches each FP (traditional state=AutoSuppressed vs AI req_risk=false positive)' });
    blocks.push({
      type: 'table',
      headers: ['Sig ID', 'Name', 'Events', 'Traditional AutoSuppressed', 'AI false positive', 'Traditional still blocks', 'Verdict'],
      rows: fpSupp.map(f => [f.sigId, f.name, f.events, f.autoSuppressed, f.aiFalsePositive, f.stillEnabled, f.verdict]),
      grade: (row, _r, c) => {
        if (c !== 6) return undefined;
        const v = String(row[6]);
        if (v.startsWith('AI')) return { font: TP_FONT, bold: true };
        if (v.startsWith('Traditional')) return { font: 'FF1D4ED8' };
        return undefined;
      },
    });
    blocks.push({ type: 'note', text: '"AI catches it — traditional still blocks" = the AI rates req_risk a false positive while the signature is still Enabled, so AI-powered WAF avoids a block the traditional engine would apply (one fewer exclusion rule). "Traditional catches it" = the engine AutoSuppressed it; the AI did not call it a false positive.' });
  }

  // Shared widths span both tables (policy table = 9 cols, FP-suppression = 7 cols).
  return { blocks, widths: [38, 34, 14, 14, 16, 16, 16, 30, 12] };
}

// ═══════════════════════════════════════════════════════════════════
// WORKBOOK ASSEMBLY (no DOM access — testable)
// ═══════════════════════════════════════════════════════════════════

export async function buildFPAnalysisWorkbook(opts: FPExcelReportOptions): Promise<ExcelJS.Workbook> {
  const wb = new ExcelJS.Workbook();
  wb.creator = 'F5 XC FP Analyzer';
  wb.created = new Date();

  const add = (name: string, spec: SheetSpec): void => renderSheet(wb.addWorksheet(name), spec.blocks, spec.widths);

  // Always add summary sheet
  add('Summary', buildSummarySheet(opts));

  if (opts.summary.recommendations && opts.summary.recommendations.steps.length > 0) {
    add('Next Steps', buildNextStepsSheet(opts));
  }

  // Findings first: signatures, violations, bots.
  if (opts.scopes.includes('waf_signatures') && opts.summary.signatures.length > 0) {
    add('WAF Signatures', buildSignaturesSheet(opts));
  }

  if (opts.scopes.includes('waf_violations') && opts.summary.violations.length > 0) {
    add('WAF Violations', buildViolationsSheet(opts));
  }

  if (opts.summary.botAnalysis) {
    // Always present when the Signature-based Bots scope ran — shows "none found" when empty.
    add('Malicious Bots', buildBotClassificationSheet(opts));
  }

  if (opts.scopes.includes('threat_mesh') && opts.summary.threatMeshIPs.length > 0) {
    add('Threat Mesh Summary', buildThreatMeshSummarySheet(opts));

    if (opts.threatMeshDetails && opts.threatMeshDetails.length > 0) {
      add('Threat Mesh Details', buildThreatMeshDetailSheet(opts.threatMeshDetails));
    }
  }

  if (opts.scopes.includes('service_policy') && opts.summary.policyRules.length > 0) {
    add('Service Policy', buildPolicyRulesSheet(opts));
  }

  // WAF Exclusion Rules sheet (the deployable policy).
  if (opts.exclusionPolicy && opts.exclusionPolicy.spec.waf_exclusion_rules.length > 0) {
    add('WAF Exclusion Rules', buildExclusionRulesSheet(opts.exclusionPolicy));
  }

  // Comparison LAST — Blocking-Mode: which policy to enable, incl. per-FP suppression detail.
  if (opts.summary.enforcementComparison && opts.summary.enforcementComparison.totalRequests > 0) {
    add('Blocking Comparison', buildBlockingComparisonSheet(opts));
  }

  return wb;
}

// ═══════════════════════════════════════════════════════════════════
// MAIN EXPORT (builds workbook, then triggers a browser download)
// ═══════════════════════════════════════════════════════════════════

export async function generateFPAnalysisExcel(opts: FPExcelReportOptions): Promise<void> {
  const wb = await buildFPAnalysisWorkbook(opts);
  const buf = await wb.xlsx.writeBuffer();
  const blob = new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `fp-analysis-${opts.lbName}-${new Date().toISOString().split('T')[0]}.xlsx`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
