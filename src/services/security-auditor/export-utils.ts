// ═══════════════════════════════════════════════════════════════════════════
// Security Auditor — Customer Export Utilities (load-balancer-centric)
//
//   • Excel (XLSX) — color-coded, multi-tab workbook (exceljs):
//        Tab 1  Summary           — score, KPIs, per-namespace AND per-LB tables
//        Tab 2  Security Checks    — every check explained (the catalog)
//        Tab 3+ <namespace>        — results grouped per load balancer
//   • CSV  — flat checklist (incl. Load Balancer column + Reviewed checkbox)
//   • PDF  — branded report (dual summary + per-namespace pages grouped by LB)
//   • JSON — machine-readable raw report
// ═══════════════════════════════════════════════════════════════════════════

import { allRules } from './rules';
import { CATEGORY_INFO, ENTITLEMENT_INFO } from './types';
import type {
  AuditReport, AuditFinding, CheckStatus, SecurityRule,
  NamespaceSummary, LoadBalancerSummary,
} from './types';

// ───────────────────────────────────────────────────────────────────────────
// Shared helpers
// ───────────────────────────────────────────────────────────────────────────

const OBJECT_TYPE_LABELS: Record<string, string> = {
  http_loadbalancer: 'HTTP Load Balancer',
  origin_pool: 'Origin Pool',
  app_firewall: 'App Firewall (WAF)',
  service_policy: 'Service Policy',
  healthcheck: 'Health Check',
  user_identification: 'User Identification',
  alert_policy: 'Alert Policy',
  alert_receiver: 'Alert Receiver',
  certificate: 'Certificate',
  global_log_receiver: 'Global Log Receiver',
};
const objectTypeLabel = (t: string): string => OBJECT_TYPE_LABELS[t] || t;

const lbLabel = (lb: string): string =>
  lb === '(tenant-wide)' ? 'Tenant-wide' : lb === '(unattached)' ? 'Unattached objects' : lb;

function resultLabel(status: CheckStatus): string {
  switch (status) {
    case 'PASS': return 'PASS';
    case 'FAIL': return 'FAIL';
    case 'WARN': return 'WARN';
    case 'INFO': return 'REVIEW';
    case 'ERROR': return 'ERROR';
    default: return 'N/A';
  }
}

function valueToText(v: unknown): string {
  if (v === undefined || v === null) return '';
  if (typeof v === 'object') { try { return JSON.stringify(v); } catch { return String(v); } }
  return String(v);
}

const ruleById = new Map(allRules.map((r) => [r.id, r]));

function expectedText(f: AuditFinding): string {
  if (f.expectedValue !== undefined && f.expectedValue !== null && f.expectedValue !== '') {
    return valueToText(f.expectedValue);
  }
  return ruleById.get(f.ruleId)?.expectedDisplay || '';
}
const actualText = (f: AuditFinding): string => valueToText(f.currentValue) || f.message || '';
const entLabel = (e: AuditFinding['entitlement']): string => ENTITLEMENT_INFO[e]?.label || e;

const timestampSlug = (report: AuditReport): string => report.timestamp.slice(0, 10);
const fileBase = (report: AuditReport): string => `xc-security-assessment-${report.tenant || 'tenant'}-${timestampSlug(report)}`;

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Sort: real LBs first (by ns, then lb), then unattached, then tenant-wide.
const lbRank = (lb: string) => (lb === '(unattached)' ? 1 : lb === '(tenant-wide)' ? 2 : 0);
function sortedLBSummary(report: AuditReport): LoadBalancerSummary[] {
  return [...report.loadBalancerSummary].sort(
    (a, b) => lbRank(a.loadBalancer) - lbRank(b.loadBalancer) || a.namespace.localeCompare(b.namespace) || a.loadBalancer.localeCompare(b.loadBalancer)
  );
}

// Severity priority: 1 = highest (Critical). Used for sorting/exports.
const SEV_RANK: Record<string, number> = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, INFO: 5 };
const RISK_RANK: Record<string, number> = { High: 0, Med: 1, Low: 2 };
const severityPriority = (f: AuditFinding): number => SEV_RANK[f.severity] ?? 5;

// The worst failing checks, ordered by severity then risk — the "fix first" list.
function topPriorities(report: AuditReport, limit: number): AuditFinding[] {
  return report.findings
    .filter((f) => f.status === 'FAIL')
    .sort(
      (a, b) =>
        severityPriority(a) - severityPriority(b) ||
        (RISK_RANK[a.risk] ?? 3) - (RISK_RANK[b.risk] ?? 3) ||
        a.ruleId.localeCompare(b.ruleId)
    )
    .slice(0, limit);
}

// ═══════════════════════════════════════════════════════════════════════════
// CSV — customer checklist (all checks, with Load Balancer column)
// ═══════════════════════════════════════════════════════════════════════════

const csvEscape = (value: string): string => (/[",\r\n]/.test(value ?? '') ? `"${(value ?? '').replace(/"/g, '""')}"` : value ?? '');

export function exportSecurityAuditCSV(report: AuditReport): void {
  const headers = [
    'Reviewed', 'Priority', 'Namespace', 'Load Balancer', 'Object Type', 'Object', 'Rule ID', 'Category',
    'Check', 'Actual Value', 'Expected', 'Result', 'Severity', 'Risk', 'Entitlement', 'Remediation', 'Reference',
  ];
  const lines: string[] = [];
  lines.push(csvEscape(`F5 XC Security Assessment — Tenant: ${report.tenant}`));
  lines.push(csvEscape(`Generated: ${report.timestamp}  |  Score: ${report.score}/100  |  Namespaces: ${report.namespaces.join('; ')}`));
  lines.push(csvEscape(`Critical: ${report.summary.critical}  High: ${report.summary.high}  Medium: ${report.summary.medium}  Passed: ${report.summary.passed}  Warnings: ${report.summary.warnings}`));
  lines.push('');
  lines.push(headers.map(csvEscape).join(','));

  // order by LB so the checklist reads load-balancer by load-balancer
  const ordered = [...report.findings].sort(
    (a, b) => lbRank(a.loadBalancer) - lbRank(b.loadBalancer) || a.namespace.localeCompare(b.namespace) || a.loadBalancer.localeCompare(b.loadBalancer)
  );
  for (const f of ordered) {
    // Priority = severity rank for FAIL rows (1=Critical); blank for non-failures.
    const priority = f.status === 'FAIL' ? String(severityPriority(f)) : '';
    lines.push([
      '', priority, f.namespace, lbLabel(f.loadBalancer), objectTypeLabel(f.objectType), f.objectName, f.ruleId,
      CATEGORY_INFO[f.category]?.label || f.category, f.ruleName,
      actualText(f), expectedText(f), resultLabel(f.status), f.severity, f.risk, entLabel(f.entitlement),
      f.remediation || '', f.referenceUrl || '',
    ].map((c) => csvEscape(String(c))).join(','));
  }

  downloadBlob(new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' }), `${fileBase(report)}.csv`);
}

// ═══════════════════════════════════════════════════════════════════════════
// EXCEL — color-coded multi-tab workbook (exceljs)
// ═══════════════════════════════════════════════════════════════════════════

const C = {
  headerNavy: 'FF1F3864', sectionBlue: 'FF2E75B6', lbBand: 'FF305496', white: 'FFFFFFFF',
  passFill: 'FFC6EFCE', passFont: 'FF006100',
  failFill: 'FFFFC7CE', failFont: 'FF9C0006',
  warnFill: 'FFFFEB9C', warnFont: 'FF7D4F00',
  infoFill: 'FFD6E8FB', infoFont: 'FF1F5F91',
  naFill: 'FFEDEDED', naFont: 'FF606060',
  riskHi: 'FFFCE4D6', riskMed: 'FFFFEB9C', riskLo: 'FFE2EFDA',
  entBase: 'FFE2EFDA', entAddon: 'FFFFF2CC', entConfig: 'FFEDEDED',
};

type XlsxCell = { value: string | number; bold?: boolean; fill?: string; font?: string; align?: 'left' | 'center' | 'right'; wrap?: boolean; size?: number };

// Controls that typically require an additional F5 subscription/SKU beyond the
// WAAP base bundle. Flagged in the sheet so customers confirm with their AM.
const needsAddOnSku = (f: AuditFinding): boolean => f.entitlement === 'Entitlement';
const SKU_CAVEAT =
  'Licensing: Some controls require an additional F5 subscription/SKU beyond the WAAP base bundle — notably Bot Defense, Malware Protection, Client-Side Defense, Rate Limiting and API Testing. Where a control is marked "$ Add-on", confirm entitlement with your F5 Account Team before planning remediation.';
const ACTION_OPTIONS = '"Open,Planned,In Progress,Completed,Not Applicable,Accepted Risk"';

function resultFill(status: CheckStatus): { fill: string; font: string } {
  switch (status) {
    case 'PASS': return { fill: C.passFill, font: C.passFont };
    case 'FAIL': return { fill: C.failFill, font: C.failFont };
    case 'WARN': return { fill: C.warnFill, font: C.warnFont };
    case 'INFO': return { fill: C.infoFill, font: C.infoFont };
    default: return { fill: C.naFill, font: C.naFont };
  }
}
const riskFill = (risk: string): string => (risk === 'High' ? C.riskHi : risk === 'Med' ? C.riskMed : C.riskLo);
const entFill = (ent: string): string => (ent === 'Base' ? C.entBase : ent === 'Entitlement' ? C.entAddon : C.entConfig);

export async function exportSecurityAuditExcel(report: AuditReport): Promise<void> {
  const mod = await import('exceljs');
  const ExcelJS = (mod as unknown as { default?: typeof import('exceljs') }).default ?? mod;
  const wb = new ExcelJS.Workbook();
  wb.creator = 'F5 XC Security Auditor';

  const thin = { style: 'thin' as const, color: { argb: 'FFD9D9D9' } };
  const border = { top: thin, left: thin, bottom: thin, right: thin };

  const write = (ws: import('exceljs').Worksheet, rowIdx: number, cells: XlsxCell[]) => {
    const row = ws.getRow(rowIdx);
    cells.forEach((c, i) => {
      const cell = row.getCell(i + 1);
      cell.value = c.value;
      cell.font = { name: 'Calibri', size: c.size ?? 10, bold: !!c.bold, color: { argb: c.font ?? 'FF1A1A1A' } };
      if (c.fill) cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: c.fill } };
      cell.alignment = { vertical: 'middle', horizontal: c.align ?? 'left', wrapText: c.wrap ?? false };
      cell.border = border;
    });
    return row;
  };

  const bandRow = (ws: import('exceljs').Worksheet, rowIdx: number, text: string, span: number, fill: string, size = 10) => {
    ws.mergeCells(rowIdx, 1, rowIdx, span);
    const c = ws.getCell(rowIdx, 1);
    c.value = text;
    c.font = { name: 'Calibri', size, bold: true, color: { argb: C.white } };
    c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: fill } };
    c.alignment = { vertical: 'middle', horizontal: 'left' };
    ws.getRow(rowIdx).height = size + 8;
  };

  const headerRow = (ws: import('exceljs').Worksheet, rowIdx: number, labels: string[]) =>
    write(ws, rowIdx, labels.map((l) => ({ value: l, bold: true, fill: C.headerNavy, font: C.white, align: 'center', size: 9, wrap: true })));

  const scoreCell = (score: number): XlsxCell => ({
    value: `${score}%`, align: 'center', bold: true,
    fill: score >= 80 ? C.passFill : score >= 50 ? C.warnFill : C.failFill,
    font: score >= 80 ? C.passFont : score >= 50 ? C.warnFont : C.failFont,
  });

  // ── Build per-load-balancer scopes (each LB becomes its own tab) ───────
  const scopeMap = new Map<string, { ns: string; lb: string; findings: AuditFinding[] }>();
  for (const f of report.findings) {
    const k = `${f.namespace}|${f.loadBalancer}`;
    if (!scopeMap.has(k)) scopeMap.set(k, { ns: f.namespace, lb: f.loadBalancer, findings: [] });
    scopeMap.get(k)!.findings.push(f);
  }
  const usedSheet = new Set(['overview & summary', 'controls reference']);
  const safeSheet = (raw: string): string => {
    const base = (raw || 'LB').replace(/[:\\/?*[\]]/g, ' ').trim().slice(0, 31) || 'LB';
    let name = base, n = 2;
    while (usedSheet.has(name.toLowerCase())) { const sfx = ` (${n++})`; name = base.slice(0, 31 - sfx.length).trim() + sfx; }
    usedSheet.add(name.toLowerCase());
    return name;
  };
  const scopes = [...scopeMap.values()]
    .sort((a, b) => lbRank(a.lb) - lbRank(b.lb) || a.ns.localeCompare(b.ns) || a.lb.localeCompare(b.lb))
    .map((s) => {
      const fail = s.findings.filter((f) => f.status === 'FAIL').length;
      const warn = s.findings.filter((f) => f.status === 'WARN').length;
      const reviews = s.findings.filter((f) => f.status === 'INFO').length;
      const pass = s.findings.filter((f) => f.status === 'PASS').length;
      const score = report.loadBalancerSummary.find((l) => l.namespace === s.ns && l.loadBalancer === s.lb)?.score ?? 0;
      const sheet = safeSheet(s.lb === '(tenant-wide)' ? 'Tenant-Wide' : lbLabel(s.lb));
      return { ...s, fail, warn, reviews, pass, actionable: fail + warn + reviews, score, sheet };
    });

  // Fixed tracker cells on each LB tab that the Overview formulas reference.
  const ACTION_FIRST = 7;        // first findings data row on each LB tab
  const TRK_TOTAL = 'C4';        // total action items (static)
  const TRK_RESOLVED = 'E4';     // resolved (COUNTIF formula)
  const overviewSheet = 'Overview & Summary';

  // ── TAB 1: OVERVIEW & SUMMARY ──────────────────────────────────────────
  {
    const COLS = 9;
    const ws = wb.addWorksheet(overviewSheet, { views: [{ showGridLines: false }] });
    ws.columns = [{ width: 26 }, { width: 34 }, { width: 10 }, { width: 9 }, { width: 9 }, { width: 9 }, { width: 14 }, { width: 12 }, { width: 13 }];

    bandRow(ws, 1, 'F5 Distributed Cloud — Application Security Assessment', COLS, C.headerNavy, 16);
    ws.getRow(1).height = 28;
    ws.mergeCells(2, 1, 2, COLS);
    const sub = ws.getCell(2, 1);
    sub.value = `Tenant: ${report.tenant || '—'}        Generated: ${report.timestamp.slice(0, 10)}        Namespaces: ${report.namespaces.join(', ')}`;
    sub.font = { name: 'Calibri', size: 10, color: { argb: 'FF555555' } };
    sub.alignment = { vertical: 'middle' };

    let r = 4;
    // Security posture: overall score + severity KPIs
    bandRow(ws, r, 'Security Posture', COLS, C.sectionBlue); r++;
    headerRow(ws, r, ['Overall Score', 'Critical', 'High', 'Medium', 'Low', 'Passed', 'Warnings', 'Skipped', 'Errors']); r++;
    write(ws, r, [
      scoreCell(report.score),
      { value: report.summary.critical, align: 'center', bold: true, fill: report.summary.critical > 0 ? C.failFill : C.naFill, font: report.summary.critical > 0 ? C.failFont : C.naFont },
      { value: report.summary.high, align: 'center', bold: true, fill: report.summary.high > 0 ? C.failFill : C.naFill, font: report.summary.high > 0 ? C.failFont : C.naFont },
      { value: report.summary.medium, align: 'center', bold: true, fill: report.summary.medium > 0 ? C.warnFill : C.naFill, font: report.summary.medium > 0 ? C.warnFont : C.naFont },
      { value: report.summary.low, align: 'center', fill: C.naFill, font: C.naFont },
      { value: report.summary.passed, align: 'center', bold: true, fill: C.passFill, font: C.passFont },
      { value: report.summary.warnings, align: 'center', fill: C.warnFill, font: C.warnFont },
      { value: report.summary.skipped, align: 'center', fill: C.naFill, font: C.naFont },
      { value: report.summary.errors, align: 'center', fill: C.naFill, font: C.naFont },
    ]);
    ws.getRow(r).height = 22; r += 2;

    // Action completeness tracker — formulas filled after the per-LB table below
    bandRow(ws, r, 'Action Completeness Tracker', COLS, C.sectionBlue); r++;
    headerRow(ws, r, ['Total Action Items', 'Resolved', 'Open', '% Complete', '', '', '', '', '']); r++;
    const trackerRow = r; r++;
    ws.mergeCells(r, 1, r, COLS);
    const note = ws.getCell(r, 1);
    note.value = 'Action Items = all Failed + Warning + Review (INFO) checks. Resolved = Completed + Not Applicable + Accepted Risk. Set the "Action" column on each load-balancer tab; this tracker updates automatically.';
    note.font = { name: 'Calibri', size: 9, italic: true, color: { argb: 'FF777777' } };
    note.alignment = { wrapText: true, vertical: 'top' };
    ws.getRow(r).height = 26; r += 2;

    // Per-load-balancer summary (clickable → opens each LB tab; live tracking)
    bandRow(ws, r, 'Per-Load-Balancer Summary   (click a load balancer to open its tab)', COLS, C.sectionBlue); r++;
    headerRow(ws, r, ['Namespace', 'Load Balancer', 'Score', 'Pass', 'Fail', 'Warn', 'Action Items', 'Resolved', '% Complete']); r++;
    const lbFirst = r;
    for (const s of scopes) {
      const title = s.lb === '(tenant-wide)' ? 'Tenant-Wide Checks' : lbLabel(s.lb);
      write(ws, r, [
        { value: s.ns },
        { value: '', wrap: true },
        scoreCell(s.score),
        { value: s.pass, align: 'center', fill: C.passFill, font: C.passFont },
        { value: s.fail, align: 'center', fill: s.fail > 0 ? C.failFill : undefined, font: s.fail > 0 ? C.failFont : undefined },
        { value: s.warn, align: 'center', fill: s.warn > 0 ? C.warnFill : undefined, font: s.warn > 0 ? C.warnFont : undefined },
        { value: '', align: 'center' },
        { value: '', align: 'center' },
        { value: '', align: 'center' },
      ]);
      const nameCell = ws.getCell(r, 2);
      nameCell.value = { text: title, hyperlink: `#'${s.sheet}'!A1` };
      nameCell.font = { name: 'Calibri', size: 10, bold: true, color: { argb: 'FF2563EB' }, underline: true };
      ws.getCell(r, 7).value = { formula: `'${s.sheet}'!${TRK_TOTAL}` };
      ws.getCell(r, 7).alignment = { horizontal: 'center' };
      ws.getCell(r, 8).value = { formula: `'${s.sheet}'!${TRK_RESOLVED}` };
      ws.getCell(r, 8).alignment = { horizontal: 'center' };
      const pc = ws.getCell(r, 9);
      pc.value = { formula: `IF(G${r}=0,1,H${r}/G${r})` };
      pc.numFmt = '0%';
      pc.alignment = { horizontal: 'center' };
      pc.font = { name: 'Calibri', size: 10, bold: true };
      r++;
    }
    const lbLast = r - 1;
    r += 1;

    // Fill tracker totals now that the per-LB table range is known
    const setTrk = (col: number, formula: string, pct = false) => {
      const c = ws.getCell(trackerRow, col);
      c.value = { formula };
      c.font = { name: 'Calibri', size: 13, bold: true, color: { argb: 'FF1F3864' } };
      c.alignment = { horizontal: 'center', vertical: 'middle' };
      c.border = border;
      if (pct) c.numFmt = '0%';
    };
    if (scopes.length > 0) {
      setTrk(1, `SUM(G${lbFirst}:G${lbLast})`);
      setTrk(2, `SUM(H${lbFirst}:H${lbLast})`);
      setTrk(3, `A${trackerRow}-B${trackerRow}`);
      setTrk(4, `IF(A${trackerRow}=0,1,B${trackerRow}/A${trackerRow})`, true);
    }

    // General remarks & licensing caveats
    bandRow(ws, r, 'General Remarks & Licensing Caveats', COLS, C.sectionBlue); r++;
    const remarks = [
      `$  ${SKU_CAVEAT}`,
      'How to use: On each load-balancer tab, set the "Action" column (Open / Planned / In Progress / Completed / Not Applicable / Accepted Risk) and add "Remarks". The tracker and per-LB % Complete update automatically.',
      'Scoring: severity-weighted — PASS = full credit, WARN = half, FAIL = none; N/A (skipped) checks are excluded from the score.',
      'Scope: HTTP Load Balancers and their attached objects (origin pools, WAF policies, certificates, service policies) plus tenant-wide logging/alerting.',
    ];
    for (const text of remarks) {
      ws.mergeCells(r, 1, r, COLS);
      const c = ws.getCell(r, 1);
      c.value = text;
      c.font = { name: 'Calibri', size: 10, color: { argb: text.startsWith('$') ? 'FF7D4F00' : 'FF333333' }, bold: text.startsWith('$') };
      if (text.startsWith('$')) c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFF6E6' } };
      c.alignment = { vertical: 'top', horizontal: 'left', wrapText: true };
      c.border = border;
      ws.getRow(r).height = 40;
      r++;
    }
    r += 1;

    // Top priorities (compact) — highest-severity failing checks
    const pri = topPriorities(report, 12);
    if (pri.length > 0) {
      bandRow(ws, r, 'Top Priorities — highest-severity failing checks', COLS, C.sectionBlue); r++;
      headerRow(ws, r, ['#', 'Severity', 'Namespace', 'Load Balancer', 'Control', 'Object', 'Risk', 'Add-on?', '']); r++;
      pri.forEach((f, i) => {
        const sevFill = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? C.failFill : f.severity === 'MEDIUM' ? C.warnFill : C.naFill;
        const sevFont = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? C.failFont : f.severity === 'MEDIUM' ? C.warnFont : C.naFont;
        write(ws, r, [
          { value: i + 1, align: 'center', size: 9 },
          { value: f.severity, align: 'center', bold: true, size: 9, fill: sevFill, font: sevFont },
          { value: f.namespace, size: 9 },
          { value: lbLabel(f.loadBalancer), size: 9, wrap: true },
          { value: `${f.ruleId} — ${f.ruleName}`, size: 9, wrap: true, bold: true },
          { value: `${objectTypeLabel(f.objectType)} — ${f.objectName}`, size: 9, wrap: true },
          { value: f.risk, align: 'center', size: 9, fill: riskFill(f.risk) },
          { value: needsAddOnSku(f) ? '$ Add-on' : '', align: 'center', size: 9, fill: needsAddOnSku(f) ? C.entAddon : undefined },
          { value: '' },
        ]);
        ws.getRow(r).height = 28;
        r++;
      });
    }
    ws.views = [{ showGridLines: false, state: 'frozen', ySplit: 3 }];
  }

  // ── ONE TAB PER LOAD BALANCER (Action + Remarks tracking) ──────────────
  const lbLabels = ['Status', 'Severity', 'Risk', 'Control', 'Category', 'Object', 'Current Value', 'Expected', 'Finding & Recommendation', 'Add-on?', 'Action', 'Remarks'];
  const lbWidths = [9, 10, 7, 30, 17, 24, 24, 22, 50, 11, 16, 30];
  const ACTION_COL = 11; // column K
  const sevSort: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const stSort: Record<string, number> = { FAIL: 0, WARN: 1, INFO: 2, ERROR: 3, PASS: 4, SKIP: 5 };

  for (const s of scopes) {
    const NC = lbLabels.length;
    const ws = wb.addWorksheet(s.sheet, { views: [{ showGridLines: false }] });
    ws.columns = lbWidths.map((w) => ({ width: w }));

    const title = s.lb === '(tenant-wide)' ? 'Tenant-Wide Checks' : lbLabel(s.lb);
    bandRow(ws, 1, `Load Balancer:  ${title}`, NC, C.headerNavy, 14);
    ws.mergeCells(2, 1, 2, NC);
    const sub = ws.getCell(2, 1);
    sub.value = `Namespace: ${s.ns}        Score: ${s.score}%        Checks: ${s.findings.length}   (Fail ${s.fail} · Warn ${s.warn} · Pass ${s.pass})`;
    sub.font = { name: 'Calibri', size: 10, color: { argb: 'FF555555' } };

    // Row 4: per-LB action tracker (live formulas reference the Action column)
    const trkLabel = (col: number, text: string) => {
      const c = ws.getCell(4, col);
      c.value = text;
      c.font = { name: 'Calibri', size: 10, bold: true, color: { argb: 'FF1F3864' } };
      c.alignment = { horizontal: 'right', vertical: 'middle' };
    };
    const trkVal = (col: number, value: import('exceljs').CellValue, pct = false) => {
      const c = ws.getCell(4, col);
      c.value = value;
      c.font = { name: 'Calibri', size: 12, bold: true, color: { argb: 'FF1A1A1A' } };
      c.alignment = { horizontal: 'center', vertical: 'middle' };
      c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFEFF3FA' } };
      c.border = border;
      if (pct) c.numFmt = '0%';
    };
    ws.getCell(4, 1).value = 'Action Tracker';
    ws.getCell(4, 1).font = { name: 'Calibri', size: 11, bold: true, color: { argb: 'FF1F3864' } };
    trkLabel(2, 'Total:'); trkVal(3, s.actionable);            // C4
    trkLabel(4, 'Resolved:');                                  // E4 (formula below)
    trkLabel(6, 'Open:');                                      // G4 (formula below)
    trkLabel(8, '% Complete:');                                // I4 (formula below)
    const back = ws.getCell(4, NC);
    back.value = { text: '↩ Overview', hyperlink: `#'${overviewSheet}'!A1` };
    back.font = { name: 'Calibri', size: 10, color: { argb: 'FF2563EB' }, underline: true };
    back.alignment = { horizontal: 'right' };

    // Header + findings (Failures/Warnings first so action items are contiguous)
    headerRow(ws, 6, lbLabels);
    const sorted = [...s.findings].sort(
      (a, b) => (stSort[a.status] ?? 5) - (stSort[b.status] ?? 5) || (sevSort[a.severity] ?? 5) - (sevSort[b.severity] ?? 5) || a.ruleId.localeCompare(b.ruleId)
    );
    let r = ACTION_FIRST;
    if (sorted.length === 0) {
      write(ws, r, [{ value: 'No checks for this scope.', fill: C.naFill, font: C.naFont }]);
      ws.mergeCells(r, 1, r, NC);
      r++;
    }
    for (const f of sorted) {
      const rf = resultFill(f.status);
      const isAction = f.status === 'FAIL' || f.status === 'WARN' || f.status === 'INFO';
      const sku = needsAddOnSku(f);
      const recommendation = isAction
        ? `${f.message || ''}${f.remediation ? '   →  ' + f.remediation : ''}`
        : (f.message || '');
      write(ws, r, [
        { value: resultLabel(f.status), align: 'center', bold: true, size: 9, fill: rf.fill, font: rf.font },
        { value: f.severity, align: 'center', size: 9 },
        { value: f.risk, align: 'center', size: 9, fill: riskFill(f.risk) },
        { value: `${f.ruleId} — ${f.ruleName}`, bold: true, size: 9, wrap: true },
        { value: CATEGORY_INFO[f.category]?.label || f.category, size: 9, wrap: true },
        { value: `${objectTypeLabel(f.objectType)} — ${f.objectName}`, size: 9, wrap: true },
        { value: actualText(f), size: 9, wrap: true },
        { value: expectedText(f), size: 9, wrap: true },
        { value: recommendation, size: 9, wrap: true },
        { value: sku ? '$ Add-on' : '', align: 'center', size: 9, fill: sku ? C.entAddon : undefined, font: sku ? 'FF7D4F00' : undefined },
        { value: isAction ? 'Open' : '—', align: 'center', size: 9, bold: isAction, fill: isAction ? 'FFFFFFFF' : C.naFill, font: isAction ? 'FF1A1A1A' : C.naFont },
        { value: '', size: 9, wrap: true },
      ]);
      ws.getRow(r).height = 30;
      if (isAction) {
        ws.getCell(r, ACTION_COL).dataValidation = { type: 'list', allowBlank: true, formulae: [ACTION_OPTIONS] };
      }
      r++;
    }

    // Tracker formulas over the (contiguous) action range
    const lastAction = ACTION_FIRST + s.actionable - 1;
    const rng = s.actionable > 0 ? `K${ACTION_FIRST}:K${lastAction}` : `K${ACTION_FIRST}:K${ACTION_FIRST}`;
    trkVal(5, { formula: `COUNTIF(${rng},"Completed")+COUNTIF(${rng},"Not Applicable")+COUNTIF(${rng},"Accepted Risk")` }); // E4
    trkVal(7, { formula: `C4-E4` });                                                                                      // G4
    trkVal(9, { formula: `IF(C4=0,1,E4/C4)` }, true);                                                                     // I4

    ws.autoFilter = { from: { row: 6, column: 1 }, to: { row: 6, column: NC } };
    ws.views = [{ showGridLines: false, state: 'frozen', ySplit: 6 }];
  }

  // ── FINAL TAB: CONTROLS REFERENCE (the full catalog) ───────────────────
  {
    const ws = wb.addWorksheet('Controls Reference', { views: [{ showGridLines: false }] });
    const labels = ['Rule ID', 'Category', 'Control', 'What it verifies & why', 'Expected', 'Severity', 'Risk', 'Entitlement', 'Applies To'];
    ws.columns = [10, 18, 30, 60, 24, 10, 8, 14, 22].map((w) => ({ width: w }));
    bandRow(ws, 1, 'Controls Reference — what each check verifies', labels.length, C.headerNavy, 14);
    headerRow(ws, 2, labels);

    const byCat = new Map<string, SecurityRule[]>();
    for (const rule of allRules) {
      const k = CATEGORY_INFO[rule.category]?.label || rule.category;
      if (!byCat.has(k)) byCat.set(k, []);
      byCat.get(k)!.push(rule);
    }
    let r = 3;
    for (const [cat, rules] of [...byCat.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      bandRow(ws, r, cat, labels.length, C.sectionBlue); r++;
      for (const rule of rules) {
        const ent = rule.entitlement ?? 'Base';
        const risk = rule.risk ?? (rule.severity === 'CRITICAL' || rule.severity === 'HIGH' ? 'High' : rule.severity === 'MEDIUM' ? 'Med' : 'Low');
        write(ws, r, [
          { value: rule.id, bold: true, size: 9 },
          { value: CATEGORY_INFO[rule.category]?.label || rule.category, size: 9, wrap: true },
          { value: rule.name, bold: true, size: 9, wrap: true },
          { value: rule.description, size: 9, wrap: true },
          { value: rule.expectedDisplay || '', size: 9, wrap: true },
          { value: rule.severity, align: 'center', size: 9 },
          { value: risk, align: 'center', size: 9, fill: riskFill(risk) },
          { value: ENTITLEMENT_INFO[ent].label === 'Add-on' ? 'Add-on ($)' : ENTITLEMENT_INFO[ent].label, align: 'center', size: 9, fill: entFill(ent) },
          { value: rule.appliesTo.map(objectTypeLabel).join(', '), size: 8, wrap: true },
        ]);
        ws.getRow(r).height = 30;
        r++;
      }
    }
    ws.views = [{ showGridLines: false, state: 'frozen', ySplit: 2 }];
  }

  const buf = await wb.xlsx.writeBuffer();
  downloadBlob(
    new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }),
    `${fileBase(report)}.xlsx`
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// PDF — branded report (dual summary + per-namespace pages grouped by LB)
// ═══════════════════════════════════════════════════════════════════════════

const PDF = {
  blue: [37, 99, 235] as [number, number, number],
  navy: [31, 56, 100] as [number, number, number],
  dark: [30, 41, 59] as [number, number, number],
  gray: [100, 116, 139] as [number, number, number],
  green: [22, 163, 74] as [number, number, number],
  red: [220, 38, 38] as [number, number, number],
  amber: [217, 119, 6] as [number, number, number],
};
const MARGIN = 14;
const scoreColor = (s: number): [number, number, number] => (s >= 80 ? PDF.green : s >= 60 ? PDF.amber : PDF.red);

export async function exportSecurityAuditPDF(report: AuditReport): Promise<void> {
  const { default: jsPDF } = await import('jspdf');
  const autoTable = (await import('jspdf-autotable')).default;

  const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  let y = MARGIN;

  doc.setFontSize(20); doc.setFont('helvetica', 'bold'); doc.setTextColor(...PDF.blue);
  doc.text('F5 XC Security Assessment', MARGIN, y); y += 8;
  doc.setFontSize(9); doc.setFont('helvetica', 'normal'); doc.setTextColor(...PDF.gray);
  doc.text(`Tenant: ${report.tenant || 'unknown'}    Generated: ${report.timestamp}`, MARGIN, y); y += 4.5;
  doc.text(`Namespaces: ${report.namespaces.join(', ')}`, MARGIN, y); y += 9;

  const sc = scoreColor(report.score);
  doc.setFontSize(26); doc.setFont('helvetica', 'bold'); doc.setTextColor(...sc);
  doc.text(`${report.score}/100`, MARGIN, y);
  doc.setFontSize(9); doc.setFont('helvetica', 'normal'); doc.setTextColor(...PDF.gray);
  doc.text('Security Score', MARGIN, y + 5);

  const s = report.summary; const es = report.entitlementSummary;
  doc.setFontSize(10); doc.setTextColor(...PDF.dark);
  doc.text(`Critical: ${s.critical}    High: ${s.high}    Medium: ${s.medium}    Low: ${s.low}`, MARGIN + 55, y - 6);
  doc.text(`Passed: ${s.passed}    Warnings: ${s.warnings}    Errors: ${s.errors}`, MARGIN + 55, y - 1);
  doc.setTextColor(...PDF.gray);
  doc.text(`Failing gaps — config/base fixes: ${es.baseFails + es.configFails}    require licensed add-on: ${es.entitlementFails}`, MARGIN + 55, y + 4);
  y += 12;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const nextY = () => (doc as any).lastAutoTable.finalY + 7;

  // Per-namespace summary table
  doc.setFontSize(11); doc.setFont('helvetica', 'bold'); doc.setTextColor(...PDF.navy);
  doc.text('Per-Namespace Summary', MARGIN, y); y += 2;
  autoTable(doc, {
    startY: y,
    head: [['Namespace', 'Load Balancers', 'Passed', 'Failed', 'Warnings', 'Score']],
    body: report.namespaceSummary.map((n: NamespaceSummary) => [n.namespace, n.loadBalancers, n.pass, n.fail, n.warn, `${n.score}%`]),
    margin: { left: MARGIN, right: MARGIN },
    styles: { fontSize: 8, cellPadding: 1.5 },
    headStyles: { fillColor: PDF.navy, textColor: 255 },
    theme: 'striped',
  });
  y = nextY();

  // Per-load-balancer summary table
  doc.setFontSize(11); doc.setFont('helvetica', 'bold'); doc.setTextColor(...PDF.navy);
  if (y > doc.internal.pageSize.getHeight() - 40) { doc.addPage(); y = MARGIN; }
  doc.text('Per-Load-Balancer Summary', MARGIN, y); y += 2;
  autoTable(doc, {
    startY: y,
    head: [['Namespace', 'Load Balancer', 'Passed', 'Failed', 'Warnings', 'Score']],
    body: sortedLBSummary(report).map((l) => [l.namespace, lbLabel(l.loadBalancer), l.pass, l.fail, l.warn, `${l.score}%`]),
    margin: { left: MARGIN, right: MARGIN },
    styles: { fontSize: 8, cellPadding: 1.5 },
    headStyles: { fillColor: PDF.navy, textColor: 255 },
    theme: 'striped',
  });

  // Top Priorities — fix-first list, on its own page
  const priorities = topPriorities(report, 25);
  if (priorities.length > 0) {
    doc.addPage();
    y = MARGIN;
    doc.setFontSize(13); doc.setFont('helvetica', 'bold'); doc.setTextColor(...PDF.red);
    doc.text('Top Priorities — fix these first', MARGIN, y); y += 6;
    autoTable(doc, {
      startY: y,
      head: [['#', 'Severity', 'Namespace', 'Load Balancer', 'Object', 'Check', 'Risk', 'Remediation']],
      body: priorities.map((f, i) => [
        i + 1, f.severity, f.namespace, lbLabel(f.loadBalancer),
        `${objectTypeLabel(f.objectType)}\n${f.objectName}`, f.ruleName, f.risk, f.remediation || '',
      ]),
      margin: { left: MARGIN, right: MARGIN },
      styles: { fontSize: 6.6, cellPadding: 1.1, overflow: 'linebreak', valign: 'top' },
      headStyles: { fillColor: PDF.navy, textColor: 255, fontSize: 7 },
      alternateRowStyles: { fillColor: [245, 247, 250] },
      columnStyles: {
        0: { cellWidth: 8, halign: 'center' }, 1: { cellWidth: 18, halign: 'center', fontStyle: 'bold' },
        2: { cellWidth: 24 }, 3: { cellWidth: 30 }, 4: { cellWidth: 34 }, 5: { cellWidth: 44 },
        6: { cellWidth: 13, halign: 'center' }, 7: { cellWidth: 78 },
      },
      theme: 'striped',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      didParseCell: (data: any) => {
        if (data.section !== 'body') return;
        if (data.column.index === 1) {
          const raw = String(data.cell.raw ?? '');
          data.cell.styles.textColor = raw === 'CRITICAL' || raw === 'HIGH' ? PDF.red : raw === 'MEDIUM' ? PDF.amber : PDF.gray;
        }
      },
    });
  }

  // Per-namespace detail, grouped/sorted by load balancer
  const byNs = new Map<string, AuditFinding[]>();
  for (const f of report.findings) {
    if (!byNs.has(f.namespace)) byNs.set(f.namespace, []);
    byNs.get(f.namespace)!.push(f);
  }
  const resultColor = (st: CheckStatus): [number, number, number] =>
    st === 'PASS' ? PDF.green : st === 'FAIL' ? PDF.red : st === 'WARN' ? PDF.amber : PDF.gray;
  const statusSort: Record<string, number> = { FAIL: 0, WARN: 1, PASS: 2, ERROR: 3, SKIP: 4 };

  for (const [ns, findings] of [...byNs.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    doc.addPage();
    y = MARGIN;
    doc.setFontSize(13); doc.setFont('helvetica', 'bold'); doc.setTextColor(...PDF.navy);
    doc.text(`Namespace: ${ns}`, MARGIN, y); y += 6;

    const ordered = [...findings].sort(
      (a, b) =>
        lbRank(a.loadBalancer) - lbRank(b.loadBalancer) ||
        a.loadBalancer.localeCompare(b.loadBalancer) ||
        (statusSort[a.status] ?? 5) - (statusSort[b.status] ?? 5)
    );

    autoTable(doc, {
      startY: y,
      head: [['Load Balancer', 'Object', 'Check', 'Expected', 'Actual', 'Result', 'Risk', 'Entl.']],
      body: ordered.map((f) => [
        lbLabel(f.loadBalancer),
        `${objectTypeLabel(f.objectType)}\n${f.objectName}`,
        f.ruleName, expectedText(f), actualText(f), resultLabel(f.status), f.risk, entLabel(f.entitlement),
      ]),
      margin: { left: MARGIN, right: MARGIN },
      styles: { fontSize: 6.6, cellPadding: 1.1, overflow: 'linebreak', valign: 'top' },
      headStyles: { fillColor: PDF.navy, textColor: 255, fontSize: 7 },
      alternateRowStyles: { fillColor: [245, 247, 250] },
      columnStyles: {
        0: { cellWidth: 32 }, 1: { cellWidth: 34 }, 2: { cellWidth: 44 }, 3: { cellWidth: 34 }, 4: { cellWidth: 44 },
        5: { cellWidth: 15, halign: 'center', fontStyle: 'bold' }, 6: { cellWidth: 13, halign: 'center' }, 7: { cellWidth: 14, halign: 'center' },
      },
      theme: 'striped',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      didParseCell: (data: any) => {
        if (data.section !== 'body') return;
        const raw = String(data.cell.raw ?? '');
        if (data.column.index === 5) data.cell.styles.textColor = resultColor(raw as CheckStatus);
        if (data.column.index === 6) data.cell.styles.textColor = raw === 'High' ? PDF.red : raw === 'Med' ? PDF.amber : PDF.green;
      },
    });
  }

  // Catalog page
  doc.addPage(); y = MARGIN;
  doc.setFontSize(13); doc.setFont('helvetica', 'bold'); doc.setTextColor(...PDF.navy);
  doc.text('Security Checks — what each check verifies', MARGIN, y); y += 6;
  autoTable(doc, {
    startY: y,
    head: [['Rule ID', 'Check', 'What it verifies & why', 'Expected', 'Sev', 'Risk', 'Entl.']],
    body: allRules.map((rule) => {
      const ent = rule.entitlement ?? 'Base';
      const risk = rule.risk ?? (rule.severity === 'CRITICAL' || rule.severity === 'HIGH' ? 'High' : rule.severity === 'MEDIUM' ? 'Med' : 'Low');
      return [rule.id, rule.name, rule.description, rule.expectedDisplay || '', rule.severity, risk, ENTITLEMENT_INFO[ent].label];
    }),
    margin: { left: MARGIN, right: MARGIN },
    styles: { fontSize: 6.8, cellPadding: 1.2, overflow: 'linebreak', valign: 'top' },
    headStyles: { fillColor: PDF.navy, textColor: 255, fontSize: 7 },
    alternateRowStyles: { fillColor: [245, 247, 250] },
    columnStyles: {
      0: { cellWidth: 16 }, 1: { cellWidth: 42 }, 2: { cellWidth: 95 }, 3: { cellWidth: 34 },
      4: { cellWidth: 16, halign: 'center' }, 5: { cellWidth: 14, halign: 'center' }, 6: { cellWidth: 16, halign: 'center' },
    },
    theme: 'striped',
  });

  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    const pageH = doc.internal.pageSize.getHeight();
    doc.setFontSize(7); doc.setFont('helvetica', 'normal'); doc.setTextColor(...PDF.gray);
    doc.text('Entl. = Entitlement (Base = included, Add-on = licensed SKU, Config = config-only)', MARGIN, pageH - 6);
    doc.text(`Page ${i} of ${pageCount}  |  F5 XC Security Auditor`, pageWidth - MARGIN, pageH - 6, { align: 'right' });
  }

  doc.save(`${fileBase(report)}.pdf`);
}

// ═══════════════════════════════════════════════════════════════════════════
// JSON
// ═══════════════════════════════════════════════════════════════════════════

export function exportSecurityAuditJSON(report: AuditReport): void {
  downloadBlob(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }), `${fileBase(report)}.json`);
}
