/**
 * FP Analysis PDF Report Generator
 *
 * Generates a comprehensive PDF report using jsPDF + jspdf-autotable.
 * Follows the pattern from rate-limit-advisor/pdf-report-generator.ts.
 */

import jsPDF from 'jspdf';
import autoTablePlugin from 'jspdf-autotable';
import type {
  AnalysisScope,
  AnalysisMode,
  SummaryResult,
  SignatureSummary,
  ViolationSummary,
  ThreatMeshSummary,
  PolicyRuleSummary,
  ThreatMeshAnalysisUnit,
  SignatureAnalysisUnit,
  ViolationAnalysisUnit,
  WafExclusionPolicyObject,
} from './types';

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export interface FPReportOptions {
  summary: SummaryResult;
  scopes: AnalysisScope[];
  namespace: string;
  lbName: string;
  mode?: AnalysisMode;
  threatMeshDetails?: ThreatMeshAnalysisUnit[];
  signatureDetails?: SignatureAnalysisUnit[];
  violationDetails?: ViolationAnalysisUnit[];
  exclusionPolicy?: WafExclusionPolicyObject;
}

// ═══════════════════════════════════════════════════════════════════
// COLORS & CONSTANTS
// ═══════════════════════════════════════════════════════════════════

const BLUE = [59, 130, 246] as const;
const DARK = [30, 41, 59] as const;
const GRAY = [100, 116, 139] as const;
const GREEN = [34, 197, 94] as const;
const RED = [239, 68, 68] as const;
const AMBER = [245, 158, 11] as const;
const PAGE_MARGIN = 20;
const CONTENT_WIDTH = 170;

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function ensureSpace(doc: jsPDF, y: number, needed: number): number {
  if (y + needed > doc.internal.pageSize.getHeight() - 25) {
    doc.addPage();
    return PAGE_MARGIN;
  }
  return y;
}

function sectionTitle(doc: jsPDF, title: string, y: number): number {
  y = ensureSpace(doc, y, 20);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...BLUE);
  doc.text(title, PAGE_MARGIN, y);
  y += 2;
  doc.setDrawColor(...BLUE);
  doc.setLineWidth(0.5);
  doc.line(PAGE_MARGIN, y, PAGE_MARGIN + CONTENT_WIDTH, y);
  doc.setTextColor(...DARK);
  return y + 8;
}

function n(num: number): string {
  return num.toLocaleString();
}

function autoTable(doc: jsPDF, opts: Record<string, unknown>): number {
  autoTablePlugin(doc, opts);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (doc as any).lastAutoTable.finalY + 8;
}

function verdictColor(verdict: string): readonly [number, number, number] {
  if (verdict.includes('likely_fp') || verdict === 'highly_likely_fp') return GREEN;
  if (verdict.includes('likely_tp') || verdict === 'confirmed_tp') return RED;
  return AMBER;
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

function truncate(str: string, max: number): string {
  return str.length > max ? str.slice(0, max - 3) + '...' : str;
}

function topEntries(record: Record<string, number>, count = 5): string {
  return Object.entries(record)
    .sort((a, b) => b[1] - a[1])
    .slice(0, count)
    .map(([k, v]) => `${k} (${v})`)
    .join(', ');
}

// ═══════════════════════════════════════════════════════════════════
// PDF SECTIONS
// ═══════════════════════════════════════════════════════════════════

function addHeader(doc: jsPDF, opts: FPReportOptions): number {
  let y = 25;

  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...BLUE);
  doc.text('False Positive Analysis Report', PAGE_MARGIN, y);
  y += 10;

  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...GRAY);
  doc.text(`Load Balancer: ${opts.lbName}`, PAGE_MARGIN, y);
  y += 5;
  doc.text(`Namespace: ${opts.namespace}`, PAGE_MARGIN, y);
  y += 5;
  doc.text(`Scopes: ${opts.scopes.join(', ')}`, PAGE_MARGIN, y);
  y += 5;

  const start = new Date(opts.summary.period.start).toLocaleString();
  const end = new Date(opts.summary.period.end).toLocaleString();
  doc.text(`Analysis Period: ${start}  —  ${end}`, PAGE_MARGIN, y);
  y += 5;
  doc.text(`Generated: ${new Date().toLocaleString()}`, PAGE_MARGIN, y);
  y += 3;

  doc.setDrawColor(...BLUE);
  doc.setLineWidth(1);
  doc.line(PAGE_MARGIN, y, PAGE_MARGIN + CONTENT_WIDTH, y);

  return y + 10;
}

function addExecutiveSummary(doc: jsPDF, summary: SummaryResult, scopes: AnalysisScope[], y: number): number {
  y = sectionTitle(doc, 'Executive Summary', y);

  const col1 = PAGE_MARGIN;
  const col2 = PAGE_MARGIN + 45;
  const col3 = PAGE_MARGIN + 90;
  const col4 = PAGE_MARGIN + 135;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...GRAY);
  doc.text('Total Events', col1, y);
  doc.text('Signatures', col2, y);
  doc.text('Violations', col3, y);
  doc.text('Threat Mesh IPs', col4, y);
  y += 5;
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...DARK);
  doc.text(n(summary.totalEvents), col1, y);
  doc.text(String(summary.signatures.length), col2, y);
  doc.text(String(summary.violations.length), col3, y);
  doc.text(String(summary.threatMeshIPs.length), col4, y);
  y += 10;

  // Scope breakdown
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...GRAY);
  doc.text(`Scopes analyzed: ${scopes.map(s => s.replace(/_/g, ' ')).join(', ')}`, PAGE_MARGIN, y);
  y += 5;

  if (summary.policyRules.length > 0) {
    doc.text(`Service Policy Rules: ${summary.policyRules.length}`, PAGE_MARGIN, y);
    y += 5;
  }

  return y + 5;
}

function addRecommendations(doc: jsPDF, summary: SummaryResult, y: number): number {
  const rec = summary.recommendations;
  if (!rec || rec.steps.length === 0) return y;
  y = sectionTitle(doc, 'Recommendations & Next Steps', y);

  doc.setFontSize(8); doc.setFont('helvetica', 'normal'); doc.setTextColor(...GRAY);
  const intro = `Goal: tune out false positives, then move this load balancer ${rec.enforcementMode === 'blocking' ? 'to a verified Blocking state' : 'from Monitoring to Blocking'} with AI-powered WAF protection.`;
  const introLines = doc.splitTextToSize(intro, CONTENT_WIDTH) as string[];
  doc.text(introLines, PAGE_MARGIN, y); y += introLines.length * 4 + 3;

  for (const s of rec.steps) {
    y = ensureSpace(doc, y, 16);
    doc.setFont('helvetica', 'bold'); doc.setFontSize(9); doc.setTextColor(...DARK);
    doc.text(`${s.num}. ${s.title}`, PAGE_MARGIN, y); y += 4;
    doc.setFont('helvetica', 'normal'); doc.setFontSize(8); doc.setTextColor(...GRAY);
    const dl = doc.splitTextToSize(s.detail, CONTENT_WIDTH - 5) as string[];
    doc.text(dl, PAGE_MARGIN + 5, y); y += dl.length * 4 + 2;
  }

  if (rec.excludeList.length > 0) {
    doc.setFont('helvetica', 'bold'); doc.setFontSize(8); doc.setTextColor(...GRAY);
    y = ensureSpace(doc, y + 1, 14); doc.text(`False positives to exclude (${rec.excludeList.length}):`, PAGE_MARGIN, y); y += 2;
    y = autoTable(doc, {
      startY: y, head: [['Type', 'ID', 'Name', 'Verdict']],
      body: rec.excludeList.slice(0, 40).map(e => [e.kind, e.id, truncate(e.name, 55), verdictLabel(e.verdict)]),
      theme: 'striped', headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 7 }, styles: { fontSize: 7, cellPadding: 1.5 }, margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    });
  }
  if (rec.investigateList.length > 0) {
    doc.setFont('helvetica', 'bold'); doc.setFontSize(8); doc.setTextColor(...GRAY);
    y = ensureSpace(doc, y + 1, 14); doc.text(`Investigate & manually confirm — do NOT auto-exclude (${rec.investigateList.length}):`, PAGE_MARGIN, y); y += 2;
    y = autoTable(doc, {
      startY: y, head: [['Type', 'ID', 'Name / Reason']],
      body: rec.investigateList.slice(0, 40).map(e => [e.kind, e.id, truncate(`${e.name} — ${e.reason}`, 90)]),
      theme: 'striped', headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 7 }, styles: { fontSize: 7, cellPadding: 1.5 }, margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    });
  }
  if (rec.autoHandledList.length > 0) {
    doc.setFont('helvetica', 'normal'); doc.setFontSize(8); doc.setTextColor(...GRAY);
    y = ensureSpace(doc, y + 1, 10);
    const note = doc.splitTextToSize(`Note: ${rec.autoHandledList.length} finding(s) are already auto-suppressed by F5's AI false-positive detection — no exclusion rule is needed for them.`, CONTENT_WIDTH) as string[];
    doc.text(note, PAGE_MARGIN, y); y += note.length * 4 + 2;
  }
  return y + 5;
}

function addWafComparison(doc: jsPDF, summary: SummaryResult, y: number): number {
  const wc = summary.wafComparison;
  if (!wc || wc.totalEvents === 0) return y;
  y = sectionTitle(doc, 'Traditional vs AI-Powered WAF', y);

  const pct = (x: number) => `${(x * 100).toFixed(0)}%`;
  // Plain-language headline (analysis — the action plan is in Recommendations above)
  doc.setFontSize(9); doc.setFont('helvetica', 'normal'); doc.setTextColor(...DARK);
  const headLines = doc.splitTextToSize(wc.headline, CONTENT_WIDTH) as string[];
  doc.text(headLines, PAGE_MARGIN, y); y += headLines.length * 4.5 + 3;
  doc.setFontSize(8); doc.setTextColor(...GRAY);
  if (wc.enforcementNote) {
    const noteLines = doc.splitTextToSize(`! ${wc.enforcementNote}`, CONTENT_WIDTH) as string[];
    doc.text(noteLines, PAGE_MARGIN, y); y += noteLines.length * 4 + 2;
  }
  doc.text(`FP-block reduction if AI enabled: ${pct(wc.fpReductionOpportunityPct)}   |   AI-benign got origin 200: ${pct(wc.aiBenignOrigin200Pct)}   |   engine<->AI agreement: ${pct(wc.agreementPct)}   |   already AutoSuppressed: ${n(wc.alreadySuppressedByAi)}   |   AI coverage: ${pct(wc.aiDataCoveragePct)}`, PAGE_MARGIN, y);
  y += 5;

  y = autoTable(doc, {
    startY: y,
    head: [['Engine state \\ AI verdict', 'AI: Attack (high/med)', 'AI: Benign (low/FP)']],
    body: [
      ['Signature Enabled', `${n(wc.matrix.bothAttack)}  (agree: attack)`, `${n(wc.matrix.engineActiveAiBenign)}  (AI would prevent FP block)`],
      ['AutoSuppressed', `${n(wc.matrix.aiSuppressedRiskAttack)}  (conflict)`, `${n(wc.matrix.bothBenign)}  (agree: benign)`],
    ],
    theme: 'grid',
    headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 7 },
    styles: { fontSize: 7, cellPadding: 1.5 },
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
  });

  const div = wc.bySignature.filter(s => s.engineActiveAiBenign > 0).slice(0, 12);
  if (div.length > 0) {
    doc.setFontSize(8); doc.setFont('helvetica', 'bold'); doc.setTextColor(...GRAY);
    y = ensureSpace(doc, y + 2, 12);
    doc.text('Tuning candidates — Enabled signatures the AI rates benign:', PAGE_MARGIN, y); y += 3;
    y = autoTable(doc, {
      startY: y,
      head: [['Sig ID', 'Name', 'Events', 'Enabled', 'AI Benign', 'Origin 200%']],
      body: div.map(s => [s.sigId, truncate(s.name, 40), n(s.events), n(s.enabled), n(s.aiBenign), pct(s.origin200Pct)]),
      theme: 'striped',
      headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 7 },
      styles: { fontSize: 7, cellPadding: 1.5 },
      margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
      columnStyles: { 2: { halign: 'right' }, 3: { halign: 'right' }, 4: { halign: 'right' }, 5: { halign: 'right' } },
    });
  }
  return y + 5;
}

function addBotClassification(doc: jsPDF, summary: SummaryResult, y: number): number {
  const ba = summary.botAnalysis;
  if (!ba || ba.maliciousEvents === 0) return y;
  y = sectionTitle(doc, 'Bot Classification', y);

  const cc = ba.classificationCounts;
  doc.setFontSize(9); doc.setFont('helvetica', 'normal'); doc.setTextColor(...DARK);
  const recLines = doc.splitTextToSize(ba.recommendation, CONTENT_WIDTH) as string[];
  doc.text(recLines, PAGE_MARGIN, y); y += recLines.length * 4.5 + 3;

  doc.setFontSize(8); doc.setTextColor(...GRAY);
  doc.text(`Malicious: ${n(cc.malicious)}  |  Suspicious: ${n(cc.suspicious)}  |  Benign/Good: ${n(cc.benign)}  |  Human: ${n(cc.human)}  |  Unknown: ${n(cc.unknown)}    (only Malicious is blocked; from aggregation)`, PAGE_MARGIN, y);
  y += 4;
  doc.text(`${n(ba.maliciousEvents)} malicious events from ${n(ba.maliciousIps)}${ba.ipsCapped ? '+' : ''} distinct client(s).`, PAGE_MARGIN, y);
  y += 5;

  if (ba.fpRiskFlags.length > 0) {
    y = ensureSpace(doc, y, 16);
    doc.setFontSize(8); doc.setFont('helvetica', 'bold'); doc.setTextColor(...RED);
    doc.text('Potential false positives in the Malicious set — verify before blocking:', PAGE_MARGIN, y); y += 3;
    doc.setFont('helvetica', 'normal');
    y = autoTable(doc, {
      startY: y,
      head: [['Type', 'User-Agent / Bot Name', 'Events']],
      body: ba.fpRiskFlags.map(f => [f.kind === 'known_good_bot' ? 'Known-good bot' : 'Real browser', truncate(f.label, 60), n(f.count)]),
      theme: 'grid',
      headStyles: { fillColor: [...RED], textColor: 255, fontSize: 7 },
      styles: { fontSize: 7, cellPadding: 1.5 },
      margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
      columnStyles: { 2: { halign: 'right' } },
    });
  }

  const ips = ba.topMaliciousIps.slice(0, 15);
  if (ips.length > 0) {
    y = ensureSpace(doc, y + 1, 16);
    doc.setFontSize(8); doc.setFont('helvetica', 'bold'); doc.setTextColor(...GRAY);
    doc.text('Top malicious source IPs:', PAGE_MARGIN, y); y += 3;
    doc.setFont('helvetica', 'normal');
    y = autoTable(doc, {
      startY: y,
      head: [['Source IP', 'Events']],
      body: ips.map(b => [b.key, n(b.count)]),
      theme: 'striped',
      headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 7 },
      styles: { fontSize: 7, cellPadding: 1.5 },
      margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
      columnStyles: { 1: { halign: 'right' } },
    });
  }
  return y + 5;
}

function addSignaturesSection(doc: jsPDF, signatures: SignatureSummary[], y: number): number {
  if (signatures.length === 0) return y;

  y = sectionTitle(doc, 'WAF Signatures — Summary', y);

  const rows = signatures.map(s => [
    s.sigId,
    truncate(s.name, 28),
    s.attackType,
    s.accuracy,
    n(s.totalEvents),
    String(s.uniqueUsers),
    String(s.uniquePaths),
    `${s.fpScore}%`,
    verdictLabel(s.fpVerdict),
  ]);

  y = autoTable(doc, {
    startY: y,
    head: [['Sig ID', 'Name', 'Attack Type', 'Accuracy', 'Events', 'Users', 'Paths', 'FP Score', 'Verdict']],
    body: rows,
    theme: 'striped',
    headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 7 },
    styles: { fontSize: 7, cellPadding: 1.5 },
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    columnStyles: {
      4: { halign: 'right' },
      5: { halign: 'right' },
      6: { halign: 'right' },
      7: { halign: 'right' },
    },
    didParseCell: (data: { section: string; column: { index: number }; cell: { styles: { textColor: number[] } }; row: { index: number } }) => {
      if (data.section === 'body' && (data.column.index === 7 || data.column.index === 8)) {
        const sig = signatures[data.row.index];
        if (sig) {
          data.cell.styles.textColor = [...verdictColor(sig.fpVerdict)];
        }
      }
    },
  });

  return y;
}

function addSignatureDetails(doc: jsPDF, details: SignatureAnalysisUnit[], y: number): number {
  if (details.length === 0) return y;

  y = sectionTitle(doc, 'WAF Signatures — Detailed Analysis', y);

  for (const unit of details) {
    y = ensureSpace(doc, y, 50);

    // Signature header
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...DARK);
    doc.text(`${unit.signatureId} — "${truncate(unit.signatureName, 50)}"`, PAGE_MARGIN, y);
    y += 5;

    // Metadata
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(...GRAY);
    doc.text(`Accuracy: ${unit.accuracy}  |  Attack: ${unit.attackType}  |  Context: ${unit.contextType} "${unit.contextName}"  |  Events: ${n(unit.eventCount)}  |  Users: ${n(unit.flaggedUsers)}  |  IPs: ${n(unit.flaggedIPs)}`, PAGE_MARGIN, y);
    y += 5;

    // Overall FP Score
    const vc = verdictColor(unit.signals.verdict);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...vc);
    doc.text(`FP Score: ${unit.signals.compositeScore}% — ${verdictLabel(unit.signals.verdict)}`, PAGE_MARGIN, y);
    y += 6;

    // Signal scores
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...DARK);
    doc.text('Signal Scores:', PAGE_MARGIN, y);
    y += 4;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(...GRAY);
    const signalList = [
      { label: 'Client Breadth (15%)', score: unit.signals.clientBreadth.score, reason: unit.signals.clientBreadth.reason },
      { label: 'Path Breadth (10%)', score: unit.signals.pathBreadth.score, reason: unit.signals.pathBreadth.reason },
      { label: 'Context (10%)', score: unit.signals.context.score, reason: unit.signals.context.reason },
      { label: 'Matching Evidence (15%)', score: unit.signals.matchingEvidence.score, reason: unit.signals.matchingEvidence.reason },
      { label: 'Origin Response (15%)', score: unit.signals.originResponse.score, reason: unit.signals.originResponse.reason },
      { label: 'Client Behavior (20%)', score: unit.signals.clientBehavior.score, reason: unit.signals.clientBehavior.reason },
      { label: 'Detection Confidence (15%)', score: unit.signals.detectionConfidence.score, reason: unit.signals.detectionConfidence.reason },
    ];
    for (const s of signalList) {
      y = ensureSpace(doc, y, 4);
      doc.text(`  ${s.label}: ${s.score}% — ${truncate(s.reason, 70)}`, PAGE_MARGIN + 2, y);
      y += 3.5;
    }
    y += 3;

    // Per-path FP/TP analysis
    if (unit.pathAnalyses && unit.pathAnalyses.length > 0) {
      y = ensureSpace(doc, y, 20);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...DARK);
      doc.text('Per-Path FP/TP Analysis:', PAGE_MARGIN, y);
      y += 4;

      const pathRows = unit.pathAnalyses.slice(0, 15).map(pa => [
        truncate(pa.path, 45),
        n(pa.eventCount),
        String(pa.uniqueUsers),
        String(pa.uniqueIPs),
        Object.keys(pa.methods).join(', '),
        `${pa.fpScore}%`,
        verdictLabel(pa.verdict),
      ]);

      y = autoTable(doc, {
        startY: y,
        head: [['Path', 'Events', 'Users', 'IPs', 'Methods', 'FP Score', 'Verdict']],
        body: pathRows,
        theme: 'plain',
        headStyles: { fillColor: [241, 245, 249], textColor: [...DARK], fontSize: 7 },
        styles: { fontSize: 6.5, cellPadding: 1.2 },
        margin: { left: PAGE_MARGIN + 2, right: PAGE_MARGIN },
        columnStyles: {
          1: { halign: 'right' },
          2: { halign: 'right' },
          3: { halign: 'right' },
          5: { halign: 'right' },
        },
        didParseCell: (data: { section: string; column: { index: number }; cell: { styles: { textColor: number[] } }; row: { index: number } }) => {
          if (data.section === 'body' && (data.column.index === 5 || data.column.index === 6)) {
            const pa = unit.pathAnalyses?.[data.row.index];
            if (pa) {
              data.cell.styles.textColor = [...verdictColor(pa.verdict)];
            }
          }
        },
      });
    }

    // Sample matching info
    if (unit.sampleMatchingInfos.length > 0) {
      y = ensureSpace(doc, y, 15);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...DARK);
      doc.text('Sample Matching Values:', PAGE_MARGIN, y);
      y += 4;
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(...GRAY);
      for (const mi of unit.sampleMatchingInfos.slice(0, 5)) {
        y = ensureSpace(doc, y, 4);
        doc.text(`  ${truncate(mi, 80)}`, PAGE_MARGIN + 2, y);
        y += 3.5;
      }
      y += 2;
    }

    // Top user agents & countries
    if (Object.keys(unit.userAgents).length > 0) {
      y = ensureSpace(doc, y, 8);
      doc.setFontSize(7);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...GRAY);
      doc.text(`User Agents: ${topEntries(unit.userAgents, 3)}`, PAGE_MARGIN + 2, y);
      y += 3.5;
      doc.text(`Countries: ${topEntries(unit.countries, 5)}`, PAGE_MARGIN + 2, y);
      y += 3.5;
      doc.text(`Response Codes: ${topEntries(unit.rspCodes, 5)}`, PAGE_MARGIN + 2, y);
      y += 5;
    }

    // Separator
    doc.setDrawColor(200, 200, 200);
    doc.setLineWidth(0.3);
    doc.line(PAGE_MARGIN, y, PAGE_MARGIN + CONTENT_WIDTH, y);
    y += 6;
  }

  return y;
}

function addViolationsSection(doc: jsPDF, violations: ViolationSummary[], y: number): number {
  if (violations.length === 0) return y;

  y = sectionTitle(doc, 'WAF Violations — Summary', y);

  const rows = violations.map(v => [
    truncate(v.violationName, 35),
    v.attackType,
    n(v.totalEvents),
    String(v.uniqueUsers),
    String(v.uniquePaths),
    verdictLabel(v.quickVerdict),
  ]);

  y = autoTable(doc, {
    startY: y,
    head: [['Violation', 'Attack Type', 'Events', 'Users', 'Paths', 'Verdict']],
    body: rows,
    theme: 'striped',
    headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 8 },
    styles: { fontSize: 7, cellPadding: 1.5 },
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    columnStyles: {
      2: { halign: 'right' },
      3: { halign: 'right' },
      4: { halign: 'right' },
    },
    didParseCell: (data: { section: string; column: { index: number }; cell: { styles: { textColor: number[] } }; row: { index: number } }) => {
      if (data.section === 'body' && data.column.index === 5) {
        const verdict = violations[data.row.index]?.quickVerdict;
        if (verdict) {
          data.cell.styles.textColor = [...verdictColor(verdict)];
        }
      }
    },
  });

  return y;
}

function addViolationDetails(doc: jsPDF, details: ViolationAnalysisUnit[], y: number): number {
  if (details.length === 0) return y;

  y = sectionTitle(doc, 'WAF Violations — Detailed Analysis', y);

  for (const unit of details) {
    y = ensureSpace(doc, y, 35);

    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...DARK);
    doc.text(`${truncate(unit.violationName, 50)}`, PAGE_MARGIN, y);
    y += 5;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(...GRAY);
    doc.text(`Attack: ${unit.attackType}  |  Events: ${n(unit.eventCount)}  |  Users: ${n(unit.flaggedUsers)}  |  Paths: ${unit.pathCount}`, PAGE_MARGIN, y);
    y += 5;

    const vc = verdictColor(unit.signals.verdict);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...vc);
    doc.text(`FP Score: ${unit.signals.compositeScore}% — ${verdictLabel(unit.signals.verdict)}`, PAGE_MARGIN, y);
    y += 6;

    // Per-path analysis
    if (unit.pathAnalyses && unit.pathAnalyses.length > 0) {
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...DARK);
      doc.text('Per-Path Analysis:', PAGE_MARGIN, y);
      y += 4;

      const pathRows = unit.pathAnalyses.slice(0, 10).map(pa => [
        truncate(pa.path, 45),
        n(pa.eventCount),
        String(pa.uniqueUsers),
        `${pa.fpScore}%`,
        verdictLabel(pa.verdict),
      ]);

      y = autoTable(doc, {
        startY: y,
        head: [['Path', 'Events', 'Users', 'FP Score', 'Verdict']],
        body: pathRows,
        theme: 'plain',
        headStyles: { fillColor: [241, 245, 249], textColor: [...DARK], fontSize: 7 },
        styles: { fontSize: 6.5, cellPadding: 1.2 },
        margin: { left: PAGE_MARGIN + 2, right: PAGE_MARGIN },
        columnStyles: {
          1: { halign: 'right' },
          2: { halign: 'right' },
          3: { halign: 'right' },
        },
        didParseCell: (data: { section: string; column: { index: number }; cell: { styles: { textColor: number[] } }; row: { index: number } }) => {
          if (data.section === 'body' && (data.column.index === 3 || data.column.index === 4)) {
            const pa = unit.pathAnalyses?.[data.row.index];
            if (pa) {
              data.cell.styles.textColor = [...verdictColor(pa.verdict)];
            }
          }
        },
      });
    } else {
      // Fallback: show path counts
      const pathEntries = Object.entries(unit.pathCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
      if (pathEntries.length > 0) {
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...DARK);
        doc.text('Top Paths:', PAGE_MARGIN, y);
        y += 4;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);
        doc.setTextColor(...GRAY);
        for (const [path, count] of pathEntries) {
          y = ensureSpace(doc, y, 4);
          doc.text(`  ${truncate(path, 60)}  (${n(count)} events)`, PAGE_MARGIN + 2, y);
          y += 3.5;
        }
        y += 2;
      }
    }

    doc.setDrawColor(200, 200, 200);
    doc.setLineWidth(0.3);
    doc.line(PAGE_MARGIN, y, PAGE_MARGIN + CONTENT_WIDTH, y);
    y += 6;
  }

  return y;
}

function addExclusionPolicySection(doc: jsPDF, policy: WafExclusionPolicyObject, y: number): number {
  y = sectionTitle(doc, 'WAF Exclusion Policy Recommendation', y);

  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...GRAY);
  doc.text(`Policy Name: ${policy.metadata.name}`, PAGE_MARGIN, y);
  y += 4;
  doc.text(`Namespace: ${policy.metadata.namespace || '-'}`, PAGE_MARGIN, y);
  y += 4;
  doc.text(`Rules: ${policy.spec.waf_exclusion_rules.length}`, PAGE_MARGIN, y);
  y += 6;

  for (const rule of policy.spec.waf_exclusion_rules) {
    y = ensureSpace(doc, y, 25);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...DARK);
    doc.text(`Rule: ${rule.metadata.name}`, PAGE_MARGIN, y);
    y += 4;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(...GRAY);

    const domain = rule.any_domain ? 'any' : rule.exact_value || '-';
    const path = rule.any_path ? 'any' : rule.path_prefix || rule.path_regex || '-';
    doc.text(`Domain: ${domain}  |  Path: ${truncate(path, 50)}  |  Methods: ${rule.methods.join(', ') || 'any'}`, PAGE_MARGIN + 2, y);
    y += 3.5;

    if (rule.app_firewall_detection_control.exclude_signature_contexts.length > 0) {
      doc.text(`Signature Exclusions: ${rule.app_firewall_detection_control.exclude_signature_contexts.map(s => `${s.signature_id} (${s.context})`).join(', ')}`, PAGE_MARGIN + 2, y);
      y += 3.5;
    }
    if (rule.app_firewall_detection_control.exclude_violation_contexts.length > 0) {
      doc.text(`Violation Exclusions: ${rule.app_firewall_detection_control.exclude_violation_contexts.map(v => v.exclude_violation).join(', ')}`, PAGE_MARGIN + 2, y);
      y += 3.5;
    }
    y += 3;
  }

  return y;
}

function addThreatMeshSummaryTable(doc: jsPDF, ips: ThreatMeshSummary[], y: number): number {
  if (ips.length === 0) return y;

  y = sectionTitle(doc, 'Threat Mesh — IP Summary', y);

  const rows = ips.map(ip => [
    ip.srcIp,
    ip.country || '-',
    truncate(ip.asOrg || '-', 20),
    n(ip.eventCount),
    ip.accessLogRequests != null ? n(ip.accessLogRequests) : '-',
    ip.successRate != null ? `${(ip.successRate * 100).toFixed(0)}%` : '-',
    String(ip.paths),
    String(ip.tenantCount || 0),
    ip.action || '-',
    truncate(ip.userAgent || '-', 20),
    ip.enrichedVerdict ? verdictLabel(ip.enrichedVerdict) : verdictLabel(ip.quickVerdict),
  ]);

  y = autoTable(doc, {
    startY: y,
    head: [['IP Address', 'Country', 'AS Org', 'Sec Events', 'Access Reqs', 'Success%', 'Paths', 'Tenants', 'Action', 'User Agent', 'Verdict']],
    body: rows,
    theme: 'striped',
    headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 7 },
    styles: { fontSize: 6, cellPadding: 1.2 },
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    columnStyles: {
      3: { halign: 'right' },
      4: { halign: 'right' },
      5: { halign: 'right' },
      6: { halign: 'right' },
      7: { halign: 'right' },
    },
    didParseCell: (data: { section: string; column: { index: number }; cell: { styles: { textColor: number[] } }; row: { index: number } }) => {
      if (data.section === 'body' && data.column.index === 10) {
        const ip = ips[data.row.index];
        const verdict = ip?.enrichedVerdict || ip?.quickVerdict;
        if (verdict) {
          data.cell.styles.textColor = [...verdictColor(verdict)];
        }
      }
    },
  });

  return y;
}

function addThreatMeshDetails(doc: jsPDF, details: ThreatMeshAnalysisUnit[], y: number): number {
  if (details.length === 0) return y;

  y = sectionTitle(doc, 'Threat Mesh — Per-IP Deep Analysis', y);

  for (const ip of details) {
    y = ensureSpace(doc, y, 60);

    // IP Header
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...DARK);
    doc.text(`IP: ${ip.srcIp}`, PAGE_MARGIN, y);
    y += 5;

    // Metadata row
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(...GRAY);
    const meta = [
      `Country: ${ip.country || '-'}`,
      `AS Org: ${ip.asOrg || '-'}`,
      `User Agent: ${truncate(ip.userAgent || '-', 40)}`,
      `User: ${truncate(ip.user || '-', 20)}`,
    ].join('  |  ');
    doc.text(meta, PAGE_MARGIN, y);
    y += 5;

    // Why Blocked
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...DARK);
    doc.text('Why Blocked', PAGE_MARGIN, y);
    y += 4;
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(...GRAY);
    if (ip.threatDetails) {
      doc.text(`Description: ${truncate(ip.threatDetails.description || '-', 80)}`, PAGE_MARGIN + 2, y);
      y += 3.5;
      doc.text(`Attack Types: ${(ip.threatDetails.attackTypes || []).join(', ') || '-'}`, PAGE_MARGIN + 2, y);
      y += 3.5;
      doc.text(`Tenant Count: ${ip.threatDetails.tenantCount || 0}  |  Global Events: ${n(ip.threatDetails.events || 0)}  |  High Accuracy Sigs: ${ip.threatDetails.highAccuracySignatures || 0}`, PAGE_MARGIN + 2, y);
      y += 3.5;
      doc.text(`TLS Events: ${ip.threatDetails.tlsCount || 0}  |  Malicious Bot Events: ${ip.threatDetails.maliciousBotEvents || 0}`, PAGE_MARGIN + 2, y);
      y += 5;
    }

    // FP Assessment
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...DARK);
    doc.text('FP Assessment', PAGE_MARGIN, y);
    y += 4;
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');

    const vc = verdictColor(ip.verdict);
    doc.setTextColor(...vc);
    doc.text(`Verdict: ${verdictLabel(ip.verdict)}  |  Score: ${ip.fpScore}`, PAGE_MARGIN + 2, y);
    y += 4;

    // Reasons
    if (ip.reasons && ip.reasons.length > 0) {
      doc.setTextColor(...GRAY);
      for (const reason of ip.reasons) {
        y = ensureSpace(doc, y, 5);
        // Color: reasons with "+" are FP signals (green), "-" are TP signals (red)
        if (reason.startsWith('+') || reason.toLowerCase().includes('benign') || reason.toLowerCase().includes('cdn')) {
          doc.setTextColor(...GREEN);
        } else if (reason.startsWith('-') || reason.toLowerCase().includes('exploit') || reason.toLowerCase().includes('malicious')) {
          doc.setTextColor(...RED);
        } else {
          doc.setTextColor(...GRAY);
        }
        doc.text(`  ${truncate(reason, 90)}`, PAGE_MARGIN + 2, y);
        y += 3.5;
      }
      y += 2;
    }

    // Behavioral Profile — Paths
    if (ip.pathsAccessed && Object.keys(ip.pathsAccessed).length > 0) {
      y = ensureSpace(doc, y, 15);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...DARK);
      doc.text('Paths Accessed', PAGE_MARGIN, y);
      y += 4;

      const pathRows = Object.entries(ip.pathsAccessed)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([path, count]) => [truncate(path, 60), String(count)]);

      y = autoTable(doc, {
        startY: y,
        head: [['Path', 'Requests']],
        body: pathRows,
        theme: 'plain',
        headStyles: { fillColor: [241, 245, 249], textColor: [...DARK], fontSize: 7 },
        styles: { fontSize: 7, cellPadding: 1 },
        margin: { left: PAGE_MARGIN + 2, right: PAGE_MARGIN },
        columnStyles: { 1: { halign: 'right' } },
      });
    }

    // Response Codes
    if (ip.rspCodes && Object.keys(ip.rspCodes).length > 0) {
      y = ensureSpace(doc, y, 10);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...GRAY);
      doc.text(`Response Codes: ${topEntries(ip.rspCodes)}`, PAGE_MARGIN + 2, y);
      y += 4;
    }

    // WAF Correlation
    if (ip.wafEventsFromThisIP > 0) {
      doc.text(`WAF Events from this IP: ${n(ip.wafEventsFromThisIP)}`, PAGE_MARGIN + 2, y);
      y += 4;
    }

    // Suggested Action
    if (ip.suggestedAction) {
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...BLUE);
      doc.text(`Suggested Action: ${ip.suggestedAction === 'trusted_client' ? 'Add as Trusted Client' : 'No Action Needed'}`, PAGE_MARGIN, y);
      y += 6;
    }

    // Separator
    doc.setDrawColor(200, 200, 200);
    doc.setLineWidth(0.3);
    doc.line(PAGE_MARGIN, y, PAGE_MARGIN + CONTENT_WIDTH, y);
    y += 6;
  }

  return y;
}

function addPolicyRulesSection(doc: jsPDF, rules: PolicyRuleSummary[], y: number): number {
  if (rules.length === 0) return y;

  y = sectionTitle(doc, 'Service Policy Rules', y);

  const rows = rules.map(r => [
    truncate(r.ruleName, 30),
    truncate(r.policyName, 30),
    n(r.totalBlocked),
    String(r.uniqueIPs),
  ]);

  return autoTable(doc, {
    startY: y,
    head: [['Rule Name', 'Policy', 'Total Blocked', 'Unique IPs']],
    body: rows,
    theme: 'striped',
    headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 8 },
    styles: { fontSize: 8, cellPadding: 2 },
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    columnStyles: {
      2: { halign: 'right' },
      3: { halign: 'right' },
    },
  });
}

function addFooters(doc: jsPDF) {
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    const pageH = doc.internal.pageSize.getHeight();
    const pageW = doc.internal.pageSize.getWidth();
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.text(`Page ${i} of ${pageCount}`, pageW / 2, pageH - 10, { align: 'center' });
    doc.text('XC App Store — FP Analyzer', PAGE_MARGIN, pageH - 10);
  }
}

// ═══════════════════════════════════════════════════════════════════
// MAIN EXPORT
// ═══════════════════════════════════════════════════════════════════

export function generateFPAnalysisPDF(opts: FPReportOptions): void {
  const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });

  let y = addHeader(doc, opts);
  y = addExecutiveSummary(doc, opts.summary, opts.scopes, y);
  y = addRecommendations(doc, opts.summary, y);
  y = addWafComparison(doc, opts.summary, y);
  y = addBotClassification(doc, opts.summary, y);

  if (opts.scopes.includes('waf_signatures')) {
    y = addSignaturesSection(doc, opts.summary.signatures, y);
    if (opts.signatureDetails && opts.signatureDetails.length > 0) {
      y = addSignatureDetails(doc, opts.signatureDetails, y);
    }
  }

  if (opts.scopes.includes('waf_violations')) {
    y = addViolationsSection(doc, opts.summary.violations, y);
    if (opts.violationDetails && opts.violationDetails.length > 0) {
      y = addViolationDetails(doc, opts.violationDetails, y);
    }
  }

  if (opts.scopes.includes('threat_mesh')) {
    y = addThreatMeshSummaryTable(doc, opts.summary.threatMeshIPs, y);
    if (opts.threatMeshDetails && opts.threatMeshDetails.length > 0) {
      y = addThreatMeshDetails(doc, opts.threatMeshDetails, y);
    }
  }

  if (opts.scopes.includes('service_policy')) {
    y = addPolicyRulesSection(doc, opts.summary.policyRules, y);
  }

  if (opts.exclusionPolicy && opts.exclusionPolicy.spec.waf_exclusion_rules.length > 0) {
    addExclusionPolicySection(doc, opts.exclusionPolicy, y);
  }

  addFooters(doc);

  // Manual blob download — avoids doc.save() which creates an <a> element
  // that React Router can intercept
  const blob = doc.output('blob');
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `fp-analysis-${opts.lbName}-${new Date().toISOString().split('T')[0]}.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
