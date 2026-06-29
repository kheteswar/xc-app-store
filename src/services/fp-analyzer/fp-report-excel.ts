/**
 * FP Analysis Excel Report Generator
 *
 * Generates a well-formatted Excel workbook using SheetJS (xlsx).
 * Each scope gets its own sheet with proper headers, column widths, and styling.
 * Designed for easy copy-paste into emails and reports.
 */

import * as XLSX from 'xlsx';
import type {
  AnalysisScope,
  AnalysisMode,
  SummaryResult,
  ThreatMeshAnalysisUnit,
  SignatureAnalysisUnit,
  ViolationAnalysisUnit,
  WafExclusionPolicyObject,
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
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function setColWidths(ws: XLSX.WorkSheet, widths: number[]): void {
  ws['!cols'] = widths.map(w => ({ wch: w }));
}

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

// ═══════════════════════════════════════════════════════════════════
// SHEET BUILDERS
// ═══════════════════════════════════════════════════════════════════

function buildSummarySheet(opts: FPExcelReportOptions): XLSX.WorkSheet {
  const rows: (string | number)[][] = [];

  rows.push(['FP Analysis Report — Executive Summary']);
  rows.push([]);
  rows.push(['Load Balancer', opts.lbName]);
  rows.push(['Namespace', opts.namespace]);
  rows.push(['Scopes', opts.scopes.join(', ')]);
  rows.push(['Period Start', opts.summary.period.start]);
  rows.push(['Period End', opts.summary.period.end]);
  rows.push(['Generated', new Date().toISOString()]);
  rows.push([]);
  rows.push(['Metric', 'Value']);
  rows.push(['Total flagged events', opts.summary.totalEvents]);
  rows.push(['Unique Signatures', opts.summary.signatures.length]);
  rows.push(['Unique Violations', opts.summary.violations.length]);
  if (opts.summary.enforcementMode) rows.push(['WAF Enforcement Mode', opts.summary.enforcementMode]);
  const fp = opts.summary.signatures.filter(s => s.fpVerdict === 'highly_likely_fp' || s.fpVerdict === 'likely_fp').length;
  const tp = opts.summary.signatures.filter(s => s.fpVerdict === 'likely_tp' || s.fpVerdict === 'confirmed_tp').length;
  rows.push(['Signatures: likely false positive', fp]);
  rows.push(['Signatures: likely true positive', tp]);
  if (opts.summary.wafComparison) {
    rows.push([]);
    rows.push(['AI vs Traditional WAF', opts.summary.wafComparison.headline]);
  }

  const ws = XLSX.utils.aoa_to_sheet(rows);
  setColWidths(ws, [28, 90]);
  return ws;
}

function buildNextStepsSheet(opts: FPExcelReportOptions): XLSX.WorkSheet {
  const rec = opts.summary.recommendations!;
  const rows: (string | number)[][] = [];
  rows.push(['Recommendations & Next Steps']);
  rows.push([]);
  rows.push(['Goal', `Tune out false positives, then move this load balancer ${rec.enforcementMode === 'blocking' ? 'to a verified Blocking state' : 'from Monitoring to Blocking'} with AI-powered WAF protection.`]);
  rows.push(['Recommended AI blocking threshold', rec.aiBlockingThreshold === 'high_medium' ? 'High + Medium risk' : 'High risk']);
  rows.push(['Reason', rec.aiThresholdReason]);
  rows.push([]);
  rows.push(['Step', 'Action', 'How to do it']);
  for (const s of rec.steps) rows.push([s.num, s.title, s.detail]);
  rows.push([]);
  if (rec.excludeList.length > 0) {
    rows.push([`False positives to exclude (${rec.excludeList.length})`]);
    rows.push(['Type', 'ID', 'Name', 'Verdict']);
    for (const e of rec.excludeList) rows.push([e.kind, e.id, e.name, verdictLabel(e.verdict)]);
    rows.push([]);
  }
  if (rec.investigateList.length > 0) {
    rows.push([`Investigate & manually confirm — do NOT auto-exclude (${rec.investigateList.length})`]);
    rows.push(['Type', 'ID', 'Name', 'Why / How to investigate']);
    for (const e of rec.investigateList) rows.push([e.kind, e.id, e.name, e.reason]);
    rows.push([]);
  }
  if (rec.autoHandledList.length > 0) {
    rows.push([`Already auto-suppressed by F5 AI — NO exclusion needed (${rec.autoHandledList.length})`]);
    rows.push(['Type', 'ID', 'Name']);
    for (const e of rec.autoHandledList) rows.push([e.kind, e.id, e.name]);
  }
  const ws = XLSX.utils.aoa_to_sheet(rows);
  setColWidths(ws, [10, 46, 110, 22]);
  return ws;
}

function buildWafComparisonSheet(opts: FPExcelReportOptions): XLSX.WorkSheet {
  const wc = opts.summary.wafComparison!;
  const pct = (x: number) => `${(x * 100).toFixed(0)}%`;
  const rows: (string | number)[][] = [];
  rows.push(['Traditional vs AI-Powered WAF (analysis — see the Next Steps sheet for actions)']);
  rows.push([]);
  rows.push(['Summary', wc.headline]);
  if (wc.enforcementNote) rows.push(['Note', wc.enforcementNote]);
  rows.push([]);
  rows.push(['Metric', 'Value']);
  rows.push(['Total flagged events', wc.totalEvents]);
  rows.push(['AI data coverage (events with req_risk)', pct(wc.aiDataCoveragePct)]);
  rows.push(['Enforcement mode', wc.enforcementMode]);
  rows.push(['FP-block reduction if AI enabled', pct(wc.fpReductionOpportunityPct)]);
  rows.push(['AI-benign requests origin returned 200', pct(wc.aiBenignOrigin200Pct)]);
  rows.push(['Engine <-> AI agreement', pct(wc.agreementPct)]);
  rows.push(['Already AutoSuppressed by AI', wc.alreadySuppressedByAi]);
  rows.push([]);
  rows.push(['Outcome breakdown', 'Count', 'Meaning']);
  rows.push(['Real attack — both agree', wc.matrix.bothAttack, 'Signature flagged + AI rates high/medium risk']);
  rows.push(['Likely false positive', wc.matrix.engineActiveAiBenign, 'Signature Enabled but AI rates benign — AI-based blocking would skip these']);
  rows.push(['AI flags, signature suppressed', wc.matrix.aiSuppressedRiskAttack, 'AI sees risk on an auto-suppressed signature — review']);
  rows.push(['False positive — auto-tuned out', wc.matrix.bothBenign, 'AutoSuppressed by F5 tuning + AI agrees benign']);
  rows.push([]);
  rows.push(['req_risk distribution', 'high', 'medium', 'low', 'false positive', 'unknown']);
  rows.push(['', wc.riskCounts.high, wc.riskCounts.medium, wc.riskCounts.low, wc.riskCounts.falsePositive, wc.riskCounts.unknown]);
  rows.push(['action distribution', 'block', 'report', 'allow', 'other']);
  rows.push(['', wc.actionCounts.block, wc.actionCounts.report, wc.actionCounts.allow, wc.actionCounts.other]);
  rows.push([]);
  rows.push(['Tuning candidates — Enabled signatures the AI rates benign']);
  rows.push(['Sig ID', 'Name', 'Events', 'Enabled', 'AutoSuppressed', 'AI Attack', 'AI Benign', 'Origin 200%', 'Enabled+AI-benign']);
  for (const s of wc.bySignature.filter(s => s.engineActiveAiBenign > 0).slice(0, 50)) {
    rows.push([s.sigId, s.name, s.events, s.enabled, s.autoSuppressed, s.aiAttack, s.aiBenign, pct(s.origin200Pct), s.engineActiveAiBenign]);
  }
  const ws = XLSX.utils.aoa_to_sheet(rows);
  setColWidths(ws, [42, 40, 10, 10, 14, 10, 10, 12, 18]);
  return ws;
}

function buildBotClassificationSheet(opts: FPExcelReportOptions): XLSX.WorkSheet {
  const ba = opts.summary.botAnalysis!;
  const cc = ba.classificationCounts;
  const rows: (string | number)[][] = [];
  rows.push(['Bot Classification — is it safe to block the Malicious bots?']);
  rows.push(['(Computed from server-side aggregation — no raw malicious-bot logs downloaded)']);
  rows.push([]);
  rows.push(['Recommendation', ba.recommendation]);
  rows.push([]);
  rows.push(['F5 Bot Defense classification', 'Events', 'Bot Defense action']);
  rows.push(['Malicious', cc.malicious, 'Blocked (when enabled)']);
  rows.push(['Suspicious', cc.suspicious, 'Allowed / ignored']);
  rows.push(['Benign / Good', cc.benign, 'Allowed / ignored']);
  rows.push(['Human', cc.human, 'Allowed']);
  rows.push(['Unknown', cc.unknown, '—']);
  rows.push([]);
  rows.push(['Malicious events', ba.maliciousEvents, '']);
  rows.push(['Distinct malicious clients', `${ba.maliciousIps}${ba.ipsCapped ? '+ (capped at 500)' : ''}`, '']);
  rows.push([]);

  rows.push([`Potential false positives in the Malicious set (${ba.fpRiskFlags.length}) — verify before blocking`]);
  rows.push(['Type', 'User-Agent / Bot Name', 'Events']);
  if (ba.fpRiskFlags.length === 0) rows.push(['—', 'None — no known-good bot or real-browser client in the Malicious set', '']);
  for (const f of ba.fpRiskFlags) rows.push([f.kind === 'known_good_bot' ? 'Known-good bot' : 'Real browser', f.label, f.count]);
  rows.push([]);

  rows.push(['Top malicious source IPs', 'Events']);
  for (const b of ba.topMaliciousIps) rows.push([b.key, b.count]);
  rows.push([]);

  rows.push(['Top user-agents in the Malicious set', 'Events', 'FP risk?']);
  const flagLabels = new Set(ba.fpRiskFlags.map(f => f.label));
  for (const b of ba.topUserAgents) rows.push([b.key, b.count, flagLabels.has(b.key) ? 'YES — verify' : '']);
  rows.push([]);

  if (ba.topBotNames.length > 0) {
    rows.push(['Top bot names in the Malicious set', 'Events']);
    for (const b of ba.topBotNames) rows.push([b.key, b.count]);
    rows.push([]);
  }

  rows.push(['Top countries (malicious)', 'Events']);
  for (const b of ba.topCountries) rows.push([b.key, b.count]);

  const ws = XLSX.utils.aoa_to_sheet(rows);
  setColWidths(ws, [40, 60, 16]);
  return ws;
}

const aiRiskLabel = (r?: string): string => (r && r !== 'unknown' ? r : '');

function buildSignaturesSheet(opts: FPExcelReportOptions): XLSX.WorkSheet {
  const header = [
    'Sig ID', 'Name', 'FP Verdict', 'FP Score', 'AI Risk', 'Events',
    'Unique IPs', 'Unique Paths', 'Accuracy', 'Attack Type', 'Auto Suppressed', 'Top Paths',
  ];

  const dataRows = opts.summary.signatures.map(s => [
    s.sigId,
    s.name,
    verdictLabel(s.fpVerdict),
    s.fpScore,
    aiRiskLabel(s.aiRisk),
    s.totalEvents,
    s.uniqueIPs,
    s.uniquePaths,
    s.accuracy,
    s.attackType,
    s.autoSuppressed ? 'Yes' : 'No',
    s.topPaths.map(p => `${p.path} (${p.count})`).join('\n'),
  ]);

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [15, 38, 16, 9, 9, 9, 11, 12, 15, 22, 14, 50]);
  return ws;
}

function buildViolationsSheet(opts: FPExcelReportOptions): XLSX.WorkSheet {
  const header = [
    'Violation Name', 'FP Verdict', 'FP Score', 'AI Risk', 'Attack Type',
    'Events', 'Unique Users', 'Unique Paths', 'Top Paths',
  ];

  const dataRows = opts.summary.violations.map(v => [
    v.violationName,
    verdictLabel(v.fpVerdict),
    v.fpScore,
    aiRiskLabel(v.aiRisk),
    v.attackType,
    v.totalEvents,
    v.uniqueUsers,
    v.uniquePaths,
    v.topPaths.map(p => `${p.path} (${p.count})`).join('\n'),
  ]);

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [40, 16, 9, 9, 22, 9, 12, 12, 50]);
  return ws;
}

function buildPerPathAnalysisSheet(
  sigDetails: SignatureAnalysisUnit[],
  violDetails: ViolationAnalysisUnit[],
): XLSX.WorkSheet {
  const header = [
    'Type', 'ID/Name', 'Path', 'Events', 'Users', 'IPs',
    'Methods', 'FP Score', 'Verdict', 'Reasons',
  ];

  const dataRows: (string | number)[][] = [];

  for (const unit of sigDetails) {
    if (!unit.pathAnalyses) continue;
    for (const pa of unit.pathAnalyses) {
      dataRows.push([
        'Signature',
        `${unit.signatureId} - ${unit.signatureName}`,
        pa.path,
        pa.eventCount,
        pa.uniqueUsers,
        pa.uniqueIPs,
        Object.keys(pa.methods).join(', '),
        pa.fpScore,
        verdictLabel(pa.verdict),
        pa.reasons.join('; '),
      ]);
    }
  }

  for (const unit of violDetails) {
    if (!unit.pathAnalyses) continue;
    for (const pa of unit.pathAnalyses) {
      dataRows.push([
        'Violation',
        unit.violationName,
        pa.path,
        pa.eventCount,
        pa.uniqueUsers,
        pa.uniqueIPs,
        Object.keys(pa.methods).join(', '),
        pa.fpScore,
        verdictLabel(pa.verdict),
        pa.reasons.join('; '),
      ]);
    }
  }

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [12, 40, 50, 10, 10, 10, 25, 10, 18, 60]);
  return ws;
}

function buildExclusionRulesSheet(policy: WafExclusionPolicyObject): XLSX.WorkSheet {
  const header = [
    'Rule Name', 'Domain', 'Path', 'Methods',
    'Sig Exclusions', 'Violation Exclusions', 'Attack Type Exclusions',
    'Description',
  ];

  const dataRows = policy.spec.waf_exclusion_rules.map(rule => [
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

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [25, 15, 40, 20, 50, 50, 40, 50]);
  return ws;
}

function buildThreatMeshSummarySheet(opts: FPExcelReportOptions): XLSX.WorkSheet {
  const header = [
    'Source IP', 'Country', 'AS Organization', 'Sec Events', 'Access Log Reqs',
    'Success Rate', 'Avg Req/Hour', 'Paths', 'Description', 'Action',
    'User Agent', 'Attack Types', 'Tenant Count',
    'Quick Verdict', 'Enriched Verdict', 'Enriched Score',
  ];

  const dataRows = opts.summary.threatMeshIPs.map(ip => [
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

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [18, 12, 25, 12, 14, 12, 12, 8, 40, 10, 35, 30, 12, 18, 18, 12]);
  return ws;
}

function buildThreatMeshDetailSheet(details: ThreatMeshAnalysisUnit[]): XLSX.WorkSheet {
  const header = [
    'Source IP', 'User', 'Country', 'AS Org', 'User Agent',
    'Event Count', 'Total Requests on App', 'WAF Events from IP',
    'Description', 'Attack Types', 'Tenant Count', 'Global Events',
    'High Accuracy Sigs', 'TLS Events', 'Malicious Bot Events',
    'Paths Accessed', 'Response Codes',
    'FP Score', 'Verdict', 'Reasons',
    'Suggested Action',
  ];

  const dataRows = details.map(ip => [
    ip.srcIp,
    ip.user || '',
    ip.country || '',
    ip.asOrg || '',
    ip.userAgent || '',
    ip.totalRequestsOnApp || 0,
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

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [
    18, 20, 12, 25, 35,
    12, 15, 12,
    40, 30, 12, 12,
    15, 12, 15,
    50, 30,
    10, 18, 50,
    18,
  ]);
  return ws;
}

function buildPolicyRulesSheet(opts: FPExcelReportOptions): XLSX.WorkSheet {
  const header = ['Rule Name', 'Policy Name', 'Total Blocked', 'Unique IPs'];

  const dataRows = opts.summary.policyRules.map(r => [
    r.ruleName,
    r.policyName,
    r.totalBlocked,
    r.uniqueIPs,
  ]);

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [30, 30, 15, 12]);
  return ws;
}

// ═══════════════════════════════════════════════════════════════════
// MAIN EXPORT
// ═══════════════════════════════════════════════════════════════════

export function generateFPAnalysisExcel(opts: FPExcelReportOptions): void {
  const wb = XLSX.utils.book_new();

  // Always add summary sheet
  XLSX.utils.book_append_sheet(wb, buildSummarySheet(opts), 'Summary');

  if (opts.summary.recommendations && opts.summary.recommendations.steps.length > 0) {
    XLSX.utils.book_append_sheet(wb, buildNextStepsSheet(opts), 'Next Steps');
  }

  if (opts.summary.wafComparison && opts.summary.wafComparison.totalEvents > 0) {
    XLSX.utils.book_append_sheet(wb, buildWafComparisonSheet(opts), 'WAF Comparison');
  }

  if (opts.summary.botAnalysis && opts.summary.botAnalysis.maliciousEvents > 0) {
    XLSX.utils.book_append_sheet(wb, buildBotClassificationSheet(opts), 'Bot Classification');
  }

  if (opts.scopes.includes('waf_signatures') && opts.summary.signatures.length > 0) {
    XLSX.utils.book_append_sheet(wb, buildSignaturesSheet(opts), 'WAF Signatures');
  }

  if (opts.scopes.includes('waf_violations') && opts.summary.violations.length > 0) {
    XLSX.utils.book_append_sheet(wb, buildViolationsSheet(opts), 'WAF Violations');
  }

  // Per-path analysis sheet (if detailed data available)
  const sigDetails = opts.signatureDetails || [];
  const violDetails = opts.violationDetails || [];
  if (sigDetails.length > 0 || violDetails.length > 0) {
    XLSX.utils.book_append_sheet(wb, buildPerPathAnalysisSheet(sigDetails, violDetails), 'Per-Path Analysis');
  }

  if (opts.scopes.includes('threat_mesh') && opts.summary.threatMeshIPs.length > 0) {
    XLSX.utils.book_append_sheet(wb, buildThreatMeshSummarySheet(opts), 'Threat Mesh Summary');

    if (opts.threatMeshDetails && opts.threatMeshDetails.length > 0) {
      XLSX.utils.book_append_sheet(wb, buildThreatMeshDetailSheet(opts.threatMeshDetails), 'Threat Mesh Details');
    }
  }

  if (opts.scopes.includes('service_policy') && opts.summary.policyRules.length > 0) {
    XLSX.utils.book_append_sheet(wb, buildPolicyRulesSheet(opts), 'Service Policy');
  }

  // WAF Exclusion Rules sheet
  if (opts.exclusionPolicy && opts.exclusionPolicy.spec.waf_exclusion_rules.length > 0) {
    XLSX.utils.book_append_sheet(wb, buildExclusionRulesSheet(opts.exclusionPolicy), 'WAF Exclusion Rules');
  }

  // Write and download
  const wbout = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
  const blob = new Blob([wbout], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `fp-analysis-${opts.lbName}-${new Date().toISOString().split('T')[0]}.xlsx`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
