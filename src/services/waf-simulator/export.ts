// WAF Attack Simulator — CSV export
import type { SimReport } from './types';

function csvEscape(v: unknown): string {
  const s = v === undefined || v === null ? '' : String(v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function exportSimReportCSV(report: SimReport): void {
  const headers = [
    'Verdict',
    'Category',
    'OWASP',
    'Payload',
    'Severity',
    'Method',
    'Vector',
    'Path',
    'Request URL',
    'Live Status',
    'Live Verdict',
    'Expected Signature',
    'WAF Event',
    'WAF Action',
    'WAF Mode',
    'Req ID',
    'Response (ms)',
    'Support ID',
  ];

  const rows = report.results.map((r) =>
    [
      r.verdict,
      r.categoryName,
      r.owasp,
      r.payloadName,
      r.severity,
      r.method,
      r.vector,
      r.path,
      r.requestUrl,
      r.statusCode,
      r.liveVerdict,
      r.expectedSignature,
      r.matchedSecurityEvent?.secEventName || '',
      r.matchedSecurityEvent?.action || '',
      r.matchedSecurityEvent?.wafMode || '',
      r.matchedSecurityEvent?.reqId || r.matchedAccessLog?.reqId || '',
      r.responseTimeMs,
      r.blockSupportId || '',
    ]
      .map(csvEscape)
      .join(',')
  );

  const meta = [
    `# F5 XC WAF Attack Simulation Report`,
    `# Tenant,${csvEscape(report.tenant)}`,
    `# Generated,${report.timestamp}`,
    `# Target,${csvEscape(`${report.config.target.scheme}://${report.config.target.domain}`)}`,
    `# Namespace,${csvEscape(report.config.namespace)}`,
    `# Load Balancer,${csvEscape(report.config.loadBalancer)}`,
    `# Source IP,${csvEscape(report.config.sourceIp)}`,
    `# Mode,${report.reconciled ? 'Attack + Reconcile' : 'Attack-only'}`,
    `# Total,${report.summary.total}`,
    `# Blocked,${report.summary.blocked}`,
    `# Reached Origin,${report.summary.reachedOrigin}`,
    `# Inconclusive,${report.summary.inconclusive}`,
    `# Block Rate,${report.summary.blockRate}%`,
  ].join('\r\n');

  const csv = '﻿' + meta + '\r\n\r\n' + headers.map(csvEscape).join(',') + '\r\n' + rows.join('\r\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `waf-attack-sim-${report.config.namespace}-${report.timestamp.slice(0, 19).replace(/[:T]/g, '-')}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
