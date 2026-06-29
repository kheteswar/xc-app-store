import type {
  FPAnalysisResults,
  WafExclusionRule,
} from './types';

// ═══════════════════════════════════════════════════════════════
// CSV EXPORT
// ═══════════════════════════════════════════════════════════════

function escapeCSV(val: string | number | boolean): string {
  const str = String(val);
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function csvRow(fields: (string | number | boolean)[]): string {
  return fields.map(escapeCSV).join(',');
}

export function exportAnalysisCSV(results: FPAnalysisResults): string {
  const lines: string[] = [];

  // Header info
  lines.push(`# FP Analysis Report`);
  lines.push(`# LB: ${results.lbName} | Namespace: ${results.namespace}`);
  lines.push(`# Domains: ${results.domains.join(', ')}`);
  lines.push(`# Period: ${results.analysisStart} to ${results.analysisEnd}`);
  lines.push(`# Generated: ${results.generatedAt}`);
  lines.push(`# Total Security Events: ${results.totalSecurityEvents} | Access Logs: ${results.totalAccessLogs}`);
  lines.push('');

  // Signature Units
  if (results.signatureUnits && results.signatureUnits.length > 0) {
    lines.push('## WAF Signature Analysis');
    lines.push(csvRow([
      'Signature ID', 'Signature Name', 'Attack Type', 'Accuracy',
      'Context Type', 'Context Name', 'Path', 'Path Count',
      'Events', 'Flagged Users', 'Total Users', 'User Ratio',
      'Total Requests', 'Request Ratio',
      'Composite Score', 'Verdict',
      'Client Breadth', 'Path Breadth', 'Context',
      'Matching Evidence', 'Origin Response', 'Client Behavior', 'Detection Confidence',
      'Override', 'AI Confirmed',
    ]));
    for (const u of results.signatureUnits) {
      lines.push(csvRow([
        u.signatureId, u.signatureName, u.attackType, u.accuracy,
        u.contextType, u.contextName, u.path, u.pathCount,
        u.eventCount, u.flaggedUsers, u.totalUsersOnPath, u.userRatio.toFixed(4),
        u.totalRequestsOnPath, u.requestRatio.toFixed(4),
        u.signals.compositeScore, u.signals.verdict,
        u.signals.clientBreadth.score, u.signals.pathBreadth.score, u.signals.context.score,
        u.signals.matchingEvidence.score, u.signals.originResponse.score, u.signals.clientBehavior.score, u.signals.detectionConfidence.score,
        u.signals.override || '', u.aiConfirmed,
      ]));
    }
    lines.push('');
  }

  // Violation Units
  if (results.violationUnits && results.violationUnits.length > 0) {
    lines.push('## WAF Violation Analysis');
    lines.push(csvRow([
      'Violation Name', 'Attack Type', 'Path', 'Path Count',
      'Events', 'Flagged Users', 'Total Users', 'User Ratio',
      'Total Requests', 'Request Ratio',
      'Composite Score', 'Verdict',
    ]));
    for (const u of results.violationUnits) {
      lines.push(csvRow([
        u.violationName, u.attackType, u.path, u.pathCount,
        u.eventCount, u.flaggedUsers, u.totalUsersOnPath, u.userRatio.toFixed(4),
        u.totalRequestsOnPath, u.requestRatio.toFixed(4),
        u.signals.compositeScore, u.signals.verdict,
      ]));
    }
    lines.push('');
  }

  // Threat Mesh Units
  if (results.threatMeshUnits && results.threatMeshUnits.length > 0) {
    lines.push('## Threat Mesh Analysis');
    lines.push(csvRow([
      'Source IP', 'User', 'User Agent', 'Country', 'AS Org',
      'Tenant Count', 'Global Events', 'WAF Events on App',
      'FP Score', 'Verdict', 'Suggested Action',
    ]));
    for (const u of results.threatMeshUnits) {
      lines.push(csvRow([
        u.srcIp, u.user, u.userAgent, u.country, u.asOrg,
        u.threatDetails.tenantCount, u.threatDetails.events, u.wafEventsFromThisIP,
        u.fpScore, u.verdict, u.suggestedAction || '',
      ]));
    }
    lines.push('');
  }

  // Service Policy Units
  if (results.servicePolicyUnits && results.servicePolicyUnits.length > 0) {
    lines.push('## Service Policy Analysis');
    lines.push(csvRow([
      'Policy', 'Rule', 'Total Blocked', 'Blocked IPs',
      'Real Browser %', 'Avg Trust Score',
      'FP Score', 'Verdict',
    ]));
    for (const u of results.servicePolicyUnits) {
      lines.push(csvRow([
        u.policyName, u.ruleName, u.totalBlocked, u.blockedIPs.length,
        (u.realBrowserPct * 100).toFixed(0) + '%', u.avgTrustScore.toFixed(0),
        u.fpScore, u.verdict,
      ]));
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ═══════════════════════════════════════════════════════════════
// EXCLUSION JSON EXPORT
// ═══════════════════════════════════════════════════════════════

export function exportExclusionJSON(rules: WafExclusionRule[]): string {
  return JSON.stringify(rules, null, 2);
}
