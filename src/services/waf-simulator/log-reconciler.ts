// ═══════════════════════════════════════════════════════════════════════════
// WAF Attack Simulator — Log Reconciliation
//
// After attacks are fired, waits out XC log-ingestion latency, then pulls
// security events + access logs for our source IP and time window and matches
// each fired request (by its correlation marker) to the authoritative verdict:
//   • a blocking security event           → BLOCKED
//   • a detection event in monitoring mode → REACHED_ORIGIN (detected, not blocked)
//   • an access-log entry, no block event  → REACHED_ORIGIN (WAF gap)
//   • nothing found                         → INCONCLUSIVE (ingestion lag / filtered)
// ═══════════════════════════════════════════════════════════════════════════

import { apiClient } from '../api';
import { normalizeLogEntries } from '../rate-limit-advisor/log-collector';
import { getCategory } from './attack-library';
import type {
  AttackResult,
  CategoryRollup,
  ReconciledResult,
  ReconciledVerdict,
  ReconciliationSummary,
  Severity,
  SimProgress,
  SimReport,
  SimRunConfig,
} from './types';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

type Rec = Record<string, unknown>;

function field(o: Rec, names: string[]): string | undefined {
  for (const n of names) {
    const v = o[n];
    if (v !== undefined && v !== null && v !== '') return String(v);
  }
  return undefined;
}

interface SecResp {
  events?: unknown[];
}
interface AccessResp {
  logs?: unknown[];
}

// Pull security events for our source IP + time window.
async function pullSecurityEvents(config: SimRunConfig, startTime: string, endTime: string): Promise<Rec[]> {
  const query = `{src_ip="${config.sourceIp}"}`;
  const resp = (await apiClient.getSecurityEvents(config.namespace, {
    query,
    namespace: config.namespace,
    start_time: startTime,
    end_time: endTime,
    scroll: false,
    limit: 500,
  })) as SecResp;
  return normalizeLogEntries<Rec>(resp.events ?? [], 'wafsim-sec');
}

// Pull access (request) logs for our source IP + time window.
async function pullAccessLogs(config: SimRunConfig, startTime: string, endTime: string): Promise<Rec[]> {
  const query = `{src_ip="${config.sourceIp}"}`;
  const resp = (await apiClient.getAccessLogs(config.namespace, {
    query,
    namespace: config.namespace,
    start_time: startTime,
    end_time: endTime,
    scroll: false,
    limit: 500,
  })) as AccessResp;
  return normalizeLogEntries<Rec>(resp.logs ?? [], 'wafsim-access');
}

function actionIsBlock(action?: string): boolean {
  if (!action) return false;
  const a = action.toLowerCase();
  return a.includes('block') || a.includes('deny') || a.includes('drop');
}

// Find the log entry whose req_path carries our marker.
function matchByMarker(entries: Rec[], marker: string): Rec | undefined {
  return entries.find((e) => {
    const path = field(e, ['req_path', 'request_path', 'path', 'uri']) || '';
    return path.includes(marker);
  });
}

export interface ReconcileOutput {
  reconciled: ReconciledResult[];
  notes: string[];
}

// Wait + poll for logs, then reconcile each result.
export async function reconcile(
  config: SimRunConfig,
  results: AttackResult[],
  onProgress: (p: SimProgress) => void,
  shouldAbort: () => boolean
): Promise<ReconcileOutput> {
  const notes: string[] = [];

  // Window: a minute before the first request to a minute after the last.
  const times = results.map((r) => new Date(r.sentAt).getTime()).filter((t) => !isNaN(t));
  const minT = times.length ? Math.min(...times) : Date.now();
  const startTime = new Date(minT - 60_000).toISOString();

  // Initial ingestion wait.
  for (let s = 0; s < config.ingestionWaitSec; s++) {
    if (shouldAbort()) break;
    onProgress({
      phase: 'waiting',
      message: `Waiting for XC log ingestion… ${config.ingestionWaitSec - s}s`,
      progress: Math.round((s / Math.max(config.ingestionWaitSec, 1)) * 100),
    });
    await sleep(1000);
  }

  let secEvents: Rec[] = [];
  let accessLogs: Rec[] = [];
  let matchedCount = 0;

  for (let attempt = 1; attempt <= config.pollAttempts; attempt++) {
    if (shouldAbort()) break;
    const endTime = new Date(Date.now() + 60_000).toISOString();
    onProgress({
      phase: 'pulling-logs',
      message: `Pulling XC logs (attempt ${attempt}/${config.pollAttempts})…`,
      progress: Math.round((attempt / config.pollAttempts) * 100),
    });

    try {
      [secEvents, accessLogs] = await Promise.all([
        pullSecurityEvents(config, startTime, endTime),
        pullAccessLogs(config, startTime, endTime).catch(() => [] as Rec[]),
      ]);
    } catch (e) {
      notes.push(`Log pull error on attempt ${attempt}: ${(e as Error).message}`);
    }

    // How many of our markers are visible yet?
    matchedCount = results.filter(
      (r) => matchByMarker(secEvents, r.marker) || matchByMarker(accessLogs, r.marker)
    ).length;

    if (matchedCount >= results.length) break; // everything ingested
    if (attempt < config.pollAttempts) await sleep(config.pollIntervalSec * 1000);
  }

  if (secEvents.length === 0 && accessLogs.length === 0) {
    notes.push(
      `No logs returned for src_ip ${config.sourceIp}. The egress IP may differ from what XC records, the log query API may be unavailable for this tenant, or ingestion is still pending.`
    );
  }
  if (matchedCount < results.length) {
    notes.push(
      `${results.length - matchedCount} of ${results.length} requests had no correlating log entry yet (ingestion lag or req_path query stripping). They are marked Inconclusive — re-run the log pull shortly.`
    );
  }

  onProgress({ phase: 'reconciling', message: 'Reconciling results…', progress: 100 });

  const reconciled: ReconciledResult[] = results.map((r) => {
    const sec = matchByMarker(secEvents, r.marker);
    const acc = matchByMarker(accessLogs, r.marker);

    let verdict: ReconciledVerdict = 'INCONCLUSIVE';
    let matchedSecurityEvent: ReconciledResult['matchedSecurityEvent'];
    let matchedAccessLog: ReconciledResult['matchedAccessLog'];

    if (sec) {
      const action = field(sec, ['action', 'waf_action', 'sec_event_action']);
      matchedSecurityEvent = {
        reqId: field(sec, ['req_id', 'request_id']),
        action,
        secEventName: field(sec, ['sec_event_name', 'sec_event_type', 'attack_type']),
        wafMode: field(sec, ['waf_mode', 'enforcement_mode']),
        rspCode: field(sec, ['rsp_code', 'response_code']),
        time: field(sec, ['time', '@timestamp']),
      };
      verdict = actionIsBlock(action) ? 'BLOCKED' : 'REACHED_ORIGIN';
    } else if (acc) {
      verdict = 'REACHED_ORIGIN';
    } else if (r.liveVerdict === 'BLOCKED' && r.blockSupportId) {
      // No log yet, but the live response was a confirmed XC block page.
      verdict = 'BLOCKED';
    }

    if (acc) {
      matchedAccessLog = {
        reqId: field(acc, ['req_id', 'request_id']),
        rspCode: field(acc, ['rsp_code', 'response_code']),
        origRspCode: field(acc, ['original_rsp_code', 'origin_rsp_code']),
        time: field(acc, ['time', '@timestamp']),
      };
    }

    return enrich(r, { ...r, verdict, matchedSecurityEvent, matchedAccessLog });
  });

  return { reconciled, notes };
}

// Attack-only mode: derive verdicts from the live response only.
export function liveOnly(results: AttackResult[]): ReconciledResult[] {
  return results.map((r) => {
    const verdict: ReconciledVerdict =
      r.liveVerdict === 'BLOCKED' ? 'BLOCKED' : r.liveVerdict === 'PASSED_TO_ORIGIN' ? 'REACHED_ORIGIN' : 'INCONCLUSIVE';
    return enrich(r, { ...r, verdict });
  });
}

// Fill in category display fields (runner leaves placeholders).
function enrich(src: AttackResult, partial: ReconciledResult): ReconciledResult {
  const cat = getCategory(src.categoryId);
  return {
    ...partial,
    categoryName: cat?.name || src.categoryId,
    owasp: cat?.owasp || '',
  };
}

export function buildReport(
  config: SimRunConfig,
  reconciled: ReconciledResult[],
  durationMs: number,
  reconciledMode: boolean,
  notes: string[]
): SimReport {
  const summary = summarize(reconciled);
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    tenant: apiClient.getTenant() || '',
    config,
    durationMs,
    results: reconciled,
    summary,
    reconciled: reconciledMode,
    notes,
  };
}

function summarize(rows: ReconciledResult[]): ReconciliationSummary {
  const blocked = rows.filter((r) => r.verdict === 'BLOCKED').length;
  const reachedOrigin = rows.filter((r) => r.verdict === 'REACHED_ORIGIN').length;
  const inconclusive = rows.filter((r) => r.verdict === 'INCONCLUSIVE').length;
  const conclusive = blocked + reachedOrigin;

  const bySeverity = {} as ReconciliationSummary['bySeverity'];
  for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]) {
    const sevRows = rows.filter((r) => r.severity === sev);
    bySeverity[sev] = {
      total: sevRows.length,
      blocked: sevRows.filter((r) => r.verdict === 'BLOCKED').length,
      reachedOrigin: sevRows.filter((r) => r.verdict === 'REACHED_ORIGIN').length,
    };
  }

  const catMap = new Map<string, CategoryRollup>();
  for (const r of rows) {
    let c = catMap.get(r.categoryId);
    if (!c) {
      const cat = getCategory(r.categoryId);
      c = {
        categoryId: r.categoryId,
        categoryName: r.categoryName,
        owasp: r.owasp,
        family: cat?.family || 'WAF',
        total: 0,
        blocked: 0,
        reachedOrigin: 0,
        inconclusive: 0,
      };
      catMap.set(r.categoryId, c);
    }
    c.total++;
    if (r.verdict === 'BLOCKED') c.blocked++;
    else if (r.verdict === 'REACHED_ORIGIN') c.reachedOrigin++;
    else c.inconclusive++;
  }

  return {
    total: rows.length,
    blocked,
    reachedOrigin,
    inconclusive,
    gaps: reachedOrigin,
    blockRate: conclusive > 0 ? Math.round((blocked / conclusive) * 100) : 0,
    byCategory: [...catMap.values()].sort((a, b) => b.reachedOrigin - a.reachedOrigin || a.categoryName.localeCompare(b.categoryName)),
    bySeverity,
  };
}
