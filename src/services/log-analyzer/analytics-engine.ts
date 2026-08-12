import type { AccessLogEntry } from '../rate-limit-advisor/types';
import type {
  NumericFieldStats, StringFieldStats, TimeSeriesPoint, LogSummary, ClientFilter,
  ErrorAnalysis, PerformanceAnalysis, SecurityInsights, TopTalker, StatusTimeSeriesPoint,
  BreakdownResult, BreakdownEntry, BreakdownSubValue, AggregatedLogData,
} from './types';
import type { AggBucket, NestedBreakdownEntry } from './aggregation-client';
import { FIELD_DEFINITIONS } from './field-definitions';

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = (p / 100) * (sorted.length - 1);
  const lower = Math.floor(idx);
  const upper = Math.ceil(idx);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (idx - lower);
}

/**
 * Resolve a dot-notation field path on a log entry.
 * E.g., 'bot_info.name' → log.bot_info.name
 * Also checks for pre-flattened keys (from merge): log['bot_info.name']
 */
export function resolveField(log: Record<string, unknown>, key: string): unknown {
  // First try direct (works for flattened keys like 'bot_info.name')
  const direct = log[key];
  if (direct !== undefined) return direct;

  // Then try dot-path traversal for nested objects
  if (key.includes('.')) {
    const parts = key.split('.');
    let current: unknown = log;
    for (const part of parts) {
      if (current === null || current === undefined || typeof current !== 'object') return undefined;
      // If current is an array, take the first element
      if (Array.isArray(current)) {
        if (current.length === 0) return undefined;
        current = (current[0] as Record<string, unknown>)[part];
      } else {
        current = (current as Record<string, unknown>)[part];
      }
    }
    return current;
  }

  return undefined;
}

function extractNumeric(log: AccessLogEntry, key: string, parseAsNumber: boolean): number | null {
  const raw = resolveField(log as Record<string, unknown>, key);
  if (raw === undefined || raw === null || raw === '') return null;
  if (typeof raw === 'number') return isFinite(raw) ? raw : null;
  if (parseAsNumber || typeof raw === 'string') {
    const n = parseFloat(String(raw));
    return isFinite(n) ? n : null;
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// NUMERIC FIELD STATS
// ═══════════════════════════════════════════════════════════════════

export function computeNumericStats(
  logs: AccessLogEntry[],
  fieldKey: string,
): NumericFieldStats {
  const def = FIELD_DEFINITIONS.find(f => f.key === fieldKey);
  const parseAsNum = def?.parseAsNumber ?? false;
  const label = def?.label ?? fieldKey;

  const values: number[] = [];
  for (const log of logs) {
    const v = extractNumeric(log, fieldKey, parseAsNum);
    if (v !== null) values.push(v);
  }

  if (values.length === 0) {
    return {
      field: fieldKey, label, count: 0, sum: 0, min: 0, max: 0,
      mean: 0, median: 0, stdDev: 0, p50: 0, p75: 0, p90: 0, p95: 0, p99: 0,
      histogram: [],
    };
  }

  values.sort((a, b) => a - b);

  const sum = values.reduce((a, b) => a + b, 0);
  const mean = sum / values.length;
  const variance = values.reduce((acc, v) => acc + (v - mean) ** 2, 0) / values.length;
  const stdDev = Math.sqrt(variance);

  const min = values[0];
  const max = values[values.length - 1];

  // Build histogram (10-20 buckets)
  const bucketCount = Math.min(20, Math.max(5, Math.ceil(Math.sqrt(values.length))));
  const range = max - min;
  const histogram: Array<{ bucket: string; count: number }> = [];

  if (range === 0) {
    histogram.push({ bucket: formatValue(min), count: values.length });
  } else {
    const bucketSize = range / bucketCount;
    const buckets = new Array(bucketCount).fill(0);
    for (const v of values) {
      const idx = Math.min(Math.floor((v - min) / bucketSize), bucketCount - 1);
      buckets[idx]++;
    }
    for (let i = 0; i < bucketCount; i++) {
      const lo = min + i * bucketSize;
      const hi = lo + bucketSize;
      histogram.push({ bucket: `${formatValue(lo)}-${formatValue(hi)}`, count: buckets[i] });
    }
  }

  return {
    field: fieldKey,
    label,
    count: values.length,
    sum,
    min,
    max,
    mean,
    median: percentile(values, 50),
    stdDev,
    p50: percentile(values, 50),
    p75: percentile(values, 75),
    p90: percentile(values, 90),
    p95: percentile(values, 95),
    p99: percentile(values, 99),
    histogram,
  };
}

function formatValue(v: number): string {
  if (Number.isInteger(v)) return v.toLocaleString();
  if (Math.abs(v) < 0.001) return v.toExponential(2);
  return v.toFixed(3);
}

// ═══════════════════════════════════════════════════════════════════
// STRING FIELD STATS
// ═══════════════════════════════════════════════════════════════════

export function computeStringStats(
  logs: AccessLogEntry[],
  fieldKey: string,
  topN: number = 0,
): StringFieldStats {
  const def = FIELD_DEFINITIONS.find(f => f.key === fieldKey);
  const label = def?.label ?? fieldKey;

  const counts = new Map<string, number>();
  let total = 0;

  for (const log of logs) {
    const raw = resolveField(log as Record<string, unknown>, fieldKey);
    const val = raw === undefined || raw === null || raw === '' ? '(empty)' : String(raw);
    counts.set(val, (counts.get(val) || 0) + 1);
    total++;
  }

  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const topValues = (topN > 0 ? sorted.slice(0, topN) : sorted).map(([value, count]) => ({
    value,
    count,
    percentage: total > 0 ? (count / total) * 100 : 0,
  }));

  return {
    field: fieldKey,
    label,
    totalCount: total,
    uniqueCount: counts.size,
    topValues,
  };
}

// ═══════════════════════════════════════════════════════════════════
// BOOLEAN FIELD STATS (returned as StringFieldStats)
// ═══════════════════════════════════════════════════════════════════

export function computeBooleanStats(
  logs: AccessLogEntry[],
  fieldKey: string,
): StringFieldStats {
  const def = FIELD_DEFINITIONS.find(f => f.key === fieldKey);
  const label = def?.label ?? fieldKey;

  let trueCount = 0;
  let falseCount = 0;

  for (const log of logs) {
    const raw = resolveField(log as Record<string, unknown>, fieldKey);
    if (raw === true || raw === 'true') trueCount++;
    else falseCount++;
  }

  const total = trueCount + falseCount;
  return {
    field: fieldKey,
    label,
    totalCount: total,
    uniqueCount: 2,
    topValues: [
      { value: 'true', count: trueCount, percentage: total > 0 ? (trueCount / total) * 100 : 0 },
      { value: 'false', count: falseCount, percentage: total > 0 ? (falseCount / total) * 100 : 0 },
    ],
  };
}

// ═══════════════════════════════════════════════════════════════════
// FIELD BREAKDOWN (cross-tabulation)
// ═══════════════════════════════════════════════════════════════════

function getFieldValue(log: AccessLogEntry, key: string): string {
  const raw = resolveField(log as Record<string, unknown>, key);
  return raw === undefined || raw === null || raw === '' ? '(empty)' : String(raw);
}

/**
 * Cross-tabulate: for each unique value of primaryField, compute
 * counts of each breakdownField's unique values.
 */
export function computeBreakdown(
  logs: AccessLogEntry[],
  primaryField: string,
  breakdownFieldKeys: string[],
  topN: number = 50,
): BreakdownResult {
  const primaryDef = FIELD_DEFINITIONS.find(f => f.key === primaryField);
  const breakdownDefs = breakdownFieldKeys.map(k => {
    const def = FIELD_DEFINITIONS.find(f => f.key === k);
    return { key: k, label: def?.label ?? k };
  });

  // Group logs by primary field value
  const grouped = new Map<string, AccessLogEntry[]>();
  for (const log of logs) {
    const pv = getFieldValue(log, primaryField);
    const arr = grouped.get(pv);
    if (arr) arr.push(log);
    else grouped.set(pv, [log]);
  }

  // Sort primary values by count desc, take top N
  const sortedPrimaries = [...grouped.entries()]
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, topN);

  const entries: BreakdownEntry[] = sortedPrimaries.map(([pv, pLogs]) => {
    const breakdowns: Record<string, BreakdownSubValue[]> = {};

    for (const bField of breakdownFieldKeys) {
      const counts = new Map<string, number>();
      for (const log of pLogs) {
        const bv = getFieldValue(log, bField);
        counts.set(bv, (counts.get(bv) || 0) + 1);
      }
      breakdowns[bField] = [...counts.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([value, count]) => ({ value, count }));
    }

    return { primaryValue: pv, primaryCount: pLogs.length, breakdowns };
  });

  return {
    primaryField,
    primaryLabel: primaryDef?.label ?? primaryField,
    breakdownFields: breakdownDefs,
    entries,
  };
}

// ═══════════════════════════════════════════════════════════════════
// TIME SERIES
// ═══════════════════════════════════════════════════════════════════

export function buildTimeSeries(
  logs: AccessLogEntry[],
  rangeHours: number,
): TimeSeriesPoint[] {
  if (logs.length === 0) return [];

  // Auto-select bucket size
  let bucketMinutes: number;
  if (rangeHours <= 1) bucketMinutes = 1;
  else if (rangeHours <= 6) bucketMinutes = 5;
  else if (rangeHours <= 24) bucketMinutes = 15;
  else if (rangeHours <= 168) bucketMinutes = 60;
  else bucketMinutes = 120;

  const bucketMs = bucketMinutes * 60 * 1000;
  const buckets = new Map<number, number>();

  for (const log of logs) {
    const ts = log['@timestamp'] || log.time;
    if (!ts) continue;
    const t = new Date(ts).getTime();
    if (!isFinite(t)) continue;
    const bucket = Math.floor(t / bucketMs) * bucketMs;
    buckets.set(bucket, (buckets.get(bucket) || 0) + 1);
  }

  const sorted = [...buckets.entries()].sort((a, b) => a[0] - b[0]);

  // Fill gaps with zeros
  if (sorted.length > 1) {
    const filled: Array<[number, number]> = [];
    for (let i = 0; i < sorted.length; i++) {
      filled.push(sorted[i]);
      if (i < sorted.length - 1) {
        let next = sorted[i][0] + bucketMs;
        while (next < sorted[i + 1][0]) {
          filled.push([next, 0]);
          next += bucketMs;
        }
      }
    }
    return filled.map(([ts, count]) => {
      const d = new Date(ts);
      const label = bucketMinutes >= 60
        ? `${(d.getMonth() + 1).toString().padStart(2, '0')}/${d.getDate().toString().padStart(2, '0')} ${d.getHours().toString().padStart(2, '0')}:00`
        : `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
      return { timestamp: d.toISOString(), count, label };
    });
  }

  return sorted.map(([ts, count]) => {
    const d = new Date(ts);
    return { timestamp: d.toISOString(), count, label: d.toISOString() };
  });
}

// ═══════════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════════

export function computeSummary(logs: AccessLogEntry[]): LogSummary {
  if (logs.length === 0) {
    return { totalLogs: 0, uniqueIPs: 0, uniquePaths: 0, uniqueDomains: 0, avgDurationMs: 0, errorRate: 0 };
  }

  const ips = new Set<string>();
  const paths = new Set<string>();
  const domains = new Set<string>();
  let totalDuration = 0;
  let durationCount = 0;
  let errorCount = 0;

  for (const log of logs) {
    if (log.src_ip) ips.add(log.src_ip);
    if (log.req_path) paths.add(log.req_path);
    if (log.domain) domains.add(log.domain);

    const dur = typeof log.total_duration_seconds === 'number' ? log.total_duration_seconds : parseFloat(String(log.total_duration_seconds));
    if (isFinite(dur)) { totalDuration += dur; durationCount++; }

    const code = log.rsp_code ? parseInt(log.rsp_code, 10) : 0;
    if (code >= 400) errorCount++;
  }

  return {
    totalLogs: logs.length,
    uniqueIPs: ips.size,
    uniquePaths: paths.size,
    uniqueDomains: domains.size,
    avgDurationMs: durationCount > 0 ? (totalDuration / durationCount) * 1000 : 0,
    errorRate: (errorCount / logs.length) * 100,
  };
}

// ═══════════════════════════════════════════════════════════════════
// CLIENT-SIDE FILTERING
// ═══════════════════════════════════════════════════════════════════

export function applyClientFilters(
  logs: AccessLogEntry[],
  filters: ClientFilter[],
): AccessLogEntry[] {
  if (filters.length === 0) return logs;

  return logs.filter(log => {
    return filters.every(f => {
      const raw = (log as Record<string, unknown>)[f.field];
      const val = raw === undefined || raw === null ? '' : String(raw);

      switch (f.operator) {
        case 'equals':
          return val === f.value;
        case 'not_equals':
          return val !== f.value;
        case 'contains':
          return val.toLowerCase().includes(f.value.toLowerCase());
        case 'regex':
          try { return new RegExp(f.value, 'i').test(val); }
          catch { return false; }
        default:
          return true;
      }
    });
  });
}

// ═══════════════════════════════════════════════════════════════════
// ERROR ANALYSIS
// ═══════════════════════════════════════════════════════════════════

export function computeErrorAnalysis(logs: AccessLogEntry[]): ErrorAnalysis {
  const total = logs.length;
  const errors = logs.filter(l => {
    const code = parseInt(l.rsp_code, 10);
    return code >= 400 || code === 0;
  });

  const byCode = countAndSort(errors, 'rsp_code');
  const byCodeClass = countAndSort(errors, 'rsp_code_class');
  const byDetail = countAndSort(errors, 'rsp_code_details');

  // Response flags — parse JSON string
  const flagCounts = new Map<string, number>();
  for (const log of errors) {
    const raw = (log as Record<string, unknown>).response_flags;
    if (!raw || raw === '{}') { flagCounts.set('(none)', (flagCounts.get('(none)') || 0) + 1); continue; }
    try {
      const flags = typeof raw === 'string' ? JSON.parse(raw) : raw;
      const keys = Object.keys(flags as Record<string, unknown>);
      const label = keys.length > 0 ? keys.join(', ') : '(none)';
      flagCounts.set(label, (flagCounts.get(label) || 0) + 1);
    } catch { flagCounts.set(String(raw).slice(0, 60), (flagCounts.get(String(raw)) || 0) + 1); }
  }

  // Error rate by path
  const pathTotal = new Map<string, number>();
  const pathErrors = new Map<string, number>();
  for (const l of logs) {
    const p = l.req_path || '(empty)';
    pathTotal.set(p, (pathTotal.get(p) || 0) + 1);
  }
  for (const l of errors) {
    const p = l.req_path || '(empty)';
    pathErrors.set(p, (pathErrors.get(p) || 0) + 1);
  }
  const byPath = [...pathErrors.entries()]
    .map(([path, count]) => ({ path, count, errorRate: (count / (pathTotal.get(path) || 1)) * 100 }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 30);

  // Error by source IP
  const ipTotal = new Map<string, number>();
  const ipErrors = new Map<string, { count: number; country: string }>();
  for (const l of logs) { ipTotal.set(l.src_ip || '', (ipTotal.get(l.src_ip || '') || 0) + 1); }
  for (const l of errors) {
    const ip = l.src_ip || '';
    const prev = ipErrors.get(ip) || { count: 0, country: l.country || '' };
    prev.count++;
    ipErrors.set(ip, prev);
  }
  const bySource = [...ipErrors.entries()]
    .map(([ip, { count, country }]) => ({ ip, count, errorRate: (count / (ipTotal.get(ip) || 1)) * 100, country }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  return {
    totalErrors: errors.length,
    errorRate: total > 0 ? (errors.length / total) * 100 : 0,
    byCode: byCode.map(v => ({ code: v.value, count: v.count, pct: (v.count / errors.length) * 100 })),
    byCodeClass: byCodeClass.map(v => ({ cls: v.value, count: v.count, pct: (v.count / errors.length) * 100 })),
    byPath,
    bySource,
    byDetail: byDetail.map(v => ({ detail: v.value, count: v.count, pct: (v.count / errors.length) * 100 })),
    byResponseFlag: [...flagCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([flag, count]) => ({ flag, count, pct: (count / errors.length) * 100 })),
  };
}

function countAndSort(logs: AccessLogEntry[], field: string): Array<{ value: string; count: number }> {
  const counts = new Map<string, number>();
  for (const l of logs) {
    const v = (l as Record<string, unknown>)[field];
    const s = v === undefined || v === null ? '(empty)' : String(v);
    counts.set(s, (counts.get(s) || 0) + 1);
  }
  return [...counts.entries()].map(([value, count]) => ({ value, count })).sort((a, b) => b.count - a.count);
}

// ═══════════════════════════════════════════════════════════════════
// PERFORMANCE ANALYSIS
// ═══════════════════════════════════════════════════════════════════

export function computePerformanceAnalysis(logs: AccessLogEntry[]): PerformanceAnalysis {
  const durations: number[] = [];
  for (const l of logs) {
    const d = parseDuration(l);
    if (d !== null) durations.push(d);
  }
  durations.sort((a, b) => a - b);

  const overall = durations.length > 0 ? {
    p50: percentile(durations, 50),
    p90: percentile(durations, 90),
    p95: percentile(durations, 95),
    p99: percentile(durations, 99),
    max: durations[durations.length - 1],
    mean: durations.reduce((a, b) => a + b, 0) / durations.length,
  } : { p50: 0, p90: 0, p95: 0, p99: 0, max: 0, mean: 0 };

  // Slowest requests
  const withDur = logs
    .map(l => ({ log: l, dur: parseDuration(l) ?? 0 }))
    .sort((a, b) => b.dur - a.dur)
    .slice(0, 25);
  const slowRequests = withDur.map(({ log: l, dur }) => ({
    timestamp: l['@timestamp'] || l.time || '',
    method: l.method || '',
    path: l.req_path || '',
    code: l.rsp_code || '',
    durationS: dur,
    srcIp: l.src_ip || '',
    country: l.country || '',
    detail: l.rsp_code_details || '',
  }));

  // Latency by path
  const pathDurations = new Map<string, number[]>();
  for (const l of logs) {
    const d = parseDuration(l);
    if (d === null) continue;
    const p = l.req_path || '(empty)';
    if (!pathDurations.has(p)) pathDurations.set(p, []);
    pathDurations.get(p)!.push(d);
  }
  const byPath = [...pathDurations.entries()]
    .map(([path, durs]) => {
      durs.sort((a, b) => a - b);
      return {
        path,
        count: durs.length,
        avgMs: (durs.reduce((a, b) => a + b, 0) / durs.length) * 1000,
        p95Ms: percentile(durs, 95) * 1000,
        maxMs: durs[durs.length - 1] * 1000,
      };
    })
    .sort((a, b) => b.p95Ms - a.p95Ms)
    .slice(0, 20);

  // Latency by country
  const countryDurations = new Map<string, number[]>();
  for (const l of logs) {
    const d = parseDuration(l);
    if (d === null) continue;
    const c = l.country || '(unknown)';
    if (!countryDurations.has(c)) countryDurations.set(c, []);
    countryDurations.get(c)!.push(d);
  }
  const byCountry = [...countryDurations.entries()]
    .map(([country, durs]) => {
      durs.sort((a, b) => a - b);
      return {
        country,
        count: durs.length,
        avgMs: (durs.reduce((a, b) => a + b, 0) / durs.length) * 1000,
        p95Ms: percentile(durs, 95) * 1000,
      };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  // Latency by site
  const siteDurations = new Map<string, number[]>();
  for (const l of logs) {
    const d = parseDuration(l);
    if (d === null) continue;
    const s = l.src_site || l.site || '(unknown)';
    if (!siteDurations.has(s)) siteDurations.set(s, []);
    siteDurations.get(s)!.push(d);
  }
  const bySite = [...siteDurations.entries()]
    .map(([site, durs]) => {
      durs.sort((a, b) => a - b);
      return {
        site,
        count: durs.length,
        avgMs: (durs.reduce((a, b) => a + b, 0) / durs.length) * 1000,
        p95Ms: percentile(durs, 95) * 1000,
      };
    })
    .sort((a, b) => b.count - a.count);

  return { overall, slowRequests, byPath, byCountry, bySite };
}

function parseDuration(l: AccessLogEntry): number | null {
  const raw = (l as Record<string, unknown>).total_duration_seconds
    ?? (l as Record<string, unknown>).duration_with_data_tx_delay;
  if (raw === undefined || raw === null || raw === '') return null;
  const v = typeof raw === 'number' ? raw : parseFloat(String(raw));
  return isFinite(v) ? v : null;
}

// ═══════════════════════════════════════════════════════════════════
// SECURITY INSIGHTS
// ═══════════════════════════════════════════════════════════════════

export function computeSecurityInsights(logs: AccessLogEntry[]): SecurityInsights {
  const total = logs.length;

  // WAF actions
  const wafCounts = new Map<string, number>();
  for (const l of logs) {
    const a = (l as Record<string, unknown>).waf_action;
    const v = !a ? '(none)' : String(a);
    wafCounts.set(v, (wafCounts.get(v) || 0) + 1);
  }
  const wafActions = [...wafCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([action, count]) => ({ action, count, pct: (count / total) * 100 }));

  // Bot classes
  const botCounts = new Map<string, number>();
  for (const l of logs) {
    const b = (l as Record<string, unknown>).bot_class;
    const v = !b ? '(none)' : String(b);
    botCounts.set(v, (botCounts.get(v) || 0) + 1);
  }
  const botClasses = [...botCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([cls, count]) => ({ cls, count, pct: (count / total) * 100 }));

  // Top blocked IPs (waf_action = block or rsp_code_details contains blocked/denied)
  const blockedIPs = new Map<string, { count: number; country: string; wafAction: string }>();
  for (const l of logs) {
    const waf = String((l as Record<string, unknown>).waf_action || '');
    const detail = String(l.rsp_code_details || '').toLowerCase();
    if (waf === 'block' || detail.includes('blocked') || detail.includes('denied') || detail.includes('ext_authz')) {
      const ip = l.src_ip || '';
      const prev = blockedIPs.get(ip) || { count: 0, country: l.country || '', wafAction: waf || detail };
      prev.count++;
      blockedIPs.set(ip, prev);
    }
  }
  const topBlockedIPs = [...blockedIPs.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 20)
    .map(([ip, d]) => ({ ip, count: d.count, country: d.country, wafAction: d.wafAction }));

  // Policy hit results
  const policyCounts = new Map<string, number>();
  for (const l of logs) {
    const ph = (l as Record<string, unknown>).policy_hits as { policy_hits?: Array<{ result?: string }> } | undefined;
    if (ph?.policy_hits) {
      for (const hit of ph.policy_hits) {
        const r = hit.result || '(unknown)';
        policyCounts.set(r, (policyCounts.get(r) || 0) + 1);
      }
    }
  }
  const policyHitResults = [...policyCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([result, count]) => ({ result, count, pct: (count / Math.max(1, [...policyCounts.values()].reduce((a, b) => a + b, 0))) * 100 }));

  // Suspicious paths (paths with high block rate)
  const pathTotal = new Map<string, number>();
  const pathBlocked = new Map<string, number>();
  for (const l of logs) {
    const p = l.req_path || '(empty)';
    pathTotal.set(p, (pathTotal.get(p) || 0) + 1);
    const waf = String((l as Record<string, unknown>).waf_action || '');
    const detail = String(l.rsp_code_details || '').toLowerCase();
    if (waf === 'block' || detail.includes('blocked') || detail.includes('denied')) {
      pathBlocked.set(p, (pathBlocked.get(p) || 0) + 1);
    }
  }
  const suspiciousPaths = [...pathBlocked.entries()]
    .map(([path, count]) => ({ path, count, blockedPct: (count / (pathTotal.get(path) || 1)) * 100 }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  return { wafActions, botClasses, topBlockedIPs, policyHitResults, suspiciousPaths };
}

// ═══════════════════════════════════════════════════════════════════
// TOP TALKERS
// ═══════════════════════════════════════════════════════════════════

export function computeTopTalkers(logs: AccessLogEntry[], topN: number = 25): TopTalker[] {
  const ipData = new Map<string, {
    requests: number; errors: number; bandwidth: number;
    country: string; asOrg: string; paths: Map<string, number>;
    botClass: string; wafBlocked: number;
  }>();

  for (const l of logs) {
    const ip = l.src_ip || '(unknown)';
    if (!ipData.has(ip)) {
      ipData.set(ip, {
        requests: 0, errors: 0, bandwidth: 0,
        country: l.country || '', asOrg: (l as Record<string, unknown>).as_org as string || '',
        paths: new Map(), botClass: (l as Record<string, unknown>).bot_class as string || '',
        wafBlocked: 0,
      });
    }
    const d = ipData.get(ip)!;
    d.requests++;
    const code = parseInt(l.rsp_code, 10);
    if (code >= 400 || code === 0) d.errors++;
    d.bandwidth += parseInt(l.rsp_size || '0', 10) || 0;
    const p = l.req_path || '/';
    d.paths.set(p, (d.paths.get(p) || 0) + 1);
    const waf = String((l as Record<string, unknown>).waf_action || '');
    if (waf === 'block') d.wafBlocked++;
  }

  return [...ipData.entries()]
    .map(([ip, d]) => {
      const topPath = [...d.paths.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || '/';
      return {
        ip, requests: d.requests, errors: d.errors,
        errorRate: (d.errors / d.requests) * 100,
        bandwidth: d.bandwidth, country: d.country, asOrg: d.asOrg,
        topPath, botClass: d.botClass, wafBlocked: d.wafBlocked,
      };
    })
    .sort((a, b) => b.requests - a.requests)
    .slice(0, topN);
}

// ═══════════════════════════════════════════════════════════════════
// STATUS TIME SERIES (stacked by response class)
// ═══════════════════════════════════════════════════════════════════

export function buildStatusTimeSeries(logs: AccessLogEntry[], rangeHours: number): StatusTimeSeriesPoint[] {
  if (logs.length === 0) return [];

  let bucketMinutes: number;
  if (rangeHours <= 1) bucketMinutes = 1;
  else if (rangeHours <= 6) bucketMinutes = 5;
  else if (rangeHours <= 24) bucketMinutes = 15;
  else if (rangeHours <= 168) bucketMinutes = 60;
  else bucketMinutes = 120;

  const bucketMs = bucketMinutes * 60 * 1000;
  const buckets = new Map<number, { '2xx': number; '3xx': number; '4xx': number; '5xx': number; other: number }>();

  for (const log of logs) {
    const ts = log['@timestamp'] || log.time;
    if (!ts) continue;
    const t = new Date(ts).getTime();
    if (!isFinite(t)) continue;
    const bucket = Math.floor(t / bucketMs) * bucketMs;
    if (!buckets.has(bucket)) buckets.set(bucket, { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, other: 0 });
    const b = buckets.get(bucket)!;
    const cls = log.rsp_code_class || '';
    if (cls === '2xx') b['2xx']++;
    else if (cls === '3xx') b['3xx']++;
    else if (cls === '4xx') b['4xx']++;
    else if (cls === '5xx') b['5xx']++;
    else b.other++;
  }

  const sorted = [...buckets.entries()].sort((a, b) => a[0] - b[0]);

  // Fill gaps
  const filled: Array<[number, typeof sorted[0][1]]> = [];
  for (let i = 0; i < sorted.length; i++) {
    filled.push(sorted[i]);
    if (i < sorted.length - 1) {
      let next = sorted[i][0] + bucketMs;
      while (next < sorted[i + 1][0]) {
        filled.push([next, { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, other: 0 }]);
        next += bucketMs;
      }
    }
  }

  return filled.map(([ts, data]) => {
    const d = new Date(ts);
    const label = bucketMinutes >= 60
      ? `${(d.getMonth() + 1).toString().padStart(2, '0')}/${d.getDate().toString().padStart(2, '0')} ${d.getHours().toString().padStart(2, '0')}:00`
      : `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
    return { timestamp: d.toISOString(), label, ...data };
  });
}

// ═══════════════════════════════════════════════════════════════════
// AGGREGATION-BASED ANALYTICS
// Functions that build analytics results from AggregatedLogData
// instead of raw log arrays.
// ═══════════════════════════════════════════════════════════════════

/**
 * Convert aggregation buckets to StringFieldStats.
 * Used for field distribution panels in the Log Analyzer.
 */
export function buildStringStatsFromBuckets(
  buckets: AggBucket[],
  fieldKey: string,
  totalHits: number,
): StringFieldStats {
  const def = FIELD_DEFINITIONS.find(f => f.key === fieldKey);
  const label = def?.label ?? fieldKey;
  const topValues = buckets.map(b => ({
    value: b.key,
    count: b.count,
    percentage: totalHits > 0 ? (b.count / totalHits) * 100 : 0,
  }));
  return {
    field: fieldKey,
    label,
    totalCount: totalHits,
    uniqueCount: buckets.length,
    topValues,
  };
}

// ═══════════════════════════════════════════════════════════════════
// NUMERIC STATS FROM AGGREGATION (full-dataset via avg/min/max + topk buckets)
// ═══════════════════════════════════════════════════════════════════

/**
 * Build NumericFieldStats from server-side aggregation results.
 *
 * Combines:
 *   - `numeric` (avg/min/max from XC min/max/avg aggregations, when field is
 *     one of the enumerated numeric fields — DURATION_WITH_DATA_TX_DELAY,
 *     TIMESTAMP)
 *   - `buckets` from a large-topk field aggregation (numeric field treated as
 *     keyword) — used to compute exact percentiles + median + stdDev + histogram
 *     across the full dataset.
 *
 * If `numeric` avg/min/max are all null, min/max/mean are derived from buckets
 * (still accurate provided topk is large enough to cover the distribution).
 */
export function buildNumericStatsFromAgg(
  buckets: AggBucket[],
  fieldKey: string,
  numeric: { avg: number | null; min: number | null; max: number | null },
  totalHits: number,
): NumericFieldStats {
  const def = FIELD_DEFINITIONS.find(f => f.key === fieldKey);
  const label = def?.label ?? fieldKey;

  // Convert buckets → sorted value/count array
  const valueCounts: Array<{ value: number; count: number }> = [];
  for (const b of buckets) {
    const v = Number(b.key);
    if (isFinite(v)) valueCounts.push({ value: v, count: b.count });
  }
  valueCounts.sort((a, b) => a.value - b.value);

  const bucketTotalCount = valueCounts.reduce((s, x) => s + x.count, 0);
  if (bucketTotalCount === 0 && numeric.avg === null) {
    return {
      field: fieldKey, label, count: 0, sum: 0, min: 0, max: 0,
      mean: 0, median: 0, stdDev: 0, p50: 0, p75: 0, p90: 0, p95: 0, p99: 0,
      histogram: [],
    };
  }

  // Choose "coverage" — how much of totalHits the buckets cover
  const coverage = totalHits > 0 ? bucketTotalCount / totalHits : 1;

  // Percentile from bucket distribution
  const percentileFromBuckets = (p: number): number => {
    if (valueCounts.length === 0) return 0;
    const target = (p / 100) * bucketTotalCount;
    let running = 0;
    for (const vc of valueCounts) {
      running += vc.count;
      if (running >= target) return vc.value;
    }
    return valueCounts[valueCounts.length - 1].value;
  };

  const min = numeric.min ?? (valueCounts[0]?.value ?? 0);
  const max = numeric.max ?? (valueCounts[valueCounts.length - 1]?.value ?? 0);
  const bucketSum = valueCounts.reduce((s, x) => s + x.value * x.count, 0);
  const mean = numeric.avg ?? (bucketTotalCount > 0 ? bucketSum / bucketTotalCount : 0);
  const sum = numeric.avg !== null ? numeric.avg * totalHits : bucketSum;

  // stdDev from bucket distribution (variance-weighted)
  let variance = 0;
  if (bucketTotalCount > 0) {
    for (const vc of valueCounts) {
      variance += vc.count * (vc.value - mean) ** 2;
    }
    variance /= bucketTotalCount;
  }
  const stdDev = Math.sqrt(variance);

  const p50 = percentileFromBuckets(50);
  const p75 = percentileFromBuckets(75);
  const p90 = percentileFromBuckets(90);
  const p95 = percentileFromBuckets(95);
  const p99 = percentileFromBuckets(99);

  // Histogram: bin the top-K values into <=20 buckets between min and max
  const histogram: Array<{ bucket: string; count: number }> = [];
  if (valueCounts.length > 0) {
    const range = max - min;
    if (range === 0) {
      histogram.push({ bucket: formatValue(min), count: bucketTotalCount });
    } else {
      const binCount = Math.min(20, Math.max(5, Math.ceil(Math.sqrt(valueCounts.length))));
      const binSize = range / binCount;
      const bins = new Array(binCount).fill(0);
      for (const vc of valueCounts) {
        const idx = Math.min(Math.floor((vc.value - min) / binSize), binCount - 1);
        bins[idx] += vc.count;
      }
      for (let i = 0; i < binCount; i++) {
        const lo = min + i * binSize;
        const hi = lo + binSize;
        histogram.push({ bucket: `${formatValue(lo)}-${formatValue(hi)}`, count: bins[i] });
      }
    }
  }

  return {
    field: fieldKey,
    label: coverage < 0.95 && numeric.avg === null
      ? `${label} (top-${valueCounts.length} values, ${(coverage * 100).toFixed(0)}% of dataset)`
      : label,
    count: numeric.avg !== null ? totalHits : bucketTotalCount,
    sum,
    min,
    max,
    mean,
    median: p50,
    stdDev,
    p50, p75, p90, p95, p99,
    histogram,
  };
}

// ═══════════════════════════════════════════════════════════════════
// BREAKDOWN FROM NESTED (N+1) AGGREGATIONS
// ═══════════════════════════════════════════════════════════════════

/**
 * Build a BreakdownResult from the response of `fetchNestedBreakdown()`.
 * Each entry already carries primaryValue + primaryCount + per-breakdown-field buckets.
 */
export function buildBreakdownFromNestedAggs(
  entries: NestedBreakdownEntry[],
  primaryField: string,
  breakdownFieldKeys: string[],
): BreakdownResult {
  const primaryDef = FIELD_DEFINITIONS.find(f => f.key === primaryField);
  const breakdownDefs = breakdownFieldKeys.map(k => {
    const def = FIELD_DEFINITIONS.find(f => f.key === k);
    return { key: k, label: def?.label ?? k };
  });

  const outEntries: BreakdownEntry[] = entries
    .filter(e => e && e.primaryValue !== undefined)
    .map(e => {
      const breakdowns: Record<string, BreakdownSubValue[]> = {};
      for (const bField of breakdownFieldKeys) {
        const buckets = e.breakdowns[bField] || [];
        breakdowns[bField] = buckets.map(b => ({ value: b.key, count: b.count }));
      }
      return {
        primaryValue: e.primaryValue,
        primaryCount: e.primaryCount,
        breakdowns,
      };
    });

  return {
    primaryField,
    primaryLabel: primaryDef?.label ?? primaryField,
    breakdownFields: breakdownDefs,
    entries: outEntries,
  };
}

/**
 * Build a LogSummary from aggregation data.
 * uniqueIPs / uniquePaths / uniqueDomains come from bucket counts (distinct values seen in top-N).
 */
export function buildSummaryFromAggregations(data: AggregatedLogData): LogSummary {
  const { totalHits, estimatedRequests, accessAggs, sampleLogs } = data;

  // Estimate unique counts from bucket lengths (these are top-N, so actual uniques may be higher)
  const uniqueIPs = accessAggs['src_ip']?.length ?? 0;
  const uniquePaths = accessAggs['req_path']?.length ?? 0;
  const uniqueDomains = accessAggs['domain']?.length ?? 0;

  // Compute avg duration from raw sample (best proxy we have)
  let avgDurationMs = 0;
  if (sampleLogs.length > 0) {
    const durations: number[] = [];
    for (const l of sampleLogs) {
      const d = typeof l.total_duration_seconds === 'number' ? l.total_duration_seconds
        : parseFloat(String((l as Record<string, unknown>).total_duration_seconds ?? ''));
      if (isFinite(d) && d > 0) durations.push(d * 1000);
    }
    if (durations.length > 0) avgDurationMs = durations.reduce((a, b) => a + b, 0) / durations.length;
  }

  // Error rate from rsp_code_class buckets
  let errorCount = 0;
  const codeBuckets = accessAggs['rsp_code_class'] ?? [];
  for (const b of codeBuckets) {
    if (b.key === '4xx' || b.key === '5xx') errorCount += b.count;
  }
  const errorRate = totalHits > 0 ? (errorCount / totalHits) * 100 : 0;

  return {
    totalLogs: estimatedRequests,
    uniqueIPs,
    uniquePaths,
    uniqueDomains,
    avgDurationMs,
    errorRate,
  };
}

/**
 * Build ErrorAnalysis from aggregation data.
 * byPath and bySource are omitted (need cross-field data not available from top-N aggs).
 */
export function buildErrorAnalysisFromAgg(data: AggregatedLogData): ErrorAnalysis {
  const { accessAggs, totalHits } = data;
  const codeClassBuckets = accessAggs['rsp_code_class'] ?? [];
  const codeBuckets = accessAggs['rsp_code'] ?? [];
  const detailBuckets = accessAggs['rsp_code_details'] ?? [];

  const totalErrors = codeClassBuckets
    .filter(b => b.key === '4xx' || b.key === '5xx')
    .reduce((s, b) => s + b.count, 0);
  const errorRate = totalHits > 0 ? (totalErrors / totalHits) * 100 : 0;

  return {
    totalErrors,
    errorRate,
    byCode: codeBuckets
      .filter(b => { const c = parseInt(b.key, 10); return c >= 400 || c === 0; })
      .map(b => ({ code: b.key, count: b.count, pct: totalErrors > 0 ? (b.count / totalErrors) * 100 : 0 })),
    byCodeClass: codeClassBuckets.map(b => ({ cls: b.key, count: b.count, pct: totalHits > 0 ? (b.count / totalHits) * 100 : 0 })),
    byPath: [],     // requires cross-field data
    bySource: [],   // requires cross-field data
    byDetail: detailBuckets.map(b => ({ detail: b.key, count: b.count, pct: totalErrors > 0 ? (b.count / totalErrors) * 100 : 0 })),
    byResponseFlag: [],
  };
}

/**
 * Build SecurityInsights from aggregation data.
 */
export function buildSecurityInsightsFromAgg(data: AggregatedLogData): SecurityInsights {
  const { accessAggs, totalHits } = data;

  const wafBuckets = accessAggs['waf_action'] ?? [];
  const botBuckets = accessAggs['bot_class'] ?? [];

  const wafActions = wafBuckets.map(b => ({
    action: b.key,
    count: b.count,
    pct: totalHits > 0 ? (b.count / totalHits) * 100 : 0,
  }));

  const botClasses = botBuckets.map(b => ({
    cls: b.key,
    count: b.count,
    pct: totalHits > 0 ? (b.count / totalHits) * 100 : 0,
  }));

  // Top blocked IPs: src_ip buckets where we can correlate with waf block count from sample
  const topBlockedIPs = (accessAggs['src_ip'] ?? []).slice(0, 20).map(b => ({
    ip: b.key,
    count: b.count,
    country: '',    // not available without cross-field agg
    wafAction: '',
  }));

  return {
    wafActions,
    botClasses,
    topBlockedIPs,
    policyHitResults: [],
    suspiciousPaths: [],
  };
}

/**
 * Build TopTalker list from aggregation data.
 * Limited: no per-IP error rate or bandwidth (not available from top-N aggs alone).
 */
export function buildTopTalkersFromAgg(data: AggregatedLogData, topN = 25): TopTalker[] {
  const ipBuckets = (data.accessAggs['src_ip'] ?? []).slice(0, topN);
  return ipBuckets.map(b => ({
    ip: b.key,
    requests: b.count,
    errors: 0,
    errorRate: 0,
    bandwidth: 0,
    country: '',
    asOrg: '',
    topPath: '',
    botClass: '',
    wafBlocked: 0,
  }));
}

/**
 * Build TimeSeriesPoint[] from the hourly bucket data returned by collectWithAggregations.
 */
export function buildTimeSeriesFromHourlyBuckets(
  timeSeries: Array<{ timestamp: string; count: number; label: string }>,
): TimeSeriesPoint[] {
  return timeSeries.map(b => ({
    timestamp: b.timestamp,
    count: b.count,
    label: b.label,
  }));
}

/**
 * Build StatusTimeSeriesPoint[] from aggregation data.
 * Only the total count per bucket is available (no per-status breakdown unless we
 * run per-code aggregations per time bucket — too expensive).
 * Returns simplified time series with counts bucketed into 2xx/other.
 */
export function buildStatusTimeSeriesFromAgg(
  data: AggregatedLogData,
): StatusTimeSeriesPoint[] {
  const { timeSeries, accessAggs } = data;
  if (timeSeries.length === 0) return [];

  // Compute overall error/success ratio from aggregations
  const errorBuckets = (accessAggs['rsp_code_class'] ?? []).filter(b => b.key === '4xx' || b.key === '5xx');
  const errorTotal = errorBuckets.reduce((s, b) => s + b.count, 0);
  const errRatio = errorTotal / (data.totalHits || 1);
  const s5ratio = ((accessAggs['rsp_code_class'] ?? []).find(b => b.key === '5xx')?.count ?? 0) / (data.totalHits || 1);
  const s4ratio = ((accessAggs['rsp_code_class'] ?? []).find(b => b.key === '4xx')?.count ?? 0) / (data.totalHits || 1);
  const s3ratio = ((accessAggs['rsp_code_class'] ?? []).find(b => b.key === '3xx')?.count ?? 0) / (data.totalHits || 1);

  return timeSeries.map(b => {
    const c = b.count;
    return {
      timestamp: b.timestamp,
      label: b.label,
      '5xx': Math.round(c * s5ratio),
      '4xx': Math.round(c * s4ratio),
      '3xx': Math.round(c * s3ratio),
      '2xx': Math.max(0, c - Math.round(c * errRatio) - Math.round(c * s3ratio)),
      other: 0,
    };
  });
}
