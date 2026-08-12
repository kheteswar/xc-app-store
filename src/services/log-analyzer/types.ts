import type { AccessLogEntry, SecurityEventEntry } from '../rate-limit-advisor/types';

// ═══════════════════════════════════════════════════════════════════
// TIME & QUERY
// ═══════════════════════════════════════════════════════════════════

export type TimePeriod = '5m' | '15m' | '1h' | '6h' | '24h' | '7d' | '14d' | '30d';
export type LogSource = 'access' | 'security' | 'both';

export const TIME_PERIOD_HOURS: Record<TimePeriod, number> = {
  '5m': 5 / 60,
  '15m': 15 / 60,
  '1h': 1,
  '6h': 6,
  '24h': 24,
  '7d': 168,
  '14d': 336,
  '30d': 720,
};

export const TIME_PERIOD_LABELS: Record<TimePeriod, string> = {
  '5m': 'Last 5 Min',
  '15m': 'Last 15 Min',
  '1h': 'Last 1 Hour',
  '6h': 'Last 6 Hours',
  '24h': 'Last 24 Hours',
  '7d': 'Last 7 Days',
  '14d': 'Last 14 Days',
  '30d': 'Last 30 Days',
};

export interface QueryFilter {
  field: string;
  value: string;
}

export interface ClientFilter {
  field: string;
  operator: 'equals' | 'contains' | 'not_equals' | 'regex';
  value: string;
}

// ═══════════════════════════════════════════════════════════════════
// FIELD DEFINITIONS
// ═══════════════════════════════════════════════════════════════════

export type FieldType = 'numeric' | 'string' | 'boolean' | 'timestamp';
export type FieldGroup = 'timing' | 'request' | 'response' | 'routing' | 'security' | 'security_event' | 'geo' | 'tls' | 'meta';

export interface FieldDefinition {
  key: string;
  label: string;
  type: FieldType;
  group: FieldGroup;
  parseAsNumber?: boolean;
  /** Which log source this field belongs to: access, security, or both */
  source?: 'access' | 'security' | 'both';
}

// ═══════════════════════════════════════════════════════════════════
// ANALYTICS RESULTS
// ═══════════════════════════════════════════════════════════════════

export interface NumericFieldStats {
  field: string;
  label: string;
  count: number;
  sum: number;
  min: number;
  max: number;
  mean: number;
  median: number;
  stdDev: number;
  p50: number;
  p75: number;
  p90: number;
  p95: number;
  p99: number;
  histogram: Array<{ bucket: string; count: number }>;
}

export interface StringFieldStats {
  field: string;
  label: string;
  totalCount: number;
  uniqueCount: number;
  topValues: Array<{ value: string; count: number; percentage: number }>;
}

export interface TimeSeriesPoint {
  timestamp: string;
  count: number;
  label: string;
}

export interface LogSummary {
  totalLogs: number;
  uniqueIPs: number;
  uniquePaths: number;
  uniqueDomains: number;
  avgDurationMs: number;
  errorRate: number;
}

// ═══════════════════════════════════════════════════════════════════
// COLLECTION PROGRESS
// ═══════════════════════════════════════════════════════════════════

export interface LogCollectionProgress {
  phase: 'idle' | 'fetching' | 'analyzing' | 'complete' | 'error';
  message: string;
  progress: number;
  logsCollected: number;
  estimatedTotal: number;
  error?: string;
}

// ═══════════════════════════════════════════════════════════════════
// ADVANCED INSIGHTS
// ═══════════════════════════════════════════════════════════════════

export interface ErrorAnalysis {
  totalErrors: number;
  errorRate: number;
  byCode: Array<{ code: string; count: number; pct: number }>;
  byCodeClass: Array<{ cls: string; count: number; pct: number }>;
  byPath: Array<{ path: string; count: number; errorRate: number }>;
  bySource: Array<{ ip: string; count: number; errorRate: number; country: string }>;
  byDetail: Array<{ detail: string; count: number; pct: number }>;
  byResponseFlag: Array<{ flag: string; count: number; pct: number }>;
}

export interface PerformanceAnalysis {
  overall: { p50: number; p90: number; p95: number; p99: number; max: number; mean: number };
  slowRequests: Array<{
    timestamp: string; method: string; path: string; code: string;
    durationS: number; srcIp: string; country: string; detail: string;
  }>;
  byPath: Array<{ path: string; count: number; avgMs: number; p95Ms: number; maxMs: number }>;
  byCountry: Array<{ country: string; count: number; avgMs: number; p95Ms: number }>;
  bySite: Array<{ site: string; count: number; avgMs: number; p95Ms: number }>;
}

export interface SecurityInsights {
  wafActions: Array<{ action: string; count: number; pct: number }>;
  botClasses: Array<{ cls: string; count: number; pct: number }>;
  topBlockedIPs: Array<{ ip: string; count: number; country: string; wafAction: string }>;
  policyHitResults: Array<{ result: string; count: number; pct: number }>;
  suspiciousPaths: Array<{ path: string; count: number; blockedPct: number }>;
}

export interface TopTalker {
  ip: string;
  requests: number;
  errors: number;
  errorRate: number;
  bandwidth: number;
  country: string;
  asOrg: string;
  topPath: string;
  botClass: string;
  wafBlocked: number;
}

export interface StatusTimeSeriesPoint {
  timestamp: string;
  label: string;
  '2xx': number;
  '3xx': number;
  '4xx': number;
  '5xx': number;
  other: number;
}

// ═══════════════════════════════════════════════════════════════════
// FIELD BREAKDOWN (cross-tabulation)
// ═══════════════════════════════════════════════════════════════════

export interface BreakdownSubValue {
  value: string;
  count: number;
}

export interface BreakdownEntry {
  primaryValue: string;
  primaryCount: number;
  breakdowns: Record<string, BreakdownSubValue[]>; // keyed by breakdown field
}

export interface BreakdownResult {
  primaryField: string;
  primaryLabel: string;
  breakdownFields: Array<{ key: string; label: string }>;
  entries: BreakdownEntry[];
}

export type { AccessLogEntry, SecurityEventEntry };

// ═══════════════════════════════════════════════════════════════════
// AGGREGATION-BASED DATA MODEL
// ═══════════════════════════════════════════════════════════════════

export type { AggBucket } from './aggregation-client';

/**
 * Result of collectWithAggregations() — replaces full raw log download.
 * Contains server-side aggregated field distributions + a small raw sample.
 */
export interface AggregatedLogData {
  /** Total matching records in the time window (from probe) */
  totalHits: number;
  /** F5 XC log sampling rate (actual requests = totalHits / sampleRate) */
  sampleRate: number;
  /** Estimated actual request count accounting for sampling */
  estimatedRequests: number;
  /** Access log field distributions keyed by field name */
  accessAggs: Record<string, import('./aggregation-client').AggBucket[]>;
  /** Security event field distributions keyed by field name */
  securityAggs: Record<string, import('./aggregation-client').AggBucket[]>;
  /** Small raw log sample (≤500 records) for table view + latency */
  sampleLogs: AccessLogEntry[];
  /** Small security event sample for WAF/threat detail */
  sampleSecurityEvents: SecurityEventEntry[];
  /** Hourly hit counts for the time series chart */
  timeSeries: Array<{ timestamp: string; count: number; label: string }>;
  /** Total security events (from probe) */
  totalSecurityEvents: number;

  // ── Context for on-demand aggregation fetches ─────────────────
  /** Namespace the analysis was run against */
  namespace: string;
  /** VoltVQL query string used for the analysis */
  query: string;
  /** ISO8601 window start */
  startTime: string;
  /** ISO8601 window end */
  endTime: string;

  // ── Metrics API summary (for 14d/30d windows beyond access-log retention) ──
  /**
   * When window > 7d, we also fetch pre-aggregated metrics from `graph/service`
   * (same source as F5 XC Console's Performance dashboard). Non-null when the
   * hybrid metrics path was used.
   */
  metricsSummary?: import('./metrics-client').MetricSummary | null;
  /** True if this analysis window exceeds access-log retention and field breakdowns are limited. */
  metricsPathActive?: boolean;
}
