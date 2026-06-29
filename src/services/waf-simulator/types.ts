// ═══════════════════════════════════════════════════════════════════════════
// WAF Attack Simulator — Types
//
// Fires curated, signature-triggering attack payloads at a user-selected F5 XC
// endpoint, then (optionally) reconciles the result against XC security events
// and access logs to report what the WAF BLOCKED vs. what REACHED ORIGIN.
//
// SAFETY: the default payload set is "prod-safe" — strings designed to trip WAF
// signatures WITHOUT being working exploits against an origin. Full-strength
// payloads are opt-in per run and gated behind an explicit non-prod ack.
// ═══════════════════════════════════════════════════════════════════════════

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD';

// Where in the request the payload is delivered.
export type AttackVector = 'QUERY' | 'BODY' | 'PATH' | 'HEADER' | 'COOKIE';

// High-level grouping for the catalog + report.
export type AttackFamily = 'WAF' | 'API';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

// One attack category (e.g. "SQL Injection"). Each holds 2–3 payloads.
export interface AttackCategory {
  id: string;
  family: AttackFamily;
  name: string;
  // OWASP reference, e.g. "A03:2021 Injection" or "API1:2023 BOLA".
  owasp: string;
  description: string;
  defaultEnabled: boolean;
}

// A single payload definition within a category.
export interface AttackPayload {
  id: string;
  categoryId: string;
  name: string;
  severity: Severity;
  vector: AttackVector;
  // Methods this payload makes sense on. The runner intersects this with the
  // user-selected methods; if empty intersection, the payload's first method is
  // used so the attack still runs at least once.
  methods: HttpMethod[];
  // Prod-safe signature string (trips WAF rules, harmless at origin).
  prodSafe: string;
  // Optional stronger variant used only when the user opts into full-strength.
  fullStrength?: string;
  // For QUERY/BODY/COOKIE injection: the parameter name to carry the payload.
  paramName?: string;
  // For HEADER injection: the header name to carry the payload.
  headerName?: string;
  // Body content type when vector === 'BODY' ('json' | 'form' | 'xml').
  bodyType?: 'json' | 'form' | 'xml';
  // Human-readable description of the WAF signature that SHOULD catch this — used
  // in the report to explain the expected detection.
  expectedSignature: string;
}

// Target the user is testing.
export interface AttackTarget {
  scheme: 'https' | 'http';
  domain: string; // e.g. app.example.com
  // Base path(s) / endpoint(s) to attack. Each path is combined with every
  // selected payload.
  paths: string[];
}

// Run configuration assembled from the setup screen.
export interface SimRunConfig {
  namespace: string;
  loadBalancer: string;
  target: AttackTarget;
  methods: HttpMethod[];
  categoryIds: string[];
  fullStrength: boolean;
  // 'attack-only' fires payloads and reports live responses only.
  // 'reconcile' additionally pulls XC logs and builds the blocked/origin report.
  mode: 'attack-only' | 'reconcile';
  // Pacing between requests (ms) to avoid hammering the target.
  pacingMs: number;
  // Reconcile-mode only: how long to wait before the first log pull (ingestion
  // latency), and how many times to re-poll.
  ingestionWaitSec: number;
  pollAttempts: number;
  pollIntervalSec: number;
  // Source IP as XC will see it (auto-detected, user-overridable).
  sourceIp: string;
}

// How the live (synchronous) HTTP response was classified.
export type LiveVerdict = 'BLOCKED' | 'PASSED_TO_ORIGIN' | 'ERROR' | 'UNKNOWN';

// Result of firing one payload against one path with one method.
export interface AttackResult {
  // Stable per-request correlation id (also embedded in the request).
  marker: string;
  seq: number;
  categoryId: string;
  categoryName: string;
  owasp: string;
  payloadId: string;
  payloadName: string;
  severity: Severity;
  vector: AttackVector;
  method: HttpMethod;
  path: string;
  // The fully composed request (for the report + replay).
  requestUrl: string;
  requestHeaders: Record<string, string>;
  requestBody?: string;
  expectedSignature: string;
  // Live response.
  liveVerdict: LiveVerdict;
  statusCode: number;
  statusText?: string;
  responseTimeMs: number;
  responseSnippet?: string;
  blockSupportId?: string; // XC support-id parsed from a block page, if present
  error?: string;
  sentAt: string; // ISO timestamp
}

// Final reconciled verdict per attack (reconcile mode).
export type ReconciledVerdict =
  | 'BLOCKED' // a security event with a blocking action matched this request
  | 'REACHED_ORIGIN' // seen in access logs / origin response, no blocking event
  | 'INCONCLUSIVE'; // no correlating log found (ingestion lag or filtered out)

export interface ReconciledResult extends AttackResult {
  verdict: ReconciledVerdict;
  // Matched XC security event fields (if blocked).
  matchedSecurityEvent?: {
    reqId?: string;
    action?: string;
    secEventName?: string;
    wafMode?: string;
    rspCode?: string;
    time?: string;
  };
  // Matched access-log fields (proves the request was received / origin reply).
  matchedAccessLog?: {
    reqId?: string;
    rspCode?: string;
    origRspCode?: string;
    time?: string;
  };
}

export interface ReconciliationSummary {
  total: number;
  blocked: number;
  reachedOrigin: number;
  inconclusive: number;
  // Of the requests that reached origin, how many were genuine attack payloads
  // (i.e. WAF gaps the customer should care about).
  gaps: number;
  // Blocked rate over conclusive results, 0–100.
  blockRate: number;
  byCategory: CategoryRollup[];
  bySeverity: Record<Severity, { total: number; blocked: number; reachedOrigin: number }>;
}

export interface CategoryRollup {
  categoryId: string;
  categoryName: string;
  owasp: string;
  family: AttackFamily;
  total: number;
  blocked: number;
  reachedOrigin: number;
  inconclusive: number;
}

export interface SimReport {
  id: string;
  timestamp: string;
  tenant: string;
  config: SimRunConfig;
  durationMs: number;
  results: ReconciledResult[];
  summary: ReconciliationSummary;
  // True when logs were pulled (reconcile mode + connected).
  reconciled: boolean;
  notes: string[];
}

// Progress callback payload during a run.
export interface SimProgress {
  phase: 'detecting-ip' | 'attacking' | 'waiting' | 'pulling-logs' | 'reconciling' | 'complete';
  message: string;
  progress: number; // 0–100
  sent?: number;
  total?: number;
  blocked?: number;
  reachedOrigin?: number;
}

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export const SEVERITY_META: Record<Severity, { label: string; color: string; bg: string }> = {
  CRITICAL: { label: 'Critical', color: 'text-red-400', bg: 'bg-red-500/20' },
  HIGH: { label: 'High', color: 'text-orange-400', bg: 'bg-orange-500/20' },
  MEDIUM: { label: 'Medium', color: 'text-yellow-400', bg: 'bg-yellow-500/20' },
  LOW: { label: 'Low', color: 'text-blue-400', bg: 'bg-blue-500/20' },
};

export const VERDICT_META: Record<ReconciledVerdict, { label: string; color: string; bg: string; icon: string }> = {
  BLOCKED: { label: 'Blocked by WAF', color: 'text-emerald-400', bg: 'bg-emerald-500/20', icon: '🛡️' },
  REACHED_ORIGIN: { label: 'Reached Origin', color: 'text-red-400', bg: 'bg-red-500/20', icon: '⚠️' },
  INCONCLUSIVE: { label: 'Inconclusive', color: 'text-slate-400', bg: 'bg-slate-500/20', icon: '❔' },
};
