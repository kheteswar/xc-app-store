/**
 * Progressive Analysis Job — Replaces batch analysis-job.ts
 *
 * Three-phase progressive flow:
 *   Phase 0: Quick Summary (15-30 sec) — fetch ALL security events, build summary table
 *   Phase 1: On-demand detail — user clicks signature → compute detail from in-memory data
 *   Phase 2: Optional enrichment — fetch access logs for specific paths only
 *
 * Raw security events are stored in memory indexed by signature_id (~100MB for 200K events).
 * Detail computation is instant since events are already in memory.
 * Pre-fetches next 3 signatures after each detail view.
 */

import { NodeApiCaller } from './node-api-caller';
import { AdaptiveConcurrencyController } from '../src/services/fp-analyzer/adaptive-concurrency';
import { runAdaptivePool } from '../src/services/fp-analyzer/adaptive-worker-pool';
import { computeQuickModeSignals, computeAllSignals } from '../src/services/fp-analyzer/fp-scorer';
import type { QuickModeSignalsInput, ComputeSignalsInput } from '../src/services/fp-analyzer/fp-scorer';
import { computeQuickVerdict, mapToRecord } from '../src/services/fp-analyzer/signal-calculator';
import { classifyMatchingInfo } from '../src/services/fp-analyzer/matching-info-analyzer';
import { generateSignatureExclusion, generateViolationExclusion, buildWafExclusionPolicy, groupExclusionRules } from '../src/services/fp-analyzer/exclusion-generator';
import { parseContext } from '../src/services/fp-analyzer/context-parser';
import { AnalysisLogger } from '../src/services/fp-analyzer/analysis-logger';
import type {
  AnalysisScope,
  AnalysisMode,
  SecurityEventEntry,
  FPVerdict,
  QuickVerdict,
  ConfidenceLevel,
  SignatureSummary,
  ViolationSummary,
  ThreatMeshSummary,
  ThreatMeshAnalysisUnit,
  ThreatMeshDetails,
  ThreatMeshEnrichmentResult,
  PolicyRuleSummary,
  SummaryResult,
  ProgressiveJobStatus,
  ProgressiveJobProgress,
  SignatureAnalysisUnit,
  ViolationAnalysisUnit,
  PathAnalysis,
  SignalResult,
  EnrichmentResult,
  WafExclusionRule,
  WafExclusionPolicyObject,
} from '../src/services/fp-analyzer/types';
import type { RateLimitState } from '../src/services/fp-analyzer/adaptive-concurrency';

// ═══════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════

const CHUNK_HOURS = 2;
const PAGE_SIZE = 500;
const JOB_EXPIRY_MS = 30 * 60 * 1000;
const PREFETCH_COUNT = 3;

// ═══════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════

export interface ProgressiveJobConfig {
  tenant: string;
  token: string;
  namespace: string;
  lbName: string;
  domains: string[];
  scopes: AnalysisScope[];
  hoursBack: number;
  mode: AnalysisMode;
}

interface TimeChunk {
  start: string;
  end: string;
  label: string;
}

interface AccessLogPathStats {
  totalRequests: number;
  uniqueUsers: Set<string>;
  countries: Map<string, number>;
  timestamps: string[];
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

function splitIntoChunks(startTime: string, endTime: string, chunkHours: number): TimeChunk[] {
  const chunks: TimeChunk[] = [];
  const start = new Date(startTime).getTime();
  const end = new Date(endTime).getTime();
  const chunkMs = chunkHours * 60 * 60 * 1000;

  let cursor = start;
  while (cursor < end) {
    const chunkEnd = Math.min(cursor + chunkMs, end);
    const d = new Date(cursor);
    const label = `${(d.getUTCMonth() + 1).toString().padStart(2, '0')}/${d.getUTCDate().toString().padStart(2, '0')} ${d.getUTCHours().toString().padStart(2, '0')}:00`;
    chunks.push({
      start: new Date(cursor).toISOString(),
      end: new Date(chunkEnd).toISOString(),
      label,
    });
    cursor = chunkEnd;
  }
  return chunks;
}

const F5_DATA_FIELDS = ['rsp_code', 'rsp_code_details', 'src_ip', 'vh_name', 'req_path', 'waf_action', 'sample_rate'];

function hasF5DataFields(obj: Record<string, unknown>): boolean {
  let matchCount = 0;
  for (const field of F5_DATA_FIELDS) {
    if (obj[field] !== undefined && obj[field] !== null) matchCount++;
  }
  return matchCount >= 2;
}

function normalizeEntries<T>(rawEntries: unknown[], logType: string): T[] {
  if (rawEntries.length === 0) return [];

  let entries = rawEntries;
  if (typeof entries[0] === 'string') {
    entries = entries.map((e) => {
      try { return JSON.parse(e as string); } catch { return {}; }
    });
  }

  const sample = entries[0] as Record<string, unknown>;
  if (hasF5DataFields(sample)) return entries as T[];

  const WRAPPER_KEYS = ['_source', 'attributes', 'data', 'log', 'fields', 'record', 'event', 'message'];
  for (const key of WRAPPER_KEYS) {
    if (sample[key] && typeof sample[key] === 'object' && !Array.isArray(sample[key])) {
      if (hasF5DataFields(sample[key] as Record<string, unknown>)) {
        return entries.map(e => (e as Record<string, unknown>)[key] as T);
      }
    }
  }

  for (const [key, val] of Object.entries(sample)) {
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      if (hasF5DataFields(val as Record<string, unknown>)) {
        return entries.map(e => (e as Record<string, unknown>)[key] as T);
      }
    }
  }

  return entries as T[];
}

type RawEvent = Record<string, unknown>;

/**
 * Map selected scopes to the sec_event_name values used by F5 XC.
 * This allows us to filter at the API level so we only download relevant logs.
 *
 * sec_event_name values:
 *   "WAF"                       → waf_signatures, waf_violations
 *   "Threat Mesh"               → threat_mesh
 *   "L7 Policy Violation"       → service_policy
 *   "Malicious User Mitigation" → bot_defense / malicious_user
 */
function buildScopedQuery(lbName: string, scopes: AnalysisScope[]): string {
  const vhFilter = `vh_name="ves-io-http-loadbalancer-${lbName}"`;

  const eventNames = new Set<string>();
  for (const scope of scopes) {
    switch (scope) {
      case 'waf_signatures':
      case 'waf_violations':
        eventNames.add('WAF');
        break;
      case 'threat_mesh':
        eventNames.add('Threat Mesh');
        break;
      case 'service_policy':
        eventNames.add('L7 Policy Violation');
        break;
      case 'bot_defense':
        eventNames.add('Malicious User Mitigation');
        break;
      // api_security: no known sec_event_name mapping — fetch all
      case 'api_security':
        return `{${vhFilter}}`;
    }
  }

  if (eventNames.size === 0) return `{${vhFilter}}`;

  // Use regex match for multiple event names
  if (eventNames.size === 1) {
    const name = [...eventNames][0];
    return `{${vhFilter}, sec_event_name="${name}"}`;
  }

  const regex = [...eventNames].join('|');
  return `{${vhFilter}, sec_event_name=~"${regex}"}`;
}

/**
 * Classify a security event by its sec_event_name.
 * Known values from F5 XC:
 *   "WAF"                      → waf (signatures + violations)
 *   "Threat Mesh"              → threat_mesh
 *   "L7 Policy Violation"      → service_policy
 *   "Malicious User Mitigation"→ malicious_user
 *
 * Falls back to sec_event_type and object detection for robustness.
 */
type EventCategory = 'waf' | 'threat_mesh' | 'service_policy' | 'malicious_user' | 'unknown';

function classifyEvent(event: RawEvent): EventCategory {
  const eventName = ((event.sec_event_name as string) || '').toLowerCase();

  if (eventName === 'waf') return 'waf';
  if (eventName === 'threat mesh') return 'threat_mesh';
  if (eventName === 'l7 policy violation') return 'service_policy';
  if (eventName === 'malicious user mitigation') return 'malicious_user';

  // Fallback heuristics when sec_event_name is missing
  if (event.threat_mesh_details && typeof event.threat_mesh_details === 'object') return 'threat_mesh';

  const policyHits = event.policy_hits as Record<string, unknown> | undefined;
  if (policyHits) {
    const hits = (policyHits.policy_hits || []) as Array<Record<string, unknown>>;
    for (const hit of hits) {
      if (hit.policy_set === 'threat_mesh') return 'threat_mesh';
    }
  }

  const eventType = (event.sec_event_type as string) || '';
  if (eventType === 'waf_sec_event') return 'waf';
  if (eventType === 'svc_policy_sec_event') return 'service_policy';

  return 'unknown';
}

function getStr(event: RawEvent, key: string): string {
  return (event[key] as string) || '';
}

function getNum(event: RawEvent, key: string): number {
  const v = event[key];
  if (typeof v === 'number') return v;
  if (typeof v === 'string') return parseInt(v, 10) || 0;
  return 0;
}

function getSignatures(event: RawEvent): Array<{
  id: string; name: string; accuracy: string; attackType: string;
  context: string; contextName: string; contextType: string;
  matchingInfo: string; state: string;
}> {
  const sigs = event.signatures as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(sigs)) return [];
  return sigs.map(s => ({
    id: String(s.id || ''),
    name: String(s.name || ''),
    accuracy: String(s.accuracy || 'medium_accuracy'),
    attackType: String(s.attack_type || ''),
    context: String(s.context || ''),
    contextName: String(s.context_name || ''),
    contextType: String(s.context_type || ''),
    matchingInfo: String(s.matching_info || ''),
    state: String(s.state || ''),
  }));
}

/**
 * XC security events carry signature context as a display string like
 * "parameter (q)"; the structured context_type/context_name fields are
 * almost always absent. WAF exclusion rules, however, require a CONTEXT_*
 * enum and a bare context name. Prefer XC's structured fields when present,
 * otherwise parse the human-readable string into the enum + name.
 */
function normalizeSignatureContext(sig: { context: string; contextName: string; contextType: string }): { contextType: string; contextName: string } {
  if (sig.contextType && sig.contextType.startsWith('CONTEXT_')) {
    return { contextType: sig.contextType, contextName: sig.contextName || '' };
  }
  const parsed = parseContext(sig.context || sig.contextType || '');
  return { contextType: parsed.contextType, contextName: sig.contextName || parsed.contextName };
}

function getViolations(event: RawEvent): Array<{
  name: string; attackType: string; state: string; context?: string; matchingInfo?: string;
}> {
  const viols = event.violations as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(viols)) return [];
  return viols.map(v => ({
    name: String(v.name || ''),
    attackType: String(v.attack_type || ''),
    state: String(v.state || ''),
    context: v.context ? String(v.context) : undefined,
    matchingInfo: v.matching_info ? String(v.matching_info) : undefined,
  }));
}

// ═══════════════════════════════════════════════════════════════
// THREAT MESH SCORING PATTERNS (from threat-mesh-analyzer.ts)
// ═══════════════════════════════════════════════════════════════

const BENIGN_BOT_RE = /bingbot|googlebot|yandexbot|baiduspider|slurp|duckduckbot|facebot|applebot|linkedinbot|twitterbot|pinterestbot/i;
const SCRIPTING_TOOL_RE = /python|curl|wget|httpie|go-http|java|axios|node-fetch|ruby|perl/i;
const EXPLOIT_PATHS = /\/wp-admin|\/phpmyadmin|\/\.env|\/cgi-bin|\/actuator|\/\.git|\/admin|\/shell|\/eval|\/exec/i;
const CDN_PROXY_ORGS = /cloudflare|akamai|fastly|google cloud|amazon|azure|microsoft/i;

function tmScoreToVerdict(score: number): FPVerdict {
  if (score > 75) return 'highly_likely_fp';
  if (score > 55) return 'likely_fp';
  if (score > 35) return 'ambiguous';
  if (score > 15) return 'likely_tp';
  return 'confirmed_tp';
}

function getTopEntry(map: Map<string, number>): string {
  let top = '';
  let max = 0;
  for (const [k, v] of map) {
    if (v > max) { max = v; top = k; }
  }
  return top;
}

// ═══════════════════════════════════════════════════════════════
// PROGRESSIVE ANALYSIS JOB
// ═══════════════════════════════════════════════════════════════

export class ProgressiveAnalysisJob {
  readonly id: string;
  private config: ProgressiveJobConfig;
  private api: NodeApiCaller;
  private logger: AnalysisLogger;
  private cancelled = false;
  private createdAt = Date.now();
  private startMs = Date.now();

  // Progress
  private status: ProgressiveJobStatus = 'collecting';
  private securityEventsCollected = 0;
  private signaturesFound = 0;
  private violationsFound = 0;
  private totalChunks = 0;
  private chunksCompleted = 0;
  private currentPhaseLabel = 'Initializing...';
  private error?: string;
  private adaptiveState: RateLimitState = 'GREEN';
  private adaptiveConcurrency = 3;
  private tmEnrichTotal = 0;
  private tmEnrichCompleted = 0;

  // Hybrid enrichment state
  private accessLogStore: Map<string, AccessLogPathStats> | null = null;
  private hybridEnrichPhase: 'idle' | 'fetching_access_logs' | 'enriching_signatures' | 'enriching_violations' | 'enriching_tm' | 'complete' = 'idle';
  private accessLogsCollected = 0;
  private sigEnrichTotal = 0;
  private sigEnrichCompleted = 0;
  private violEnrichTotal = 0;
  private violEnrichCompleted = 0;

  // Adaptive controller
  private controller: AdaptiveConcurrencyController;

  // In-memory event indexes
  private secEventsBySignature = new Map<string, RawEvent[]>();
  private secEventsByViolation = new Map<string, RawEvent[]>();
  private allSecurityEvents: RawEvent[] = [];

  // Summary
  private summary: SummaryResult | null = null;

  // Caches
  private detailCache = new Map<string, SignatureAnalysisUnit>();
  private violationDetailCache = new Map<string, ViolationAnalysisUnit>();
  private tmDetailCache = new Map<string, ThreatMeshAnalysisUnit>();

  // Time range
  private startTime = '';
  private endTime = '';

  // WAF config
  private wafPolicyName?: string;

  // Sort order for navigation
  private sortedSigIds: string[] = [];
  private sortedTMIPs: string[] = [];

  constructor(id: string, config: ProgressiveJobConfig) {
    this.id = id;
    this.config = config;
    this.api = new NodeApiCaller({ tenant: config.tenant, token: config.token });
    this.logger = new AnalysisLogger();
    this.controller = new AdaptiveConcurrencyController({
      initialConcurrency: 3,
      minConcurrency: 1,
      maxConcurrency: 8,
      rampUpAfterSuccesses: 10,
    });
  }

  isExpired(): boolean {
    return Date.now() - this.createdAt > JOB_EXPIRY_MS;
  }

  cancel(): void {
    this.cancelled = true;
    this.status = 'cancelled';
    console.log(`[ProgressiveJob ${this.id}] Cancelled`);
  }

  getProgress(): ProgressiveJobProgress {
    return {
      status: this.status,
      securityEventsCollected: this.securityEventsCollected,
      signaturesFound: this.signaturesFound,
      violationsFound: this.violationsFound,
      totalChunks: this.totalChunks,
      chunksCompleted: this.chunksCompleted,
      currentPhaseLabel: this.currentPhaseLabel,
      elapsedMs: Date.now() - this.startMs,
      estimatedRemainingMs: this.estimateRemaining(),
      adaptiveState: this.adaptiveState,
      adaptiveConcurrency: this.adaptiveConcurrency,
      error: this.error,
      tmEnrichTotal: this.tmEnrichTotal,
      tmEnrichCompleted: this.tmEnrichCompleted,
      hybridEnrichPhase: this.hybridEnrichPhase !== 'idle' ? this.hybridEnrichPhase : undefined,
      accessLogsCollected: this.accessLogsCollected || undefined,
      sigEnrichTotal: this.sigEnrichTotal || undefined,
      sigEnrichCompleted: this.sigEnrichCompleted || undefined,
      violEnrichTotal: this.violEnrichTotal || undefined,
      violEnrichCompleted: this.violEnrichCompleted || undefined,
    };
  }

  getSummary(): SummaryResult | null {
    return this.summary;
  }

  getStatus(): ProgressiveJobStatus {
    return this.status;
  }

  // ═══════════════════════════════════════════════════════════════
  // PHASE 0: COLLECT SECURITY EVENTS + BUILD SUMMARY
  // ═══════════════════════════════════════════════════════════════

  async run(): Promise<void> {
    this.startMs = Date.now();
    const now = new Date();
    this.endTime = now.toISOString();
    this.startTime = new Date(now.getTime() - this.config.hoursBack * 60 * 60 * 1000).toISOString();

    this.logger.reset();
    console.log(`[ProgressiveJob ${this.id}] Starting: ns=${this.config.namespace} lb=${this.config.lbName} hours=${this.config.hoursBack} mode=${this.config.mode}`);

    try {
      // Fetch all security events
      this.status = 'collecting';
      this.currentPhaseLabel = 'Fetching security events from F5 XC API...';
      const rawEvents = await this.collectAllSecurityEvents();
      if (this.cancelled) return;

      this.allSecurityEvents = rawEvents;

      // Index events by signature_id and violation name
      this.currentPhaseLabel = 'Indexing events by type...';
      this.indexEvents(rawEvents);

      // Detect WAF config
      this.currentPhaseLabel = 'Detecting WAF configuration...';
      await this.detectWafConfig();

      // Build summary
      this.currentPhaseLabel = 'Building summary...';
      this.summary = this.buildSummary();
      this.currentPhaseLabel = 'Summary ready';
      this.status = 'summary_ready';

      // Pre-compute detail for top 3 signatures (only if waf_signatures scope selected)
      if (this.config.scopes.includes('waf_signatures')) {
        const topSigs = this.sortedSigIds.slice(0, PREFETCH_COUNT);
        for (const sigId of topSigs) {
          if (!this.detailCache.has(sigId)) {
            this.detailCache.set(sigId, this.computeSignatureDetail(sigId));
          }
        }
      }

      // Pre-compute detail for all threat mesh IPs (only if scope selected)
      if (this.config.scopes.includes('threat_mesh') && this.sortedTMIPs.length > 0) {
        for (const ip of this.sortedTMIPs) {
          if (!this.tmDetailCache.has(ip)) {
            this.tmDetailCache.set(ip, this.computeThreatMeshDetail(ip));
          }
        }
      }

      const elapsed = Date.now() - this.startMs;
      console.log(`[ProgressiveJob ${this.id}] Summary ready in ${(elapsed / 1000).toFixed(1)}s: ${this.signaturesFound} sigs, ${this.violationsFound} viols, ${this.sortedTMIPs.length} tm IPs, ${this.securityEventsCollected} events`);

      // Mode-aware enrichment
      if (this.config.mode === 'hybrid' && !this.cancelled) {
        this.status = 'enriching';
        await this.runHybridEnrichment();
      } else {
        // Quick mode: only auto-enrich TM IPs
        if (this.config.scopes.includes('threat_mesh') && this.sortedTMIPs.length > 0 && !this.cancelled) {
          await this.autoEnrichThreatMeshIPs();
        }
      }

      if (!this.cancelled) {
        this.status = 'complete';
        this.currentPhaseLabel = 'Analysis complete';
      }

    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.status = 'error';
      this.error = msg;
      console.error(`[ProgressiveJob ${this.id}] Error: ${msg}`);
    }
  }

  private async collectAllSecurityEvents(): Promise<RawEvent[]> {
    const query = buildScopedQuery(this.config.lbName, this.config.scopes);
    const chunks = splitIntoChunks(this.startTime, this.endTime, CHUNK_HOURS);
    this.totalChunks = chunks.length;
    this.chunksCompleted = 0;
    this.currentPhaseLabel = `Downloading security events (0/${chunks.length} time chunks)...`;
    console.log(`[ProgressiveJob ${this.id}] Fetching security events: ${chunks.length} chunks, query: ${query}`);

    const allEvents: RawEvent[] = [];

    const tasks = chunks.map((chunk, idx) => ({
      id: idx,
      execute: async (): Promise<RawEvent[]> => {
        const chunkEvents: unknown[] = [];

        const initial = await this.api.fetchSecurityEventsPage(
          this.config.namespace, query, chunk.start, chunk.end, PAGE_SIZE,
        );
        if (initial.events) chunkEvents.push(...initial.events);

        let scrollId = initial.scroll_id;
        while (scrollId) {
          try {
            const page = await this.api.scrollSecurityEvents(this.config.namespace, scrollId);
            if (!page.events || page.events.length === 0) break;
            chunkEvents.push(...page.events);
            scrollId = page.scroll_id;
          } catch { break; }
        }

        return normalizeEntries<RawEvent>(chunkEvents, `sec-${chunk.label}`);
      },
    }));

    await runAdaptivePool(
      tasks,
      this.controller,
      (r) => {
        if (r.result) {
          allEvents.push(...r.result);
          this.chunksCompleted++;
          this.securityEventsCollected = allEvents.length;
          this.adaptiveState = this.controller.getState();
          this.adaptiveConcurrency = this.controller.concurrency;
          this.currentPhaseLabel = `Downloading security events (${this.chunksCompleted}/${this.totalChunks} time chunks)...`;
        }
      },
      undefined,
      () => this.cancelled,
    );

    // Filter for this LB
    const expectedVh = `ves-io-http-loadbalancer-${this.config.lbName}`;
    const filtered = allEvents.filter(e => {
      const vh = getStr(e, 'vh_name');
      return !vh || vh === expectedVh;
    });

    this.securityEventsCollected = filtered.length;
    return filtered;
  }

  private indexEvents(events: RawEvent[]): void {
    const scopes = this.config.scopes;

    for (const event of events) {
      const category = classifyEvent(event);

      // Only index signatures/violations from WAF events
      if (category === 'waf') {
        if (scopes.includes('waf_signatures')) {
          const sigs = getSignatures(event);
          for (const sig of sigs) {
            if (!sig.id) continue;
            if (!this.secEventsBySignature.has(sig.id)) {
              this.secEventsBySignature.set(sig.id, []);
            }
            this.secEventsBySignature.get(sig.id)!.push(event);
          }
        }

        if (scopes.includes('waf_violations')) {
          const viols = getViolations(event);
          for (const viol of viols) {
            if (!viol.name) continue;
            if (!this.secEventsByViolation.has(viol.name)) {
              this.secEventsByViolation.set(viol.name, []);
            }
            this.secEventsByViolation.get(viol.name)!.push(event);
          }
        }
      }
    }

    this.signaturesFound = this.secEventsBySignature.size;
    this.violationsFound = this.secEventsByViolation.size;
  }

  private async detectWafConfig(): Promise<void> {
    try {
      const lbConfig = await this.api.getLBConfig(this.config.namespace, this.config.lbName);
      const spec = lbConfig.spec as Record<string, unknown> | undefined;
      if (spec?.app_firewall) {
        const af = spec.app_firewall as Record<string, unknown>;
        this.wafPolicyName = (af.name as string) || undefined;
      }
    } catch {
      // Non-critical
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // BUILD SUMMARY FROM INDEXED DATA
  // ═══════════════════════════════════════════════════════════════

  private buildSummary(): SummaryResult {
    const scopes = this.config.scopes;
    const signatures: SignatureSummary[] = [];

    if (scopes.includes('waf_signatures')) {
    for (const [sigId, events] of this.secEventsBySignature) {
      const uniqueUsers = new Set<string>();
      const uniqueIPs = new Set<string>();
      const pathCounts = new Map<string, number>();
      const userAgentCounts = new Map<string, number>();
      const countryCounts = new Map<string, number>();
      const botClassifications = new Map<string, number>();
      const trustScores: number[] = [];
      const timestamps: string[] = [];
      let blockCount = 0;
      let reportCount = 0;
      let autoSuppressed = false;
      let sigName = '';
      let accuracy = '';
      let attackType = '';
      let contextType = '';
      let contextName = '';
      let sigState = '';
      let aiConfirmed = false;
      let rsp200Count = 0;
      let calculatedAction = '';

      for (const event of events) {
        uniqueUsers.add(getStr(event, 'user') || getStr(event, 'src_ip'));
        uniqueIPs.add(getStr(event, 'src_ip'));
        const p = getStr(event, 'req_path') || '/';
        pathCounts.set(p, (pathCounts.get(p) || 0) + 1);
        const action = getStr(event, 'action');
        if (action === 'block') blockCount++;
        else reportCount++;

        const ua = getStr(event, 'user_agent') || getStr(event, 'browser_type') || 'unknown';
        userAgentCounts.set(ua, (userAgentCounts.get(ua) || 0) + 1);
        const c = getStr(event, 'country') || 'unknown';
        countryCounts.set(c, (countryCounts.get(c) || 0) + 1);
        const rsp = getStr(event, 'rsp_code') || '0';
        if (rsp === '200') rsp200Count++;
        timestamps.push(getStr(event, '@timestamp') || getStr(event, 'time') || '');

        if (!calculatedAction) calculatedAction = getStr(event, 'calculated_action');

        const botInfo = event.bot_info as Record<string, unknown> | undefined;
        if (botInfo?.classification) {
          const cls = String(botInfo.classification);
          botClassifications.set(cls, (botClassifications.get(cls) || 0) + 1);
        }

        const policyHits = event.policy_hits as Record<string, unknown> | undefined;
        if (policyHits) {
          const hits = (policyHits.policy_hits || []) as Array<Record<string, unknown>>;
          for (const hit of hits) {
            const ts = hit.ip_trustscore;
            if (ts) trustScores.push(typeof ts === 'number' ? ts : parseInt(String(ts), 10) || 0);
          }
        }

        // Extract sig metadata from first occurrence
        if (!sigName) {
          const sigs = getSignatures(event);
          const sig = sigs.find(s => s.id === sigId);
          if (sig) {
            sigName = sig.name;
            accuracy = sig.accuracy;
            attackType = sig.attackType;
            const ctx = normalizeSignatureContext(sig);
            contextType = ctx.contextType;
            contextName = ctx.contextName;
            sigState = sig.state;
            if (sig.state === 'AutoSuppressed') autoSuppressed = true;
          }
        }

        const riskReasons = event.req_risk_reasons as string | string[] | undefined;
        if (riskReasons) {
          if (typeof riskReasons === 'string' && riskReasons.includes('100')) aiConfirmed = true;
          if (Array.isArray(riskReasons) && riskReasons.some(r => r.includes('100'))) aiConfirmed = true;
        }
      }

      // Top 3 paths
      const sortedPaths = [...pathCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([path, count]) => ({ path, count }));

      // Compute FP score via signal scoring
      const signalInput: QuickModeSignalsInput = {
        flaggedUsers: uniqueUsers.size,
        flaggedIPs: uniqueIPs.size,
        eventCount: events.length,
        pathCount: pathCounts.size,
        totalAppPaths: pathCounts.size,
        contextType,
        contextName,
        userAgents: mapToRecord(userAgentCounts),
        botClassifications: mapToRecord(botClassifications),
        trustScores,
        countries: mapToRecord(countryCounts),
        timestamps,
        accuracy,
        sigState,
        aiConfirmed,
        violationRatings: [],
        calculatedAction,
        rspCode200Pct: events.length > 0 ? rsp200Count / events.length : 0,
      };
      const signals = computeQuickModeSignals(signalInput);

      const summaryEntry: SignatureSummary = {
        sigId,
        name: sigName,
        accuracy,
        attackType,
        totalEvents: events.length,
        uniqueUsers: uniqueUsers.size,
        uniquePaths: pathCounts.size,
        uniqueIPs: uniqueIPs.size,
        topPaths: sortedPaths,
        autoSuppressed,
        actions: { block: blockCount, report: reportCount },
        quickVerdict: 'investigate',
        quickConfidence: 'low',
        fpScore: signals.compositeScore,
        fpVerdict: signals.verdict,
      };

      const qv = computeQuickVerdict(summaryEntry);
      summaryEntry.quickVerdict = qv.verdict;
      summaryEntry.quickConfidence = qv.confidence;

      signatures.push(summaryEntry);
    }

    // Sort: investigate first, then likely_fp, then likely_tp. Within: by event count desc.
    const priority: Record<string, number> = { investigate: 0, likely_fp: 1, likely_tp: 2 };
    signatures.sort((a, b) => {
      const pA = priority[a.quickVerdict] ?? 1;
      const pB = priority[b.quickVerdict] ?? 1;
      if (pA !== pB) return pA - pB;
      return b.totalEvents - a.totalEvents;
    });

    this.sortedSigIds = signatures.map(s => s.sigId);
    } // end waf_signatures scope check

    // Violations summary (only if waf_violations scope selected)
    const violations: ViolationSummary[] = [];
    if (scopes.includes('waf_violations')) {
      for (const [violName, events] of this.secEventsByViolation) {
        const uniqueUsers = new Set<string>();
        const pathCounts = new Map<string, number>();
        let attackType = '';

        for (const event of events) {
          uniqueUsers.add(getStr(event, 'user') || getStr(event, 'src_ip'));
          const p = getStr(event, 'req_path') || '/';
          pathCounts.set(p, (pathCounts.get(p) || 0) + 1);
          if (!attackType) {
            const viols = getViolations(event);
            const v = viols.find(vv => vv.name === violName);
            if (v) attackType = v.attackType;
          }
        }

        const topPaths = [...pathCounts.entries()]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 3)
          .map(([path, count]) => ({ path, count }));

        // Quick FP score for violations
        const violUBScore = uniqueUsers.size > 100 ? 90 : uniqueUsers.size > 50 ? 75 : uniqueUsers.size > 10 ? 50 : uniqueUsers.size > 2 ? 25 : 5;
        const violPBScore = pathCounts.size > 10 ? 80 : pathCounts.size > 3 ? 50 : 20;
        const violComposite = Math.round(violUBScore * 0.40 + 50 * 0.20 + violPBScore * 0.20 + 50 * 0.20);
        const violVerdict: FPVerdict = violComposite > 75 ? 'highly_likely_fp' : violComposite > 55 ? 'likely_fp' : violComposite > 35 ? 'ambiguous' : violComposite > 15 ? 'likely_tp' : 'confirmed_tp';

        const violSummary: ViolationSummary = {
          violationName: violName,
          attackType,
          totalEvents: events.length,
          uniqueUsers: uniqueUsers.size,
          uniquePaths: pathCounts.size,
          topPaths,
          quickVerdict: 'investigate',
          quickConfidence: 'low',
          fpScore: violComposite,
          fpVerdict: violVerdict,
        };

        if (uniqueUsers.size > 50 && pathCounts.size > 5) {
          violSummary.quickVerdict = 'likely_fp';
          violSummary.quickConfidence = 'medium';
        } else if (uniqueUsers.size <= 2) {
          violSummary.quickVerdict = 'likely_tp';
          violSummary.quickConfidence = 'medium';
        }

        violations.push(violSummary);
      }
    }

    // Threat mesh summary (only if threat_mesh scope selected)
    const threatMeshIPs: ThreatMeshSummary[] = [];
    if (scopes.includes('threat_mesh')) {
      const tmIndex = new Map<string, {
        count: number; paths: Set<string>; desc: string;
        action: string; userAgents: Map<string, number>; countries: Map<string, number>;
        asOrg: string; attackTypes: Set<string>; tenantCount: number;
      }>();
      for (const event of this.allSecurityEvents) {
        if (classifyEvent(event) !== 'threat_mesh') continue;
        const ip = getStr(event, 'src_ip');
        if (!ip) continue;
        if (!tmIndex.has(ip)) {
          tmIndex.set(ip, {
            count: 0, paths: new Set(), desc: '', action: '',
            userAgents: new Map(), countries: new Map(), asOrg: '',
            attackTypes: new Set(), tenantCount: 0,
          });
        }
        const entry = tmIndex.get(ip)!;
        entry.count++;
        entry.paths.add(getStr(event, 'req_path') || '/');
        if (!entry.action) entry.action = getStr(event, 'action') || 'block';

        const ua = getStr(event, 'user_agent') || getStr(event, 'browser_type') || 'unknown';
        entry.userAgents.set(ua, (entry.userAgents.get(ua) || 0) + 1);
        const country = getStr(event, 'country') || 'unknown';
        entry.countries.set(country, (entry.countries.get(country) || 0) + 1);
        if (!entry.asOrg) entry.asOrg = getStr(event, 'as_org') || getStr(event, 'asn') || '';

        const details = event.threat_mesh_details as Record<string, unknown> | undefined;
        if (details) {
          if (!entry.desc) entry.desc = String(details.description || '');
          if (!entry.tenantCount) entry.tenantCount = getNum(event, 'tenant_count') || (typeof details.tenant_count === 'number' ? details.tenant_count : 0);
          const ats = details.attack_types as string[] | undefined;
          if (ats) ats.forEach(at => entry.attackTypes.add(at));
        }
      }

      for (const [ip, data] of tmIndex) {
        const topUA = getTopEntry(data.userAgents);
        const topCountry = getTopEntry(data.countries);

        // Quick verdict based on key signals
        let qv: QuickVerdict = 'investigate';
        let qc: ConfidenceLevel = 'low';
        if (data.tenantCount >= 5 || data.attackTypes.size >= 3) {
          qv = 'likely_tp'; qc = 'medium';
        } else if (BENIGN_BOT_RE.test(topUA) && data.tenantCount <= 2) {
          qv = 'likely_fp'; qc = 'medium';
        } else if (data.tenantCount >= 3) {
          qv = 'likely_tp'; qc = 'low';
        }

        threatMeshIPs.push({
          srcIp: ip, eventCount: data.count, paths: data.paths.size, description: data.desc,
          action: data.action, userAgent: topUA, country: topCountry, asOrg: data.asOrg,
          attackTypes: [...data.attackTypes], tenantCount: data.tenantCount,
          quickVerdict: qv, quickConfidence: qc,
        });
      }

      // Sort: investigate first, then likely_fp, then likely_tp
      const tmPriority: Record<string, number> = { investigate: 0, likely_fp: 1, likely_tp: 2 };
      threatMeshIPs.sort((a, b) => {
        const pA = tmPriority[a.quickVerdict] ?? 1;
        const pB = tmPriority[b.quickVerdict] ?? 1;
        if (pA !== pB) return pA - pB;
        return b.eventCount - a.eventCount;
      });
      this.sortedTMIPs = threatMeshIPs.map(t => t.srcIp);
    }

    // Policy rules summary (only if service_policy scope selected)
    // classifyEvent() already separates threat_mesh from service_policy
    const policyRules: PolicyRuleSummary[] = [];
    if (scopes.includes('service_policy')) {
      const polIndex = new Map<string, { policy: string; count: number; ips: Set<string> }>();
      for (const event of this.allSecurityEvents) {
        if (classifyEvent(event) !== 'service_policy') continue;
        const hits = event.policy_hits as Record<string, unknown> | undefined;
        if (!hits) continue;
        const policyHits = (hits.policy_hits || []) as Array<Record<string, unknown>>;
        for (const hit of policyHits) {
          const rule = String(hit.policy_rule || 'unknown');
          const policy = String(hit.policy || 'unknown');
          if (!polIndex.has(rule)) polIndex.set(rule, { policy, count: 0, ips: new Set() });
          const entry = polIndex.get(rule)!;
          entry.count++;
          entry.ips.add(getStr(event, 'src_ip'));
        }
      }
      for (const [rule, data] of polIndex) {
        policyRules.push({ ruleName: rule, policyName: data.policy, totalBlocked: data.count, uniqueIPs: data.ips.size });
      }
    }

    return {
      signatures,
      violations,
      threatMeshIPs,
      policyRules,
      totalEvents: this.securityEventsCollected,
      period: { start: this.startTime, end: this.endTime },
    };
  }

  // ═══════════════════════════════════════════════════════════════
  // PHASE 1: ON-DEMAND SIGNATURE DETAIL
  // ═══════════════════════════════════════════════════════════════

  getSignatureDetail(sigId: string): SignatureAnalysisUnit | null {
    if (this.detailCache.has(sigId)) {
      // Trigger pre-fetch in background
      this.prefetchNextSignatures(sigId);
      return this.detailCache.get(sigId)!;
    }

    const events = this.secEventsBySignature.get(sigId);
    if (!events || events.length === 0) return null;

    const detail = this.computeSignatureDetail(sigId);
    this.detailCache.set(sigId, detail);

    // Pre-fetch next signatures
    this.prefetchNextSignatures(sigId);

    return detail;
  }

  private computeSignatureDetail(sigId: string): SignatureAnalysisUnit {
    const events = this.secEventsBySignature.get(sigId) || [];

    const uniqueUsers = new Set<string>();
    const uniqueIPs = new Set<string>();
    const pathCounts = new Map<string, number>();
    const userAgentCounts = new Map<string, number>();
    const countryCounts = new Map<string, number>();
    const methodCounts = new Map<string, number>();
    const rspCodeCounts = new Map<string, number>();
    const botClassifications = new Map<string, number>();
    const trustScores: number[] = [];
    const matchingInfos: string[] = [];
    const timestamps: string[] = [];
    const violationRatings: number[] = [];
    const reqRiskReasons: string[] = [];
    const reqParams: string[] = [];
    let aiConfirmed = false;
    let sigName = '';
    let accuracy = '';
    let attackType = '';
    let contextType = '';
    let contextName = '';
    let contextRaw = '';
    let sigState = '';
    let autoSuppressed = false;
    let rsp200Count = 0;
    let calculatedAction = '';

    for (const event of events) {
      const user = getStr(event, 'user') || getStr(event, 'src_ip');
      uniqueUsers.add(user);
      uniqueIPs.add(getStr(event, 'src_ip'));

      const p = getStr(event, 'req_path') || '/';
      pathCounts.set(p, (pathCounts.get(p) || 0) + 1);

      const ua = getStr(event, 'user_agent') || getStr(event, 'browser_type') || 'unknown';
      userAgentCounts.set(ua, (userAgentCounts.get(ua) || 0) + 1);

      const c = getStr(event, 'country') || 'unknown';
      countryCounts.set(c, (countryCounts.get(c) || 0) + 1);

      const m = getStr(event, 'method') || 'GET';
      methodCounts.set(m, (methodCounts.get(m) || 0) + 1);

      const rsp = getStr(event, 'rsp_code') || '0';
      rspCodeCounts.set(rsp, (rspCodeCounts.get(rsp) || 0) + 1);
      if (rsp === '200') rsp200Count++;

      // Bot info
      const botInfo = event.bot_info as Record<string, unknown> | undefined;
      if (botInfo?.classification) {
        const cls = String(botInfo.classification);
        botClassifications.set(cls, (botClassifications.get(cls) || 0) + 1);
      }

      // Trust scores
      const policyHits = event.policy_hits as Record<string, unknown> | undefined;
      if (policyHits) {
        const hits = (policyHits.policy_hits || []) as Array<Record<string, unknown>>;
        for (const hit of hits) {
          const ts = hit.ip_trustscore;
          if (ts) trustScores.push(typeof ts === 'number' ? ts : parseInt(String(ts), 10) || 0);
        }
      }

      // Sig metadata
      const sigs = getSignatures(event);
      const sig = sigs.find(s => s.id === sigId);
      if (sig) {
        if (!sigName) {
          sigName = sig.name;
          accuracy = sig.accuracy;
          attackType = sig.attackType;
          const ctx = normalizeSignatureContext(sig);
          contextType = ctx.contextType;
          contextName = ctx.contextName;
          contextRaw = sig.context;
          sigState = sig.state;
          if (sig.state === 'AutoSuppressed') autoSuppressed = true;
        }
        if (sig.matchingInfo && matchingInfos.length < 20) {
          matchingInfos.push(sig.matchingInfo);
        }
      }

      // Calculated action
      if (!calculatedAction) {
        calculatedAction = getStr(event, 'calculated_action');
      }

      // Risk
      const riskReasons = event.req_risk_reasons as string | string[] | undefined;
      if (riskReasons) {
        if (typeof riskReasons === 'string' && riskReasons.includes('100')) aiConfirmed = true;
        if (Array.isArray(riskReasons)) {
          reqRiskReasons.push(...riskReasons);
          if (riskReasons.some(r => r.includes('100'))) aiConfirmed = true;
        }
      }

      timestamps.push(getStr(event, '@timestamp') || getStr(event, 'time') || '');

      if (reqParams.length < 10) {
        const rp = getStr(event, 'req_params');
        if (rp) reqParams.push(rp);
      }
    }

    const rawPaths = [...pathCounts.entries()].sort((a, b) => b[1] - a[1]).map(([p]) => p);
    const topPath = rawPaths[0] || '/';
    const rspCode200Pct = events.length > 0 ? rsp200Count / events.length : 0;

    // Compute Quick Mode signals
    const signalInput: QuickModeSignalsInput = {
      flaggedUsers: uniqueUsers.size,
      flaggedIPs: uniqueIPs.size,
      eventCount: events.length,
      pathCount: pathCounts.size,
      totalAppPaths: pathCounts.size, // Quick Mode: no total app paths
      contextType,
      contextName,
      userAgents: mapToRecord(userAgentCounts),
      botClassifications: mapToRecord(botClassifications),
      trustScores,
      countries: mapToRecord(countryCounts),
      timestamps,
      accuracy,
      sigState,
      aiConfirmed,
      violationRatings,
      calculatedAction,
      rspCode200Pct,
    };

    const signals = computeQuickModeSignals(signalInput);

    // Per-path FP/TP analysis
    const pathAnalyses = this.computePerPathAnalysis(events, sigId, accuracy, contextType, contextName);

    return {
      signatureId: sigId,
      signatureName: sigName,
      attackType,
      accuracy,
      contextType,
      contextName,
      contextRaw,
      path: topPath,
      rawPaths,
      pathCount: pathCounts.size,
      pathCounts: mapToRecord(pathCounts),
      pathAnalyses,
      eventCount: events.length,
      flaggedUsers: uniqueUsers.size,
      flaggedIPs: uniqueIPs.size,
      ipCounts: (() => { const m = new Map<string, number>(); for (const e of events) { const ip = getStr(e, 'src_ip'); if (ip) m.set(ip, (m.get(ip) || 0) + 1); } return mapToRecord(m); })(),
      ipDetails: (() => {
        const details: Record<string, { count: number; country: string; city: string; asOrg: string; userAgent: string }> = {};
        for (const e of events) {
          const ip = getStr(e, 'src_ip');
          if (!ip) continue;
          if (!details[ip]) {
            details[ip] = {
              count: 0,
              country: getStr(e, 'country') || 'unknown',
              city: getStr(e, 'city') || getStr(e, 'src_city') || '',
              asOrg: getStr(e, 'as_org') || getStr(e, 'asn') || '',
              userAgent: getStr(e, 'user_agent') || getStr(e, 'browser_type') || 'unknown',
            };
          }
          details[ip].count++;
        }
        return details;
      })(),
      totalRequestsOnPath: 0, // No access logs yet
      totalUsersOnPath: 0,
      userRatio: 0,
      requestRatio: 0,
      userAgents: mapToRecord(userAgentCounts),
      countries: mapToRecord(countryCounts),
      trustScores,
      botClassifications: mapToRecord(botClassifications),
      methods: mapToRecord(methodCounts),
      sampleMatchingInfos: matchingInfos,
      sampleReqParams: reqParams,
      timestamps,
      rspCodes: mapToRecord(rspCodeCounts),
      originAcceptedCount: rsp200Count,
      violationRatings,
      reqRiskReasons: [...new Set(reqRiskReasons)],
      aiConfirmed,
      sigState,
      signals,
      autoSuppressed,
    };
  }

  private computePerPathAnalysis(
    events: SecurityEventEntry[],
    sigId: string,
    accuracy: string,
    contextType: string,
    contextName: string,
  ): PathAnalysis[] {
    // Group events by path
    const pathGroups = new Map<string, SecurityEventEntry[]>();
    for (const event of events) {
      const p = getStr(event, 'req_path') || '/';
      if (!pathGroups.has(p)) pathGroups.set(p, []);
      pathGroups.get(p)!.push(event);
    }

    const analyses: PathAnalysis[] = [];
    const EXPLOIT_PATH_RE = /\.\.(\/|\\)|<script|%3cscript|\/etc\/passwd|\/proc\/|cmd=|exec\(|union\s+select/i;

    for (const [path, pathEvents] of pathGroups) {
      const users = new Set<string>();
      const ips = new Set<string>();
      const uas = new Map<string, number>();
      const countries = new Map<string, number>();
      const methods = new Map<string, number>();
      const rspCodes = new Map<string, number>();
      const matchingInfos: string[] = [];

      for (const event of pathEvents) {
        users.add(getStr(event, 'user') || getStr(event, 'src_ip'));
        ips.add(getStr(event, 'src_ip'));
        const ua = getStr(event, 'user_agent') || getStr(event, 'browser_type') || 'unknown';
        uas.set(ua, (uas.get(ua) || 0) + 1);
        const c = getStr(event, 'country') || 'unknown';
        countries.set(c, (countries.get(c) || 0) + 1);
        const m = getStr(event, 'method') || 'GET';
        methods.set(m, (methods.get(m) || 0) + 1);
        const rsp = getStr(event, 'rsp_code') || '0';
        rspCodes.set(rsp, (rspCodes.get(rsp) || 0) + 1);

        const sigs = getSignatures(event);
        const sig = sigs.find(s => s.id === sigId);
        if (sig?.matchingInfo && matchingInfos.length < 5) {
          matchingInfos.push(sig.matchingInfo);
        }
      }

      // Per-path FP scoring
      let score = 50; // Start neutral
      const reasons: string[] = [];

      // User breadth: many users on same path = FP signal
      if (users.size > 50) { score += 20; reasons.push(`${users.size} users — broad population`); }
      else if (users.size > 10) { score += 10; reasons.push(`${users.size} users — moderate population`); }
      else if (users.size <= 2) { score -= 15; reasons.push(`Only ${users.size} user(s) — targeted`); }

      // IP diversity
      if (ips.size > 20) { score += 10; reasons.push(`${ips.size} IPs — diverse sources`); }
      else if (ips.size <= 2) { score -= 10; reasons.push(`Only ${ips.size} IP(s) — concentrated`); }

      // Accuracy: low accuracy sigs on busy paths = FP
      if (accuracy === 'low_accuracy') { score += 15; reasons.push('Low accuracy signature'); }
      else if (accuracy === 'high_accuracy' && users.size <= 3) { score -= 20; reasons.push('High accuracy + few users'); }

      // Context: header/cookie on common path = likely FP
      if (contextType === 'CONTEXT_HEADER' || contextType === 'CONTEXT_COOKIE') {
        score += 10; reasons.push(`${contextType} context — common in normal traffic`);
      }

      // Matching info analysis: exploit patterns = TP
      const hasExploitPattern = matchingInfos.some(mi => EXPLOIT_PATH_RE.test(mi));
      if (hasExploitPattern) { score -= 25; reasons.push('Exploit pattern in matching info'); }

      // Response codes: mostly 200 = normal traffic, mostly errors = suspicious
      const rsp200 = rspCodes.get('200') || 0;
      const successRate = pathEvents.length > 0 ? rsp200 / pathEvents.length : 0;
      if (successRate > 0.8) { score += 10; reasons.push(`${(successRate * 100).toFixed(0)}% success rate`); }
      else if (successRate < 0.3) { score -= 10; reasons.push(`${(successRate * 100).toFixed(0)}% success rate — many errors`); }

      // Country diversity: many countries = broad traffic
      if (countries.size > 5) { score += 5; reasons.push(`${countries.size} countries`); }

      score = Math.max(0, Math.min(100, score));

      let verdict: FPVerdict;
      if (score >= 75) verdict = 'highly_likely_fp';
      else if (score >= 60) verdict = 'likely_fp';
      else if (score >= 40) verdict = 'ambiguous';
      else if (score >= 25) verdict = 'likely_tp';
      else verdict = 'confirmed_tp';

      analyses.push({
        path,
        eventCount: pathEvents.length,
        uniqueUsers: users.size,
        uniqueIPs: ips.size,
        userAgents: mapToRecord(uas),
        countries: mapToRecord(countries),
        methods: mapToRecord(methods),
        rspCodes: mapToRecord(rspCodes),
        sampleMatchingInfos: matchingInfos,
        fpScore: score,
        verdict,
        reasons,
      });
    }

    // Sort by event count desc
    analyses.sort((a, b) => b.eventCount - a.eventCount);
    return analyses;
  }

  private computeViolationPerPathAnalysis(
    events: SecurityEventEntry[],
    violName: string,
  ): PathAnalysis[] {
    const pathGroups = new Map<string, SecurityEventEntry[]>();
    for (const event of events) {
      const p = getStr(event, 'req_path') || '/';
      if (!pathGroups.has(p)) pathGroups.set(p, []);
      pathGroups.get(p)!.push(event);
    }

    const analyses: PathAnalysis[] = [];
    const EXPLOIT_RE = /\.\.(\/|\\)|<script|%3cscript|\/etc\/passwd|\/proc\/|cmd=|exec\(|union\s+select/i;

    for (const [path, pathEvents] of pathGroups) {
      const users = new Set<string>();
      const ips = new Set<string>();
      const uas = new Map<string, number>();
      const countries = new Map<string, number>();
      const methods = new Map<string, number>();
      const rspCodes = new Map<string, number>();
      const matchingInfos: string[] = [];

      for (const event of pathEvents) {
        users.add(getStr(event, 'user') || getStr(event, 'src_ip'));
        ips.add(getStr(event, 'src_ip'));
        const ua = getStr(event, 'user_agent') || 'unknown';
        uas.set(ua, (uas.get(ua) || 0) + 1);
        const c = getStr(event, 'country') || 'unknown';
        countries.set(c, (countries.get(c) || 0) + 1);
        const m = getStr(event, 'method') || 'GET';
        methods.set(m, (methods.get(m) || 0) + 1);
        const rsp = getStr(event, 'rsp_code') || '0';
        rspCodes.set(rsp, (rspCodes.get(rsp) || 0) + 1);

        const viols = getViolations(event);
        const v = viols.find(vv => vv.name === violName);
        if (v?.matchingInfo && matchingInfos.length < 5) matchingInfos.push(v.matchingInfo);
      }

      let score = 50;
      const reasons: string[] = [];

      if (users.size > 50) { score += 20; reasons.push(`${users.size} users — broad population`); }
      else if (users.size > 10) { score += 10; reasons.push(`${users.size} users — moderate population`); }
      else if (users.size <= 2) { score -= 15; reasons.push(`Only ${users.size} user(s) — targeted`); }

      if (ips.size > 20) { score += 10; reasons.push(`${ips.size} IPs — diverse sources`); }
      else if (ips.size <= 2) { score -= 10; reasons.push(`Only ${ips.size} IP(s) — concentrated`); }

      const hasExploit = matchingInfos.some(mi => EXPLOIT_RE.test(mi));
      if (hasExploit) { score -= 25; reasons.push('Exploit pattern in matching info'); }

      const rsp200 = rspCodes.get('200') || 0;
      const successRate = pathEvents.length > 0 ? rsp200 / pathEvents.length : 0;
      if (successRate > 0.8) { score += 10; reasons.push(`${(successRate * 100).toFixed(0)}% success rate`); }
      else if (successRate < 0.3) { score -= 10; reasons.push(`${(successRate * 100).toFixed(0)}% success rate — many errors`); }

      if (countries.size > 5) { score += 5; reasons.push(`${countries.size} countries`); }

      score = Math.max(0, Math.min(100, score));

      let verdict: FPVerdict;
      if (score >= 75) verdict = 'highly_likely_fp';
      else if (score >= 60) verdict = 'likely_fp';
      else if (score >= 40) verdict = 'ambiguous';
      else if (score >= 25) verdict = 'likely_tp';
      else verdict = 'confirmed_tp';

      analyses.push({
        path,
        eventCount: pathEvents.length,
        uniqueUsers: users.size,
        uniqueIPs: ips.size,
        userAgents: mapToRecord(uas),
        countries: mapToRecord(countries),
        methods: mapToRecord(methods),
        rspCodes: mapToRecord(rspCodes),
        sampleMatchingInfos: matchingInfos,
        fpScore: score,
        verdict,
        reasons,
      });
    }

    analyses.sort((a, b) => b.eventCount - a.eventCount);
    return analyses;
  }

  private prefetchNextSignatures(currentSigId: string): void {
    const idx = this.sortedSigIds.indexOf(currentSigId);
    if (idx < 0) return;

    for (let i = idx + 1; i <= idx + PREFETCH_COUNT && i < this.sortedSigIds.length; i++) {
      const nextId = this.sortedSigIds[i];
      if (!this.detailCache.has(nextId)) {
        this.detailCache.set(nextId, this.computeSignatureDetail(nextId));
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // VIOLATION DETAIL (on-demand)
  // ═══════════════════════════════════════════════════════════════

  getViolationDetail(violName: string): ViolationAnalysisUnit | null {
    if (this.violationDetailCache.has(violName)) return this.violationDetailCache.get(violName)!;

    const events = this.secEventsByViolation.get(violName);
    if (!events || events.length === 0) return null;

    const uniqueUsers = new Set<string>();
    const uniqueIPs = new Set<string>();
    const ipCountMap = new Map<string, number>();
    const pathCounts = new Map<string, number>();
    const userAgentCounts = new Map<string, number>();
    const countryCounts = new Map<string, number>();
    const methodCounts = new Map<string, number>();
    const rspCodeCounts = new Map<string, number>();
    const matchingInfos: string[] = [];
    const timestamps: string[] = [];
    let attackType = '';

    for (const event of events) {
      uniqueUsers.add(getStr(event, 'user') || getStr(event, 'src_ip'));
      const ip = getStr(event, 'src_ip');
      if (ip) { uniqueIPs.add(ip); ipCountMap.set(ip, (ipCountMap.get(ip) || 0) + 1); }
      const p = getStr(event, 'req_path') || '/';
      pathCounts.set(p, (pathCounts.get(p) || 0) + 1);
      const ua = getStr(event, 'user_agent') || 'unknown';
      userAgentCounts.set(ua, (userAgentCounts.get(ua) || 0) + 1);
      const c = getStr(event, 'country') || 'unknown';
      countryCounts.set(c, (countryCounts.get(c) || 0) + 1);
      const m = getStr(event, 'method') || 'GET';
      methodCounts.set(m, (methodCounts.get(m) || 0) + 1);
      const rsp = getStr(event, 'rsp_code') || '0';
      rspCodeCounts.set(rsp, (rspCodeCounts.get(rsp) || 0) + 1);
      timestamps.push(getStr(event, '@timestamp') || getStr(event, 'time') || '');

      if (!attackType) {
        const viols = getViolations(event);
        const v = viols.find(vv => vv.name === violName);
        if (v) {
          attackType = v.attackType;
          if (v.matchingInfo && matchingInfos.length < 20) matchingInfos.push(v.matchingInfo);
        }
      }
    }

    const rawPaths = [...pathCounts.entries()].sort((a, b) => b[1] - a[1]).map(([p]) => p);
    const topPath = rawPaths[0] || '/';

    // Simplified scoring for violations
    const userBreadthScore = uniqueUsers.size > 100 ? 90 : uniqueUsers.size > 50 ? 75 : uniqueUsers.size > 10 ? 50 : uniqueUsers.size > 2 ? 25 : 5;
    const signals: SignalResult = {
      userBreadth: { score: userBreadthScore, rawValue: uniqueUsers.size, reason: `${uniqueUsers.size} users` },
      requestBreadth: { score: 50, rawValue: events.length, reason: `${events.length} events` },
      pathBreadth: { score: pathCounts.size > 10 ? 80 : pathCounts.size > 3 ? 50 : 20, rawValue: pathCounts.size, reason: `${pathCounts.size} paths` },
      contextAnalysis: { score: 50, rawValue: 'violation', reason: 'Violation context' },
      clientProfile: { score: 50, rawValue: 50, reason: 'Neutral' },
      temporalPattern: { score: 50, rawValue: 50, reason: 'Not computed for violations' },
      signatureAccuracy: { score: 50, rawValue: 50, reason: 'N/A for violations' },
      compositeScore: 50,
      verdict: 'ambiguous',
    };
    signals.compositeScore = Math.round(
      signals.userBreadth.score * 0.30 +
      signals.requestBreadth.score * 0.20 +
      signals.pathBreadth.score * 0.20 +
      signals.contextAnalysis.score * 0.15 +
      signals.clientProfile.score * 0.15
    );
    if (signals.compositeScore > 75) signals.verdict = 'highly_likely_fp';
    else if (signals.compositeScore > 55) signals.verdict = 'likely_fp';
    else if (signals.compositeScore > 35) signals.verdict = 'ambiguous';
    else if (signals.compositeScore > 15) signals.verdict = 'likely_tp';
    else signals.verdict = 'confirmed_tp';

    // Per-path analysis for violations
    const violPathAnalyses = this.computeViolationPerPathAnalysis(events, violName);

    const detail: ViolationAnalysisUnit = {
      violationName: violName,
      attackType,
      path: topPath,
      rawPaths,
      pathCount: pathCounts.size,
      pathCounts: mapToRecord(pathCounts),
      pathAnalyses: violPathAnalyses,
      eventCount: events.length,
      flaggedUsers: uniqueUsers.size,
      flaggedIPs: uniqueIPs.size,
      ipCounts: mapToRecord(ipCountMap),
      ipDetails: (() => {
        const details: Record<string, { count: number; country: string; city: string; asOrg: string; userAgent: string }> = {};
        for (const e of events) {
          const ip = getStr(e, 'src_ip');
          if (!ip) continue;
          if (!details[ip]) {
            details[ip] = {
              count: 0,
              country: getStr(e, 'country') || 'unknown',
              city: getStr(e, 'city') || getStr(e, 'src_city') || '',
              asOrg: getStr(e, 'as_org') || getStr(e, 'asn') || '',
              userAgent: getStr(e, 'user_agent') || getStr(e, 'browser_type') || 'unknown',
            };
          }
          details[ip].count++;
        }
        return details;
      })(),
      totalRequestsOnPath: 0,
      totalUsersOnPath: 0,
      userRatio: 0,
      requestRatio: 0,
      userAgents: mapToRecord(userAgentCounts),
      countries: mapToRecord(countryCounts),
      methods: mapToRecord(methodCounts),
      sampleMatchingInfos: matchingInfos,
      timestamps,
      signals,
    };

    this.violationDetailCache.set(violName, detail);
    return detail;
  }

  // ═══════════════════════════════════════════════════════════════
  // THREAT MESH DETAIL (on-demand)
  // ═══════════════════════════════════════════════════════════════

  getThreatMeshDetail(srcIp: string): ThreatMeshAnalysisUnit | null {
    if (this.tmDetailCache.has(srcIp)) {
      this.prefetchNextTMIPs(srcIp);
      return this.tmDetailCache.get(srcIp)!;
    }

    const detail = this.computeThreatMeshDetail(srcIp);
    if (!detail) return null;

    this.tmDetailCache.set(srcIp, detail);
    this.prefetchNextTMIPs(srcIp);
    return detail;
  }

  private computeThreatMeshDetail(srcIp: string): ThreatMeshAnalysisUnit {
    // Gather all threat mesh events for this IP
    const events = this.allSecurityEvents.filter(e =>
      classifyEvent(e) === 'threat_mesh' && getStr(e, 'src_ip') === srcIp
    );

    const pathCounts = new Map<string, number>();
    const userAgentCounts = new Map<string, number>();
    const countryCounts = new Map<string, number>();
    const methodCounts = new Map<string, number>();
    const rspCodeCounts = new Map<string, number>();
    const timestamps: string[] = [];
    let user = '';
    let asOrg = '';
    let desc = '';
    let tenantCount = 0;
    let globalEvents = 0;
    let highAccSigs = 0;
    let tlsCount = 0;
    let malBotEvents = 0;
    const attackTypes = new Set<string>();
    let action = '';

    for (const event of events) {
      if (!user) user = getStr(event, 'user') || `IP-${srcIp}`;
      if (!asOrg) asOrg = getStr(event, 'as_org') || getStr(event, 'asn') || '';
      if (!action) action = getStr(event, 'action');

      const p = getStr(event, 'req_path') || '/';
      pathCounts.set(p, (pathCounts.get(p) || 0) + 1);
      const ua = getStr(event, 'user_agent') || getStr(event, 'browser_type') || 'unknown';
      userAgentCounts.set(ua, (userAgentCounts.get(ua) || 0) + 1);
      const c = getStr(event, 'country') || 'unknown';
      countryCounts.set(c, (countryCounts.get(c) || 0) + 1);
      const m = getStr(event, 'method') || 'GET';
      methodCounts.set(m, (methodCounts.get(m) || 0) + 1);
      const rsp = getStr(event, 'rsp_code') || '0';
      rspCodeCounts.set(rsp, (rspCodeCounts.get(rsp) || 0) + 1);
      timestamps.push(getStr(event, '@timestamp') || getStr(event, 'time') || '');

      const details = event.threat_mesh_details as Record<string, unknown> | undefined;
      if (details) {
        if (!desc) desc = String(details.description || '');
        if (!tenantCount) tenantCount = (details.tenant_count as number) || 0;
        if (!globalEvents) globalEvents = (details.events as number) || 0;
        if (!highAccSigs) highAccSigs = (details.high_accuracy_signatures as number) || 0;
        if (!tlsCount) tlsCount = (details.tls_count as number) || 0;
        if (!malBotEvents) malBotEvents = (details.malicious_bot_events as number) || 0;
        const ats = details.attack_types as string[] | undefined;
        if (ats) ats.forEach(at => attackTypes.add(at));
      }
    }

    const topUA = getTopEntry(userAgentCounts) || 'unknown';
    const topCountry = getTopEntry(countryCounts) || 'unknown';

    // Cross-reference: count WAF events from this IP
    let wafEventsFromThisIP = 0;
    for (const sigEvents of this.secEventsBySignature.values()) {
      for (const e of sigEvents) {
        if (getStr(e, 'src_ip') === srcIp) wafEventsFromThisIP++;
      }
    }

    // Scoring (adapted from threat-mesh-analyzer.ts)
    let fpScore = 50;
    const reasons: string[] = [];

    // TP signals (lower FP score)
    if (tenantCount >= 5) { fpScore -= 20; reasons.push(`Flagged by ${tenantCount} tenants — widely recognized threat`); }
    else if (tenantCount >= 3) { fpScore -= 10; reasons.push(`Flagged by ${tenantCount} tenants`); }
    if (globalEvents >= 1000) { fpScore -= 15; reasons.push(`${globalEvents.toLocaleString()} attack events globally`); }
    else if (globalEvents >= 100) { fpScore -= 5; reasons.push(`${globalEvents} attack events globally`); }
    if (highAccSigs > 0) { fpScore -= 10; reasons.push(`${highAccSigs} high-accuracy signature matches on other tenants`); }
    if (wafEventsFromThisIP > 0) { fpScore -= 15; reasons.push(`Also triggered ${wafEventsFromThisIP} WAF events on this app`); }
    if (SCRIPTING_TOOL_RE.test(topUA)) { fpScore -= 10; reasons.push('Uses scripting tool user agent'); }
    const pathKeys = [...pathCounts.keys()];
    const exploitPathCount = pathKeys.filter(p => EXPLOIT_PATHS.test(p)).length;
    if (exploitPathCount > 0) { fpScore -= 10; reasons.push(`Probed ${exploitPathCount} exploit paths (wp-admin, phpmyadmin, etc.)`); }

    // FP signals (raise FP score)
    if (BENIGN_BOT_RE.test(topUA)) { fpScore += 30; reasons.push(`Known search engine bot (${topUA.match(BENIGN_BOT_RE)?.[0] || 'bot'})`); }
    if (CDN_PROXY_ORGS.test(asOrg)) { fpScore += 15; reasons.push(`IP from CDN/proxy provider: ${asOrg}`); }
    if (wafEventsFromThisIP === 0) { fpScore += 15; reasons.push('No WAF events on this app — only Threat Mesh flagged this IP'); }
    if (tenantCount <= 2) { fpScore += 10; reasons.push(`Low tenant count (${tenantCount}) — possibly shared IP`); }
    if (pathKeys.length > 10 && exploitPathCount === 0) { fpScore += 10; reasons.push(`Accessed ${pathKeys.length} unique content paths — sequential crawling pattern`); }

    fpScore = Math.max(0, Math.min(100, fpScore));
    const verdict = tmScoreToVerdict(fpScore);
    let suggestedAction: 'trusted_client' | 'no_action' | undefined;
    if (verdict === 'highly_likely_fp' || verdict === 'likely_fp') suggestedAction = 'trusted_client';

    const threatDetails: ThreatMeshDetails = {
      description: desc,
      attackTypes: [...attackTypes],
      events: globalEvents,
      tenantCount,
      highAccuracySignatures: highAccSigs,
      tlsCount,
      maliciousBotEvents: malBotEvents,
    };

    return {
      srcIp,
      user,
      threatDetails,
      totalRequestsOnApp: events.length,
      pathsAccessed: mapToRecord(pathCounts),
      userAgent: topUA,
      country: topCountry,
      asOrg,
      rspCodes: mapToRecord(rspCodeCounts),
      wafEventsFromThisIP,
      fpScore,
      verdict,
      reasons,
      suggestedAction,
    };
  }

  private prefetchNextTMIPs(currentIp: string): void {
    const idx = this.sortedTMIPs.indexOf(currentIp);
    if (idx < 0) return;
    for (let i = idx + 1; i <= idx + PREFETCH_COUNT && i < this.sortedTMIPs.length; i++) {
      const nextIp = this.sortedTMIPs[i];
      if (!this.tmDetailCache.has(nextIp)) {
        this.tmDetailCache.set(nextIp, this.computeThreatMeshDetail(nextIp));
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // HYBRID MODE: BACKGROUND ENRICHMENT ENGINE
  // ═══════════════════════════════════════════════════════════════

  private async runHybridEnrichment(): Promise<void> {
    console.log(`[ProgressiveJob ${this.id}] Starting hybrid enrichment...`);

    // Phase 1: Bulk fetch ALL access logs for the LB
    if (!this.cancelled) {
      this.hybridEnrichPhase = 'fetching_access_logs';
      this.currentPhaseLabel = 'Fetching access logs for all paths...';
      await this.collectAllAccessLogs();
    }

    // Phase 2: Enrich all signatures with access log denominators
    if (!this.cancelled && this.config.scopes.includes('waf_signatures') && this.secEventsBySignature.size > 0) {
      this.hybridEnrichPhase = 'enriching_signatures';
      this.currentPhaseLabel = 'Enriching signatures with access log data...';
      await this.enrichAllSignatures();
    }

    // Phase 3: Enrich all violations with access log denominators
    if (!this.cancelled && this.config.scopes.includes('waf_violations') && this.secEventsByViolation.size > 0) {
      this.hybridEnrichPhase = 'enriching_violations';
      this.currentPhaseLabel = 'Enriching violations with access log data...';
      await this.enrichAllViolations();
    }

    // Phase 4: Enrich threat mesh IPs with per-IP access logs
    if (!this.cancelled && this.config.scopes.includes('threat_mesh') && this.sortedTMIPs.length > 0) {
      this.hybridEnrichPhase = 'enriching_tm';
      this.currentPhaseLabel = 'Enriching threat mesh IPs with access logs...';
      await this.autoEnrichThreatMeshIPs();
    }

    // Free memory
    this.accessLogStore = null;

    if (!this.cancelled) {
      this.hybridEnrichPhase = 'complete';
      const elapsed = Date.now() - this.startMs;
      console.log(`[ProgressiveJob ${this.id}] Hybrid enrichment complete in ${(elapsed / 1000).toFixed(1)}s`);
    }
  }

  private async collectAllAccessLogs(): Promise<void> {
    const query = `{vh_name="ves-io-http-loadbalancer-${this.config.lbName}"}`;
    const chunks = splitIntoChunks(this.startTime, this.endTime, CHUNK_HOURS);
    this.accessLogsCollected = 0;
    this.accessLogStore = new Map();

    console.log(`[ProgressiveJob ${this.id}] Fetching ALL access logs: ${chunks.length} chunks`);

    const accessController = new AdaptiveConcurrencyController({
      initialConcurrency: 3,
      minConcurrency: 1,
      maxConcurrency: 6, // Lower than sec events — access logs are heavier
      rampUpAfterSuccesses: 10,
    });

    const tasks = chunks.map((chunk, idx) => ({
      id: idx,
      execute: async (): Promise<RawEvent[]> => {
        const chunkLogs: unknown[] = [];
        try {
          const initial = await this.api.fetchAccessLogsPage(
            this.config.namespace, query, chunk.start, chunk.end, PAGE_SIZE,
          );
          if (initial.logs) chunkLogs.push(...initial.logs);

          let scrollId = initial.scroll_id;
          while (scrollId) {
            try {
              const page = await this.api.scrollAccessLogs(this.config.namespace, scrollId);
              if (!page.logs || page.logs.length === 0) break;
              chunkLogs.push(...page.logs);
              scrollId = page.scroll_id;
            } catch { break; }
          }
        } catch {
          // Skip failed chunks
        }
        return normalizeEntries<RawEvent>(chunkLogs, `access-${chunk.label}`);
      },
    }));

    await runAdaptivePool(
      tasks,
      accessController,
      (r) => {
        if (r.result) {
          // Aggregate per-path stats
          for (const log of r.result) {
            const vh = getStr(log, 'vh_name');
            if (vh && vh !== `ves-io-http-loadbalancer-${this.config.lbName}`) continue;

            const path = getStr(log, 'req_path') || '/';
            let stats = this.accessLogStore!.get(path);
            if (!stats) {
              stats = { totalRequests: 0, uniqueUsers: new Set(), countries: new Map(), timestamps: [] };
              this.accessLogStore!.set(path, stats);
            }
            stats.totalRequests++;
            const user = getStr(log, 'user') || getStr(log, 'src_ip');
            if (user) stats.uniqueUsers.add(user);
            const country = getStr(log, 'country') || 'unknown';
            stats.countries.set(country, (stats.countries.get(country) || 0) + 1);
            // Sample timestamps (max 500 per path to limit memory)
            if (stats.timestamps.length < 500) {
              stats.timestamps.push(getStr(log, '@timestamp') || getStr(log, 'time') || '');
            }
          }
          this.accessLogsCollected += r.result.length;
          this.currentPhaseLabel = `Fetching access logs (${this.accessLogsCollected.toLocaleString()} collected, ${this.accessLogStore!.size} paths)...`;
        }
      },
      undefined,
      () => this.cancelled,
    );

    console.log(`[ProgressiveJob ${this.id}] Access logs collected: ${this.accessLogsCollected} entries across ${this.accessLogStore!.size} paths`);
  }

  private async enrichAllSignatures(): Promise<void> {
    this.sigEnrichTotal = this.secEventsBySignature.size;
    this.sigEnrichCompleted = 0;

    for (const [sigId] of this.secEventsBySignature) {
      if (this.cancelled) return;

      // Get or compute detail from cache
      let detail = this.detailCache.get(sigId);
      if (!detail) {
        detail = this.computeSignatureDetail(sigId);
        this.detailCache.set(sigId, detail);
      }

      // Aggregate access log stats across all paths for this signature
      let totalRequestsOnPath = 0;
      const allUsersOnPaths = new Set<string>();
      const normalCountries = new Map<string, number>();
      const normalTimestamps: string[] = [];

      for (const path of detail.rawPaths) {
        const pathStats = this.accessLogStore?.get(path);
        if (pathStats) {
          totalRequestsOnPath += pathStats.totalRequests;
          for (const u of pathStats.uniqueUsers) allUsersOnPaths.add(u);
          for (const [c, n] of pathStats.countries) normalCountries.set(c, (normalCountries.get(c) || 0) + n);
          normalTimestamps.push(...pathStats.timestamps.slice(0, 100));
        }
      }

      const totalUsersOnPath = allUsersOnPaths.size;

      // Recompute with deep/hybrid signals (ratio-based)
      if (totalRequestsOnPath > 0) {
        const deepInput: ComputeSignalsInput = {
          flaggedUsers: detail.flaggedUsers,
          flaggedIPs: detail.flaggedIPs,
          eventCount: detail.eventCount,
          totalUsersOnPath,
          totalRequestsOnPath,
          pathCount: detail.pathCount,
          totalAppPaths: this.accessLogStore?.size || detail.pathCount,
          contextType: detail.contextType,
          contextName: detail.contextName,
          userAgents: detail.userAgents,
          botClassifications: detail.botClassifications || {},
          trustScores: detail.trustScores || [],
          countries: detail.countries,
          normalCountries: mapToRecord(normalCountries),
          timestamps: detail.timestamps,
          normalTimestamps,
          accuracy: detail.accuracy,
          sigState: detail.sigState || '',
          aiConfirmed: detail.aiConfirmed || false,
          violationRatings: detail.violationRatings || [],
        };

        const deepSignals = computeAllSignals(deepInput);

        // Update detail cache
        detail.totalRequestsOnPath = totalRequestsOnPath;
        detail.totalUsersOnPath = totalUsersOnPath;
        detail.userRatio = totalUsersOnPath > 0 ? detail.flaggedUsers / totalUsersOnPath : 0;
        detail.requestRatio = totalRequestsOnPath > 0 ? detail.eventCount / totalRequestsOnPath : 0;
        detail.signals = deepSignals;
        detail.enriched = true;
        this.detailCache.set(sigId, detail);

        // Update summary entry
        if (this.summary) {
          const summaryEntry = this.summary.signatures.find(s => s.sigId === sigId);
          if (summaryEntry) {
            summaryEntry.enrichedFpScore = deepSignals.compositeScore;
            summaryEntry.enrichedFpVerdict = deepSignals.verdict;
            summaryEntry.enrichmentStatus = 'complete';
          }
        }
      }

      this.sigEnrichCompleted++;
      this.currentPhaseLabel = `Enriching signatures (${this.sigEnrichCompleted}/${this.sigEnrichTotal})...`;
    }

    console.log(`[ProgressiveJob ${this.id}] Enriched ${this.sigEnrichCompleted} signatures`);
  }

  private async enrichAllViolations(): Promise<void> {
    this.violEnrichTotal = this.secEventsByViolation.size;
    this.violEnrichCompleted = 0;

    for (const [violName] of this.secEventsByViolation) {
      if (this.cancelled) return;

      // Get or compute detail from cache
      let detail = this.violationDetailCache.get(violName);
      if (!detail) {
        detail = this.getViolationDetail(violName)!;
      }
      if (!detail) { this.violEnrichCompleted++; continue; }

      // Aggregate access log stats across all paths for this violation
      let totalRequestsOnPath = 0;
      const allUsersOnPaths = new Set<string>();
      const normalCountries = new Map<string, number>();
      const normalTimestamps: string[] = [];

      for (const path of detail.rawPaths) {
        const pathStats = this.accessLogStore?.get(path);
        if (pathStats) {
          totalRequestsOnPath += pathStats.totalRequests;
          for (const u of pathStats.uniqueUsers) allUsersOnPaths.add(u);
          for (const [c, n] of pathStats.countries) normalCountries.set(c, (normalCountries.get(c) || 0) + n);
          normalTimestamps.push(...pathStats.timestamps.slice(0, 100));
        }
      }

      const totalUsersOnPath = allUsersOnPaths.size;

      if (totalRequestsOnPath > 0) {
        const deepInput: ComputeSignalsInput = {
          flaggedUsers: detail.flaggedUsers,
          flaggedIPs: detail.flaggedIPs,
          eventCount: detail.eventCount,
          totalUsersOnPath,
          totalRequestsOnPath,
          pathCount: detail.pathCount,
          totalAppPaths: this.accessLogStore?.size || detail.pathCount,
          contextType: 'violation',
          contextName: detail.violationName,
          userAgents: detail.userAgents,
          botClassifications: {},
          trustScores: [],
          countries: detail.countries,
          normalCountries: mapToRecord(normalCountries),
          timestamps: detail.timestamps,
          normalTimestamps,
          accuracy: 'medium_accuracy',
          sigState: 'Enabled',
          aiConfirmed: false,
          violationRatings: [],
        };

        const deepSignals = computeAllSignals(deepInput);

        // Update detail cache
        detail.totalRequestsOnPath = totalRequestsOnPath;
        detail.totalUsersOnPath = totalUsersOnPath;
        detail.userRatio = totalUsersOnPath > 0 ? detail.flaggedUsers / totalUsersOnPath : 0;
        detail.requestRatio = totalRequestsOnPath > 0 ? detail.eventCount / totalRequestsOnPath : 0;
        detail.signals = deepSignals;
        this.violationDetailCache.set(violName, detail);

        // Update summary entry
        if (this.summary) {
          const summaryEntry = this.summary.violations.find(v => v.violationName === violName);
          if (summaryEntry) {
            summaryEntry.enrichedFpScore = deepSignals.compositeScore;
            summaryEntry.enrichedFpVerdict = deepSignals.verdict;
            summaryEntry.enrichmentStatus = 'complete';
          }
        }
      }

      this.violEnrichCompleted++;
      this.currentPhaseLabel = `Enriching violations (${this.violEnrichCompleted}/${this.violEnrichTotal})...`;
    }

    console.log(`[ProgressiveJob ${this.id}] Enriched ${this.violEnrichCompleted} violations`);
  }

  // ═══════════════════════════════════════════════════════════════
  // AUTO ENRICH ALL THREAT MESH IPs WITH ACCESS LOGS
  // ═══════════════════════════════════════════════════════════════

  private async autoEnrichThreatMeshIPs(): Promise<void> {
    const ips = this.sortedTMIPs;
    this.tmEnrichTotal = ips.length;
    this.tmEnrichCompleted = 0;
    this.currentPhaseLabel = `Enriching threat mesh IPs with access logs (0/${ips.length})...`;
    console.log(`[ProgressiveJob ${this.id}] Auto-enriching ${ips.length} threat mesh IPs with access logs`);

    // Build a single access log query for ALL threat mesh IPs using regex
    // This is more efficient than querying each IP individually
    const enrichController = new AdaptiveConcurrencyController({
      initialConcurrency: 3, minConcurrency: 1, maxConcurrency: 10, rampUpAfterSuccesses: 10,
    });

    const chunks = splitIntoChunks(this.startTime, this.endTime, CHUNK_HOURS);
    const ipSet = new Set(ips);

    // Per-IP aggregation
    const ipData = new Map<string, {
      totalRequests: number;
      pathCounts: Map<string, number>;
      rspCodes: Map<string, number>;
      methodCounts: Map<string, number>;
      timestamps: string[];
    }>();
    for (const ip of ips) {
      ipData.set(ip, { totalRequests: 0, pathCounts: new Map(), rspCodes: new Map(), methodCounts: new Map(), timestamps: [] });
    }

    // Build IP regex for query — e.g. src_ip=~"1.2.3.4|5.6.7.8"
    // If too many IPs, batch them
    const MAX_IPS_PER_QUERY = 30;
    const ipBatches: string[][] = [];
    for (let i = 0; i < ips.length; i += MAX_IPS_PER_QUERY) {
      ipBatches.push(ips.slice(i, i + MAX_IPS_PER_QUERY));
    }

    for (const ipBatch of ipBatches) {
      if (this.cancelled) return;

      const ipRegex = ipBatch.map(ip => ip.replace(/\./g, '\\\\.')).join('|');
      const query = ipBatch.length === 1
        ? `{vh_name="ves-io-http-loadbalancer-${this.config.lbName}", src_ip="${ipBatch[0]}"}`
        : `{vh_name="ves-io-http-loadbalancer-${this.config.lbName}", src_ip=~"${ipRegex}"}`;

      const tasks = chunks.map((chunk, idx) => ({
        id: idx,
        execute: async (): Promise<number> => {
          const chunkLogs: unknown[] = [];
          try {
            const initial = await this.api.fetchAccessLogsPage(
              this.config.namespace, query, chunk.start, chunk.end, PAGE_SIZE,
            );
            if (initial.logs) chunkLogs.push(...initial.logs);
            let scrollId = initial.scroll_id;
            while (scrollId) {
              try {
                const page = await this.api.scrollAccessLogs(this.config.namespace, scrollId);
                if (!page.logs || page.logs.length === 0) break;
                chunkLogs.push(...page.logs);
                scrollId = page.scroll_id;
              } catch { break; }
            }
          } catch {
            // Skip failed chunks
          }

          const normalized = normalizeEntries<RawEvent>(chunkLogs, `tm-auto-enrich-${chunk.label}`);
          for (const log of normalized) {
            const logIp = getStr(log, 'src_ip');
            if (!logIp || !ipSet.has(logIp)) continue;
            const data = ipData.get(logIp)!;
            data.totalRequests++;
            const p = getStr(log, 'req_path') || '/';
            data.pathCounts.set(p, (data.pathCounts.get(p) || 0) + 1);
            const rsp = getStr(log, 'rsp_code') || '0';
            data.rspCodes.set(rsp, (data.rspCodes.get(rsp) || 0) + 1);
            const m = getStr(log, 'method') || 'GET';
            data.methodCounts.set(m, (data.methodCounts.get(m) || 0) + 1);
            data.timestamps.push(getStr(log, '@timestamp') || getStr(log, 'time') || '');
          }
          return normalized.length;
        },
      }));

      await runAdaptivePool(tasks, enrichController, () => {}, undefined, () => this.cancelled);
    }

    if (this.cancelled) return;

    // Apply enrichment to each IP's detail + update summary
    const timeSpanMs = new Date(this.endTime).getTime() - new Date(this.startTime).getTime();
    const timeSpanHours = timeSpanMs / (1000 * 60 * 60);

    for (const ip of ips) {
      const data = ipData.get(ip)!;
      const detail = this.tmDetailCache.get(ip);
      if (!detail) continue;

      const successCount = data.rspCodes.get('200') || 0;
      const successRate = data.totalRequests > 0 ? successCount / data.totalRequests : 0;
      const avgReqPerHour = timeSpanHours > 0 ? data.totalRequests / timeSpanHours : 0;

      // Adjust scoring
      let adjustedScore = detail.fpScore;
      const updatedReasons = [...detail.reasons];

      if (data.totalRequests > 0) {
        if (successRate > 0.8) {
          adjustedScore += 15;
          updatedReasons.push(`Access logs: ${(successRate * 100).toFixed(0)}% of ${data.totalRequests} requests got 200 OK — normal browsing`);
        } else if (successRate < 0.3) {
          adjustedScore -= 10;
          updatedReasons.push(`Access logs: only ${(successRate * 100).toFixed(0)}% success rate — mostly errors/blocks`);
        }
        if (avgReqPerHour > 100) {
          adjustedScore -= 5;
          updatedReasons.push(`Access logs: ${avgReqPerHour.toFixed(0)} req/hour — possible automation`);
        } else if (data.totalRequests > 0 && avgReqPerHour < 10) {
          adjustedScore += 5;
          updatedReasons.push(`Access logs: ${avgReqPerHour.toFixed(1)} req/hour — low traffic, unlikely bot`);
        }
      } else {
        updatedReasons.push('Access logs: no access log activity found for this IP');
      }

      adjustedScore = Math.max(0, Math.min(100, adjustedScore));
      const updatedVerdict = tmScoreToVerdict(adjustedScore);

      // Update detail cache
      detail.fpScore = adjustedScore;
      detail.verdict = updatedVerdict;
      detail.reasons = updatedReasons;
      detail.totalRequestsOnApp = data.totalRequests;
      detail.pathsAccessed = mapToRecord(data.pathCounts);
      detail.rspCodes = mapToRecord(data.rspCodes);
      this.tmDetailCache.set(ip, detail);

      // Update summary entry
      if (this.summary) {
        const summaryEntry = this.summary.threatMeshIPs.find(t => t.srcIp === ip);
        if (summaryEntry) {
          summaryEntry.accessLogRequests = data.totalRequests;
          summaryEntry.successRate = successRate;
          summaryEntry.avgReqPerHour = avgReqPerHour;
          summaryEntry.enrichedVerdict = updatedVerdict;
          summaryEntry.enrichedScore = adjustedScore;
        }
      }

      this.tmEnrichCompleted++;
      this.currentPhaseLabel = `Enriching threat mesh IPs with access logs (${this.tmEnrichCompleted}/${this.tmEnrichTotal})...`;
    }

    this.currentPhaseLabel = `Enrichment complete — ${ips.length} IPs analyzed`;
    console.log(`[ProgressiveJob ${this.id}] Auto-enrichment complete for ${ips.length} threat mesh IPs`);
  }

  // ═══════════════════════════════════════════════════════════════
  // THREAT MESH ACCESS LOG ENRICHMENT (on-demand, single IP)
  // ═══════════════════════════════════════════════════════════════

  async enrichThreatMeshIP(srcIp: string): Promise<ThreatMeshEnrichmentResult | null> {
    const detail = this.tmDetailCache.get(srcIp) || this.computeThreatMeshDetail(srcIp);
    if (!detail) return null;

    const enrichController = new AdaptiveConcurrencyController({
      initialConcurrency: 3, minConcurrency: 1, maxConcurrency: 10, rampUpAfterSuccesses: 10,
    });

    // Query access logs for this specific IP
    const query = `{vh_name="ves-io-http-loadbalancer-${this.config.lbName}", src_ip="${srcIp}"}`;
    const chunks = splitIntoChunks(this.startTime, this.endTime, CHUNK_HOURS);

    const pathCounts = new Map<string, number>();
    const rspCodes = new Map<string, number>();
    const methodCounts = new Map<string, number>();
    const allTimestamps: string[] = [];
    let totalRequests = 0;

    const tasks = chunks.map((chunk, idx) => ({
      id: idx,
      execute: async (): Promise<number> => {
        const chunkLogs: unknown[] = [];
        const initial = await this.api.fetchAccessLogsPage(
          this.config.namespace, query, chunk.start, chunk.end, PAGE_SIZE,
        );
        if (initial.logs) chunkLogs.push(...initial.logs);
        let scrollId = initial.scroll_id;
        while (scrollId) {
          try {
            const page = await this.api.scrollAccessLogs(this.config.namespace, scrollId);
            if (!page.logs || page.logs.length === 0) break;
            chunkLogs.push(...page.logs);
            scrollId = page.scroll_id;
          } catch { break; }
        }

        const normalized = normalizeEntries<RawEvent>(chunkLogs, `tm-enrich-${chunk.label}`);
        for (const log of normalized) {
          totalRequests++;
          const p = getStr(log, 'req_path') || '/';
          pathCounts.set(p, (pathCounts.get(p) || 0) + 1);
          const rsp = getStr(log, 'rsp_code') || '0';
          rspCodes.set(rsp, (rspCodes.get(rsp) || 0) + 1);
          const m = getStr(log, 'method') || 'GET';
          methodCounts.set(m, (methodCounts.get(m) || 0) + 1);
          allTimestamps.push(getStr(log, '@timestamp') || getStr(log, 'time') || '');
        }
        return normalized.length;
      },
    }));

    await runAdaptivePool(tasks, enrichController, () => {}, undefined, () => this.cancelled);

    // Compute behavioral signals
    const successCount = rspCodes.get('200') || 0;
    const successRate = totalRequests > 0 ? successCount / totalRequests : 0;
    const timeSpanMs = new Date(this.endTime).getTime() - new Date(this.startTime).getTime();
    const timeSpanHours = timeSpanMs / (1000 * 60 * 60);
    const avgReqPerHour = timeSpanHours > 0 ? totalRequests / timeSpanHours : 0;

    // Adjust scoring based on access log behavior
    let adjustedScore = detail.fpScore;
    const updatedReasons = [...detail.reasons];

    if (totalRequests > 0) {
      if (successRate > 0.8) {
        adjustedScore += 15;
        updatedReasons.push(`${(successRate * 100).toFixed(0)}% of ${totalRequests} requests got 200 OK — normal browsing behavior`);
      } else if (successRate < 0.3) {
        adjustedScore -= 10;
        updatedReasons.push(`Only ${(successRate * 100).toFixed(0)}% success rate — mostly errors/blocks`);
      }
      if (avgReqPerHour > 100) {
        adjustedScore -= 5;
        updatedReasons.push(`High request rate: ${avgReqPerHour.toFixed(0)} req/hour — possible automation`);
      }
    } else {
      updatedReasons.push('No access log activity found for this IP');
    }

    adjustedScore = Math.max(0, Math.min(100, adjustedScore));
    const updatedVerdict = tmScoreToVerdict(adjustedScore);

    // Update cached detail
    detail.fpScore = adjustedScore;
    detail.verdict = updatedVerdict;
    detail.reasons = updatedReasons;
    detail.totalRequestsOnApp = totalRequests;
    this.tmDetailCache.set(srcIp, detail);

    return {
      enriched: true,
      totalAccessLogRequests: totalRequests,
      successRate,
      rspCodeBreakdown: mapToRecord(rspCodes),
      pathsAccessed: mapToRecord(pathCounts),
      methodBreakdown: mapToRecord(methodCounts),
      timeSpanHours,
      avgRequestsPerHour: avgReqPerHour,
      updatedVerdict,
      updatedScore: adjustedScore,
      updatedReasons,
    };
  }

  // ═══════════════════════════════════════════════════════════════
  // PHASE 2: OPTIONAL ACCESS LOG ENRICHMENT (per-signature)
  // ═══════════════════════════════════════════════════════════════

  async enrichSignature(sigId: string, paths: string[]): Promise<EnrichmentResult | null> {
    const detail = this.detailCache.get(sigId);
    if (!detail) return null;

    const enrichController = new AdaptiveConcurrencyController({
      initialConcurrency: 3,
      minConcurrency: 1,
      maxConcurrency: 10,
      rampUpAfterSuccesses: 10,
    });

    // Build query for specific paths
    const query = `{vh_name="ves-io-http-loadbalancer-${this.config.lbName}"}`;
    const chunks = splitIntoChunks(this.startTime, this.endTime, CHUNK_HOURS);
    const pathSet = new Set(paths.map(p => p.replace(/\*$/, '')));

    // Accumulate per-path stats
    const pathStats = new Map<string, { totalRequests: number; totalUsers: Set<string>; flaggedRequests: number; flaggedUsers: Set<string> }>();

    const tasks = chunks.map((chunk, idx) => ({
      id: idx,
      execute: async (): Promise<number> => {
        const chunkLogs: unknown[] = [];
        const initial = await this.api.fetchAccessLogsPage(
          this.config.namespace, query, chunk.start, chunk.end, PAGE_SIZE,
        );
        if (initial.logs) chunkLogs.push(...initial.logs);

        let scrollId = initial.scroll_id;
        while (scrollId) {
          try {
            const page = await this.api.scrollAccessLogs(this.config.namespace, scrollId);
            if (!page.logs || page.logs.length === 0) break;
            chunkLogs.push(...page.logs);
            scrollId = page.scroll_id;
          } catch { break; }
        }

        const normalized = normalizeEntries<RawEvent>(chunkLogs, `enrich-${chunk.label}`);
        let counted = 0;

        for (const log of normalized) {
          const p = getStr(log, 'req_path') || '/';
          // Match against target paths (prefix match)
          const matches = paths.some(target => {
            const prefix = target.replace(/\*$/, '');
            return p === target || p.startsWith(prefix);
          });
          if (!matches) continue;

          if (!pathStats.has(p)) {
            pathStats.set(p, { totalRequests: 0, totalUsers: new Set(), flaggedRequests: 0, flaggedUsers: new Set() });
          }
          const stats = pathStats.get(p)!;
          stats.totalRequests++;
          const user = getStr(log, 'user') || getStr(log, 'src_ip');
          stats.totalUsers.add(user);

          // Check if this request was flagged
          const secEvents = log.sec_event_name || log.waf_action;
          if (secEvents) {
            stats.flaggedRequests++;
            stats.flaggedUsers.add(user);
          }

          counted++;
        }

        return counted;
      },
    }));

    await runAdaptivePool(
      tasks,
      enrichController,
      () => { /* progress not critical for enrichment */ },
      undefined,
      () => this.cancelled,
    );

    // Build serializable result
    const pathStatsResult: Record<string, { totalRequests: number; totalUsers: number; flaggedRequests: number; flaggedUsers: number }> = {};
    let totalReqOnPaths = 0;
    let totalUsersOnPaths = 0;

    for (const [path, stats] of pathStats) {
      pathStatsResult[path] = {
        totalRequests: stats.totalRequests,
        totalUsers: stats.totalUsers.size,
        flaggedRequests: stats.flaggedRequests,
        flaggedUsers: stats.flaggedUsers.size,
      };
      totalReqOnPaths += stats.totalRequests;
      totalUsersOnPaths = Math.max(totalUsersOnPaths, stats.totalUsers.size);
    }

    // Update detail with enrichment data
    detail.totalRequestsOnPath = totalReqOnPaths;
    detail.totalUsersOnPath = totalUsersOnPaths;
    detail.userRatio = totalUsersOnPaths > 0 ? detail.flaggedUsers / totalUsersOnPaths : 0;
    detail.requestRatio = totalReqOnPaths > 0 ? detail.eventCount / totalReqOnPaths : 0;
    detail.enriched = true;

    // Recompute with Deep Mode weights if we now have ratio data
    // (for now, keep the Quick Mode signals but update the ratios)

    return {
      enriched: true,
      pathStats: pathStatsResult,
      updatedSignals: detail.signals,
      updatedComposite: detail.signals.compositeScore,
      updatedVerdict: detail.signals.verdict,
    };
  }

  // ═══════════════════════════════════════════════════════════════
  // EXCLUSION GENERATION
  // ═══════════════════════════════════════════════════════════════

  generateExclusionForSignature(sigId: string): WafExclusionRule | null {
    const detail = this.detailCache.get(sigId) || this.computeSignatureDetail(sigId);
    if (!detail) return null;

    const domain = this.config.domains[0] || '';
    return generateSignatureExclusion(
      detail.signatureId,
      detail.contextType,
      detail.contextName,
      domain,
      detail.path,
      Object.keys(detail.methods),
    );
  }

  generatePolicyForConfirmedFPs(confirmedSigIds: string[]): WafExclusionPolicyObject | null {
    const rules: WafExclusionRule[] = [];
    const domain = this.config.domains[0] || '';

    for (const sigId of confirmedSigIds) {
      const detail = this.detailCache.get(sigId) || this.computeSignatureDetail(sigId);
      if (detail) {
        rules.push(generateSignatureExclusion(
          detail.signatureId,
          detail.contextType,
          detail.contextName,
          domain,
          detail.path,
          Object.keys(detail.methods),
        ));
      }
    }

    if (rules.length === 0) return null;

    return buildWafExclusionPolicy(this.config.lbName, this.config.namespace, rules);
  }

  // ═══════════════════════════════════════════════════════════════
  // HELPERS
  // ═══════════════════════════════════════════════════════════════

  private estimateRemaining(): number {
    if (this.status !== 'collecting') return 0;
    if (this.chunksCompleted === 0 || this.totalChunks === 0) return 30000;
    const elapsed = Date.now() - this.startMs;
    const msPerChunk = elapsed / this.chunksCompleted;
    const remaining = this.totalChunks - this.chunksCompleted;
    return Math.max(0, Math.round(msPerChunk * remaining));
  }

  getLogText(): string {
    return this.logger.exportAsText();
  }
}
