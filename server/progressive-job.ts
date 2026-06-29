/**
 * FP Analyzer Engine (2026 redesign) — single flow, WAF signatures + violations only.
 *
 * Flow:
 *   1. Collect WAF security events for the LB (chunked, scroll-paged, adaptive-concurrent).
 *   2. Index by signature_id / violation; collect the set of flagged client IPs.
 *   3. For the top-N flagged IPs (by event volume), pull EACH IP's own access logs and
 *      build a behavioral profile (success/404 ratio, path diversity, exploit probing,
 *      request rate, UA, WAF-event ratio) — NOT the whole LB's access logs.
 *   4. Score signatures & violations with the 7 redesigned signals (fp-signals-v2).
 *
 * Class/exports kept (ProgressiveAnalysisJob, ProgressiveJobConfig) for the plugin contract.
 */
import { NodeApiCaller } from './node-api-caller';
import { AdaptiveConcurrencyController } from '../src/services/fp-analyzer/adaptive-concurrency';
import { runAdaptivePool } from '../src/services/fp-analyzer/adaptive-worker-pool';
import { computeFpSignals, EXPLOIT_PATH_RE } from '../src/services/fp-analyzer/fp-signals-v2';
import { computeWafComparison } from '../src/services/fp-analyzer/waf-comparison';
import { buildFpRecommendations } from '../src/services/fp-analyzer/recommendations';
import { computeBotAnalysisFromAggregates, classifyBot } from '../src/services/fp-analyzer/bot-analysis';
import type { BotAggregateInput } from '../src/services/fp-analyzer/bot-analysis';
import type { BotAggBucket } from '../src/services/fp-analyzer/types';
import {
  emptyAiRiskCounts, tallyReqRisk, dominantRiskLevel, parseRiskReasons,
  isStagedState, parseEnforcementMode, estimateActualCountFromRate,
} from '../src/services/fp-analyzer/ai-signals';
import type { AiRiskCounts, AiSignalInput } from '../src/services/fp-analyzer/ai-signals';
import { computeQuickVerdict, mapToRecord } from '../src/services/fp-analyzer/signal-calculator';
import { parseContext } from '../src/services/fp-analyzer/context-parser';
import {
  generateSignatureExclusion, generateViolationExclusion, buildWafExclusionPolicy,
  buildSignatureExclusionsWithRollup,
} from '../src/services/fp-analyzer/exclusion-generator';
import type { SigExclusionIntent } from '../src/services/fp-analyzer/exclusion-generator';
import { AnalysisLogger } from '../src/services/fp-analyzer/analysis-logger';
import type {
  AnalysisScope, FPVerdict, IPBehaviorProfile, PathAnalysis,
  SignatureAnalysisUnit, ViolationAnalysisUnit, SignatureSummary, ViolationSummary,
  SummaryResult, ProgressiveJobProgress, ProgressiveJobStatus,
  WafExclusionRule, WafExclusionPolicyObject,
} from '../src/services/fp-analyzer/types';
import type { RateLimitState } from '../src/services/fp-analyzer/adaptive-concurrency';

// ═══════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════

const CHUNK_HOURS = 2;
const PAGE_SIZE = 500;
const JOB_EXPIRY_MS = 30 * 60 * 1000;
const MAX_ENRICH_IPS = 500;       // cap: enrich the top-500 flagged IPs by event volume
const IPS_PER_QUERY = 30;          // src_ip=~ regex batch size
const BOT_AGG_TOPK = 500;          // distinct malicious src_ip buckets to request
// Server-side exclusion of malicious-bot rows from the WAF/violation pull. Substring
// regex (`!~`) tolerates token variants (malicious / malicious_bot). Correctness is also
// guaranteed by an always-on client-side drop, so this is purely a bandwidth optimization.
const MALICIOUS_BOT_EXCLUDE = `bot_class!~"malicious"`;
const MALICIOUS_BOT_MATCH = `bot_class=~"malicious"`;

export interface ProgressiveJobConfig {
  tenant: string;
  token: string;
  namespace: string;
  lbName: string;
  domains: string[];
  scopes: AnalysisScope[];   // only 'waf_signatures' | 'waf_violations' are honored
  hoursBack: number;
}

interface TimeChunk { start: string; end: string; label: string; }
type RawEvent = Record<string, unknown>;

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

function splitIntoChunks(startTime: string, endTime: string, chunkHours: number): TimeChunk[] {
  const chunks: TimeChunk[] = [];
  const start = new Date(startTime).getTime();
  const end = new Date(endTime).getTime();
  const chunkMs = chunkHours * 3600 * 1000;
  let cursor = start;
  while (cursor < end) {
    const chunkEnd = Math.min(cursor + chunkMs, end);
    const d = new Date(cursor);
    const label = `${(d.getUTCMonth() + 1).toString().padStart(2, '0')}/${d.getUTCDate().toString().padStart(2, '0')} ${d.getUTCHours().toString().padStart(2, '0')}:00`;
    chunks.push({ start: new Date(cursor).toISOString(), end: new Date(chunkEnd).toISOString(), label });
    cursor = chunkEnd;
  }
  return chunks;
}

const F5_DATA_FIELDS = ['rsp_code', 'rsp_code_class', 'src_ip', 'vh_name', 'req_path', 'sample_rate', 'sec_event_type'];
function hasF5DataFields(obj: Record<string, unknown>): boolean {
  let m = 0;
  for (const f of F5_DATA_FIELDS) if (obj[f] !== undefined && obj[f] !== null) m++;
  return m >= 2;
}
function normalizeEntries(rawEntries: unknown[]): RawEvent[] {
  if (rawEntries.length === 0) return [];
  let entries = rawEntries;
  if (typeof entries[0] === 'string') {
    entries = entries.map(e => { try { return JSON.parse(e as string); } catch { return {}; } });
  }
  const sample = entries[0] as Record<string, unknown>;
  if (hasF5DataFields(sample)) return entries as RawEvent[];
  const WRAPPERS = ['_source', 'attributes', 'data', 'log', 'fields', 'record', 'event', 'message'];
  for (const key of WRAPPERS) {
    const v = sample[key];
    if (v && typeof v === 'object' && !Array.isArray(v) && hasF5DataFields(v as Record<string, unknown>)) {
      return entries.map(e => (e as Record<string, unknown>)[key] as RawEvent);
    }
  }
  return entries as RawEvent[];
}

function getStr(e: RawEvent, key: string): string { return (e[key] as string) || ''; }
function getNum(e: RawEvent, key: string): number {
  const v = e[key];
  if (typeof v === 'number') return v;
  if (typeof v === 'string') return parseInt(v, 10) || 0;
  return 0;
}
function parseTotalHits(raw: unknown): number {
  if (typeof raw === 'number' && isFinite(raw)) return Math.floor(raw);
  if (typeof raw === 'string') return parseInt(raw, 10) || 0;
  if (raw && typeof raw === 'object' && 'value' in (raw as Record<string, unknown>)) {
    return parseInt(String((raw as Record<string, unknown>).value), 10) || 0;
  }
  return 0;
}
function dominantAction(map: Map<string, number>): string {
  const sev: Record<string, number> = { block: 3, report: 2, allow: 1 };
  let best = '', bestCount = 0, bestSev = -1;
  for (const [k, v] of map) {
    const s = sev[k.toLowerCase()] ?? 0;
    if (v > bestCount || (v === bestCount && s > bestSev)) { best = k; bestCount = v; bestSev = s; }
  }
  return best;
}
function topEntry(map: Map<string, number>): string {
  let best = '', max = 0;
  for (const [k, v] of map) if (v > max) { max = v; best = k; }
  return best;
}

interface ParsedSig { id: string; name: string; accuracy: string; attackType: string; context: string; contextName: string; contextType: string; matchingInfo: string; state: string; }
function getSignatures(e: RawEvent): ParsedSig[] {
  const sigs = e.signatures as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(sigs)) return [];
  return sigs.map(s => ({
    id: String(s.id || ''), name: String(s.name || ''), accuracy: String(s.accuracy || 'medium_accuracy'),
    attackType: String(s.attack_type || ''), context: String(s.context || ''), contextName: String(s.context_name || ''),
    contextType: String(s.context_type || ''), matchingInfo: String(s.matching_info || ''), state: String(s.state || ''),
  }));
}
function normalizeSigContext(sig: ParsedSig): { contextType: string; contextName: string } {
  if (sig.contextType && sig.contextType.startsWith('CONTEXT_')) return { contextType: sig.contextType, contextName: sig.contextName || '' };
  const parsed = parseContext(sig.context || sig.contextType || '');
  return { contextType: parsed.contextType, contextName: sig.contextName || parsed.contextName };
}
interface ParsedViol { name: string; attackType: string; state: string; matchingInfo?: string; }
function getViolations(e: RawEvent): ParsedViol[] {
  const viols = e.violations as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(viols)) return [];
  return viols.map(v => ({ name: String(v.name || ''), attackType: String(v.attack_type || ''), state: String(v.state || ''), matchingInfo: v.matching_info ? String(v.matching_info) : undefined }));
}
function isWafEvent(e: RawEvent): boolean {
  const name = getStr(e, 'sec_event_name').toLowerCase();
  if (name === 'waf') return true;
  if (name) return false;
  return getStr(e, 'sec_event_type') === 'waf_sec_event' || Array.isArray(e.signatures) || Array.isArray(e.violations);
}

// Build an AiSignalInput from accumulated AI tallies.
function aiInputFrom(riskCounts: AiRiskCounts, reasons: string[], recommendedAction: string): AiSignalInput {
  return { riskCounts, reasonVerdict: parseRiskReasons(reasons), recommendedAction };
}

// ═══════════════════════════════════════════════════════════════
// ENGINE
// ═══════════════════════════════════════════════════════════════

export class ProgressiveAnalysisJob {
  private id: string;
  private config: ProgressiveJobConfig;
  private api: NodeApiCaller;
  private logger: AnalysisLogger;
  private controller: AdaptiveConcurrencyController;

  private createdAt = Date.now();
  private startMs = Date.now();
  private cancelled = false;

  // progress
  private status: ProgressiveJobStatus = 'collecting';
  private securityEventsCollected = 0;
  private securityEventsExpected = 0;
  private dataPartial = false;
  private signaturesFound = 0;
  private violationsFound = 0;
  private totalChunks = 0;
  private chunksCompleted = 0;
  private currentPhaseLabel = 'Initializing...';
  private error?: string;
  private adaptiveState: RateLimitState = 'green';
  private adaptiveConcurrency = 3;
  private ipEnrichTotal = 0;
  private ipEnrichCompleted = 0;

  // data
  private allSecurityEvents: RawEvent[] = [];
  private botAggregates: BotAggregateInput | null = null;
  private maliciousDroppedClientSide = 0;
  private serverBotFilterUsed = false;
  private secEventsBySignature = new Map<string, RawEvent[]>();
  private secEventsByViolation = new Map<string, RawEvent[]>();
  private flaggedIpEventCount = new Map<string, number>();
  private ipBehavior = new Map<string, IPBehaviorProfile>();
  private flaggedPathEventCount = new Map<string, number>();
  private pathBehavior = new Map<string, { totalUsers: number; totalRequests: number }>();
  private totalDistinctPaths = 0;
  private enforcementMode = '';

  private summary: SummaryResult | null = null;
  private detailCache = new Map<string, SignatureAnalysisUnit>();
  private violationDetailCache = new Map<string, ViolationAnalysisUnit>();
  private sortedSigIds: string[] = [];

  private startTime = '';
  private endTime = '';
  private wafPolicyName?: string;

  constructor(id: string, config: ProgressiveJobConfig) {
    this.id = id;
    this.config = config;
    this.api = new NodeApiCaller({ tenant: config.tenant, token: config.token });
    this.logger = new AnalysisLogger();
    this.controller = new AdaptiveConcurrencyController({ initialConcurrency: 3, minConcurrency: 1, maxConcurrency: 8, rampUpAfterSuccesses: 10 });
  }

  isExpired(): boolean { return Date.now() - this.createdAt > JOB_EXPIRY_MS; }
  cancel(): void { this.cancelled = true; this.status = 'cancelled'; }
  getStatus(): ProgressiveJobStatus { return this.status; }
  getSummary(): SummaryResult | null { return this.summary; }
  getLogText(): string { return this.logger.exportAsText(); }

  getProgress(): ProgressiveJobProgress {
    return {
      status: this.status,
      securityEventsCollected: this.securityEventsCollected,
      securityEventsExpected: this.securityEventsExpected || undefined,
      dataPartial: this.dataPartial || undefined,
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
      ipEnrichTotal: this.ipEnrichTotal || undefined,
      ipEnrichCompleted: this.ipEnrichCompleted || undefined,
    };
  }

  // ── Main flow ──
  async run(): Promise<void> {
    this.startMs = Date.now();
    const now = new Date();
    this.endTime = now.toISOString();
    this.startTime = new Date(now.getTime() - this.config.hoursBack * 3600 * 1000).toISOString();
    this.logger.reset();
    console.log(`[FP ${this.id}] start ns=${this.config.namespace} lb=${this.config.lbName} hours=${this.config.hoursBack}`);

    try {
      this.status = 'collecting';
      this.currentPhaseLabel = 'Fetching WAF security events...';
      this.allSecurityEvents = await this.collectWafEvents();
      if (this.cancelled) return;

      this.currentPhaseLabel = 'Aggregating malicious-bot classification...';
      await this.collectMaliciousBotAggregates();
      if (this.cancelled) return;

      this.currentPhaseLabel = 'Indexing events...';
      this.indexEvents();

      this.currentPhaseLabel = 'Detecting WAF configuration...';
      await this.detectWafConfig();

      if (!this.cancelled) {
        this.status = 'enriching';
        this.currentPhaseLabel = 'Pulling per-IP client traffic...';
        await this.collectFlaggedIpBehavior();
      }
      if (this.cancelled) return;

      if (!this.cancelled) {
        this.currentPhaseLabel = 'Pulling per-path traffic (user breadth)...';
        await this.collectFlaggedPathBehavior();
      }
      if (this.cancelled) return;

      this.currentPhaseLabel = 'Scoring signatures & violations...';
      this.summary = this.buildSummary();

      if (!this.cancelled) { this.status = 'complete'; this.currentPhaseLabel = 'Analysis complete'; }
      console.log(`[FP ${this.id}] done in ${((Date.now() - this.startMs) / 1000).toFixed(1)}s: ${this.signaturesFound} sigs, ${this.violationsFound} viols, ${this.ipBehavior.size} IPs enriched`);
    } catch (err) {
      this.status = 'error';
      this.error = err instanceof Error ? err.message : String(err);
      console.error(`[FP ${this.id}] error: ${this.error}`);
    }
  }

  private get vhName(): string { return `ves-io-http-loadbalancer-${this.config.lbName}`; }

  /**
   * Probe whether the API accepts the malicious-bot exclusion filter on this tenant.
   * If the field/operator is unsupported the call errors → we fall back to a client-side
   * drop (correct, just no bandwidth saving). A success means we can exclude server-side.
   */
  private async probeServerBotFilter(): Promise<boolean> {
    const q = `{vh_name="${this.vhName}", sec_event_name="WAF", ${MALICIOUS_BOT_EXCLUDE}}`;
    try {
      await this.api.fetchSecurityEventsPage(this.config.namespace, q, this.startTime, this.endTime, 1);
      return true;
    } catch (e) {
      console.warn(`[FP ${this.id}] server-side bot_class filter unsupported — using client-side drop. (${e instanceof Error ? e.message : String(e)})`);
      return false;
    }
  }

  // ── Phase 1: collect WAF events (malicious bots excluded) ──
  private async collectWafEvents(): Promise<RawEvent[]> {
    const useServerFilter = await this.probeServerBotFilter();
    this.serverBotFilterUsed = useServerFilter;
    const query = useServerFilter
      ? `{vh_name="${this.vhName}", sec_event_name="WAF", ${MALICIOUS_BOT_EXCLUDE}}`
      : `{vh_name="${this.vhName}", sec_event_name="WAF"}`;
    const chunks = splitIntoChunks(this.startTime, this.endTime, CHUNK_HOURS);
    this.totalChunks = chunks.length;
    this.chunksCompleted = 0;

    const allEvents: RawEvent[] = [];
    let expectedHits = 0;
    let anyScrollBroke = false;

    const tasks = chunks.map((chunk, idx) => ({
      id: idx,
      execute: async (): Promise<{ events: RawEvent[]; totalHits: number; scrollBroke: boolean }> => {
        const raw: unknown[] = [];
        let scrollBroke = false;
        const initial = await this.api.fetchSecurityEventsPage(this.config.namespace, query, chunk.start, chunk.end, PAGE_SIZE);
        const totalHits = parseTotalHits(initial.total_hits);
        if (initial.events) raw.push(...initial.events);
        let scrollId = initial.scroll_id;
        while (scrollId) {
          try {
            const page = await this.api.scrollSecurityEvents(this.config.namespace, scrollId);
            if (!page.events || page.events.length === 0) break;
            raw.push(...page.events);
            scrollId = page.scroll_id;
          } catch { scrollBroke = true; break; }
        }
        return { events: normalizeEntries(raw), totalHits, scrollBroke };
      },
    }));

    await runAdaptivePool(tasks, this.controller, (r) => {
      if (r.result) {
        allEvents.push(...r.result.events);
        expectedHits += r.result.totalHits;
        if (r.result.scrollBroke) anyScrollBroke = true;
        this.chunksCompleted++;
        this.securityEventsCollected = allEvents.length;
        this.adaptiveState = this.controller.getState();
        this.adaptiveConcurrency = this.controller.concurrency;
        this.currentPhaseLabel = `Downloading WAF events (${this.chunksCompleted}/${this.totalChunks} chunks)...`;
      }
    }, undefined, () => this.cancelled);

    const expectedVh = this.vhName;
    const scoped = allEvents.filter(e => { const vh = getStr(e, 'vh_name'); return !vh || vh === expectedVh; }).filter(isWafEvent);
    // Always-on safety net: drop Malicious-classified rows even if the server-side filter
    // was absent or silently ignored, so they never pollute FP scoring. No-op when the
    // server already excluded them.
    const filtered = scoped.filter(e => classifyBot((e.bot_info as Record<string, unknown> | undefined)?.classification) !== 'malicious');
    this.maliciousDroppedClientSide = scoped.length - filtered.length;
    if (this.maliciousDroppedClientSide > 0) console.log(`[FP ${this.id}] dropped ${this.maliciousDroppedClientSide} malicious-bot events client-side (serverFilter=${this.serverBotFilterUsed})`);
    this.securityEventsCollected = filtered.length;
    this.securityEventsExpected = expectedHits;
    this.dataPartial = !this.cancelled && ((this.totalChunks - this.chunksCompleted) > 0 || anyScrollBroke);
    if (this.dataPartial) console.warn(`[FP ${this.id}] PARTIAL: ${this.totalChunks - this.chunksCompleted} chunk(s) failed, scrollBroke=${anyScrollBroke}`);
    return filtered;
  }

  /** One terms aggregation over the security events; returns sorted buckets (or [] on error). */
  private async aggField(query: string, field: string, topk: number): Promise<BotAggBucket[]> {
    const key = `${field.replace(/\./g, '_')}_agg`;
    try {
      const resp = await this.api.fetchSecurityEventsAggregation(this.config.namespace, query, this.startTime, this.endTime, { [key]: { field, topk } });
      const bucket = (resp.aggs as Record<string, unknown> | undefined)?.[key] as { buckets?: unknown[] } | undefined;
      const out: BotAggBucket[] = [];
      for (const b of bucket?.buckets ?? []) {
        const o = b as Record<string, unknown>;
        const k = o.key ?? o.value ?? '';
        const count = Number(o.count ?? o.doc_count ?? 0);
        if (k !== '' && k != null) out.push({ key: String(k), count });
      }
      return out.sort((a, b) => b.count - a.count);
    } catch (e) {
      console.warn(`[FP ${this.id}] agg ${field} failed: ${e instanceof Error ? e.message : String(e)}`);
      return [];
    }
  }

  /**
   * Bot-classification track — SERVER-SIDE AGGREGATION ONLY (no raw malicious rows).
   * One distribution agg over all WAF events for the classification counts, plus
   * Malicious-only terms aggs (src_ip / bot_name / user_agent / country).
   */
  private async collectMaliciousBotAggregates(): Promise<void> {
    const allWaf = `{vh_name="${this.vhName}", sec_event_name="WAF"}`;
    const malicious = `{vh_name="${this.vhName}", sec_event_name="WAF", ${MALICIOUS_BOT_MATCH}}`;
    const [classDistribution, byIp, byBotName, byUserAgent, byCountry] = await Promise.all([
      this.aggField(allWaf, 'bot_class', 16),
      this.aggField(malicious, 'src_ip', BOT_AGG_TOPK),
      this.aggField(malicious, 'bot_name', 50),
      this.aggField(malicious, 'user_agent', 50),
      this.aggField(malicious, 'country', 30),
    ]);
    this.botAggregates = { classDistribution, byIp, byBotName, byUserAgent, byCountry, ipTopk: BOT_AGG_TOPK };
  }

  // ── Phase 2: index + collect flagged IPs + distinct paths ──
  private indexEvents(): void {
    const scopes = this.config.scopes;
    const wantSig = scopes.includes('waf_signatures');
    const wantViol = scopes.includes('waf_violations');
    const distinctPaths = new Set<string>();

    for (const event of this.allSecurityEvents) {
      const evPath = getStr(event, 'req_path') || '/';
      distinctPaths.add(evPath);
      this.flaggedPathEventCount.set(evPath, (this.flaggedPathEventCount.get(evPath) || 0) + 1);
      if (!this.enforcementMode) { const em = getStr(event, 'enforcement_mode'); if (em) this.enforcementMode = em; }

      const ip = getStr(event, 'src_ip');
      if (ip) this.flaggedIpEventCount.set(ip, (this.flaggedIpEventCount.get(ip) || 0) + 1);

      if (wantSig) {
        for (const sig of getSignatures(event)) {
          if (!sig.id) continue;
          if (!this.secEventsBySignature.has(sig.id)) this.secEventsBySignature.set(sig.id, []);
          this.secEventsBySignature.get(sig.id)!.push(event);
        }
      }
      if (wantViol) {
        for (const viol of getViolations(event)) {
          if (!viol.name) continue;
          if (!this.secEventsByViolation.has(viol.name)) this.secEventsByViolation.set(viol.name, []);
          this.secEventsByViolation.get(viol.name)!.push(event);
        }
      }
    }
    this.totalDistinctPaths = distinctPaths.size;
    this.signaturesFound = this.secEventsBySignature.size;
    this.violationsFound = this.secEventsByViolation.size;
  }

  private async detectWafConfig(): Promise<void> {
    try {
      const lb = await this.api.getLBConfig(this.config.namespace, this.config.lbName);
      const spec = lb.spec as Record<string, unknown> | undefined;
      if (spec?.app_firewall) this.wafPolicyName = ((spec.app_firewall as Record<string, unknown>).name as string) || undefined;
    } catch { /* non-critical */ }
  }

  // ── Phase 3: per-IP behavioral enrichment (top-N flagged IPs) ──
  private async collectFlaggedIpBehavior(): Promise<void> {
    const ips = [...this.flaggedIpEventCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_ENRICH_IPS).map(([ip]) => ip);
    if (ips.length === 0) return;
    this.ipEnrichTotal = ips.length;
    this.ipEnrichCompleted = 0;

    const ipSet = new Set(ips);
    interface Acc { rspCodes: Map<string, number>; paths: Set<string>; ua: Map<string, number>; total: number; srSum: number; srCount: number; country: string; asOrg: string; timestamps: string[]; }
    const acc = new Map<string, Acc>();
    for (const ip of ips) acc.set(ip, { rspCodes: new Map(), paths: new Set(), ua: new Map(), total: 0, srSum: 0, srCount: 0, country: '', asOrg: '', timestamps: [] });

    const chunks = splitIntoChunks(this.startTime, this.endTime, CHUNK_HOURS);
    const controller = new AdaptiveConcurrencyController({ initialConcurrency: 3, minConcurrency: 1, maxConcurrency: 10, rampUpAfterSuccesses: 10 });

    const batches: string[][] = [];
    for (let i = 0; i < ips.length; i += IPS_PER_QUERY) batches.push(ips.slice(i, i + IPS_PER_QUERY));

    for (const batch of batches) {
      if (this.cancelled) return;
      const ipRegex = batch.map(ip => ip.replace(/\./g, '\\.')).join('|');
      const query = batch.length === 1
        ? `{vh_name="ves-io-http-loadbalancer-${this.config.lbName}", src_ip="${batch[0]}"}`
        : `{vh_name="ves-io-http-loadbalancer-${this.config.lbName}", src_ip=~"${ipRegex}"}`;

      const tasks = chunks.map((chunk, idx) => ({
        id: idx,
        execute: async (): Promise<number> => {
          const raw: unknown[] = [];
          try {
            const initial = await this.api.fetchAccessLogsPage(this.config.namespace, query, chunk.start, chunk.end, PAGE_SIZE);
            if (initial.logs) raw.push(...initial.logs);
            let scrollId = initial.scroll_id;
            while (scrollId) {
              try {
                const page = await this.api.scrollAccessLogs(this.config.namespace, scrollId);
                if (!page.logs || page.logs.length === 0) break;
                raw.push(...page.logs);
                scrollId = page.scroll_id;
              } catch { break; }
            }
          } catch { /* skip failed chunk */ }
          for (const log of normalizeEntries(raw)) {
            const ip = getStr(log, 'src_ip');
            if (!ip || !ipSet.has(ip)) continue;
            const a = acc.get(ip)!;
            a.total++;
            const code = getStr(log, 'rsp_code') || '0';
            a.rspCodes.set(code, (a.rspCodes.get(code) || 0) + 1);
            a.paths.add(getStr(log, 'req_path') || '/');
            const ua = getStr(log, 'user_agent') || getStr(log, 'browser_type') || 'unknown';
            a.ua.set(ua, (a.ua.get(ua) || 0) + 1);
            const sr = getNum(log, 'sample_rate');
            if (sr > 0) { a.srSum += sr; a.srCount++; }
            if (!a.country) a.country = getStr(log, 'country');
            if (!a.asOrg) a.asOrg = getStr(log, 'as_org') || getStr(log, 'asn');
            if (a.timestamps.length < 200) a.timestamps.push(getStr(log, '@timestamp') || getStr(log, 'time') || '');
          }
          return raw.length;
        },
      }));
      await runAdaptivePool(tasks, controller, () => {}, undefined, () => this.cancelled);
      this.ipEnrichCompleted = Math.min(this.ipEnrichTotal, this.ipEnrichCompleted + batch.length);
      this.currentPhaseLabel = `Analyzing client traffic (${this.ipEnrichCompleted}/${this.ipEnrichTotal} IPs)...`;
    }

    const spanHrs = Math.max(1 / 60, (new Date(this.endTime).getTime() - new Date(this.startTime).getTime()) / 3600000);
    for (const [ip, a] of acc) {
      const avgRate = a.srCount > 0 ? Math.max(1, a.srSum / a.srCount) : 1;
      const total = estimateActualCountFromRate(a.total, avgRate);
      let c2xx = 0, c404 = 0, c4xx = 0, c5xx = 0;
      for (const [code, n] of a.rspCodes) {
        const cc = parseInt(code, 10);
        if (cc >= 200 && cc < 300) c2xx += n; else if (cc === 404) c404 += n;
        else if (cc >= 400 && cc < 500) c4xx += n; else if (cc >= 500) c5xx += n;
      }
      const rawTotal = a.total || 1;
      const exploitHits = [...a.paths].filter(p => EXPLOIT_PATH_RE.test(p)).length;
      const wafCount = this.flaggedIpEventCount.get(ip) || 0;
      this.ipBehavior.set(ip, {
        ip, enriched: a.total > 0, totalRequests: total,
        rspCodes: mapToRecord(a.rspCodes),
        successRatio: c2xx / rawTotal, notFoundRatio: c404 / rawTotal,
        clientErrorRatio: c4xx / rawTotal, serverErrorRatio: c5xx / rawTotal,
        uniquePaths: a.paths.size, exploitPathHits: exploitHits,
        reqPerHour: total / spanHrs, topUserAgent: topEntry(a.ua) || 'unknown',
        country: a.country || 'unknown', asOrg: a.asOrg || '',
        wafEventCount: wafCount,
        wafEventRatio: total > 0 ? Math.min(1, wafCount / total) : 1,
      });
    }
  }

  // ── Phase 3b: per-PATH behavior — how many distinct users use each flagged path? ──
  // This answers "does the WAF fire for OTHER users on this path, or just this client?".
  // Only enrich clean (non-payload) paths — attack-payload paths have no legit users anyway.
  private async collectFlaggedPathBehavior(): Promise<void> {
    const CLEAN_PATH = /^\/[a-zA-Z0-9/_.\-~]*$/;
    const paths = [...this.flaggedPathEventCount.entries()]
      .filter(([p]) => p && p !== '/' && CLEAN_PATH.test(p) && p.length < 200)
      .sort((a, b) => b[1] - a[1]).slice(0, MAX_ENRICH_IPS).map(([p]) => p);
    if (paths.length === 0) return;

    const pathSet = new Set(paths);
    const acc = new Map<string, { users: Set<string>; total: number; srSum: number; srCount: number }>();
    for (const p of paths) acc.set(p, { users: new Set(), total: 0, srSum: 0, srCount: 0 });

    const chunks = splitIntoChunks(this.startTime, this.endTime, CHUNK_HOURS);
    const controller = new AdaptiveConcurrencyController({ initialConcurrency: 3, minConcurrency: 1, maxConcurrency: 8, rampUpAfterSuccesses: 10 });
    const PATHS_PER_QUERY = 20;
    const batches: string[][] = [];
    for (let i = 0; i < paths.length; i += PATHS_PER_QUERY) batches.push(paths.slice(i, i + PATHS_PER_QUERY));

    for (const batch of batches) {
      if (this.cancelled) return;
      const regex = batch.map(p => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('|');
      const query = `{vh_name="ves-io-http-loadbalancer-${this.config.lbName}", req_path=~"${regex}"}`;
      const tasks = chunks.map((chunk, idx) => ({
        id: idx,
        execute: async (): Promise<number> => {
          const raw: unknown[] = [];
          try {
            const initial = await this.api.fetchAccessLogsPage(this.config.namespace, query, chunk.start, chunk.end, PAGE_SIZE);
            if (initial.logs) raw.push(...initial.logs);
            let scrollId = initial.scroll_id;
            while (scrollId) {
              try {
                const page = await this.api.scrollAccessLogs(this.config.namespace, scrollId);
                if (!page.logs || page.logs.length === 0) break;
                raw.push(...page.logs);
                scrollId = page.scroll_id;
              } catch { break; }
            }
          } catch { /* skip */ }
          for (const log of normalizeEntries(raw)) {
            const p = getStr(log, 'req_path') || '/';
            const a = acc.get(p);
            if (!a) continue;
            a.total++;
            const u = getStr(log, 'user') || getStr(log, 'src_ip');
            if (u) a.users.add(u);
            const sr = getNum(log, 'sample_rate');
            if (sr > 0) { a.srSum += sr; a.srCount++; }
          }
          return raw.length;
        },
      }));
      await runAdaptivePool(tasks, controller, () => {}, undefined, () => this.cancelled);
    }

    for (const [p, a] of acc) {
      if (a.total === 0) continue;
      const rate = a.srCount > 0 ? Math.max(1, a.srSum / a.srCount) : 1;
      this.pathBehavior.set(p, { totalUsers: a.users.size, totalRequests: estimateActualCountFromRate(a.total, rate) });
    }
    void pathSet;
  }

  // ── Aggregation helper shared by summary + detail ──
  private aggregateSignature(sigId: string, events: RawEvent[]) {
    const uniqueUsers = new Set<string>();
    const uniqueIPs = new Set<string>();
    const pathCounts = new Map<string, number>();
    const methods = new Map<string, number>();
    const rspCodes = new Map<string, number>();
    const userAgents = new Map<string, number>();
    const countries = new Map<string, number>();
    const botClassifications = new Map<string, number>();
    const matchingInfos: string[] = [];
    const violationRatings: number[] = [];
    const aiRiskCounts = emptyAiRiskCounts();
    const recommendedActions = new Map<string, number>();
    const riskReasons: string[] = [];
    let name = '', accuracy = '', attackType = '', contextType = '', contextName = '', contextRaw = '', sigState = '';
    let autoSuppressed = false, staged = false, block = 0, report = 0;

    for (const e of events) {
      const ip = getStr(e, 'src_ip');
      uniqueUsers.add(getStr(e, 'user') || ip);
      if (ip) uniqueIPs.add(ip);
      pathCounts.set(getStr(e, 'req_path') || '/', (pathCounts.get(getStr(e, 'req_path') || '/') || 0) + 1);
      methods.set(getStr(e, 'method') || 'GET', (methods.get(getStr(e, 'method') || 'GET') || 0) + 1);
      const rc = getStr(e, 'rsp_code') || '0'; rspCodes.set(rc, (rspCodes.get(rc) || 0) + 1);
      const ua = getStr(e, 'user_agent') || getStr(e, 'browser_type') || 'unknown'; userAgents.set(ua, (userAgents.get(ua) || 0) + 1);
      const c = getStr(e, 'country') || 'unknown'; countries.set(c, (countries.get(c) || 0) + 1);
      const bc = classifyBot((e.bot_info as Record<string, unknown> | undefined)?.classification); botClassifications.set(bc, (botClassifications.get(bc) || 0) + 1);
      if (getStr(e, 'action') === 'block') block++; else report++;
      const vr = getNum(e, 'violation_rating'); if (vr > 0) violationRatings.push(vr);
      tallyReqRisk(aiRiskCounts, e.req_risk);
      const ra = getStr(e, 'recommended_action'); if (ra) recommendedActions.set(ra, (recommendedActions.get(ra) || 0) + 1);
      const rr = e.req_risk_reasons; if (Array.isArray(rr)) riskReasons.push(...rr.map(String)); else if (rr) riskReasons.push(String(rr));
      const sig = getSignatures(e).find(s => s.id === sigId);
      if (sig) {
        if (!name) { name = sig.name; accuracy = sig.accuracy; attackType = sig.attackType; const ctx = normalizeSigContext(sig); contextType = ctx.contextType; contextName = ctx.contextName; contextRaw = sig.context; sigState = sig.state; }
        if (sig.state === 'AutoSuppressed') autoSuppressed = true;
        if (isStagedState(sig.state)) staged = true;
        if (sig.matchingInfo && matchingInfos.length < 20) matchingInfos.push(sig.matchingInfo);
      }
    }
    const reasonVerdict = parseRiskReasons(riskReasons);
    return {
      uniqueUsers, uniqueIPs, pathCounts, methods, rspCodes, userAgents, countries, botClassifications, matchingInfos, violationRatings,
      aiRiskCounts, recommendedAction: dominantAction(recommendedActions), riskReasons, reasonVerdict,
      name, accuracy, attackType, contextType, contextName, contextRaw, sigState, autoSuppressed, staged, block, report,
    };
  }

  private ipProfilesFor(ips: Iterable<string>): IPBehaviorProfile[] {
    const out: IPBehaviorProfile[] = [];
    for (const ip of ips) { const p = this.ipBehavior.get(ip); if (p) out.push(p); }
    return out;
  }

  /** Distinct users on the most-hit flagged path (for the cross-user breadth ratio). */
  private topPathUsers(pathCounts: Map<string, number>): number | undefined {
    let top = ''; let max = 0;
    for (const [p, c] of pathCounts) if (c > max) { max = c; top = p; }
    return top ? this.pathBehavior.get(top)?.totalUsers : undefined;
  }

  // ── Phase 4: build summary (final scored result) ──
  private buildSummary(): SummaryResult {
    const signatures: SignatureSummary[] = [];
    const violations: ViolationSummary[] = [];

    if (this.config.scopes.includes('waf_signatures')) {
      for (const [sigId, events] of this.secEventsBySignature) {
        const a = this.aggregateSignature(sigId, events);
        const ipProfiles = this.ipProfilesFor(a.uniqueIPs);
        const signals = computeFpSignals({
          distinctIPs: a.uniqueIPs.size, distinctUsers: a.uniqueUsers.size,
          pathCount: a.pathCounts.size, totalAppPaths: this.totalDistinctPaths || a.pathCounts.size, pathTotalUsers: this.topPathUsers(a.pathCounts),
          contextType: a.contextType, contextName: a.contextName,
          sampleMatchingInfos: a.matchingInfos, rspCodes: mapToRecord(a.rspCodes), ipProfiles,
          accuracy: a.accuracy, sigState: a.sigState, aiConfirmed: a.reasonVerdict.aiConfirmedAttack,
          violationRatings: a.violationRatings, aiInput: aiInputFrom(a.aiRiskCounts, a.riskReasons, a.recommendedAction),
          botClassifications: mapToRecord(a.botClassifications),
        });
        const topPaths = [...a.pathCounts.entries()].sort((x, y) => y[1] - x[1]).slice(0, 3).map(([path, count]) => ({ path, count }));
        const entry: SignatureSummary = {
          sigId, name: a.name, accuracy: a.accuracy, attackType: a.attackType,
          totalEvents: events.length, uniqueUsers: a.uniqueUsers.size, uniquePaths: a.pathCounts.size, uniqueIPs: a.uniqueIPs.size,
          topPaths, autoSuppressed: a.autoSuppressed, aiRisk: dominantRiskLevel(a.aiRiskCounts),
          recommendedAction: a.recommendedAction || undefined, staged: a.staged || undefined,
          actions: { block: a.block, report: a.report }, quickVerdict: 'investigate', quickConfidence: 'low',
          fpScore: signals.compositeScore, fpVerdict: signals.verdict,
        };
        const qv = computeQuickVerdict(entry); entry.quickVerdict = qv.verdict; entry.quickConfidence = qv.confidence;
        signatures.push(entry);
      }
      const pri: Record<string, number> = { highly_likely_fp: 0, likely_fp: 1, ambiguous: 2, likely_tp: 3, confirmed_tp: 4 };
      signatures.sort((x, y) => (pri[x.fpVerdict] - pri[y.fpVerdict]) || (y.fpScore - x.fpScore) || (y.totalEvents - x.totalEvents));
      this.sortedSigIds = signatures.map(s => s.sigId);
    }

    if (this.config.scopes.includes('waf_violations')) {
      for (const [violName, events] of this.secEventsByViolation) {
        const uniqueUsers = new Set<string>(); const uniqueIPs = new Set<string>(); const pathCounts = new Map<string, number>();
        const rspCodes = new Map<string, number>(); const matchingInfos: string[] = [];
        const botClassifications = new Map<string, number>();
        const aiRiskCounts = emptyAiRiskCounts(); const recommendedActions = new Map<string, number>(); const riskReasons: string[] = [];
        let attackType = '';
        for (const e of events) {
          const ip = getStr(e, 'src_ip'); uniqueUsers.add(getStr(e, 'user') || ip); if (ip) uniqueIPs.add(ip);
          pathCounts.set(getStr(e, 'req_path') || '/', (pathCounts.get(getStr(e, 'req_path') || '/') || 0) + 1);
          const rc = getStr(e, 'rsp_code') || '0'; rspCodes.set(rc, (rspCodes.get(rc) || 0) + 1);
          const bc = classifyBot((e.bot_info as Record<string, unknown> | undefined)?.classification); botClassifications.set(bc, (botClassifications.get(bc) || 0) + 1);
          tallyReqRisk(aiRiskCounts, e.req_risk);
          const ra = getStr(e, 'recommended_action'); if (ra) recommendedActions.set(ra, (recommendedActions.get(ra) || 0) + 1);
          const rr = e.req_risk_reasons; if (Array.isArray(rr)) riskReasons.push(...rr.map(String)); else if (rr) riskReasons.push(String(rr));
          if (!attackType) { const v = getViolations(e).find(vv => vv.name === violName); if (v) { attackType = v.attackType; if (v.matchingInfo && matchingInfos.length < 20) matchingInfos.push(v.matchingInfo); } }
        }
        const ipProfiles = this.ipProfilesFor(uniqueIPs);
        const signals = computeFpSignals({
          distinctIPs: uniqueIPs.size, distinctUsers: uniqueUsers.size, pathCount: pathCounts.size,
          totalAppPaths: this.totalDistinctPaths || pathCounts.size, pathTotalUsers: this.topPathUsers(pathCounts), contextType: 'violation', contextName: violName,
          sampleMatchingInfos: matchingInfos, rspCodes: mapToRecord(rspCodes), ipProfiles,
          accuracy: 'medium_accuracy', sigState: 'Enabled', aiConfirmed: parseRiskReasons(riskReasons).aiConfirmedAttack,
          violationRatings: [], aiInput: aiInputFrom(aiRiskCounts, riskReasons, dominantAction(recommendedActions)), violationName: violName,
          botClassifications: mapToRecord(botClassifications),
        });
        const topPaths = [...pathCounts.entries()].sort((x, y) => y[1] - x[1]).slice(0, 3).map(([path, count]) => ({ path, count }));
        violations.push({
          violationName: violName, attackType, totalEvents: events.length, uniqueUsers: uniqueUsers.size, uniquePaths: pathCounts.size,
          topPaths, aiRisk: dominantRiskLevel(aiRiskCounts), quickVerdict: 'investigate', quickConfidence: 'low',
          fpScore: signals.compositeScore, fpVerdict: signals.verdict,
        });
      }
      const pri: Record<string, number> = { highly_likely_fp: 0, likely_fp: 1, ambiguous: 2, likely_tp: 3, confirmed_tp: 4 };
      violations.sort((x, y) => (pri[x.fpVerdict] - pri[y.fpVerdict]) || (y.fpScore - x.fpScore));
    }

    const enforcement = parseEnforcementMode(this.enforcementMode);
    const wafComparison = computeWafComparison(this.allSecurityEvents, enforcement);
    const botAnalysis = this.botAggregates ? computeBotAnalysisFromAggregates(this.botAggregates) : undefined;
    const recommendations = buildFpRecommendations({ signatures, violations, comparison: wafComparison, enforcementMode: enforcement, botAnalysis });
    return {
      signatures, violations, threatMeshIPs: [], policyRules: [],
      totalEvents: this.securityEventsCollected, period: { start: this.startTime, end: this.endTime },
      enforcementMode: enforcement, avgSampleRate: 1, dataPartial: this.dataPartial || undefined,
      wafComparison, recommendations, botAnalysis,
    };
  }

  // ── On-demand signature detail ──
  getSignatureDetail(sigId: string): SignatureAnalysisUnit | null {
    if (this.detailCache.has(sigId)) return this.detailCache.get(sigId)!;
    const events = this.secEventsBySignature.get(sigId);
    if (!events || events.length === 0) return null;
    const a = this.aggregateSignature(sigId, events);
    const ipProfiles = this.ipProfilesFor(a.uniqueIPs);
    const signals = computeFpSignals({
      distinctIPs: a.uniqueIPs.size, distinctUsers: a.uniqueUsers.size, pathCount: a.pathCounts.size,
      totalAppPaths: this.totalDistinctPaths || a.pathCounts.size, pathTotalUsers: this.topPathUsers(a.pathCounts), contextType: a.contextType, contextName: a.contextName,
      sampleMatchingInfos: a.matchingInfos, rspCodes: mapToRecord(a.rspCodes), ipProfiles,
      accuracy: a.accuracy, sigState: a.sigState, aiConfirmed: a.reasonVerdict.aiConfirmedAttack,
      violationRatings: a.violationRatings, aiInput: aiInputFrom(a.aiRiskCounts, a.riskReasons, a.recommendedAction),
      botClassifications: mapToRecord(a.botClassifications),
    });
    const rawPaths = [...a.pathCounts.entries()].sort((x, y) => y[1] - x[1]).map(([p]) => p);
    const ipCounts: Record<string, number> = {};
    const ipDetails: Record<string, { count: number; country: string; city: string; asOrg: string; userAgent: string }> = {};
    for (const e of events) {
      const ip = getStr(e, 'src_ip'); if (!ip) continue;
      ipCounts[ip] = (ipCounts[ip] || 0) + 1;
      if (!ipDetails[ip]) ipDetails[ip] = { count: 0, country: getStr(e, 'country') || 'unknown', city: getStr(e, 'city') || getStr(e, 'src_city') || '', asOrg: getStr(e, 'as_org') || getStr(e, 'asn') || '', userAgent: getStr(e, 'user_agent') || getStr(e, 'browser_type') || 'unknown' };
      ipDetails[ip].count++;
    }
    const unit: SignatureAnalysisUnit = {
      signatureId: sigId, signatureName: a.name, attackType: a.attackType, accuracy: a.accuracy,
      contextType: a.contextType, contextName: a.contextName, contextRaw: a.contextRaw,
      path: rawPaths[0] || '/', rawPaths, pathCount: a.pathCounts.size, pathCounts: mapToRecord(a.pathCounts),
      pathAnalyses: this.perPathAnalysis(events, sigId, a),
      eventCount: events.length, flaggedUsers: a.uniqueUsers.size, flaggedIPs: a.uniqueIPs.size, ipCounts, ipDetails,
      totalRequestsOnPath: 0, totalUsersOnPath: 0, userRatio: 0, requestRatio: 0,
      userAgents: mapToRecord(a.userAgents), countries: mapToRecord(a.countries), trustScores: [],
      botClassifications: mapToRecord(a.botClassifications), methods: mapToRecord(a.methods), sampleMatchingInfos: a.matchingInfos, sampleReqParams: [],
      timestamps: [], rspCodes: mapToRecord(a.rspCodes), originAcceptedCount: a.rspCodes.get('200') || 0,
      violationRatings: a.violationRatings, reqRiskReasons: [...new Set(a.riskReasons)], aiConfirmed: a.reasonVerdict.aiConfirmedAttack,
      sigState: a.sigState, signals, ipProfiles, autoSuppressed: a.autoSuppressed, staged: a.staged,
      aiRiskCounts: a.aiRiskCounts, recommendedAction: a.recommendedAction || undefined,
    };
    this.detailCache.set(sigId, unit);
    return unit;
  }

  private perPathAnalysis(events: RawEvent[], sigId: string, agg: ReturnType<ProgressiveAnalysisJob['aggregateSignature']>): PathAnalysis[] {
    const byPath = new Map<string, RawEvent[]>();
    for (const e of events) { const p = getStr(e, 'req_path') || '/'; if (!byPath.has(p)) byPath.set(p, []); byPath.get(p)!.push(e); }
    const out: PathAnalysis[] = [];
    for (const [path, evs] of byPath) {
      const users = new Set<string>(); const ips = new Set<string>(); const uas = new Map<string, number>();
      const countries = new Map<string, number>(); const methods = new Map<string, number>(); const rsp = new Map<string, number>();
      const bots = new Map<string, number>();
      const mi: string[] = [];
      for (const e of evs) {
        const ip = getStr(e, 'src_ip'); users.add(getStr(e, 'user') || ip); if (ip) ips.add(ip);
        uas.set(getStr(e, 'user_agent') || 'unknown', 1); countries.set(getStr(e, 'country') || 'unknown', 1);
        methods.set(getStr(e, 'method') || 'GET', (methods.get(getStr(e, 'method') || 'GET') || 0) + 1);
        const rc = getStr(e, 'rsp_code') || '0'; rsp.set(rc, (rsp.get(rc) || 0) + 1);
        const bc = classifyBot((e.bot_info as Record<string, unknown> | undefined)?.classification); bots.set(bc, (bots.get(bc) || 0) + 1);
        const sig = getSignatures(e).find(s => s.id === sigId); if (sig?.matchingInfo && mi.length < 5) mi.push(sig.matchingInfo);
      }
      const signals = computeFpSignals({
        distinctIPs: ips.size, distinctUsers: users.size, pathCount: 1, totalAppPaths: this.totalDistinctPaths || 1, pathTotalUsers: this.pathBehavior.get(path)?.totalUsers,
        contextType: agg.contextType, contextName: agg.contextName, sampleMatchingInfos: mi, rspCodes: mapToRecord(rsp),
        ipProfiles: this.ipProfilesFor(ips), accuracy: agg.accuracy, sigState: agg.sigState,
        aiConfirmed: agg.reasonVerdict.aiConfirmedAttack, violationRatings: [],
        aiInput: aiInputFrom(agg.aiRiskCounts, agg.riskReasons, agg.recommendedAction),
        botClassifications: mapToRecord(bots),
      });
      out.push({ path, eventCount: evs.length, uniqueUsers: users.size, uniqueIPs: ips.size, userAgents: mapToRecord(uas), countries: mapToRecord(countries), methods: mapToRecord(methods), rspCodes: mapToRecord(rsp), sampleMatchingInfos: mi, fpScore: signals.compositeScore, verdict: signals.verdict, reasons: [signals.clientBehavior.reason, signals.originResponse.reason] });
    }
    out.sort((x, y) => y.fpScore - x.fpScore);
    return out;
  }

  // ── On-demand violation detail ──
  getViolationDetail(violName: string): ViolationAnalysisUnit | null {
    if (this.violationDetailCache.has(violName)) return this.violationDetailCache.get(violName)!;
    const events = this.secEventsByViolation.get(violName);
    if (!events || events.length === 0) return null;
    const uniqueUsers = new Set<string>(); const uniqueIPs = new Set<string>(); const pathCounts = new Map<string, number>();
    const userAgents = new Map<string, number>(); const countries = new Map<string, number>(); const methods = new Map<string, number>();
    const rspCodes = new Map<string, number>(); const matchingInfos: string[] = [];
    const botClassifications = new Map<string, number>();
    const aiRiskCounts = emptyAiRiskCounts(); const recommendedActions = new Map<string, number>(); const riskReasons: string[] = [];
    let attackType = '';
    for (const e of events) {
      const ip = getStr(e, 'src_ip'); uniqueUsers.add(getStr(e, 'user') || ip); if (ip) uniqueIPs.add(ip);
      pathCounts.set(getStr(e, 'req_path') || '/', (pathCounts.get(getStr(e, 'req_path') || '/') || 0) + 1);
      userAgents.set(getStr(e, 'user_agent') || 'unknown', (userAgents.get(getStr(e, 'user_agent') || 'unknown') || 0) + 1);
      countries.set(getStr(e, 'country') || 'unknown', (countries.get(getStr(e, 'country') || 'unknown') || 0) + 1);
      methods.set(getStr(e, 'method') || 'GET', (methods.get(getStr(e, 'method') || 'GET') || 0) + 1);
      rspCodes.set(getStr(e, 'rsp_code') || '0', (rspCodes.get(getStr(e, 'rsp_code') || '0') || 0) + 1);
      const bc = classifyBot((e.bot_info as Record<string, unknown> | undefined)?.classification); botClassifications.set(bc, (botClassifications.get(bc) || 0) + 1);
      tallyReqRisk(aiRiskCounts, e.req_risk);
      const ra = getStr(e, 'recommended_action'); if (ra) recommendedActions.set(ra, (recommendedActions.get(ra) || 0) + 1);
      const rr = e.req_risk_reasons; if (Array.isArray(rr)) riskReasons.push(...rr.map(String)); else if (rr) riskReasons.push(String(rr));
      if (!attackType) { const v = getViolations(e).find(vv => vv.name === violName); if (v) { attackType = v.attackType; if (v.matchingInfo && matchingInfos.length < 20) matchingInfos.push(v.matchingInfo); } }
    }
    const ipProfiles = this.ipProfilesFor(uniqueIPs);
    const signals = computeFpSignals({
      distinctIPs: uniqueIPs.size, distinctUsers: uniqueUsers.size, pathCount: pathCounts.size,
      totalAppPaths: this.totalDistinctPaths || pathCounts.size, pathTotalUsers: this.topPathUsers(pathCounts), contextType: 'violation', contextName: violName,
      sampleMatchingInfos: matchingInfos, rspCodes: mapToRecord(rspCodes), ipProfiles,
      accuracy: 'medium_accuracy', sigState: 'Enabled', aiConfirmed: parseRiskReasons(riskReasons).aiConfirmedAttack,
      violationRatings: [], aiInput: aiInputFrom(aiRiskCounts, riskReasons, dominantAction(recommendedActions)), violationName: violName,
      botClassifications: mapToRecord(botClassifications),
    });
    const rawPaths = [...pathCounts.entries()].sort((x, y) => y[1] - x[1]).map(([p]) => p);
    const unit: ViolationAnalysisUnit = {
      violationName: violName, attackType, path: rawPaths[0] || '/', rawPaths, pathCount: pathCounts.size, pathCounts: mapToRecord(pathCounts),
      eventCount: events.length, flaggedUsers: uniqueUsers.size, flaggedIPs: uniqueIPs.size, ipCounts: {},
      totalRequestsOnPath: 0, totalUsersOnPath: 0, userRatio: 0, requestRatio: 0,
      userAgents: mapToRecord(userAgents), countries: mapToRecord(countries), methods: mapToRecord(methods),
      botClassifications: mapToRecord(botClassifications),
      sampleMatchingInfos: matchingInfos, timestamps: [], signals, ipProfiles,
    };
    if ((signals.verdict === 'highly_likely_fp' || signals.verdict === 'likely_fp') && signals.override !== 'ALWAYS_TP_VIOLATION') {
      unit.suggestedExclusion = generateViolationExclusion(violName, 'CONTEXT_ANY', '', this.config.domains[0] || '', unit.path, Object.keys(unit.methods));
    }
    this.violationDetailCache.set(violName, unit);
    return unit;
  }

  // ── Exclusion generation ──
  generatePolicyForConfirmedFPs(confirmedSigIds: string[]): WafExclusionPolicyObject | null {
    const domain = this.config.domains[0] || '';
    const intents: SigExclusionIntent[] = [];
    for (const sigId of confirmedSigIds) {
      const d = this.detailCache.get(sigId) || this.getSignatureDetail(sigId);
      if (d) intents.push({ signatureId: d.signatureId, attackType: d.attackType, contextType: d.contextType, contextName: d.contextName, path: d.path, methods: Object.keys(d.methods) });
    }
    if (intents.length === 0) return null;
    const rules = buildSignatureExclusionsWithRollup(intents, domain);
    if (rules.length === 0) return null;
    return buildWafExclusionPolicy(this.config.lbName, this.config.namespace, rules);
  }

  async applyExclusionPolicy(confirmedSigIds: string[]): Promise<{ created: boolean; name?: string; namespace?: string; ruleCount?: number; error?: string }> {
    const policy = this.generatePolicyForConfirmedFPs(confirmedSigIds);
    if (!policy) return { created: false, error: 'No confirmed-FP signatures to build a policy from' };
    try {
      await this.api.createWafExclusionPolicy(this.config.namespace, policy);
      return { created: true, name: policy.metadata.name, namespace: this.config.namespace, ruleCount: policy.spec.waf_exclusion_rules.length };
    } catch (err) {
      return { created: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  generateExclusionForSignature(sigId: string): WafExclusionRule | null {
    const d = this.detailCache.get(sigId) || this.getSignatureDetail(sigId);
    if (!d) return null;
    return generateSignatureExclusion(d.signatureId, d.contextType, d.contextName, this.config.domains[0] || '', d.path, Object.keys(d.methods));
  }

  private estimateRemaining(): number {
    if (this.status !== 'collecting') return 0;
    if (this.chunksCompleted === 0 || this.totalChunks === 0) return 30000;
    const msPer = (Date.now() - this.startMs) / this.chunksCompleted;
    return Math.max(0, Math.round(msPer * (this.totalChunks - this.chunksCompleted)));
  }
}
