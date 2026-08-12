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
import { computeBotAnalysisFromAggregates, computeBotAggregatesFromEvents, classifyBot, botClassificationRaw } from '../src/services/fp-analyzer/bot-analysis';
import type { BotAggregateInput } from '../src/services/fp-analyzer/bot-analysis';
import {
  emptyAiRiskCounts, tallyReqRisk, dominantRiskLevel, dominantRiskLabel, parseRiskReasons, parseReqRisk,
  isStagedState, isAutoSuppressedState, parseEnforcementMode, estimateActualCountFromRate,
} from '../src/services/fp-analyzer/ai-signals';
import type { AiRiskCounts, AiSignalInput } from '../src/services/fp-analyzer/ai-signals';
import { computeQuickVerdict, mapToRecord } from '../src/services/fp-analyzer/signal-calculator';
import { parseContext } from '../src/services/fp-analyzer/context-parser';
import {
  generateSignatureExclusion, generateViolationExclusion, buildWafExclusionPolicy,
  buildSignatureExclusionsWithRollup,
} from '../src/services/fp-analyzer/exclusion-generator';
import type { SigExclusionIntent } from '../src/services/fp-analyzer/exclusion-generator';
import { computeEnforcementComparison } from '../src/services/fp-analyzer/enforcement-comparison';
import type { ComparisonEvent, SignatureMeta, ViolationMeta } from '../src/services/fp-analyzer/enforcement-comparison';
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
const IPS_PER_QUERY = 50;          // src_ip=~ regex batch size (more IPs/query = fewer enrichment round-trips)
const BOT_AGG_TOPK = 500;          // distinct malicious src_ip buckets to request
// Malicious bots are EXCLUDED from the main raw pull (server-side filter) — they're always req_risk
// High true positives, so the comparison only needs their count (from total_hits). We pull a BOUNDED
// raw sample purely for the breakdown detail (name/IPs/paths), so collection never bloats even when a
// load balancer is heavily scanned. Field is `bot_info.classification` = "malicious" (lowercase).
const MALICIOUS_BOT_SELECTOR = 'bot_info.classification=~"malicious"';
const MALICIOUS_BOT_EXCLUDE = 'bot_info.classification!~"malicious"';
const BOT_SAMPLE_CAP = 2000;       // max malicious-bot rows pulled for the breakdown sample
// Server-side exclusion of malicious-bot rows from the WAF/violation pull. Substring
// regex (`!~`) tolerates token variants (malicious / malicious_bot). Correctness is also
// guaranteed by an always-on client-side drop, so this is purely a bandwidth optimization.

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

// Coerce to a string so equality checks (rsp_code === '200', '404') hold on tenants that emit
// numeric values; (number) || '' would otherwise return the raw number, not a string.
function getStr(e: RawEvent, key: string): string { const v = e[key]; return v == null ? '' : String(v); }
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
  private allSecurityEvents: RawEvent[] = [];      // malicious bots excluded (FP scoring / indexing)
  private allSecurityEventsFull: RawEvent[] = [];  // WAF events EXCLUDING malicious bots (bots synthesized into the comparison from their count)
  private botAggregates: BotAggregateInput | null = null;
  private maliciousDroppedClientSide = 0;
  private serverBotFilterUsed = false;
  private maliciousBotCount = 0;                   // full malicious-bot count (from total_hits — exact even when the detail sample is capped)
  private maliciousBotEventsRaw: RawEvent[] = [];  // raw malicious-bot rows when the server filter is unavailable (client-drop fallback)
  private botBreakdownSampled = false;             // true when the per-IP/path breakdown is from a capped sample, not all events
  private botBreakdownSampleSize = 0;              // the sample size, for honest labelling in the report
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
    this.controller = new AdaptiveConcurrencyController({ initialConcurrency: 5, minConcurrency: 1, maxConcurrency: 12, rampUpAfterSuccesses: 6 });
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

  private get domainFilter(): string {
    if (!this.config.domains || this.config.domains.length === 0) return '';
    if (this.config.domains.length === 1) return `, authority="${this.config.domains[0]}"`;
    return `, authority=~"${this.config.domains.join('|')}"`;
  }

  // ── Phase 1: collect WAF events ──
  // Fetch WAF events with malicious bots EXCLUDED at the source (server-side filter, when supported)
  // so the raw download stays small. Malicious bots are always req_risk High true positives, so the
  // Traditional-vs-AI comparison reconstructs them from their exact count (total_hits); their breakdown
  // detail comes from a separate bounded sample. See probeBotFilter / synthesizeMaliciousBotEvents.
  /**
   * Probe whether the API actually filters on `bot_info.classification`, so we can exclude malicious
   * bots at the SOURCE. We don't trust "no error" — a silently-ignored filter returns everything — so
   * we VERIFY by comparing total_hits: the exclude filter must return strictly fewer rows than the
   * unfiltered query. The difference is the exact malicious-bot count (kept even when the later detail
   * sample is capped).
   */
  private async probeBotFilter(baseSelector: string): Promise<void> {
    this.serverBotFilterUsed = false;
    this.maliciousBotCount = 0;
    try {
      const [all, nonBot] = await Promise.all([
        this.api.fetchSecurityEventsPage(this.config.namespace, `{${baseSelector}}`, this.startTime, this.endTime, 1),
        this.api.fetchSecurityEventsPage(this.config.namespace, `{${baseSelector}, ${MALICIOUS_BOT_EXCLUDE}}`, this.startTime, this.endTime, 1),
      ]);
      const tAll = parseTotalHits(all.total_hits);
      const tNon = parseTotalHits(nonBot.total_hits);
      if (tAll > 0 && tNon < tAll) {        // filter discriminates → usable; difference = malicious count
        this.serverBotFilterUsed = true;
        this.maliciousBotCount = tAll - tNon;
      }
      console.log(`[FP ${this.id}] BOT FILTER PROBE: total=${tAll}, non-malicious=${tNon} → serverFilter=${this.serverBotFilterUsed}, malicious=${this.maliciousBotCount}`);
    } catch (e) {
      console.log(`[FP ${this.id}] BOT FILTER PROBE failed (${e instanceof Error ? e.message : String(e)}) — will pull all + drop client-side`);
    }
  }

  private async collectWafEvents(): Promise<RawEvent[]> {
    const baseSelector = `vh_name="${this.vhName}", sec_event_name="WAF"${this.domainFilter}`;
    await this.probeBotFilter(baseSelector);
    // Exclude malicious bots at the source when the filter is supported — keeps the raw download small.
    const query = this.serverBotFilterUsed ? `{${baseSelector}, ${MALICIOUS_BOT_EXCLUDE}}` : `{${baseSelector}}`;
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
    // Malicious bots are EXCLUDED from the analysed/comparison set: they're always req_risk High true
    // positives (no FP scoring needed) and the comparison reconstructs them from their count. When the
    // server filter was unavailable, the bots are still in `scoped` here, so drop them client-side and
    // keep the raw rows for the breakdown detail.
    const nonBot = scoped.filter(e => classifyBot(botClassificationRaw(e)) !== 'malicious');
    if (!this.serverBotFilterUsed) {
      this.maliciousBotEventsRaw = scoped.filter(e => classifyBot(botClassificationRaw(e)) === 'malicious');
      this.maliciousBotCount = this.maliciousBotEventsRaw.length;
    }
    this.maliciousDroppedClientSide = scoped.length - nonBot.length;
    this.allSecurityEventsFull = nonBot;
    console.log(`[FP ${this.id}] WAF pull: ${nonBot.length} non-bot events (serverFilter=${this.serverBotFilterUsed}, malicious bots excluded=${this.maliciousBotCount}, droppedClientSide=${this.maliciousDroppedClientSide})`);
    this.securityEventsCollected = nonBot.length;
    this.securityEventsExpected = expectedHits;
    this.dataPartial = !this.cancelled && ((this.totalChunks - this.chunksCompleted) > 0 || anyScrollBroke);
    if (this.dataPartial) console.warn(`[FP ${this.id}] PARTIAL: ${this.totalChunks - this.chunksCompleted} chunk(s) failed, scrollBroke=${anyScrollBroke}`);
    return nonBot;
  }

  /**
   * Bot-classification track. Malicious bots are EXCLUDED from the main raw pull (so collection stays
   * fast even when an LB is hit by 1M+ scanner requests). So:
   *  • COUNT is the exact total_hits figure (from the probe) — never the sample.
   *  • Per-IP / per-path / per-country breakdowns come from server-side AGGREGATION over ALL malicious
   *    events (accurate top-N with true counts — the old raw sample was the first 2k rows and missed
   *    the heaviest IPs).
   *  • Nested bot_info.* fields (name/type) that the aggregation API may not support fall back to a
   *    small raw sample.
   * The classification distribution = exact malicious total + the non-malicious bots from the main pull.
   */
  private async collectMaliciousBotAggregates(): Promise<void> {
    const malQuery = `{vh_name="${this.vhName}", sec_event_name="WAF"${this.domainFilter}, ${MALICIOUS_BOT_SELECTOR}}`;
    const empty: Array<{ key: string; count: number }> = [];
    const [aggIp, aggPath, aggCountry, aggAsOrg, aggAction, aggReqRisk, aggReco, aggUa, aggName, aggType, aggDetect] =
      this.maliciousBotCount > 0
        ? await Promise.all([
            this.aggField(malQuery, 'src_ip', BOT_AGG_TOPK),
            this.aggField(malQuery, 'req_path', 100),
            this.aggField(malQuery, 'country', 50),
            this.aggField(malQuery, 'as_org', 50),
            this.aggField(malQuery, 'action', 20),
            this.aggField(malQuery, 'req_risk', 10),
            this.aggField(malQuery, 'recommended_action', 20),
            this.aggField(malQuery, 'user_agent', 50),
            this.aggField(malQuery, 'bot_info.name', 50),
            this.aggField(malQuery, 'bot_info.type', 20),
            this.aggField(malQuery, 'risk_score_info.source', 20),
          ])
        : [empty, empty, empty, empty, empty, empty, empty, empty, empty, empty, empty];

    // Sample fallback: only when aggregation didn't cover the data (no IP buckets, or nested name/type
    // unsupported). In client-drop mode we already hold the raw rows; otherwise pull a bounded sample.
    const aggWorked = aggIp.length > 0;
    let sample = this.maliciousBotEventsRaw;
    if (this.maliciousBotCount > 0 && sample.length === 0 && (!aggWorked || aggName.length === 0)) {
      sample = await this.pullMaliciousBotSample();
    }
    if (this.maliciousBotCount === 0) this.maliciousBotCount = sample.length;
    const s = computeBotAggregatesFromEvents(sample, BOT_AGG_TOPK);
    const pick = (a: Array<{ key: string; count: number }>, b: Array<{ key: string; count: number }> | undefined) => (a.length > 0 ? a : (b ?? []));

    // Classification distribution: EXACT malicious total + non-malicious classes from the main pull.
    const nonMal = new Map<string, number>();
    for (const e of this.allSecurityEventsFull) {
      const raw = botClassificationRaw(e) || '(unclassified)';
      if (classifyBot(raw) === 'malicious') continue;
      nonMal.set(raw, (nonMal.get(raw) || 0) + 1);
    }
    const classDistribution = [{ key: 'Malicious', count: this.maliciousBotCount }, ...[...nonMal].map(([key, count]) => ({ key, count }))]
      .filter(b => b.count > 0);

    this.botAggregates = {
      classDistribution,
      byIp: pick(aggIp, s.byIp),
      byBotName: pick(aggName, s.byBotName),
      byBotType: pick(aggType, s.byBotType),
      byDetection: pick(aggDetect, s.byDetection),
      byUserAgent: pick(aggUa, s.byUserAgent),
      byCountry: pick(aggCountry, s.byCountry),
      byAsOrg: pick(aggAsOrg, s.byAsOrg),
      byReqRisk: pick(aggReqRisk, s.byReqRisk),
      byAction: pick(aggAction, s.byAction),
      byRecommendation: pick(aggReco, s.byRecommendation),
      byPath: pick(aggPath, s.byPath),
      ipTopk: BOT_AGG_TOPK,
    };
    // Honest labelling: when aggregation was unavailable AND the exact count exceeds the sample we pulled,
    // the per-IP/path breakdown is a SAMPLE — the report must say so (distinct-client count is a floor).
    this.botBreakdownSampled = !aggWorked && this.maliciousBotCount > sample.length;
    this.botBreakdownSampleSize = sample.length;
    console.log(`[FP ${this.id}] BOT SCAN: malicious=${this.maliciousBotCount} (exact), breakdown source=${aggWorked ? 'aggregation' : 'sample'}${this.botBreakdownSampled ? ` (SAMPLED — breakdown from ${sample.length} of ${this.maliciousBotCount})` : ''}, distinct top IPs=${this.botAggregates.byIp.length}, sampleRows=${sample.length}`);
  }

  /** One server-side terms aggregation over the malicious-bot query — accurate top-N with true counts
   *  across ALL events. Returns [] when the field is unsupported (some nested bot_info.*), so callers
   *  fall back to the raw sample. Parses the common F5 bucket shapes defensively. */
  private async aggField(query: string, field: string, topk: number): Promise<Array<{ key: string; count: number }>> {
    try {
      const res = await this.api.fetchSecurityEventsAggregation(this.config.namespace, query, this.startTime, this.endTime, { a: { field, topk } });
      const node = (res.aggs as Record<string, unknown> | undefined)?.a as { buckets?: unknown } | undefined;
      const buckets = Array.isArray(node?.buckets) ? (node!.buckets as Array<Record<string, unknown>>) : [];
      return buckets
        .map(b => ({ key: String(b.key ?? b.value ?? ''), count: Number(b.count ?? b.doc_count ?? (b as { value?: number }).value ?? 0) }))
        .filter(b => b.key && b.count > 0);
    } catch {
      return [];
    }
  }

  /** Bounded raw pull of malicious-bot rows for the breakdown detail only (capped so a scanned LB
   *  can't bloat collection). The exact count already came from total_hits in the probe. */
  private async pullMaliciousBotSample(): Promise<RawEvent[]> {
    const query = `{vh_name="${this.vhName}", sec_event_name="WAF"${this.domainFilter}, ${MALICIOUS_BOT_SELECTOR}}`;
    const out: RawEvent[] = [];
    try {
      const initial = await this.api.fetchSecurityEventsPage(this.config.namespace, query, this.startTime, this.endTime, PAGE_SIZE);
      if (initial.events) out.push(...normalizeEntries(initial.events));
      let scrollId = initial.scroll_id;
      while (scrollId && out.length < BOT_SAMPLE_CAP) {
        try {
          const page = await this.api.scrollSecurityEvents(this.config.namespace, scrollId);
          if (!page.events || page.events.length === 0) break;
          out.push(...normalizeEntries(page.events));
          scrollId = page.scroll_id;
        } catch { break; }
      }
    } catch (e) {
      console.warn(`[FP ${this.id}] malicious-bot detail sample failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    return out.slice(0, BOT_SAMPLE_CAP);
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
    const controller = new AdaptiveConcurrencyController({ initialConcurrency: 6, minConcurrency: 1, maxConcurrency: 16, rampUpAfterSuccesses: 5 });

    const batches: string[][] = [];
    for (let i = 0; i < ips.length; i += IPS_PER_QUERY) batches.push(ips.slice(i, i + IPS_PER_QUERY));

    for (const batch of batches) {
      if (this.cancelled) return;
      const ipRegex = batch.map(ip => ip.replace(/\./g, '\\.')).join('|');
      const query = batch.length === 1
        ? `{vh_name="ves-io-http-loadbalancer-${this.config.lbName}"${this.domainFilter}, src_ip="${batch[0]}"}`
        : `{vh_name="ves-io-http-loadbalancer-${this.config.lbName}"${this.domainFilter}, src_ip=~"${ipRegex}"}`;

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
    const controller = new AdaptiveConcurrencyController({ initialConcurrency: 6, minConcurrency: 1, maxConcurrency: 16, rampUpAfterSuccesses: 5 });
    const PATHS_PER_QUERY = 20;
    const batches: string[][] = [];
    for (let i = 0; i < paths.length; i += PATHS_PER_QUERY) batches.push(paths.slice(i, i + PATHS_PER_QUERY));

    for (const batch of batches) {
      if (this.cancelled) return;
      const regex = batch.map(p => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('|');
      const query = `{vh_name="ves-io-http-loadbalancer-${this.config.lbName}"${this.domainFilter}, req_path=~"${regex}"}`;
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
      const bc = classifyBot(botClassificationRaw(e)); botClassifications.set(bc, (botClassifications.get(bc) || 0) + 1);
      if (getStr(e, 'action') === 'block') block++; else report++;
      const vr = getNum(e, 'violation_rating'); if (vr > 0) violationRatings.push(vr);
      tallyReqRisk(aiRiskCounts, e.req_risk);
      const ra = getStr(e, 'recommended_action'); if (ra) recommendedActions.set(ra, (recommendedActions.get(ra) || 0) + 1);
      const rr = e.req_risk_reasons; if (Array.isArray(rr)) riskReasons.push(...rr.map(String)); else if (rr) riskReasons.push(String(rr));
      const sig = getSignatures(e).find(s => s.id === sigId);
      if (sig) {
        if (!name) { name = sig.name; accuracy = sig.accuracy; attackType = sig.attackType; const ctx = normalizeSigContext(sig); contextType = ctx.contextType; contextName = ctx.contextName; contextRaw = sig.context; }
        // Detect F5 state via the canonical helpers (case/separator/whitespace tolerant —
        // F5 emits "AutoSuppressed", but also variants like "Auto-Suppressed"/"auto_suppressed").
        // A brittle `=== 'AutoSuppressed'` here disagreed with the scorer (which uses the regex),
        // leaving the signature flagged FP by the score yet missing from the auto-handled list.
        if (isAutoSuppressedState(sig.state)) autoSuppressed = true;
        if (isStagedState(sig.state)) staged = true;
        // Representative state for display (FPAnalyzer UI) + scorer input (drives the
        // F5_CONFIRMED_FP override). State is normally constant per signature; if events
        // disagree or the first is empty, let a non-empty suppressed/staged value win so
        // sigState stays consistent with the flags above.
        if (sig.state && (!sigState || isAutoSuppressedState(sig.state) || isStagedState(sig.state))) sigState = sig.state;
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
    // Per-signature / per-violation metadata + enriched verdict, fed to the blocking-mode comparison engine.
    const sigMeta = new Map<string, SignatureMeta>();
    const violMeta = new Map<string, ViolationMeta>();

    if (this.config.scopes.includes('waf_signatures')) {
      for (const [sigId, events] of this.secEventsBySignature) {
        const a = this.aggregateSignature(sigId, events);
        const ipProfiles = this.ipProfilesFor(a.uniqueIPs);
        const signals = computeFpSignals({
          distinctIPs: a.uniqueIPs.size, distinctUsers: a.uniqueUsers.size,
          pathCount: a.pathCounts.size, totalAppPaths: this.totalDistinctPaths || a.pathCounts.size, pathTotalUsers: this.topPathUsers(a.pathCounts),
          contextType: a.contextType, contextName: a.contextName,
          sampleMatchingInfos: a.matchingInfos, rspCodes: mapToRecord(a.rspCodes), ipProfiles,
          accuracy: a.accuracy, sigState: a.sigState, aiConfirmed: a.reasonVerdict.aiConfirmedAttack, attackType: a.attackType, eventCount: events.length,
          violationRatings: a.violationRatings, aiInput: aiInputFrom(a.aiRiskCounts, a.riskReasons, a.recommendedAction),
          botClassifications: mapToRecord(a.botClassifications),
        });
        const topPaths = [...a.pathCounts.entries()].sort((x, y) => y[1] - x[1]).slice(0, 3).map(([path, count]) => ({ path, count }));
        const entry: SignatureSummary = {
          sigId, name: a.name, accuracy: a.accuracy, attackType: a.attackType,
          totalEvents: events.length, uniqueUsers: a.uniqueUsers.size, uniquePaths: a.pathCounts.size, uniqueIPs: a.uniqueIPs.size,
          topPaths, autoSuppressed: a.autoSuppressed, aiRisk: dominantRiskLabel(a.aiRiskCounts),
          recommendedAction: a.recommendedAction || undefined, staged: a.staged || undefined,
          actions: { block: a.block, report: a.report }, quickVerdict: 'investigate', quickConfidence: 'low',
          fpScore: signals.compositeScore, fpVerdict: signals.verdict,
        };
        const qv = computeQuickVerdict(entry); entry.quickVerdict = qv.verdict; entry.quickConfidence = qv.confidence;
        signatures.push(entry);
        sigMeta.set(sigId, {
          sigId, name: a.name, verdict: entry.fpVerdict, attackType: a.attackType,
          contextType: a.contextType, contextName: a.contextName,
          path: topPaths[0]?.path || '/', methods: [...a.methods.keys()],
        });
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
          const bc = classifyBot(botClassificationRaw(e)); botClassifications.set(bc, (botClassifications.get(bc) || 0) + 1);
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
          violationRatings: [], aiInput: aiInputFrom(aiRiskCounts, riskReasons, dominantAction(recommendedActions)), violationName: violName, attackType, eventCount: events.length,
          botClassifications: mapToRecord(botClassifications),
        });
        const topPaths = [...pathCounts.entries()].sort((x, y) => y[1] - x[1]).slice(0, 3).map(([path, count]) => ({ path, count }));
        violations.push({
          violationName: violName, attackType, totalEvents: events.length, uniqueUsers: uniqueUsers.size, uniquePaths: pathCounts.size,
          topPaths, aiRisk: dominantRiskLabel(aiRiskCounts), quickVerdict: 'investigate', quickConfidence: 'low',
          fpScore: signals.compositeScore, fpVerdict: signals.verdict,
        });
        // Violations don't carry per-method aggregation here; the engine defaults methods for the exclusion intent.
        violMeta.set(violName, { name: violName, verdict: signals.verdict, path: topPaths[0]?.path || '/', methods: [] });
      }
      const pri: Record<string, number> = { highly_likely_fp: 0, likely_fp: 1, ambiguous: 2, likely_tp: 3, confirmed_tp: 4 };
      violations.sort((x, y) => (pri[x.fpVerdict] - pri[y.fpVerdict]) || (y.fpScore - x.fpScore));
    }

    const enforcement = parseEnforcementMode(this.enforcementMode);
    // Malicious bots are excluded from the raw set (to keep the pull small) but ARE part of the
    // comparison: every one is a req_risk High true positive, so reconstruct them from the exact count.
    const botRequests = this.synthesizeMaliciousBotEvents();
    const wafComparison = computeWafComparison([...this.allSecurityEventsFull, ...botRequests], enforcement);
    const botAnalysis = this.botAggregates ? computeBotAnalysisFromAggregates(this.botAggregates) : undefined;
    if (botAnalysis) {
      botAnalysis.maliciousEvents = this.maliciousBotCount; // exact total_hits count (the detail sample may be capped)
      botAnalysis.breakdownSampled = this.botBreakdownSampled;
      botAnalysis.breakdownSampleSize = this.botBreakdownSampleSize;
    }
    const recommendations = buildFpRecommendations({ signatures, violations, comparison: wafComparison, enforcementMode: enforcement, botAnalysis });

    // Blocking-mode comparison: simulate legacy-accuracy vs AI-risk policies over the pulled
    // events (signatures + violations) and weigh each policy's exclusion-rule overhead.
    const enforcementComparison = (sigMeta.size > 0 || violMeta.size > 0)
      ? computeEnforcementComparison(this.buildComparisonEvents(violMeta.size > 0), sigMeta, violMeta)
      : undefined;

    return {
      signatures, violations, threatMeshIPs: [], policyRules: [],
      totalEvents: this.securityEventsCollected, period: { start: this.startTime, end: this.endTime },
      enforcementMode: enforcement, avgSampleRate: 1, dataPartial: this.dataPartial || undefined,
      wafComparison, recommendations, botAnalysis, enforcementComparison,
    };
  }

  /**
   * Reduce the raw pulled events to the minimal shape the blocking-mode comparison reads.
   * Violations are included only when the violations scope was analyzed (so we have verdicts
   * for them); otherwise they are omitted to keep signature-only analysis unchanged.
   */
  private buildComparisonEvents(includeViolations: boolean): ComparisonEvent[] {
    const out: ComparisonEvent[] = [];
    for (const e of this.allSecurityEventsFull) {
      const sigs = getSignatures(e);
      const viols = includeViolations ? getViolations(e) : [];
      if (sigs.length === 0 && viols.length === 0) continue;
      out.push({
        reqRisk: getStr(e, 'req_risk'),
        signatures: sigs.map(s => ({ id: s.id, accuracy: s.accuracy, state: s.state })),
        violations: viols.map(v => ({ name: v.name, state: v.state })),
      });
    }
    // Malicious bots are excluded from the raw set — reconstruct them: each is a req_risk High true
    // positive blocked by the traditional WAF (Bot Defense) and by the AI risk score.
    const botEvent: ComparisonEvent = { reqRisk: 'high', signatures: [], violations: [], maliciousBot: true };
    for (let i = 0; i < this.maliciousBotCount; i++) out.push(botEvent);
    return out;
  }

  /** Reconstruct the malicious-bot requests (excluded from the raw pull) for the WAF comparison: each
   *  is a req_risk High true positive flagged as a malicious bot. One shared read-only prototype. */
  private synthesizeMaliciousBotEvents(): RawEvent[] {
    if (this.maliciousBotCount <= 0) return [];
    const proto = { req_risk: 'high', 'bot_info.classification': 'malicious', rsp_code: '404' } as unknown as RawEvent;
    return new Array(this.maliciousBotCount).fill(proto);
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
      accuracy: a.accuracy, sigState: a.sigState, aiConfirmed: a.reasonVerdict.aiConfirmedAttack, attackType: a.attackType, eventCount: events.length,
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
        const bc = classifyBot(botClassificationRaw(e)); bots.set(bc, (bots.get(bc) || 0) + 1);
        const sig = getSignatures(e).find(s => s.id === sigId); if (sig?.matchingInfo && mi.length < 5) mi.push(sig.matchingInfo);
      }
      const signals = computeFpSignals({
        distinctIPs: ips.size, distinctUsers: users.size, pathCount: 1, totalAppPaths: this.totalDistinctPaths || 1, pathTotalUsers: this.pathBehavior.get(path)?.totalUsers,
        contextType: agg.contextType, contextName: agg.contextName, sampleMatchingInfos: mi, rspCodes: mapToRecord(rsp),
        ipProfiles: this.ipProfilesFor(ips), accuracy: agg.accuracy, sigState: agg.sigState,
        aiConfirmed: agg.reasonVerdict.aiConfirmedAttack, violationRatings: [], attackType: agg.attackType,
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
      const bc = classifyBot(botClassificationRaw(e)); botClassifications.set(bc, (botClassifications.get(bc) || 0) + 1);
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
      violationRatings: [], aiInput: aiInputFrom(aiRiskCounts, riskReasons, dominantAction(recommendedActions)), violationName: violName, attackType, eventCount: events.length,
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
