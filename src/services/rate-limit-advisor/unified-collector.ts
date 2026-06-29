/**
 * Rate Limit Advisor — Unified Collector
 *
 * Orchestrates two phases with a shared adaptive concurrency controller:
 *
 * Phase A — Weekly Baseline (always 7 days, ~14 API calls)
 *   Provides: daily traffic shape, trend detection, seasonality, filter breakdown,
 *   top users by volume. NO per-user raw log fetches (Phase B handles that).
 *
 * Phase B — Deep Scan (user-selected: 1h/4h/12h/24h, variable calls)
 *   Fetches ALL raw logs using dynamic chunking (≤400 records/chunk, no scroll needed).
 *   Applies cleaning filter, builds per-user per-minute counts.
 *
 * API constraints (confirmed by testing):
 *   - 500 records max per request
 *   - scroll_id NOT reliably returned — avoided entirely
 *   - Only label matchers in queries ({field="value"}), no pipe filters
 *   - `user` field = rate limiting identifier (e.g., "IP-136.226.234.89")
 *   - policy_hits.policy_hits[0] contains ip_risk, malicious_user_mitigate_action, result
 *   - 429 rate limits handled by adaptive concurrency + exponential backoff
 */

import { apiClient } from '../api';
import { AdaptiveConcurrencyController } from '../fp-analyzer/adaptive-concurrency';
import type { AccessLogResponse } from './types';
import { fetchBatchAggregation, probeVolume } from '../log-analyzer/aggregation-client';
import type { AggBucket } from '../log-analyzer/aggregation-client';

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const PAGE_SIZE = 500;
const RECORDS_PER_CHUNK = 50000;   // target raw records per coarse chunk (each fully scrolled)
const MAX_CHUNKS = 200;            // cap on coarse chunks (parallelism + progress granularity)
const MIN_CHUNK_SECONDS = 30;
const MAX_SPLIT_DEPTH = 12;         // bisection fallback depth when scroll is unavailable
const MIN_SPLIT_MS = 1000;         // don't bisect below 1s
const MAX_RETRIES = 4;
const RETRY_BASE_MS = 2000;
const TOP_USERS_AGG = 20;
// Peak measurement: max requests in any rolling 60s window (what a token-bucket limiter sees),
// computed from per-SECOND buckets. Bounded so bursty users (few active seconds) are exact while
// sustained users fall back to the calendar-minute peak (already accurate for steady traffic).
const PEAK_WINDOW_SECONDS = 60;
const MAX_SEC_PER_USER = 5000;        // per-user active-second cap (≈83 min of distinct seconds)
const GLOBAL_SEC_BUDGET = 3_000_000;  // total per-second entries cap (~bounded memory)

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export interface UnifiedProgress {
  phase: 'baseline' | 'deep' | 'processing' | 'complete' | 'error';
  stage: string;
  message: string;
  progress: number; // 0–100
  apiCalls: number;
}

export interface DailyBucket {
  dayStart: string;
  count: number;
}

export interface FilterBreakdown {
  waf_block: number;
  bot_malicious: number;
  good_bot: number;
  policy_deny: number;
  mum_action: number;
  ip_high_risk: number;
  rate_limited: number;
  total: number;
}

export interface UnifiedCollection {
  lbName: string;
  namespace: string;
  domains: string[];

  // Phase A — 7-day baseline
  baselineStart: string;
  baselineEnd: string;
  totalRequests7d: number;
  dailyShape: DailyBucket[];
  filterBreakdown: FilterBreakdown;
  topUsers7d: AggBucket[]; // top users across 7 days by volume

  // Phase B — deep scan
  deepStart: string;
  deepEnd: string;
  deepWindowHours: number;
  deepTotalExpected: number;
  deepTotalFetched: number;
  deepCleanLogs: number;
  deepFilterBreakdown: FilterBreakdown;

  /** Per-user per-minute counts from Phase B (clean traffic only, DE-SAMPLED) — for median/total/simulator. */
  userMinuteCounts: Record<string, number[]>;
  /** Per-user PEAK = max requests in any rolling 60s window (DE-SAMPLED) — the rate-limit input. */
  userPeakRpm: Record<string, number>;
  /** Width of the rolling peak window in seconds (60). */
  peakWindowSeconds: number;
  /** Users whose peak fell back to calendar-minute (sustained/cap hit) — calendar is accurate for them. */
  peakFallbackUsers: number;
  /** All unique user IDs from Phase B */
  allUsers: string[];

  // Sampling
  sampleRateMax: number;   // largest sample_rate seen (1 = no sampling)
  sampledShare: number;    // fraction of clean records that were sampled (sample_rate > 1)

  // Coverage
  coverageGaps: number;    // time segments that stayed saturated after max bisection (possible undercount)

  // LB context (for key-correctness warnings)
  userIdMode: string;          // "client IP (default)" or 'User Identification policy "<name>"'
  hasUserIdPolicy: boolean;
  existingRateLimit: boolean;  // LB already has rate_limit / api_rate_limit configured

  apiCallsUsed: number;
  runtimeMs: number;
}

// ═══════════════════════════════════════════════════════════════════
// RETRY + ADAPTIVE CONCURRENCY
// ═══════════════════════════════════════════════════════════════════

function isRateLimitError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  const l = msg.toLowerCase();
  return msg.includes('429') || l.includes('too many') || l.includes('rate limit');
}

function isTransientError(err: unknown): boolean {
  if (isRateLimitError(err)) return true;
  const msg = err instanceof Error ? err.message : String(err);
  return msg.includes('502') || msg.includes('503') || msg.includes('504');
}

async function withRetry<T>(
  fn: () => Promise<T>,
  label: string,
  controller: AdaptiveConcurrencyController,
): Promise<T> {
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const pace = Math.max(controller.getRequestDelay(), 100);
    await new Promise(r => setTimeout(r, pace));
    try {
      const result = await fn();
      controller.recordSuccess();
      return result;
    } catch (err) {
      if (isRateLimitError(err)) controller.recordRateLimit();
      else controller.recordError();
      if (!isTransientError(err) || attempt === MAX_RETRIES) throw err;
      const delay = RETRY_BASE_MS * Math.pow(2, attempt) + Math.random() * 1000;
      console.log(`[Unified] ${label}: retry ${attempt + 1}/${MAX_RETRIES} in ${Math.round(delay)}ms`);
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw new Error('Unreachable');
}

// ═══════════════════════════════════════════════════════════════════
// CLEANING FILTER
// ═══════════════════════════════════════════════════════════════════

function lower(val: unknown): string {
  if (typeof val === 'string') return val.toLowerCase();
  if (val == null) return '';
  return String(val).toLowerCase();
}

function isExcluded(entry: Record<string, unknown>): { excluded: boolean; reason: string } {
  if (lower(entry.waf_action) === 'block')
    return { excluded: true, reason: 'waf_block' };
  const botInsight = lower(entry.bot_defense_insight) || lower(entry['bot_defense.insight']);
  if (botInsight === 'malicious')
    return { excluded: true, reason: 'bot_malicious' };
  const botClass = lower(entry.bot_class);
  if (botClass === 'bad_bot' || botClass === 'malicious')
    return { excluded: true, reason: 'bot_malicious' };
  // Known-good bots (search-engine crawlers, etc.) are legitimate but NOT genuine users — a crawler
  // is often the single highest-rate client, so leaving it in would inflate the per-user peak.
  if (botClass === 'good_bot' || botClass === 'search_engine')
    return { excluded: true, reason: 'good_bot' };

  // Already rate-limited by an existing limiter → don't fold throttled traffic into the
  // baseline (it would bias the new threshold down toward the old one).
  if (String(entry.rsp_code) === '429')
    return { excluded: true, reason: 'rate_limited' };

  const ph = entry.policy_hits;
  if (ph && typeof ph === 'object') {
    const inner = (ph as Record<string, unknown>).policy_hits;
    if (Array.isArray(inner) && inner.length > 0) {
      const hit = inner[0] as Record<string, unknown>;
      const result = lower(hit.result);
      if (result === 'deny' || result === 'default_deny')
        return { excluded: true, reason: 'policy_deny' };
      const rla = lower(hit.rate_limiter_action);
      if (rla && rla !== 'rate_limiter_action_none' && rla !== 'none' && rla !== 'allow')
        return { excluded: true, reason: 'rate_limited' };
      const mum = lower(hit.malicious_user_mitigate_action);
      if (mum && mum !== 'mum_none')
        return { excluded: true, reason: 'mum_action' };
      const risk = lower(hit.ip_risk);
      if (risk === 'high_risk')
        return { excluded: true, reason: 'ip_high_risk' };
    }
  }
  return { excluded: false, reason: '' };
}

/**
 * Fetch EVERY access-log record in [start, end] and stream batches to `onLogs`.
 *
 * The F5 XC access_logs API returns at most `limit` (≤500) rows per request, so a single
 * non-scrolled fetch silently drops everything past 500 — which is how clients went missing.
 * This drains the range completely:
 *   1. Try `scroll: true` and follow `scroll_id` to exhaustion (captures any volume).
 *   2. If the tenant doesn't return a `scroll_id` AND the first page is saturated (== limit),
 *      bisect the time range and recurse — so the overflow is captured, not dropped.
 * `saturation.gaps` counts ranges that stayed saturated even at the 1-second bisection floor.
 */
async function fetchRangeComplete(
  namespace: string,
  query: string,
  start: string,
  end: string,
  controller: AdaptiveConcurrencyController,
  onLogs: (logs: unknown[]) => void,
  saturation: { gaps: number },
  depth = 0,
): Promise<void> {
  const first = await withRetry(
    () => apiClient.post<AccessLogResponse>(
      `/api/data/namespaces/${namespace}/access_logs`,
      { query, namespace, start_time: start, end_time: end, scroll: true, limit: PAGE_SIZE },
    ),
    'chunk', controller,
  );
  const firstLogs = (first.logs as unknown[]) || [];

  // Scroll path — drains the whole range regardless of size.
  if (first.scroll_id) {
    if (firstLogs.length) onLogs(firstLogs);
    let scrollId: string | undefined = first.scroll_id;
    let guard = 0;
    while (scrollId && guard++ < 100000) {
      const currentId: string = scrollId;
      const page = await withRetry<AccessLogResponse>(
        () => apiClient.post<AccessLogResponse>(
          `/api/data/namespaces/${namespace}/access_logs/scroll`,
          { scroll_id: currentId, namespace },
        ),
        'scroll', controller,
      );
      const pageLogs = (page.logs as unknown[]) || [];
      if (!pageLogs.length) break;
      onLogs(pageLogs);
      scrollId = page.scroll_id;
    }
    return;
  }

  // No scroll support. A saturated first page means the range holds > PAGE_SIZE rows, so
  // discard it and bisect — re-fetching the halves captures everything (no client dropped).
  if (firstLogs.length >= PAGE_SIZE) {
    const sMs = new Date(start).getTime();
    const eMs = new Date(end).getTime();
    if (eMs - sMs > MIN_SPLIT_MS && depth < MAX_SPLIT_DEPTH) {
      const mid = new Date(sMs + Math.floor((eMs - sMs) / 2)).toISOString();
      await fetchRangeComplete(namespace, query, start, mid, controller, onLogs, saturation, depth + 1);
      await fetchRangeComplete(namespace, query, mid, end, controller, onLogs, saturation, depth + 1);
      return;
    }
    // Cannot split further but still saturated — accept what we have and flag the gap.
    if (firstLogs.length) onLogs(firstLogs);
    saturation.gaps++;
    return;
  }

  // Unsaturated, no scroll → this page is the complete range.
  if (firstLogs.length) onLogs(firstLogs);
}

/**
 * Max requests in ANY rolling 60-second window, from a per-second count map (values de-sampled).
 * This is what a token-bucket rate limiter actually reacts to — unlike a fixed calendar minute,
 * it doesn't undercount a burst that straddles a minute boundary. Two-pointer sweep over the
 * distinct active seconds (the optimal window always starts at an active second). O(n log n).
 */
export function slidingMax60(secondMap: Map<number, number>): number {
  if (secondMap.size === 0) return 0;
  const secs = [...secondMap.keys()].sort((a, b) => a - b);
  let max = 0, sum = 0, left = 0;
  for (let right = 0; right < secs.length; right++) {
    sum += secondMap.get(secs[right])!;
    while (secs[right] - secs[left] >= PEAK_WINDOW_SECONDS) { sum -= secondMap.get(secs[left])!; left++; }
    if (sum > max) max = sum;
  }
  return max;
}

function normalizeEntry(raw: unknown): Record<string, unknown> | null {
  if (typeof raw === 'string') { try { return JSON.parse(raw); } catch { return null; } }
  if (raw && typeof raw === 'object') return raw as Record<string, unknown>;
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function buildQuery(lbName: string): string {
  return `{vh_name="ves-io-http-loadbalancer-${lbName}"}`;
}

async function probeCount(ns: string, query: string, start: string, end: string): Promise<number> {
  const r = await probeVolume(ns, 'access_logs', query, start, end);
  return r.totalHits;
}

// ═══════════════════════════════════════════════════════════════════
// MAIN PIPELINE
// ═══════════════════════════════════════════════════════════════════

export async function collectUnified(
  namespace: string,
  lbName: string,
  deepWindowHours: number,
  onProgress: (p: UnifiedProgress) => void,
): Promise<UnifiedCollection> {
  const startMs = Date.now();
  let apiCalls = 0;
  const query = buildQuery(lbName);

  // Time windows
  const now = new Date();
  const endDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours()));
  const baselineStart = new Date(endDate.getTime() - 7 * 24 * 3600000).toISOString();
  const baselineEnd = endDate.toISOString();
  const deepStart = new Date(endDate.getTime() - deepWindowHours * 3600000).toISOString();
  const deepEnd = baselineEnd;

  const controller = new AdaptiveConcurrencyController({
    initialConcurrency: 3, minConcurrency: 1, maxConcurrency: 6,
    rampUpAfterSuccesses: 5, rampDownFactor: 0.5,
    yellowDelayMs: 300, redDelayMs: 3000, redCooldownMs: 10000,
  });

  const report = (phase: UnifiedProgress['phase'], stage: string, msg: string, pct: number) =>
    onProgress({ phase, stage, message: msg, progress: pct, apiCalls });

  // ════════════════════════════════════════════════════════════════
  // PHASE A — Weekly Baseline (14 calls, ~5-10s)
  // ════════════════════════════════════════════════════════════════

  // A1: LB config — also captures the rate-limit KEY (user-identification) and any existing limit
  report('baseline', 'LB Config', 'Loading LB configuration...', 1);
  let domains: string[] = [];
  let userIdMode = 'client IP (default)';
  let hasUserIdPolicy = false;
  let existingRateLimit = false;
  try {
    const lb = await withRetry(() => apiClient.getLoadBalancer(namespace, lbName), 'lb-config', controller);
    apiCalls++;
    const spec = (lb as Record<string, unknown>).spec as Record<string, unknown> | undefined;
    domains = (spec?.domains as string[]) ?? [];
    const uidRef = spec?.user_identification as { name?: string } | undefined;
    if (uidRef && uidRef.name) { hasUserIdPolicy = true; userIdMode = `User Identification policy "${uidRef.name}"`; }
    existingRateLimit = !!(spec?.rate_limit || spec?.api_rate_limit);
  } catch (err) {
    throw new Error(`Cannot load LB "${lbName}": ${err instanceof Error ? err.message : err}`);
  }

  // A2: 7-day total probe
  report('baseline', 'Volume', 'Probing 7-day traffic volume...', 3);
  let totalRequests7d = 0;
  try {
    totalRequests7d = await withRetry(() => probeCount(namespace, query, baselineStart, baselineEnd), '7d-probe', controller);
    apiCalls++;
  } catch { /* non-critical */ }

  // A3: Filter breakdown aggregation (7-day)
  report('baseline', 'Filters', 'Fetching filter breakdown...', 5);
  const filterBreakdown: FilterBreakdown = { waf_block: 0, bot_malicious: 0, good_bot: 0, policy_deny: 0, mum_action: 0, ip_high_risk: 0, rate_limited: 0, total: 0 };
  try {
    const agg = await withRetry(
      () => fetchBatchAggregation(namespace, 'access_logs', query, baselineStart, baselineEnd, [
        { field: 'waf_action', topk: 10 }, { field: 'bot_class', topk: 10 }, { field: 'ip_risk', topk: 5 },
      ]),
      'filter-agg', controller,
    );
    apiCalls++;
    filterBreakdown.waf_block = agg.waf_action?.filter(b => b.key.toLowerCase() === 'block').reduce((s, b) => s + b.count, 0) ?? 0;
    filterBreakdown.bot_malicious = agg.bot_class?.filter(b => { const k = b.key.toLowerCase(); return k === 'bad_bot' || k === 'malicious'; }).reduce((s, b) => s + b.count, 0) ?? 0;
    filterBreakdown.good_bot = agg.bot_class?.filter(b => { const k = b.key.toLowerCase(); return k === 'good_bot' || k === 'search_engine'; }).reduce((s, b) => s + b.count, 0) ?? 0;
    filterBreakdown.ip_high_risk = agg.ip_risk?.filter(b => b.key.toLowerCase() === 'high_risk').reduce((s, b) => s + b.count, 0) ?? 0;
    filterBreakdown.total = filterBreakdown.waf_block + filterBreakdown.bot_malicious + filterBreakdown.good_bot + filterBreakdown.ip_high_risk;
  } catch { /* non-critical */ }

  // A4: Daily probes (7 calls)
  report('baseline', 'Daily Shape', 'Probing daily traffic shape...', 7);
  const dayMs = 24 * 3600000;
  const dailyShape: DailyBucket[] = [];
  for (let t = new Date(baselineStart).getTime(); t < endDate.getTime(); t += dayMs) {
    const dStart = new Date(t).toISOString();
    const dEnd = new Date(Math.min(t + dayMs, endDate.getTime())).toISOString();
    try {
      const count = await withRetry(() => probeCount(namespace, query, dStart, dEnd), `day-probe`, controller);
      apiCalls++;
      dailyShape.push({ dayStart: dStart, count });
    } catch {
      dailyShape.push({ dayStart: dStart, count: 0 });
      apiCalls++;
    }
  }

  // A5: Top users aggregation (whole 7-day window)
  report('baseline', 'Top Users', 'Identifying top users (7-day)...', 15);
  let topUsers7d: AggBucket[] = [];
  try {
    const result = await withRetry(
      () => fetchBatchAggregation(namespace, 'access_logs', query, baselineStart, baselineEnd, [
        { field: 'user', topk: TOP_USERS_AGG },
      ]),
      'top-users-7d', controller,
    );
    apiCalls++;
    topUsers7d = result.user ?? [];
  } catch { /* non-critical */ }

  console.log(`[Unified] Phase A done: ${totalRequests7d.toLocaleString()} 7d requests, ${dailyShape.length} days, ${topUsers7d.length} top users, ${filterBreakdown.total} filtered`);

  // ════════════════════════════════════════════════════════════════
  // PHASE B — Deep Scan (variable calls)
  // ════════════════════════════════════════════════════════════════

  // B1: Probe deep window
  report('deep', 'Probe', `Probing ${deepWindowHours}h window...`, 20);
  let deepTotalExpected = 0;
  try {
    deepTotalExpected = await withRetry(() => probeCount(namespace, query, deepStart, deepEnd), 'deep-probe', controller);
    apiCalls++;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('index_closed')) throw new Error(`Logs for this time range are unavailable (index closed). Try a more recent window.`);
    throw new Error(`Deep probe failed: ${msg}`);
  }
  if (deepTotalExpected === 0) throw new Error(`No logs for "${lbName}" in the last ${deepWindowHours}h.`);

  // B2: Coarse time-chunks for parallelism + progress (each chunk is fully DRAINED downstream).
  // Scroll handles any per-chunk volume, so scale the chunk COUNT to the data: ≤1 page ⇒ 1 chunk
  // (no wasted calls on tiny windows); huge windows ⇒ more, smaller chunks so each scroll context
  // stays bounded and progress is granular.
  const windowSeconds = deepWindowHours * 3600;
  const chunkCount = Math.max(1, Math.min(MAX_CHUNKS, Math.ceil(deepTotalExpected / RECORDS_PER_CHUNK)));
  let chunkSeconds = Math.max(MIN_CHUNK_SECONDS, Math.ceil(windowSeconds / chunkCount));
  chunkSeconds = Math.min(chunkSeconds, windowSeconds);

  const chunks: Array<{ start: string; end: string }> = [];
  for (let t = new Date(deepStart).getTime(); t < new Date(deepEnd).getTime(); t += chunkSeconds * 1000) {
    chunks.push({
      start: new Date(t).toISOString(),
      end: new Date(Math.min(t + chunkSeconds * 1000, new Date(deepEnd).getTime())).toISOString(),
    });
  }

  console.log(`[Unified] Phase B: draining ${deepTotalExpected.toLocaleString()} expected across ${chunks.length} chunks (~${chunkSeconds}s each, complete scan)`);
  report('deep', 'Fetching', `Fetching ${deepTotalExpected.toLocaleString()} logs (complete scan)...`, 22);

  // B3+B4 STREAMED: every record is ingested as it arrives — bounds memory, de-samples inline,
  // and (via fetchRangeComplete) drains each chunk fully so no client IP is dropped.
  const deepFilter: FilterBreakdown = { waf_block: 0, bot_malicious: 0, good_bot: 0, policy_deny: 0, mum_action: 0, ip_high_risk: 0, rate_limited: 0, total: 0 };
  const userMinuteMap = new Map<string, Map<string, number>>();    // calendar-minute counts (median/total/simulator)
  const userSecondMap = new Map<string, Map<number, number>>();    // per-second counts (rolling-60s peak)
  const secondFallback = new Set<string>();                        // users that hit a cap → use calendar peak
  let globalSecEntries = 0;
  const allUsersSet = new Set<string>();
  const saturation = { gaps: 0 };
  let cleanCount = 0;
  let deepTotalFetched = 0;
  let sampleRateMax = 1;
  let sampledRecords = 0;

  const ingest = (rawLogs: unknown[]) => {
    for (const raw of rawLogs) {
      deepTotalFetched++;
      const entry = normalizeEntry(raw);
      if (!entry) continue;
      const userId = (entry.user as string) || (entry.src_ip as string) || '';
      const ts = (entry['@timestamp'] as string) || (entry.time as string) || '';
      if (!userId || !ts) continue;
      allUsersSet.add(userId);
      const { excluded, reason } = isExcluded(entry);
      if (excluded) {
        (deepFilter as unknown as Record<string, number>)[reason] = ((deepFilter as unknown as Record<string, number>)[reason] ?? 0) + 1;
        deepFilter.total++;
        continue;
      }
      cleanCount++;
      // De-sample: each stored record represents `sample_rate` real requests.
      const sr = Math.max(1, Math.round(Number(entry.sample_rate) || 1));
      if (sr > 1) { sampledRecords++; if (sr > sampleRateMax) sampleRateMax = sr; }

      // Calendar-minute bucket (for median/total/simulator)
      const minuteKey = ts.slice(0, 16);
      let minuteMap = userMinuteMap.get(userId);
      if (!minuteMap) { minuteMap = new Map(); userMinuteMap.set(userId, minuteMap); }
      minuteMap.set(minuteKey, (minuteMap.get(minuteKey) ?? 0) + sr);

      // Per-second bucket (for the rolling-60s peak) — bounded by per-user + global caps.
      const ms = new Date(ts).getTime();
      if (!Number.isNaN(ms)) {
        const sec = Math.floor(ms / 1000);
        let secMap = userSecondMap.get(userId);
        if (secMap) {
          if (secMap.has(sec)) secMap.set(sec, secMap.get(sec)! + sr);
          else if (secMap.size < MAX_SEC_PER_USER && globalSecEntries < GLOBAL_SEC_BUDGET) { secMap.set(sec, sr); globalSecEntries++; }
          else secondFallback.add(userId); // cap hit → calendar peak for this user
        } else if (globalSecEntries < GLOBAL_SEC_BUDGET) {
          secMap = new Map([[sec, sr]]); userSecondMap.set(userId, secMap); globalSecEntries++;
        } else {
          secondFallback.add(userId); // global budget exhausted → calendar peak
        }
      }
    }
  };

  let chunksDone = 0;
  let chunksActive = 0;
  const chunkQueue = [...chunks];

  await new Promise<void>((resolve) => {
    function dispatch() {
      while (chunksActive < controller.concurrency && chunkQueue.length > 0) {
        const chunk = chunkQueue.shift()!;
        chunksActive++;
        fetchRangeComplete(namespace, query, chunk.start, chunk.end, controller, ingest, saturation)
          .catch(err => {
            const msg = err instanceof Error ? err.message : String(err);
            if (!msg.includes('index_closed')) console.error(`[Unified] Chunk failed:`, msg);
          })
          .finally(() => {
            chunksActive--;
            chunksDone++;
            apiCalls++;
            if (chunksDone % 5 === 0 || chunksDone === chunks.length) {
              const stats = controller.getStats();
              report('deep', 'Fetching',
                `${deepTotalFetched.toLocaleString()} / ${deepTotalExpected.toLocaleString()} logs — chunk ${chunksDone}/${chunks.length} ×${stats.concurrency}${stats.rateLimitHits > 0 ? ` (${stats.rateLimitHits} retried)` : ''}`,
                22 + Math.round((chunksDone / chunks.length) * 55));
            }
            if (chunksDone === chunks.length) resolve();
            else dispatch();
          });
      }
    }
    if (chunks.length === 0) resolve();
    else dispatch();
  });

  const fetchPct = deepTotalExpected > 0 ? Math.round((deepTotalFetched / deepTotalExpected) * 100) : 100;
  console.log(`[Unified] Phase B fetch: ${deepTotalFetched.toLocaleString()} / ${deepTotalExpected.toLocaleString()} (${fetchPct}%), ${saturation.gaps} coverage gap(s), sampleRateMax=${sampleRateMax}`);

  // B4: finalize — build per-user arrays + sampling stats
  report('processing', 'Processing', `Processing ${cleanCount.toLocaleString()} clean entries...`, 80);

  const userMinuteCounts: Record<string, number[]> = {};
  const userPeakRpm: Record<string, number> = {};
  let peakFallbackUsers = 0;
  for (const [userId, minuteMap] of userMinuteMap) {
    const minuteVals = [...minuteMap.values()];
    userMinuteCounts[userId] = minuteVals;
    const calendarPeak = minuteVals.length ? Math.max(...minuteVals) : 0;
    const secMap = userSecondMap.get(userId);
    if (secMap && !secondFallback.has(userId)) {
      // Rolling-60s peak (≥ calendar peak; corrects boundary-straddling bursts).
      userPeakRpm[userId] = Math.max(calendarPeak, slidingMax60(secMap));
    } else {
      // Sustained user or cap hit → calendar peak (accurate for steady traffic).
      userPeakRpm[userId] = calendarPeak;
      if (secMap) peakFallbackUsers++;
    }
  }
  const sampledShare = cleanCount > 0 ? sampledRecords / cleanCount : 0;

  const runtimeMs = Date.now() - startMs;

  console.log(
    `[Unified] DONE: Phase A (${totalRequests7d.toLocaleString()} 7d) + Phase B (${deepTotalFetched.toLocaleString()} fetched, ${cleanCount} clean, ${userMinuteMap.size} users). ` +
    `${apiCalls} calls, ${(runtimeMs / 1000).toFixed(1)}s`
  );

  report('complete', 'Done',
    `${cleanCount.toLocaleString()} clean logs, ${userMinuteMap.size} users — ${apiCalls} API calls in ${(runtimeMs / 1000).toFixed(1)}s`,
    100);

  return {
    lbName, namespace, domains,
    baselineStart, baselineEnd,
    totalRequests7d, dailyShape, filterBreakdown, topUsers7d,
    deepStart, deepEnd, deepWindowHours,
    deepTotalExpected, deepTotalFetched, deepCleanLogs: cleanCount,
    deepFilterBreakdown: deepFilter,
    userMinuteCounts, userPeakRpm, peakWindowSeconds: PEAK_WINDOW_SECONDS, peakFallbackUsers,
    allUsers: [...allUsersSet],
    sampleRateMax, sampledShare, coverageGaps: saturation.gaps,
    userIdMode, hasUserIdPolicy, existingRateLimit,
    apiCallsUsed: apiCalls, runtimeMs,
  };
}
