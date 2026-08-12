/**
 * Aggregation API Client — shared across Log Analyzer, DDoS Advisor, API Shield, Rate Limit Advisor
 *
 * Instead of scrolling thousands of raw log records, this client calls F5 XC's
 * server-side aggregation endpoint to get pre-counted field distributions.
 *
 * Endpoint: POST /api/data/namespaces/{ns}/access_logs/aggregation
 *           POST /api/data/namespaces/{ns}/app_security/events/aggregation
 *
 * Each aggregation query returns top-k (value, count) buckets for a single field.
 * Multiple field aggregations can be batched into one request body.
 */

import { apiClient } from '../api';

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export interface AggBucket {
  key: string;
  count: number;
}

/** Multi-field aggregation bucket — keyed by combination of field values */
export interface MultiFieldBucket {
  keys: Record<string, string>;
  count: number;
}

/** Numeric aggregation results — from batched min/max/avg */
export interface NumericAggResult {
  avg: number | null;
  min: number | null;
  max: number | null;
}

/** Approximate distinct count from cardinality aggregation */
export interface CardinalityResult {
  count: number;
}

export type AggEndpoint = 'access_logs' | 'app_security/events';

// ═══════════════════════════════════════════════════════════════════
// RESPONSE PARSING
// ═══════════════════════════════════════════════════════════════════

/**
 * F5 XC wraps each aggregation result in its type name. E.g. for a field_aggregation,
 * the response is:
 *   resp.aggs["my_agg"] = { field_aggregation: { buckets: [...] } }
 *
 * This helper unwraps the type wrapper if present, so downstream parsers just see
 * the inner data object. Also tolerates responses where the wrapper is omitted
 * (older API versions or direct-shape responses).
 */
function unwrapAgg(raw: unknown, wrapperKey: string): unknown {
  if (!raw || typeof raw !== 'object') return raw;
  const obj = raw as Record<string, unknown>;
  const wrapped = obj[wrapperKey];
  if (wrapped && typeof wrapped === 'object') return wrapped;
  return obj;
}

function parseBuckets(raw: unknown): AggBucket[] {
  const inner = unwrapAgg(raw, 'field_aggregation') as Record<string, unknown> | null;
  if (!inner || typeof inner !== 'object') return [];
  const buckets = inner.buckets;
  if (!Array.isArray(buckets)) return [];
  return buckets
    .map((b: unknown) => {
      if (!b || typeof b !== 'object') return null;
      const entry = b as Record<string, unknown>;
      const key = entry.key ?? entry.value ?? '';
      const count = Number(entry.count ?? entry.doc_count ?? 0);
      return key !== '' && key !== null && key !== undefined
        ? { key: String(key), count }
        : null;
    })
    .filter(Boolean) as AggBucket[];
}

/** Parse multi-field aggregation buckets (each bucket has a `keys` map). */
function parseMultiFieldBuckets(raw: unknown): MultiFieldBucket[] {
  const inner = unwrapAgg(raw, 'multi_field_aggregation') as Record<string, unknown> | null;
  if (!inner || typeof inner !== 'object') return [];
  const buckets = inner.buckets;
  if (!Array.isArray(buckets)) return [];
  return buckets
    .map((b: unknown) => {
      if (!b || typeof b !== 'object') return null;
      const entry = b as Record<string, unknown>;
      const keys = entry.keys;
      const count = Number(entry.count ?? entry.doc_count ?? 0);
      if (!keys || typeof keys !== 'object') return null;
      const normKeys: Record<string, string> = {};
      for (const [k, v] of Object.entries(keys as Record<string, unknown>)) {
        normKeys[k] = String(v ?? '');
      }
      return { keys: normKeys, count };
    })
    .filter(Boolean) as MultiFieldBucket[];
}

/** Parse a single numeric-result aggregation (min/max/avg) — returns null on missing. */
function parseNumericValue(raw: unknown, wrapperKey: 'min_aggregation' | 'max_aggregation' | 'avg_aggregation'): number | null {
  const inner = unwrapAgg(raw, wrapperKey) as Record<string, unknown> | null;
  if (!inner || typeof inner !== 'object') return null;
  const v = inner.value;
  if (v === null || v === undefined) return null;
  const n = Number(v);
  return isFinite(n) ? n : null;
}

/** Parse cardinality aggregation response. */
function parseCardinality(raw: unknown): number {
  const inner = unwrapAgg(raw, 'cardinality_aggregation') as Record<string, unknown> | null;
  if (!inner || typeof inner !== 'object') return 0;
  const c = inner.count;
  const n = Number(c);
  return isFinite(n) ? n : 0;
}

// ═══════════════════════════════════════════════════════════════════
// FIELD-NAME NORMALIZATION (client-side keys → F5 XC agg field names)
// ═══════════════════════════════════════════════════════════════════

/**
 * Client-side log entries use lowercase field names (e.g. `domain`, `waf_action`).
 * The F5 XC aggregation API's `logaccess_logKeyField` enum uses UPPERCASE names
 * (e.g. `AUTHORITY`, `REQ_PATH`) and — critically — a few client field names
 * don't map 1:1 (e.g. `domain` → `AUTHORITY`).
 *
 * This table encodes known non-identity mappings. For any field not listed,
 * we try the original lowercase name first, then UPPERCASE, then give up.
 */
const AGG_FIELD_ALIASES: Record<string, string[]> = {
  // Access log fields
  domain: ['AUTHORITY', 'DOMAIN', 'domain'],
  authority: ['AUTHORITY', 'authority'],
  req_path: ['REQ_PATH', 'req_path'],
  rsp_code: ['RSP_CODE', 'rsp_code'],
  rsp_code_class: ['RSP_CODE_CLASS', 'rsp_code_class'],
  rsp_code_details: ['RSP_CODE_DETAILS', 'rsp_code_details'],
  method: ['METHOD', 'method'],
  scheme: ['SCHEME', 'scheme'],
  src_ip: ['SRC_IP', 'src_ip'],
  src_site: ['SRC_SITE', 'src_site'],
  src_instance: ['SRC_INSTANCE', 'src_instance'],
  dst_ip: ['DST', 'dst_ip'],
  dst_site: ['DST_SITE', 'dst_site'],
  dst_instance: ['DST_INSTANCE', 'dst_instance'],
  country: ['COUNTRY', 'country'],
  city: ['CITY', 'city'],
  as_org: ['ASN', 'as_org', 'AS_ORG'],
  asn: ['ASN', 'asn'],
  api_endpoint: ['API_ENDPOINT', 'api_endpoint'],
  app_type: ['APP_TYPE', 'app_type'],
  browser_type: ['BROWSER_TYPE', 'browser_type'],
  device_type: ['DEVICE_TYPE', 'device_type'],
  tls_cipher_suite: ['TLS_CIPHER_SUITE', 'tls_cipher_suite'],
  tls_fingerprint: ['TLS_FINGERPRINT', 'tls_fingerprint'],
  tls_version: ['TLS_VERSION', 'tls_version'],
  user: ['USER', 'user'],
  user_agent: ['user_agent', 'USER_AGENT'],  // not in enum — try lowercase first
  vh_name: ['VH_NAME', 'vh_name'],
  vh_type: ['VH_TYPE', 'vh_type'],
  visitor_id: ['VISITOR_ID', 'visitor_id'],
  waf_action: ['waf_action', 'WAF_ACTION'],  // not in enum — try lowercase first
  bot_class: ['bot_class', 'BOT_CLASS'],     // not in enum — try lowercase first
  protocol: ['SCHEME', 'protocol', 'PROTOCOL'],
  remote_location: ['REMOTE_LOCATION', 'remote_location'],
  ja4_t: ['JA4_T', 'ja4_t'],
  // Numeric fields
  duration_with_data_tx_delay: ['DURATION_WITH_DATA_TX_DELAY', 'duration_with_data_tx_delay'],
  '@timestamp': ['TIMESTAMP', '@timestamp'],
};

/** Return the ordered list of field-name variants to try for a given client key. */
function fieldVariants(field: string): string[] {
  const alias = AGG_FIELD_ALIASES[field];
  if (alias) return alias;
  // Default: try original, then UPPERCASE variant if different
  const upper = field.toUpperCase();
  return upper === field ? [field] : [field, upper];
}

// ═══════════════════════════════════════════════════════════════════
// TIME-WINDOW CHUNKING (works around F5 XC 60s proxy timeout on large ranges)
// ═══════════════════════════════════════════════════════════════════

/**
 * F5 XC's aggregation API often times out for windows longer than ~7 days
 * (the vite proxy has a 60s timeout, and F5 processes long-window queries slowly).
 * We split any window longer than MAX_CHUNK_HOURS into parallel sub-queries and
 * merge the results client-side.
 */
const MAX_CHUNK_HOURS = 168; // 7 days
const CHUNK_CONCURRENCY = 3;

function splitTimeWindow(startTime: string, endTime: string, maxHours = MAX_CHUNK_HOURS): Array<{ start: string; end: string }> {
  const start = new Date(startTime).getTime();
  const end = new Date(endTime).getTime();
  if (!isFinite(start) || !isFinite(end) || end <= start) return [{ start: startTime, end: endTime }];
  const rangeMs = end - start;
  const chunkMs = maxHours * 3600 * 1000;
  if (rangeMs <= chunkMs) return [{ start: startTime, end: endTime }];
  const chunks: Array<{ start: string; end: string }> = [];
  let cursor = start;
  while (cursor < end) {
    const chunkEnd = Math.min(cursor + chunkMs, end);
    chunks.push({ start: new Date(cursor).toISOString(), end: new Date(chunkEnd).toISOString() });
    cursor = chunkEnd;
  }
  return chunks;
}

/** Run async fn over items with a concurrency cap. */
async function withConcurrency<T, R>(items: T[], concurrency: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const i = cursor++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

/** Merge multiple bucket arrays by summing counts per key, sort desc, keep top-K. */
function mergeBuckets(chunks: AggBucket[][], topk: number): AggBucket[] {
  const merged = new Map<string, number>();
  for (const buckets of chunks) {
    for (const b of buckets) {
      merged.set(b.key, (merged.get(b.key) || 0) + b.count);
    }
  }
  return [...merged.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, topk);
}

// ═══════════════════════════════════════════════════════════════════
// SINGLE FIELD AGGREGATION
// ═══════════════════════════════════════════════════════════════════

/**
 * Fetch aggregation for a single field. Returns sorted (desc) top-k buckets.
 *
 * Automatically chunks long time windows (> MAX_CHUNK_HOURS) into parallel
 * sub-queries and merges results — works around F5 XC's timeout on large ranges.
 *
 * Tries known field-name variants (lowercase / UPPERCASE / enum alias) in
 * order until one returns non-empty buckets.
 */
export async function fetchFieldAggregation(
  namespace: string,
  endpoint: AggEndpoint,
  query: string,
  startTime: string,
  endTime: string,
  field: string,
  topk = 50,
): Promise<AggBucket[]> {
  const chunks = splitTimeWindow(startTime, endTime);
  if (chunks.length > 1) {
    // Chunked mode: request larger top-K per chunk to reduce merge error
    const perChunkTopk = Math.max(topk, Math.min(500, topk * 2));
    // eslint-disable-next-line no-console
    console.info(`[LogAnalyzer] Chunked aggregation for '${field}' → ${chunks.length} × ≤7d windows (topk=${perChunkTopk})`);
    const chunkResults = await withConcurrency(chunks, CHUNK_CONCURRENCY, (c) =>
      fetchFieldAggregationSingle(namespace, endpoint, query, c.start, c.end, field, perChunkTopk),
    );
    return mergeBuckets(chunkResults, topk);
  }
  return fetchFieldAggregationSingle(namespace, endpoint, query, startTime, endTime, field, topk);
}

/** Single-window fetch (no chunking). Handles variant retry and empty-response diagnostics. */
async function fetchFieldAggregationSingle(
  namespace: string,
  endpoint: AggEndpoint,
  query: string,
  startTime: string,
  endTime: string,
  field: string,
  topk = 50,
): Promise<AggBucket[]> {
  const variants = fieldVariants(field);
  for (const variant of variants) {
    const aggKey = `${variant.replace(/\./g, '_').toLowerCase()}_agg`;
    try {
      const resp = await apiClient.post<Record<string, unknown>>(
        `/api/data/namespaces/${namespace}/${endpoint}/aggregation`,
        {
          namespace,
          query,
          start_time: startTime,
          end_time: endTime,
          aggs: { [aggKey]: { field_aggregation: { field: variant, topk } } },
        },
      );
      const aggs = resp.aggs as Record<string, unknown> | undefined;
      const buckets = parseBuckets(aggs?.[aggKey]);
      if (buckets.length > 0) {
        if (variant !== variants[0]) {
          // eslint-disable-next-line no-console
          console.info(`[LogAnalyzer] Aggregation field '${field}' resolved via alias '${variant}'`);
        }
        return buckets;
      }
      // eslint-disable-next-line no-console
      console.warn(
        `[LogAnalyzer] Empty buckets for field='${variant}' on ${endpoint} (window ${startTime}..${endTime}). Raw:`,
        aggs?.[aggKey],
      );
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn(`[LogAnalyzer] Aggregation attempt failed for field='${variant}' on ${endpoint}:`, err);
    }
  }
  // eslint-disable-next-line no-console
  console.warn(`[LogAnalyzer] Aggregation returned empty for field='${field}' (tried variants: ${variants.join(', ')}) on ${endpoint} (window ${startTime}..${endTime}).`);
  return [];
}

// ═══════════════════════════════════════════════════════════════════
// MULTI-FIELD AGGREGATION (batched into one request)
// ═══════════════════════════════════════════════════════════════════

export interface FieldSpec {
  field: string;
  topk?: number;
}

/**
 * Fetch multiple field aggregations in a SINGLE API request.
 * F5 XC accepts multiple keys in the `aggs` object.
 * Returns a map of field → buckets.
 *
 * Automatically chunks long time windows (> MAX_CHUNK_HOURS) — same as fetchFieldAggregation.
 */
export async function fetchBatchAggregation(
  namespace: string,
  endpoint: AggEndpoint,
  query: string,
  startTime: string,
  endTime: string,
  fields: FieldSpec[],
): Promise<Record<string, AggBucket[]>> {
  if (fields.length === 0) return {};

  const chunks = splitTimeWindow(startTime, endTime);
  if (chunks.length > 1) {
    // eslint-disable-next-line no-console
    console.info(`[LogAnalyzer] Chunked batch aggregation on ${endpoint} → ${chunks.length} × ≤7d windows, ${fields.length} fields`);
    // Boost per-chunk topk to reduce merge error
    const chunkFields: FieldSpec[] = fields.map(f => ({ field: f.field, topk: Math.max(f.topk ?? 50, Math.min(500, (f.topk ?? 50) * 2)) }));
    const chunkResults = await withConcurrency(chunks, CHUNK_CONCURRENCY, (c) =>
      fetchBatchAggregationSingle(namespace, endpoint, query, c.start, c.end, chunkFields),
    );
    // Merge per-field
    const merged: Record<string, AggBucket[]> = {};
    for (const spec of fields) {
      const perChunk = chunkResults.map(r => r[spec.field] ?? []);
      merged[spec.field] = mergeBuckets(perChunk, spec.topk ?? 50);
    }
    return merged;
  }
  return fetchBatchAggregationSingle(namespace, endpoint, query, startTime, endTime, fields);
}

async function fetchBatchAggregationSingle(
  namespace: string,
  endpoint: AggEndpoint,
  query: string,
  startTime: string,
  endTime: string,
  fields: FieldSpec[],
): Promise<Record<string, AggBucket[]>> {
  if (fields.length === 0) return {};

  // Build request with the primary variant for each field (fast path).
  const aggs: Record<string, { field_aggregation: { field: string; topk: number } }> = {};
  const primaryVariantByField: Record<string, string> = {};
  for (const { field, topk = 50 } of fields) {
    const primaryVariant = fieldVariants(field)[0];
    primaryVariantByField[field] = primaryVariant;
    aggs[`${field.replace(/\./g, '_').toLowerCase()}_agg`] = {
      field_aggregation: { field: primaryVariant, topk },
    };
  }

  let respAggs: Record<string, unknown> | undefined;
  try {
    const resp = await apiClient.post<Record<string, unknown>>(
      `/api/data/namespaces/${namespace}/${endpoint}/aggregation`,
      { namespace, query, start_time: startTime, end_time: endTime, aggs },
    );
    respAggs = resp.aggs as Record<string, unknown> | undefined;
  } catch {
    // Full failure — fall back to per-field parallel with variant retry
    return fetchParallelAggregations(namespace, endpoint, query, startTime, endTime, fields);
  }

  const out: Record<string, AggBucket[]> = {};
  const emptyFields: FieldSpec[] = [];
  for (const spec of fields) {
    const aggKey = `${spec.field.replace(/\./g, '_').toLowerCase()}_agg`;
    const buckets = parseBuckets(respAggs?.[aggKey]);
    if (buckets.length > 0) {
      out[spec.field] = buckets;
    } else {
      // Try variant-aware per-field fetch for fields that came back empty
      emptyFields.push(spec);
    }
  }
  if (emptyFields.length > 0) {
    const retried = await fetchParallelAggregations(namespace, endpoint, query, startTime, endTime, emptyFields);
    Object.assign(out, retried);
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════
// PARALLEL INDIVIDUAL AGGREGATIONS (fallback / when batch fails)
// ═══════════════════════════════════════════════════════════════════

/**
 * Run multiple single-field aggregations in parallel.
 * Use this when the batch endpoint returns partial results.
 */
export async function fetchParallelAggregations(
  namespace: string,
  endpoint: AggEndpoint,
  query: string,
  startTime: string,
  endTime: string,
  fields: FieldSpec[],
): Promise<Record<string, AggBucket[]>> {
  const results = await Promise.allSettled(
    fields.map(({ field, topk }) =>
      fetchFieldAggregation(namespace, endpoint, query, startTime, endTime, field, topk ?? 50)
        .then(buckets => ({ field, buckets })),
    ),
  );

  const out: Record<string, AggBucket[]> = {};
  for (const r of results) {
    if (r.status === 'fulfilled') out[r.value.field] = r.value.buckets;
    else out[(r as PromiseRejectedResult).reason?.field ?? 'unknown'] = [];
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════
// VOLUME PROBE (total_hits only, no records)
// ═══════════════════════════════════════════════════════════════════

interface ProbeResponse {
  total_hits?: number | string | { value: number };
  logs?: unknown[];
  events?: unknown[];
}

export interface VolumeProbeResult {
  totalHits: number;
  sampleRate: number;
}

export async function probeVolume(
  namespace: string,
  endpoint: AggEndpoint,
  query: string,
  startTime: string,
  endTime: string,
): Promise<VolumeProbeResult> {
  const chunks = splitTimeWindow(startTime, endTime);
  if (chunks.length > 1) {
    // eslint-disable-next-line no-console
    console.info(`[LogAnalyzer] Chunked probeVolume on ${endpoint} → ${chunks.length} × ≤7d windows`);
    const results = await withConcurrency(chunks, CHUNK_CONCURRENCY, (c) =>
      probeVolumeSingle(namespace, endpoint, query, c.start, c.end),
    );
    const totalHits = results.reduce((s, r) => s + r.totalHits, 0);
    // Sample rate: take the first non-1 rate we find (should be uniform across chunks)
    const sampleRate = results.find(r => r.sampleRate !== 1)?.sampleRate ?? 1;
    return { totalHits, sampleRate };
  }
  return probeVolumeSingle(namespace, endpoint, query, startTime, endTime);
}

async function probeVolumeSingle(
  namespace: string,
  endpoint: AggEndpoint,
  query: string,
  startTime: string,
  endTime: string,
): Promise<VolumeProbeResult> {
  const path = endpoint === 'access_logs'
    ? `/api/data/namespaces/${namespace}/access_logs`
    : `/api/data/namespaces/${namespace}/app_security/events`;

  try {
    const resp = await apiClient.post<ProbeResponse>(path, {
      namespace, query, start_time: startTime, end_time: endTime, scroll: false, limit: 1,
    });

    const raw = resp.total_hits;
    let totalHits = 0;
    if (typeof raw === 'number' && isFinite(raw)) totalHits = Math.floor(raw);
    else if (typeof raw === 'string') totalHits = parseInt(raw, 10) || 0;
    else if (raw && typeof raw === 'object' && 'value' in (raw as Record<string, unknown>)) {
      totalHits = parseInt(String((raw as Record<string, unknown>).value), 10) || 0;
    }

    // Extract sample_rate from the first log entry if available
    let sampleRate = 1;
    const firstEntry = (resp.logs ?? resp.events)?.[0];
    if (firstEntry) {
      let parsed: Record<string, unknown> = {};
      if (typeof firstEntry === 'string') {
        try { parsed = JSON.parse(firstEntry); } catch { /* ignore */ }
      } else {
        parsed = firstEntry as Record<string, unknown>;
      }
      const sr = parsed.sample_rate;
      if (typeof sr === 'number' && sr > 0 && sr <= 1) sampleRate = sr;
    }

    // eslint-disable-next-line no-console
    console.debug(
      `[probeVolume] ${endpoint} [${startTime}..${endTime}]: total_hits=${totalHits.toLocaleString()}, sample_rate=${sampleRate}`,
    );

    return { totalHits, sampleRate };
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(`[probeVolume] ${endpoint} [${startTime}..${endTime}] FAILED:`, err);
    return { totalHits: 0, sampleRate: 1 };
  }
}

// ═══════════════════════════════════════════════════════════════════
// HOURLY VOLUME SCAN (for time series charts)
// ═══════════════════════════════════════════════════════════════════

export interface HourlyBucket {
  start: string;
  end: string;
  label: string;
  totalHits: number;
}

/**
 * Probes hourly (or N-hour) buckets to build a time series.
 * Uses limit=1 per bucket — very lightweight (same as DDoS Advisor Phase 1).
 * bucketHours: 1 for ≤24h windows, 6 for longer windows.
 */
export async function scanHourlyVolume(
  namespace: string,
  endpoint: AggEndpoint,
  query: string,
  startTime: string,
  endTime: string,
  bucketHours = 1,
  onProgress?: (done: number, total: number) => void,
): Promise<HourlyBucket[]> {
  const start = new Date(startTime).getTime();
  const end = new Date(endTime).getTime();
  const bucketMs = bucketHours * 3600 * 1000;

  // Build time buckets
  const buckets: Array<{ start: string; end: string; label: string }> = [];
  let cursor = start;
  while (cursor < end) {
    const bucketEnd = Math.min(cursor + bucketMs, end);
    const d = new Date(cursor);
    const label = bucketHours >= 24
      ? `${(d.getUTCMonth() + 1).toString().padStart(2, '0')}/${d.getUTCDate().toString().padStart(2, '0')}`
      : bucketHours >= 6
      ? `${(d.getUTCMonth() + 1).toString().padStart(2, '0')}/${d.getUTCDate().toString().padStart(2, '0')} ${d.getUTCHours().toString().padStart(2, '0')}:00`
      : `${(d.getUTCMonth() + 1).toString().padStart(2, '0')}/${d.getUTCDate().toString().padStart(2, '0')} ${d.getUTCHours().toString().padStart(2, '0')}:00`;
    buckets.push({ start: new Date(cursor).toISOString(), end: new Date(bucketEnd).toISOString(), label });
    cursor = bucketEnd;
  }

  const path = endpoint === 'access_logs'
    ? `/api/data/namespaces/${namespace}/access_logs`
    : `/api/data/namespaces/${namespace}/app_security/events`;

  // Run probes with controlled concurrency (max 5 at a time)
  const CONCURRENCY = 5;
  const results: HourlyBucket[] = new Array(buckets.length);
  let completed = 0;

  const queue = [...buckets.keys()];
  const active = new Set<number>();

  await new Promise<void>((resolve, _reject) => {
    function dispatch() {
      while (active.size < CONCURRENCY && queue.length > 0) {
        const idx = queue.shift()!;
        active.add(idx);
        const b = buckets[idx];
        apiClient.post<ProbeResponse>(path, {
          namespace, query, start_time: b.start, end_time: b.end, scroll: false, limit: 1,
        })
          .then(resp => {
            const raw = resp.total_hits;
            let hits = 0;
            if (typeof raw === 'number' && isFinite(raw)) hits = Math.floor(raw);
            else if (typeof raw === 'string') hits = parseInt(raw, 10) || 0;
            else if (raw && typeof raw === 'object' && 'value' in (raw as Record<string, unknown>)) {
              hits = parseInt(String((raw as Record<string, unknown>).value), 10) || 0;
            }
            results[idx] = { ...b, totalHits: hits };
          })
          .catch(() => { results[idx] = { ...b, totalHits: 0 }; })
          .finally(() => {
            active.delete(idx);
            completed++;
            onProgress?.(completed, buckets.length);
            if (completed === buckets.length) resolve();
            else dispatch();
          });
      }
    }
    if (buckets.length === 0) { resolve(); return; }
    dispatch();
  });

  return results;
}

// ═══════════════════════════════════════════════════════════════════
// MULTI-FIELD AGGREGATION (compound key — API_ENDPOINT+METHOD etc.)
// ═══════════════════════════════════════════════════════════════════

/**
 * Fetch a multi-field aggregation — returns buckets keyed by combination of field values.
 *
 * On access_logs, the `field` value must be one of the enumerated compound keys:
 *   - `VH_NAME_NAMESPACE`
 *   - `API_ENDPOINT_METHOD`
 *   - `API_ENDPOINT_METHOD_RSP_CODE_CLASS`
 *
 * On app_security/events, additional combinations may be supported.
 *
 * Response bucket shape: `{ keys: { FIELD1: value, FIELD2: value }, count }`.
 */
export async function fetchMultiFieldAggregation(
  namespace: string,
  endpoint: AggEndpoint,
  query: string,
  startTime: string,
  endTime: string,
  compoundKey: string,
  topk = 100,
): Promise<MultiFieldBucket[]> {
  const aggKey = `${compoundKey.toLowerCase()}_multi_agg`;
  try {
    const resp = await apiClient.post<Record<string, unknown>>(
      `/api/data/namespaces/${namespace}/${endpoint}/aggregation`,
      {
        namespace,
        query,
        start_time: startTime,
        end_time: endTime,
        aggs: {
          [aggKey]: { multi_field_aggregation: { field: compoundKey, topk } },
        },
      },
    );
    const aggs = resp.aggs as Record<string, unknown> | undefined;
    return parseMultiFieldBuckets(aggs?.[aggKey]);
  } catch {
    return [];
  }
}

// ═══════════════════════════════════════════════════════════════════
// NUMERIC AGGREGATIONS (min / max / avg — batched in one request)
// ═══════════════════════════════════════════════════════════════════

/**
 * Fetch min, max, and avg for a numeric field in a single request.
 * F5 XC access_logs only accepts numeric aggregations on:
 *   - `DURATION_WITH_DATA_TX_DELAY`
 *   - `TIMESTAMP`
 * Other fields will return nulls.
 */
export async function fetchNumericAggregations(
  namespace: string,
  endpoint: AggEndpoint,
  query: string,
  startTime: string,
  endTime: string,
  field: string,
): Promise<NumericAggResult> {
  const chunks = splitTimeWindow(startTime, endTime);
  if (chunks.length > 1) {
    const results = await withConcurrency(chunks, CHUNK_CONCURRENCY, (c) =>
      fetchNumericAggregationsSingle(namespace, endpoint, query, c.start, c.end, field),
    );
    // Merge: avg = mean of non-null avgs (unweighted approx; F5 XC doesn't expose per-chunk counts here)
    const avgs = results.map(r => r.avg).filter((v): v is number => v !== null);
    const mins = results.map(r => r.min).filter((v): v is number => v !== null);
    const maxs = results.map(r => r.max).filter((v): v is number => v !== null);
    return {
      avg: avgs.length > 0 ? avgs.reduce((a, b) => a + b, 0) / avgs.length : null,
      min: mins.length > 0 ? Math.min(...mins) : null,
      max: maxs.length > 0 ? Math.max(...maxs) : null,
    };
  }
  return fetchNumericAggregationsSingle(namespace, endpoint, query, startTime, endTime, field);
}

async function fetchNumericAggregationsSingle(
  namespace: string,
  endpoint: AggEndpoint,
  query: string,
  startTime: string,
  endTime: string,
  field: string,
): Promise<NumericAggResult> {
  const variants = fieldVariants(field);
  const base = field.toLowerCase().replace(/\./g, '_');
  for (const variant of variants) {
    const aggs = {
      [`${base}_min`]: { min_aggregation: { field: variant } },
      [`${base}_max`]: { max_aggregation: { field: variant } },
      [`${base}_avg`]: { avg_aggregation: { field: variant } },
    };
    try {
      const resp = await apiClient.post<Record<string, unknown>>(
        `/api/data/namespaces/${namespace}/${endpoint}/aggregation`,
        { namespace, query, start_time: startTime, end_time: endTime, aggs },
      );
      const respAggs = (resp.aggs ?? {}) as Record<string, unknown>;
      const result: NumericAggResult = {
        min: parseNumericValue(respAggs[`${base}_min`], 'min_aggregation'),
        max: parseNumericValue(respAggs[`${base}_max`], 'max_aggregation'),
        avg: parseNumericValue(respAggs[`${base}_avg`], 'avg_aggregation'),
      };
      if (result.avg !== null || result.min !== null || result.max !== null) {
        if (variant !== variants[0]) {
          // eslint-disable-next-line no-console
          console.info(`[LogAnalyzer] Numeric aggregation field '${field}' resolved via alias '${variant}'`);
        }
        return result;
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn(`[LogAnalyzer] Numeric aggregation attempt failed for field='${variant}':`, err);
    }
  }
  return { avg: null, min: null, max: null };
}

// ═══════════════════════════════════════════════════════════════════
// CARDINALITY (approximate distinct-value count)
// ═══════════════════════════════════════════════════════════════════

export async function fetchCardinality(
  namespace: string,
  endpoint: AggEndpoint,
  query: string,
  startTime: string,
  endTime: string,
  field: string,
): Promise<CardinalityResult> {
  const variants = fieldVariants(field);
  const aggKey = `${field.toLowerCase().replace(/\./g, '_')}_card`;
  for (const variant of variants) {
    try {
      const resp = await apiClient.post<Record<string, unknown>>(
        `/api/data/namespaces/${namespace}/${endpoint}/aggregation`,
        {
          namespace,
          query,
          start_time: startTime,
          end_time: endTime,
          aggs: { [aggKey]: { cardinality_aggregation: { field: variant } } },
        },
      );
      const aggs = resp.aggs as Record<string, unknown> | undefined;
      const c = parseCardinality(aggs?.[aggKey]);
      if (c > 0) return { count: c };
    } catch {
      // try next variant
    }
  }
  return { count: 0 };
}

// ═══════════════════════════════════════════════════════════════════
// N+1 BREAKDOWN (primary field + per-top-value breakdown aggregations)
// ═══════════════════════════════════════════════════════════════════

export interface NestedBreakdownEntry {
  primaryValue: string;
  primaryCount: number;
  breakdowns: Record<string, AggBucket[]>; // keyed by breakdown field
}

/**
 * Cross-tabulate a primary field × breakdown fields on the FULL dataset by:
 *   1. Aggregating the primary field to get top-K values.
 *   2. For each top primary value, running parallel aggregations on each breakdown
 *      field with the query narrowed to that primary value.
 *
 * Total API calls: 1 + (topPrimary × breakdownFields.length).
 * With controlled concurrency to avoid rate-limit issues.
 *
 * This handles ARBITRARY combinations — the pre-defined compound-key restriction
 * of `multi_field_aggregation` does not apply here.
 */
export async function fetchNestedBreakdown(
  namespace: string,
  endpoint: AggEndpoint,
  baseQuery: string,
  startTime: string,
  endTime: string,
  primaryField: string,
  breakdownFields: string[],
  topPrimary = 25,
  topBreakdown = 50,
  onProgress?: (done: number, total: number) => void,
): Promise<NestedBreakdownEntry[]> {
  // Step 1: top-K primary values
  const primaryBuckets = await fetchFieldAggregation(
    namespace, endpoint, baseQuery, startTime, endTime, primaryField, topPrimary,
  );
  if (primaryBuckets.length === 0) return [];

  const results: NestedBreakdownEntry[] = new Array(primaryBuckets.length);
  const totalCalls = primaryBuckets.length * Math.max(1, breakdownFields.length);
  let completed = 0;

  // Step 2: for each top primary value, batch its breakdown aggregations
  const CONCURRENCY = 4;
  const queue: number[] = primaryBuckets.map((_, i) => i);
  const active = new Set<number>();

  await new Promise<void>((resolve) => {
    const dispatch = () => {
      while (active.size < CONCURRENCY && queue.length > 0) {
        const idx = queue.shift()!;
        active.add(idx);

        const bucket = primaryBuckets[idx];
        // Extend query with the primary field constraint
        const narrowedQuery = extendQuery(baseQuery, primaryField, bucket.key);

        // Batch all breakdown-field aggregations in ONE request
        const fieldSpecs: FieldSpec[] = breakdownFields.map(f => ({ field: f, topk: topBreakdown }));

        fetchBatchAggregation(namespace, endpoint, narrowedQuery, startTime, endTime, fieldSpecs)
          .then(fieldMap => {
            results[idx] = {
              primaryValue: bucket.key,
              primaryCount: bucket.count,
              breakdowns: fieldMap,
            };
          })
          .catch(() => {
            results[idx] = { primaryValue: bucket.key, primaryCount: bucket.count, breakdowns: {} };
          })
          .finally(() => {
            active.delete(idx);
            completed += Math.max(1, breakdownFields.length);
            onProgress?.(Math.min(completed, totalCalls), totalCalls);
            if (queue.length === 0 && active.size === 0) resolve();
            else dispatch();
          });
      }
    };
    if (primaryBuckets.length === 0) { resolve(); return; }
    dispatch();
  });

  return results;
}

/**
 * Extend an existing VoltVQL query with a new `field="value"` constraint.
 * Handles empty query (`{}`), quoted values, and simple AND-joining.
 */
function extendQuery(existing: string, field: string, value: string): string {
  const clause = `${field}="${value.replace(/"/g, '\\"')}"`;
  const trimmed = existing.trim();
  if (!trimmed || trimmed === '{}') return clause;
  return `${trimmed} AND ${clause}`;
}
