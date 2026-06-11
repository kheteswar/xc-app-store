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

export type AggEndpoint = 'access_logs' | 'app_security/events';

// ═══════════════════════════════════════════════════════════════════
// RESPONSE PARSING
// ═══════════════════════════════════════════════════════════════════

function parseBuckets(raw: unknown): AggBucket[] {
  if (!raw || typeof raw !== 'object') return [];
  const obj = raw as Record<string, unknown>;
  const buckets = obj.buckets;
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

// ═══════════════════════════════════════════════════════════════════
// SINGLE FIELD AGGREGATION
// ═══════════════════════════════════════════════════════════════════

/**
 * Fetch aggregation for a single field.
 * Returns sorted (desc) top-k buckets.
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
  const aggKey = `${field.replace(/\./g, '_')}_agg`;
  try {
    const resp = await apiClient.post<Record<string, unknown>>(
      `/api/data/namespaces/${namespace}/${endpoint}/aggregation`,
      { namespace, query, start_time: startTime, end_time: endTime, aggs: { [aggKey]: { field, topk } } },
    );
    const aggs = resp.aggs as Record<string, unknown> | undefined;
    return parseBuckets(aggs?.[aggKey]);
  } catch {
    return [];
  }
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

  const aggs: Record<string, { field: string; topk: number }> = {};
  for (const { field, topk = 50 } of fields) {
    aggs[`${field.replace(/\./g, '_')}_agg`] = { field, topk };
  }

  try {
    const resp = await apiClient.post<Record<string, unknown>>(
      `/api/data/namespaces/${namespace}/${endpoint}/aggregation`,
      { namespace, query, start_time: startTime, end_time: endTime, aggs },
    );
    const respAggs = resp.aggs as Record<string, unknown> | undefined;
    const out: Record<string, AggBucket[]> = {};
    for (const { field } of fields) {
      const aggKey = `${field.replace(/\./g, '_')}_agg`;
      out[field] = parseBuckets(respAggs?.[aggKey]);
    }
    return out;
  } catch {
    // Fall back to individual calls on batch failure
    return fetchParallelAggregations(namespace, endpoint, query, startTime, endTime, fields);
  }
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

    return { totalHits, sampleRate };
  } catch {
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
