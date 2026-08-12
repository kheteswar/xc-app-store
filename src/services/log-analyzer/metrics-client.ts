/**
 * Metrics Client — wraps F5 XC's `/api/data/namespaces/{ns}/graph/service` endpoint.
 *
 * This is the SAME data source that powers F5 XC Console's "Performance" dashboard
 * (per-LB request rate, error rate, latency percentiles). Metrics have LONGER
 * retention (30-90 days) than raw access logs (~7 days), so this is the only
 * reliable way to get 14d / 30d totals & percentiles.
 *
 * Limitations vs access-log aggregation:
 *   - No arbitrary field breakdowns (only pre-defined metric types)
 *   - group_by limited to: NAMESPACE, SITE, APP_TYPE, SERVICE, VHOST, VIP, CACHEABILITY
 */

import { apiClient } from '../api';

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

/** Metric types supported by graph/service API for HTTP LB analytics. */
export type MetricType =
  | 'HTTP_REQUEST_RATE'
  | 'HTTP_ERROR_RATE'
  | 'HTTP_ERROR_RATE_4XX'
  | 'HTTP_ERROR_RATE_5XX'
  | 'HTTP_RESPONSE_LATENCY'
  | 'HTTP_RESPONSE_LATENCY_PERCENTILE_50'
  | 'HTTP_RESPONSE_LATENCY_PERCENTILE_90'
  | 'HTTP_RESPONSE_LATENCY_PERCENTILE_99'
  | 'HTTP_SERVER_DATA_TRANSFER_TIME'
  | 'HTTP_APP_LATENCY'
  | 'REQUEST_THROUGHPUT'
  | 'RESPONSE_THROUGHPUT'
  | 'ACTIVE_CONNECTIONS'
  | 'NEW_CONNECTION_RATE';

/** ID fields for group_by. */
export type GroupByField = 'NAMESPACE' | 'SITE' | 'APP_TYPE' | 'SERVICE' | 'VHOST' | 'VIP' | 'CACHEABILITY';

export interface MetricRequest {
  namespace: string;
  startTime: string;      // ISO
  endTime: string;        // ISO
  metrics: MetricType[];
  /** e.g. "1d", "1h", "5m" — determines the number of time-series points */
  step?: string;
  /** e.g. "1d" — evaluation window per step; defaults to same as step */
  range?: string;
  /** Filter by VHOST label — e.g. "ves-io-http-loadbalancer-my-lb" */
  vhostFilter?: string[];
  /** How to bucket the response — one row per unique combination */
  groupBy?: GroupByField[];
}

/** Single time-series point for one metric on one node/edge. */
export interface MetricPoint {
  timestamp: number; // Unix ms
  value: number;
}

/** All samples for one metric on one node. */
export interface MetricSeries {
  metric: MetricType;
  points: MetricPoint[];
  /** Aggregate value across all points (mean for rates, max/avg for latency) */
  aggregate: number | null;
}

/** All metrics for one grouped node (e.g. one VHOST/LB). */
export interface NodeMetrics {
  /** Identity labels (e.g. { VHOST: "ves-io-http-loadbalancer-foo", NAMESPACE: "ns" }) */
  labels: Record<string, string>;
  series: Record<MetricType, MetricSeries>;
}

export interface MetricResponse {
  /** One entry per grouped node (per LB when group_by=[VHOST]) */
  nodes: NodeMetrics[];
  /** Aggregate across all nodes (sums for rates, weighted averages for latency) */
  totals: Partial<Record<MetricType, number>>;
  /** Combined time series across all nodes */
  totalsTimeSeries: Record<MetricType, MetricPoint[]>;
}

// ═══════════════════════════════════════════════════════════════════
// STEP/RANGE HELPERS
// ═══════════════════════════════════════════════════════════════════

/** Choose a reasonable step for a given time window (30 buckets max). */
export function chooseStep(windowMs: number): string {
  const hours = windowMs / 3600000;
  if (hours <= 1) return '2m';
  if (hours <= 6) return '10m';
  if (hours <= 24) return '1h';
  if (hours <= 168) return '6h';   // 7d → 28 buckets
  if (hours <= 336) return '12h';  // 14d → 28 buckets
  return '1d';                     // 30d → 30 buckets
}

/** Convert a step string to milliseconds (e.g. "1h" → 3600000, "1d" → 86400000). */
export function stepToMs(step: string): number {
  const m = /^(\d+)([smhd])$/.exec(step);
  if (!m) return 3600000; // 1h default
  const n = parseInt(m[1], 10);
  const unit = m[2];
  switch (unit) {
    case 's': return n * 1000;
    case 'm': return n * 60000;
    case 'h': return n * 3600000;
    case 'd': return n * 86400000;
    default: return 3600000;
  }
}

// ═══════════════════════════════════════════════════════════════════
// REQUEST BUILDER
// ═══════════════════════════════════════════════════════════════════

interface GraphServiceRequest {
  namespace: string;
  start_time: string;
  end_time: string;
  step: string;
  range: string;
  group_by?: GroupByField[];
  label_filter?: Array<{ key: string; operator: string; value: string }>;
  field_selector: {
    node: {
      metric: {
        downstream: MetricType[];
      };
    };
  };
}

function buildRequest(req: MetricRequest): GraphServiceRequest {
  const startMs = new Date(req.startTime).getTime();
  const endMs = new Date(req.endTime).getTime();
  const windowMs = Math.max(0, endMs - startMs);

  const step = req.step ?? chooseStep(windowMs);
  const range = req.range ?? step;

  const body: GraphServiceRequest = {
    namespace: req.namespace,
    start_time: req.startTime,
    end_time: req.endTime,
    step,
    range,
    group_by: req.groupBy ?? ['VHOST'],
    field_selector: {
      node: {
        metric: {
          downstream: req.metrics,
        },
      },
    },
  };

  if (req.vhostFilter && req.vhostFilter.length > 0) {
    body.label_filter = req.vhostFilter.map(v => ({
      key: 'ves.io/vhost',
      operator: 'IN',
      value: v,
    }));
  }

  return body;
}

// ═══════════════════════════════════════════════════════════════════
// RESPONSE PARSING
// ═══════════════════════════════════════════════════════════════════

/**
 * The graph/service response has a nested structure. We extract:
 *   - Per-node time-series data
 *   - Per-node aggregate value
 *   - Cross-node totals
 *
 * F5 XC's response shape (best-effort — actual shape may vary by version):
 * {
 *   "nodes": [
 *     {
 *       "id": { "vhost": "...", "namespace": "..." },
 *       "metrics": {
 *         "downstream": {
 *           "HTTP_REQUEST_RATE": {
 *             "timeseries": [ { "time": "...", "value": ... }, ... ]
 *           },
 *           ...
 *         }
 *       }
 *     }
 *   ]
 * }
 */
function parseNodesFromResponse(raw: unknown, requestedMetrics: MetricType[]): NodeMetrics[] {
  if (!raw || typeof raw !== 'object') return [];
  const obj = raw as Record<string, unknown>;
  const nodes = obj.nodes;
  if (!Array.isArray(nodes)) return [];

  return nodes
    .map((n): NodeMetrics | null => {
      if (!n || typeof n !== 'object') return null;
      const node = n as Record<string, unknown>;

      // Extract identity labels (may come as `id`, `labels`, or `key`)
      const labels: Record<string, string> = {};
      const idObj = (node.id ?? node.labels ?? node.key) as Record<string, unknown> | undefined;
      if (idObj && typeof idObj === 'object') {
        for (const [k, v] of Object.entries(idObj)) labels[k] = String(v ?? '');
      }

      // Extract metrics (may be under `metrics.downstream`, `metrics`, or `downstream`)
      const metricsObj = (node.metrics ?? node.data) as Record<string, unknown> | undefined;
      const downstream = (metricsObj?.downstream ?? metricsObj) as Record<string, unknown> | undefined;

      const series: Record<string, MetricSeries> = {};
      for (const metricType of requestedMetrics) {
        const raw = downstream?.[metricType];
        series[metricType] = parseMetricSeries(metricType, raw);
      }

      return { labels, series: series as Record<MetricType, MetricSeries> };
    })
    .filter(Boolean) as NodeMetrics[];
}

function parseMetricSeries(metric: MetricType, raw: unknown): MetricSeries {
  const empty: MetricSeries = { metric, points: [], aggregate: null };
  if (!raw || typeof raw !== 'object') return empty;

  const obj = raw as Record<string, unknown>;
  // The F5 response may nest actual data under `timeseries`, `values`, or directly as an array
  const ts = obj.timeseries ?? obj.values ?? obj.data ?? raw;

  const points: MetricPoint[] = [];
  if (Array.isArray(ts)) {
    for (const p of ts) {
      if (!p || typeof p !== 'object') continue;
      const entry = p as Record<string, unknown>;
      const t = entry.time ?? entry.timestamp ?? entry.t;
      const v = entry.value ?? entry.v ?? entry.count;
      if (t === undefined || v === undefined) continue;
      // Time may be ms number, seconds string, or ISO
      let timestamp: number;
      if (typeof t === 'number') timestamp = t > 1e12 ? Math.floor(t) : t * 1000;
      else if (typeof t === 'string') {
        const asNum = Number(t);
        if (isFinite(asNum) && asNum > 0) timestamp = asNum > 1e12 ? asNum : asNum * 1000;
        else timestamp = new Date(t).getTime();
      } else continue;
      const value = Number(v);
      if (isFinite(timestamp) && isFinite(value)) points.push({ timestamp, value });
    }
  }

  // Aggregate: for rates → mean × count of points is meaningless without step,
  // so we return the mean here; caller must multiply by step × count for totals.
  // For latency → the mean (or user can compute p99-of-p99s upstream)
  const validPoints = points.filter(p => isFinite(p.value));
  const aggregate = validPoints.length > 0
    ? validPoints.reduce((s, p) => s + p.value, 0) / validPoints.length
    : null;

  return { metric, points, aggregate };
}

/** Aggregate a per-node metrics response into cross-node totals. */
function computeTotals(nodes: NodeMetrics[], metrics: MetricType[], stepMs: number): {
  totals: Partial<Record<MetricType, number>>;
  timeSeries: Record<MetricType, MetricPoint[]>;
} {
  const totals: Partial<Record<MetricType, number>> = {};
  const timeSeries: Record<string, MetricPoint[]> = {};

  for (const metric of metrics) {
    // Sum points across nodes by timestamp
    const byTs = new Map<number, number>();
    for (const node of nodes) {
      const series = node.series[metric];
      if (!series) continue;
      for (const p of series.points) {
        byTs.set(p.timestamp, (byTs.get(p.timestamp) || 0) + p.value);
      }
    }
    const points = [...byTs.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([timestamp, value]) => ({ timestamp, value }));
    timeSeries[metric] = points;

    // Aggregate:
    //   - For rate metrics: total = sum(rate × step_seconds) across time buckets
    //   - For latency metrics: total = mean value across time buckets (avg for %ile)
    //   - For throughput: mean bps
    const isRate = /RATE|CONNECTIONS/.test(metric);
    if (isRate) {
      const stepSeconds = stepMs / 1000;
      totals[metric] = points.reduce((s, p) => s + p.value * stepSeconds, 0);
    } else {
      const validPoints = points.filter(p => isFinite(p.value));
      totals[metric] = validPoints.length > 0
        ? validPoints.reduce((s, p) => s + p.value, 0) / validPoints.length
        : 0;
    }
  }

  return { totals, timeSeries: timeSeries as Record<MetricType, MetricPoint[]> };
}

// ═══════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════

/**
 * Fetch metrics from graph/service. Returns per-LB (or per-group) data + cross-group totals.
 *
 * For simple "total requests over 30d" queries, this uses HTTP_REQUEST_RATE integrated
 * across all time steps.
 */
export async function fetchMetrics(req: MetricRequest): Promise<MetricResponse> {
  const body = buildRequest(req);
  const stepMs = stepToMs(body.step);

  try {
    const resp = await apiClient.post<Record<string, unknown>>(
      `/api/data/namespaces/${req.namespace}/graph/service`,
      body,
    );
    const nodes = parseNodesFromResponse(resp, req.metrics);
    const { totals, timeSeries } = computeTotals(nodes, req.metrics, stepMs);

    // eslint-disable-next-line no-console
    console.debug(
      `[fetchMetrics] ns=${req.namespace} window=${req.startTime}..${req.endTime} step=${body.step}: ` +
      `${nodes.length} nodes, metrics=${req.metrics.join(',')}`,
      { totals, sampleNode: nodes[0] },
    );

    return { nodes, totals, totalsTimeSeries: timeSeries };
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(`[fetchMetrics] FAILED for ns=${req.namespace}:`, err);
    return { nodes: [], totals: {}, totalsTimeSeries: {} as Record<MetricType, MetricPoint[]> };
  }
}

/**
 * Convenience: get a simple summary (total requests, error counts, latency percentiles)
 * for a namespace over any time window (including 14d, 30d).
 *
 * Optionally filter to a specific VHOST (i.e. specific LB).
 */
export interface MetricSummary {
  totalRequests: number;
  totalErrors: number;      // 4xx + 5xx integrated
  totalErrors4xx: number;
  totalErrors5xx: number;
  errorRatePct: number;
  avgLatencyMs: number;
  p50LatencyMs: number;
  p90LatencyMs: number;
  p99LatencyMs: number;
  perLB: Array<{
    vhost: string;
    totalRequests: number;
    totalErrors: number;
    errorRatePct: number;
    p99LatencyMs: number;
  }>;
  timeSeries: Array<{ timestamp: number; requests: number; errors: number; label: string }>;
  step: string;
}

export async function fetchMetricSummary(
  namespace: string,
  startTime: string,
  endTime: string,
  vhostFilter?: string,
): Promise<MetricSummary> {
  const metrics: MetricType[] = [
    'HTTP_REQUEST_RATE',
    'HTTP_ERROR_RATE_4XX',
    'HTTP_ERROR_RATE_5XX',
    'HTTP_RESPONSE_LATENCY',
    'HTTP_RESPONSE_LATENCY_PERCENTILE_50',
    'HTTP_RESPONSE_LATENCY_PERCENTILE_90',
    'HTTP_RESPONSE_LATENCY_PERCENTILE_99',
  ];

  const windowMs = new Date(endTime).getTime() - new Date(startTime).getTime();
  const step = chooseStep(windowMs);
  const stepMs = stepToMs(step);
  const stepSeconds = stepMs / 1000;

  const resp = await fetchMetrics({
    namespace,
    startTime,
    endTime,
    metrics,
    step,
    range: step,
    groupBy: ['VHOST'],
    vhostFilter: vhostFilter ? [vhostFilter] : undefined,
  });

  const totalRequests = Math.round(resp.totals.HTTP_REQUEST_RATE ?? 0);
  const totalErrors4xx = Math.round(resp.totals.HTTP_ERROR_RATE_4XX ?? 0);
  const totalErrors5xx = Math.round(resp.totals.HTTP_ERROR_RATE_5XX ?? 0);
  const totalErrors = totalErrors4xx + totalErrors5xx;
  const errorRatePct = totalRequests > 0 ? (totalErrors / totalRequests) * 100 : 0;

  // Latency: convert seconds → ms
  const avgLatencyMs = (resp.totals.HTTP_RESPONSE_LATENCY ?? 0) * 1000;
  const p50LatencyMs = (resp.totals.HTTP_RESPONSE_LATENCY_PERCENTILE_50 ?? 0) * 1000;
  const p90LatencyMs = (resp.totals.HTTP_RESPONSE_LATENCY_PERCENTILE_90 ?? 0) * 1000;
  const p99LatencyMs = (resp.totals.HTTP_RESPONSE_LATENCY_PERCENTILE_99 ?? 0) * 1000;

  // Per-LB breakdown
  const perLB = resp.nodes.map(n => {
    const reqRateSeries = n.series.HTTP_REQUEST_RATE?.points ?? [];
    const err4xxSeries = n.series.HTTP_ERROR_RATE_4XX?.points ?? [];
    const err5xxSeries = n.series.HTTP_ERROR_RATE_5XX?.points ?? [];
    const p99Series = n.series.HTTP_RESPONSE_LATENCY_PERCENTILE_99?.points ?? [];

    const reqTotal = reqRateSeries.reduce((s, p) => s + p.value * stepSeconds, 0);
    const err4xxTotal = err4xxSeries.reduce((s, p) => s + p.value * stepSeconds, 0);
    const err5xxTotal = err5xxSeries.reduce((s, p) => s + p.value * stepSeconds, 0);
    const errTotal = err4xxTotal + err5xxTotal;
    const p99Values = p99Series.map(p => p.value).filter(v => isFinite(v));
    const p99 = p99Values.length > 0 ? p99Values.reduce((s, v) => s + v, 0) / p99Values.length : 0;

    // Try common vhost label keys
    const vhost = n.labels.VHOST ?? n.labels.vhost ?? n.labels.ves_io_vhost ?? Object.values(n.labels)[0] ?? '(unknown)';

    return {
      vhost: String(vhost),
      totalRequests: Math.round(reqTotal),
      totalErrors: Math.round(errTotal),
      errorRatePct: reqTotal > 0 ? (errTotal / reqTotal) * 100 : 0,
      p99LatencyMs: p99 * 1000,
    };
  }).sort((a, b) => b.totalRequests - a.totalRequests);

  // Time series: merge request rate + error rate into per-bucket totals
  const reqTs = resp.totalsTimeSeries.HTTP_REQUEST_RATE ?? [];
  const err4Ts = resp.totalsTimeSeries.HTTP_ERROR_RATE_4XX ?? [];
  const err5Ts = resp.totalsTimeSeries.HTTP_ERROR_RATE_5XX ?? [];
  const errByTs = new Map<number, number>();
  for (const p of err4Ts) errByTs.set(p.timestamp, (errByTs.get(p.timestamp) || 0) + p.value);
  for (const p of err5Ts) errByTs.set(p.timestamp, (errByTs.get(p.timestamp) || 0) + p.value);

  const timeSeries = reqTs.map(p => {
    const errRate = errByTs.get(p.timestamp) || 0;
    const d = new Date(p.timestamp);
    const isDaily = stepMs >= 86400000;
    const label = isDaily
      ? `${(d.getUTCMonth() + 1).toString().padStart(2, '0')}/${d.getUTCDate().toString().padStart(2, '0')}`
      : `${(d.getUTCMonth() + 1).toString().padStart(2, '0')}/${d.getUTCDate().toString().padStart(2, '0')} ${d.getUTCHours().toString().padStart(2, '0')}:00`;
    return {
      timestamp: p.timestamp,
      requests: Math.round(p.value * stepSeconds),
      errors: Math.round(errRate * stepSeconds),
      label,
    };
  });

  return {
    totalRequests,
    totalErrors,
    totalErrors4xx,
    totalErrors5xx,
    errorRatePct,
    avgLatencyMs,
    p50LatencyMs,
    p90LatencyMs,
    p99LatencyMs,
    perLB,
    timeSeries,
    step,
  };
}
