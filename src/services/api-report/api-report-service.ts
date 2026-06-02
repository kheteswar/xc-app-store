// ============================================================
// API Discovery Report Dashboard – Service Layer
// ============================================================
import { apiClient } from '../api';
import type {
  ApiEndpointStats,
  ApiEndpointRow,
  SwaggerEndpoint,
  SwaggerSpec,
  ApiReportResults,
  FetchProgress,
  LBSelection,
} from './types';
import { COLUMN_MAPPING, COLUMN_KEYS } from './types';

const scopeLabel = (namespace: string, lbName: string, multiNs: boolean) =>
  multiNs ? `${namespace}/${lbName}` : lbName;

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function getQueryParams(days: number): string {
  const now = new Date();
  const end = now.toISOString().replace(/\.\d{3}Z$/, '.000Z');
  const start = new Date(now.getTime() - days * 86400000)
    .toISOString()
    .replace(/\.\d{3}Z$/, '.000Z');
  return `?api_endpoint_info_request=1&start_time=${start}&end_time=${end}`;
}

/** Resolve nested dot-notation keys like "risk_score.score" */
function resolveNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const keys = path.split('.');
  let current: unknown = obj;
  for (const key of keys) {
    if (current == null || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

function formatValue(column: string, value: unknown): string {
  if (value === undefined || value === null) return '—';

  if ((column === 'Last Updated' || column === 'Last Request' || column === 'Last Tested')
      && typeof value === 'string' && value) {
    try {
      const dt = new Date(value.replace('Z', '+00:00'));
      return dt.toLocaleString(undefined, {
        day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
      });
    } catch {
      return String(value);
    }
  }

  if (Array.isArray(value)) {
    if (value.length === 0) return '—';
    if (value.every((x) => typeof x === 'object' && x !== null)) {
      // Try to extract a useful primitive (name/code/type) before falling back to JSON
      const flat = value.map((v) => {
        const o = v as Record<string, unknown>;
        return o.name || o.type || o.code || o.id || JSON.stringify(o);
      });
      return flat.map(String).join(', ');
    }
    return value.map(String).join(', ');
  }

  if (typeof value === 'object') {
    return JSON.stringify(value);
  }

  const s = String(value);
  return s || '—';
}

// ------------------------------------------------------------------
// 1. Namespace Stats
// ------------------------------------------------------------------

/**
 * Pull a numeric stat from the response under any of several possible keys.
 * F5 XC has changed naming over versions (e.g. risk distribution lives under
 * `high_risk`, `risk_high`, `high_risk_count`, or `risk_distribution.high`),
 * so we probe defensively rather than relying on a single shape.
 */
function pickNum(data: Record<string, unknown>, ...keys: string[]): number | undefined {
  for (const key of keys) {
    const parts = key.split('.');
    let cur: unknown = data;
    for (const p of parts) {
      if (cur == null || typeof cur !== 'object') { cur = undefined; break; }
      cur = (cur as Record<string, unknown>)[p];
    }
    if (typeof cur === 'number') return cur;
    if (typeof cur === 'string' && cur.trim() !== '' && !Number.isNaN(Number(cur))) return Number(cur);
  }
  return undefined;
}

function statsFromResponse(scope: string, data: Record<string, unknown>): ApiEndpointStats {
  return {
    scope,
    total_endpoints: pickNum(data, 'total_endpoints', 'total') ?? 0,
    discovered:      pickNum(data, 'discovered', 'discovered_count', 'learnt', 'learnt_count') ?? 0,
    inventory:       pickNum(data, 'inventory', 'inventory_count') ?? 0,
    shadow:          pickNum(data, 'shadow', 'shadow_count') ?? 0,
    pii_detected:    pickNum(data, 'pii_detected', 'pii_count', 'sensitive_data_count') ?? 0,
    zombie:          pickNum(data, 'zombie', 'zombie_count'),
    unauthenticated: pickNum(data, 'unauthenticated', 'unauthenticated_count', 'unauth_count'),
    vulnerable:      pickNum(data, 'vulnerable', 'vulnerable_count', 'vulnerability_count'),
    high_risk:       pickNum(data, 'high_risk', 'high_risk_count', 'risk_high', 'risk_distribution.high'),
    threat_high:     pickNum(data, 'threat_high', 'high_threat_count', 'risk_distribution.high', 'security_risk_high'),
    threat_medium:   pickNum(data, 'threat_medium', 'medium_threat_count', 'risk_distribution.medium', 'security_risk_medium'),
    threat_low:      pickNum(data, 'threat_low', 'low_threat_count', 'risk_distribution.low', 'security_risk_low'),
    threat_info:     pickNum(data, 'threat_info', 'info_threat_count', 'risk_distribution.info', 'security_risk_info'),
  };
}

export async function fetchNamespaceStats(namespace: string): Promise<ApiEndpointStats> {
  const data = await apiClient.post<Record<string, unknown>>(
    `/api/ml/data/namespaces/${namespace}/api_endpoints/stats`,
    {
      namespace,
      vhosts_filter: [],
      vhosts_types_filter: ['HTTP_LOAD_BALANCER', 'CDN_LOAD_BALANCER'],
    },
  );
  return statsFromResponse(`Namespace: ${namespace}`, data);
}

// ------------------------------------------------------------------
// 2. Per-LB Stats
// ------------------------------------------------------------------

export async function fetchLBStats(
  selections: LBSelection[],
  onProgress?: (p: FetchProgress) => void,
  multiNs = false,
): Promise<ApiEndpointStats[]> {
  const results: ApiEndpointStats[] = [];

  for (let i = 0; i < selections.length; i++) {
    const { namespace, lbName } = selections[i];
    const scope = scopeLabel(namespace, lbName, multiNs);
    onProgress?.({
      phase: 'stats',
      current: i + 1,
      total: selections.length,
      namespace,
      lbName,
      message: `Fetching stats for ${scope}`,
    });

    try {
      const data = await apiClient.post<Record<string, unknown>>(
        `/api/ml/data/namespaces/${namespace}/api_endpoints/stats`,
        {
          namespace,
          vhosts_filter: [`ves-io-http-loadbalancer-${lbName}`],
          vhosts_types_filter: [],
        },
      );
      const s = statsFromResponse(scope, data);
      s.namespace = namespace;
      s.lbName = lbName;
      results.push(s);
    } catch {
      results.push({
        scope, namespace, lbName,
        total_endpoints: 0, discovered: 0, inventory: 0, shadow: 0, pii_detected: 0,
      });
    }
  }

  return results;
}

// ------------------------------------------------------------------
// 3. Swagger / Learnt Schema (parsed server-side)
// ------------------------------------------------------------------

export interface SwaggerFetchResult {
  endpoints: SwaggerEndpoint[];
  specs: SwaggerSpec[];
}

export async function fetchSwaggerSpecs(
  selections: LBSelection[],
  onProgress?: (p: FetchProgress) => void,
  multiNs = false,
): Promise<SwaggerFetchResult> {
  const allEndpoints: SwaggerEndpoint[] = [];
  const allSpecs: SwaggerSpec[] = [];

  for (let i = 0; i < selections.length; i++) {
    const { namespace, lbName } = selections[i];
    const lb = scopeLabel(namespace, lbName, multiNs);
    onProgress?.({
      phase: 'swagger',
      current: i + 1,
      total: selections.length,
      namespace,
      lbName,
      message: `Downloading swagger spec for ${lb}`,
    });

    try {
      const tenant = apiClient.getTenant();
      const token = apiClient.getToken();
      if (!tenant || !token) throw new Error('Not connected');

      const resp = await fetch('/api/proxy/swagger-parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant, token, namespace, lbName }),
      });

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({}));
        allEndpoints.push({
          lb, namespace, lbName,
          fqdn: '-',
          path: (errData as Record<string, string>).error || `Error ${resp.status}`,
          method: '-',
          contentType: '-',
        });
        continue;
      }

      const data = await resp.json() as { specs: Array<{
        filename: string;
        fqdn: string;
        title?: string;
        version?: string;
        description?: string;
        openapi?: string;
        raw: unknown;
        endpoints: SwaggerSpec['endpoints'];
      }> };

      if (!data.specs || data.specs.length === 0) {
        allEndpoints.push({
          lb, namespace, lbName, fqdn: '-', path: 'No discovered APIs', method: '-', contentType: '-',
        });
        continue;
      }

      for (const spec of data.specs) {
        const enriched: SwaggerSpec = {
          lb, namespace, lbName,
          filename: spec.filename,
          fqdn: spec.fqdn,
          title: spec.title,
          version: spec.version,
          description: spec.description,
          openapi: spec.openapi,
          raw: spec.raw,
          endpoints: spec.endpoints,
        };
        allSpecs.push(enriched);

        for (const ep of spec.endpoints) {
          allEndpoints.push({
            lb, namespace, lbName,
            fqdn: spec.fqdn || '-',
            path: ep.path,
            method: ep.method,
            contentType: ep.contentType || '-',
            summary: ep.summary,
            tags: ep.tags?.join(', '),
          });
        }
      }
    } catch (err: unknown) {
      allEndpoints.push({
        lb, namespace, lbName,
        fqdn: '-',
        path: `Error: ${err instanceof Error ? err.message : String(err)}`,
        method: '-',
        contentType: '-',
      });
    }
  }

  return { endpoints: allEndpoints, specs: allSpecs };
}

// ------------------------------------------------------------------
// 4. Detailed Endpoint Data
// ------------------------------------------------------------------

export async function fetchEndpointDetails(
  selections: LBSelection[],
  days: number,
  onProgress?: (p: FetchProgress) => void,
  multiNs = false,
): Promise<ApiEndpointRow[]> {
  const allRows: ApiEndpointRow[] = [];

  for (let i = 0; i < selections.length; i++) {
    const { namespace, lbName } = selections[i];
    const lb = scopeLabel(namespace, lbName, multiNs);
    onProgress?.({
      phase: 'endpoints',
      current: i + 1,
      total: selections.length,
      namespace,
      lbName,
      message: `Fetching API endpoints for ${lb}`,
    });

    try {
      const endpoint = `/api/ml/data/namespaces/${namespace}/virtual_hosts/ves-io-http-loadbalancer-${lbName}/api_endpoints${getQueryParams(days)}`;
      const data = await apiClient.get<Record<string, unknown>>(endpoint);

      let items: Record<string, unknown>[] = [];
      if (data.apiep_list && Array.isArray(data.apiep_list)) {
        items = data.apiep_list;
      } else if (Array.isArray(data)) {
        items = data as unknown as Record<string, unknown>[];
      } else {
        for (const [, val] of Object.entries(data || {})) {
          if (Array.isArray(val) && val.length > 0 && typeof val[0] === 'object') {
            items = val as Record<string, unknown>[];
            break;
          }
        }
      }

      for (const item of items) {
        const row: ApiEndpointRow = { lb, namespace, lbName };
        for (const [column, responseKey] of Object.entries(COLUMN_MAPPING)) {
          if (responseKey.includes('.')) {
            const nested = resolveNestedValue(item, responseKey);
            row[column] = formatValue(column, nested);
          } else if (responseKey in item) {
            row[column] = formatValue(column, item[responseKey]);
          } else {
            row[column] = '—';
          }
        }
        allRows.push(row);
      }
    } catch (err) {
      console.error(`[APIReport] Failed to fetch endpoints for ${lb}:`, err);
    }
  }

  return allRows;
}

// ------------------------------------------------------------------
// 5. Full Report Orchestrator
// ------------------------------------------------------------------

interface ThreatAgg {
  high: number; medium: number; low: number; info: number;
  riskMax: number; riskSum: number; riskN: number;
  vulnerable: number;
}

function newAgg(): ThreatAgg {
  return { high: 0, medium: 0, low: 0, info: 0, riskMax: 0, riskSum: 0, riskN: 0, vulnerable: 0 };
}

function accumulate(agg: ThreatAgg, row: ApiEndpointRow): void {
  const tl = String(row['Threat Level'] ?? '').toUpperCase();
  if (tl.includes('CRITICAL') || tl.includes('HIGH')) agg.high++;
  else if (tl.includes('MED')) agg.medium++;
  else if (tl.includes('LOW')) agg.low++;
  else if (tl && tl !== '—' && tl !== '-') agg.info++;

  const rsRaw = row['Risk Score'];
  const rs = typeof rsRaw === 'number' ? rsRaw : Number(rsRaw);
  if (!Number.isNaN(rs) && rs > 0) {
    if (rs > agg.riskMax) agg.riskMax = rs;
    agg.riskSum += rs;
    agg.riskN++;
  }

  const vulnRaw = String(row['Vulnerabilities'] ?? '').trim();
  if (vulnRaw && vulnRaw !== '—' && vulnRaw !== '-') agg.vulnerable++;
}

/** Aggregate threat counters per LB (keyed by display scope, which already
 *  includes the namespace in multi-ns mode so two same-named LBs don't collide). */
function aggregateThreatByScope(endpointRows: ApiEndpointRow[]): Map<string, ThreatAgg> {
  const map = new Map<string, ThreatAgg>();
  for (const row of endpointRows) {
    let agg = map.get(row.lb);
    if (!agg) { agg = newAgg(); map.set(row.lb, agg); }
    accumulate(agg, row);
  }
  return map;
}

/** Aggregate threat counters per namespace */
function aggregateThreatByNamespace(endpointRows: ApiEndpointRow[]): Map<string, ThreatAgg> {
  const map = new Map<string, ThreatAgg>();
  for (const row of endpointRows) {
    let agg = map.get(row.namespace);
    if (!agg) { agg = newAgg(); map.set(row.namespace, agg); }
    accumulate(agg, row);
  }
  return map;
}

function mergeThreatIntoStats(
  stats: ApiEndpointStats,
  agg: ThreatAgg | undefined,
): void {
  if (!agg) return;
  // Only overwrite when the API didn't already give us a value, so any tenant
  // that does return native counters keeps the authoritative number.
  if (stats.threat_high === undefined)   stats.threat_high   = agg.high;
  if (stats.threat_medium === undefined) stats.threat_medium = agg.medium;
  if (stats.threat_low === undefined)    stats.threat_low    = agg.low;
  if (stats.threat_info === undefined)   stats.threat_info   = agg.info;
  if (stats.high_risk === undefined)     stats.high_risk     = agg.high;
  if (stats.vulnerable === undefined && agg.vulnerable > 0) stats.vulnerable = agg.vulnerable;
  if (agg.riskN > 0) {
    stats.risk_score_max = agg.riskMax;
    stats.risk_score_avg = Math.round((agg.riskSum / agg.riskN) * 10) / 10;
  }
}

export async function runFullReport(
  selections: LBSelection[],
  days: number,
  onProgress?: (p: FetchProgress) => void,
): Promise<ApiReportResults> {
  const namespaces = Array.from(new Set(selections.map(s => s.namespace)));
  const multiNs = namespaces.length > 1;

  // 1. Namespace-level rollup stats — one call per unique namespace
  const nsStats: ApiEndpointStats[] = [];
  for (let i = 0; i < namespaces.length; i++) {
    const ns = namespaces[i];
    onProgress?.({
      phase: 'stats', current: 0, total: selections.length,
      namespace: ns, message: `Fetching namespace stats for ${ns}…`,
    });
    try {
      const s = await fetchNamespaceStats(ns);
      s.namespace = ns;
      nsStats.push(s);
    } catch { /* non-critical */ }
  }

  // 2. Per-LB stats
  const lbStats = await fetchLBStats(selections, onProgress, multiNs);

  // 3. Swagger specs
  const swaggerResult = await fetchSwaggerSpecs(selections, onProgress, multiNs);

  // 4. Detailed endpoint data
  const endpointRows = await fetchEndpointDetails(selections, days, onProgress, multiNs);

  // 5. Derive threat / risk score distribution and merge into both per-LB
  //    and per-namespace rollup stats.
  const lbThreat = aggregateThreatByScope(endpointRows);
  for (const s of lbStats) mergeThreatIntoStats(s, lbThreat.get(s.scope));

  const nsThreat = aggregateThreatByNamespace(endpointRows);
  for (const s of nsStats) {
    if (s.namespace) mergeThreatIntoStats(s, nsThreat.get(s.namespace));
  }

  return {
    nsStats,
    lbStats,
    swaggerEndpoints: swaggerResult.endpoints,
    swaggerSpecs: swaggerResult.specs,
    endpointRows,
    generatedAt: new Date().toISOString(),
    namespaces,
    timeRangeDays: days,
  };
}

// ------------------------------------------------------------------
// 6. Per-LB OpenAPI Spec Download (synthesized from parsed endpoints)
// ------------------------------------------------------------------

/**
 * Build an OpenAPI 3.0 JSON document for a single LB from the already-fetched
 * swagger endpoint rows, then trigger a browser download.
 */
export function downloadLBOpenApiSpec(
  scope: string,
  swaggerEndpoints: SwaggerEndpoint[],
): { ok: boolean; reason?: string } {
  const rows = swaggerEndpoints.filter(e => e.lb === scope);
  const real = rows.filter(e =>
    e.path && e.method && e.method !== '-' &&
    !/^No discovered APIs$/i.test(e.path) &&
    !/^Error/i.test(e.path)
  );
  if (real.length === 0) return { ok: false, reason: 'No discovered APIs for this load balancer' };

  const fqdnSet = new Set<string>();
  for (const r of real) {
    if (!r.fqdn || r.fqdn === '-') continue;
    for (const u of r.fqdn.split(',').map(s => s.trim()).filter(Boolean)) {
      fqdnSet.add(u);
    }
  }
  const servers = fqdnSet.size > 0
    ? Array.from(fqdnSet).map(url => ({ url }))
    : [{ url: 'https://' + scope }];

  const paths: Record<string, Record<string, unknown>> = {};
  for (const r of real) {
    const method = r.method.toLowerCase();
    if (!paths[r.path]) paths[r.path] = {};

    const operation: Record<string, unknown> = {
      summary: r.summary || `${r.method.toUpperCase()} ${r.path}`,
      responses: { '200': { description: 'OK' } },
    };
    if (r.contentType && r.contentType !== '-') {
      const types = r.contentType.split(',').map(s => s.trim()).filter(Boolean);
      if (types.length > 0 && method !== 'get' && method !== 'head' && method !== 'delete') {
        const content: Record<string, unknown> = {};
        for (const t of types) content[t] = { schema: { type: 'object' } };
        operation.requestBody = { content };
      }
    }
    paths[r.path][method] = operation;
  }

  const spec = {
    openapi: '3.0.0',
    info: {
      title: `${scope} — Discovered APIs`,
      description: `OpenAPI spec generated from F5 XC API Discovery for load balancer ${scope}.`,
      version: '1.0.0',
    },
    servers,
    paths,
  };

  const safeName = scope.replace(/[/\\]/g, '__');
  triggerDownload(
    new Blob([JSON.stringify(spec, null, 2)], { type: 'application/json' }),
    `${safeName}_openapi.json`,
  );
  return { ok: true };
}

// ------------------------------------------------------------------
// 6b. Raw F5 XC swagger_spec ZIP Download
// ------------------------------------------------------------------

/** Download the original swagger_spec ZIP from F5 XC for one load balancer. */
export async function downloadRawSchemaZip(
  namespace: string,
  lbName: string,
): Promise<{ ok: boolean; reason?: string }> {
  const tenant = apiClient.getTenant();
  const token = apiClient.getToken();
  if (!tenant || !token) return { ok: false, reason: 'Not connected to F5 XC' };

  const resp = await fetch('/api/proxy/swagger-zip', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tenant, token, namespace, lbName }),
  });

  if (!resp.ok) {
    let reason = `HTTP ${resp.status}`;
    try {
      const j = await resp.json();
      reason = j.error || reason;
    } catch { /* ignore */ }
    return { ok: false, reason };
  }

  const blob = await resp.blob();
  if (blob.size === 0) return { ok: false, reason: 'Empty schema returned by F5 XC' };

  triggerDownload(blob, `${namespace}__${lbName}_swagger_spec.zip`);
  return { ok: true };
}

// ------------------------------------------------------------------
// 7. Excel Export (Overview-focused)
// ------------------------------------------------------------------

/**
 * View-state override so the downloaded report mirrors what the user is
 * currently looking at — same sort order, same filter subset.
 */
export interface ReportView {
  lbStats: ApiEndpointStats[];
  description?: string;
}

export async function exportAsExcel(
  results: ApiReportResults,
  filenameStem: string,
  view?: ReportView,
): Promise<void> {
  const XLSX = await import('xlsx');
  const wb = XLSX.utils.book_new();

  const lbStats = view?.lbStats ?? results.lbStats;
  const scopeSet = new Set(lbStats.map(s => s.scope));
  const swaggerEndpoints = view ? results.swaggerEndpoints.filter(e => scopeSet.has(e.lb)) : results.swaggerEndpoints;
  const endpointRows = view ? results.endpointRows.filter(r => scopeSet.has(r.lb)) : results.endpointRows;
  const nsInView = Array.from(new Set(lbStats.map(s => s.namespace).filter(Boolean) as string[]));

  // Sheet 0: Report meta — what the user was looking at when they exported
  const meta = [
    { Field: 'Namespaces', Value: (nsInView.length ? nsInView : results.namespaces).join(', ') || '—' },
    { Field: 'Namespace Count', Value: (nsInView.length || results.namespaces.length) },
    { Field: 'Generated', Value: new Date(results.generatedAt).toLocaleString() },
    { Field: 'Time Range (days)', Value: results.timeRangeDays },
    { Field: 'Load Balancers in View', Value: lbStats.length },
    ...(view?.description ? [{ Field: 'View', Value: view.description }] : []),
  ];
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(meta), 'Report Info');

  // Sheet 1: Overview (per-LB stats) — preserves the on-screen row order
  const overviewRow = (s: ApiEndpointStats) => ({
    Namespace: s.namespace ?? '—',
    'Load Balancer': s.lbName ?? s.scope,
    Scope: s.scope,
    'Total Endpoints': s.total_endpoints,
    Discovered: s.discovered,
    Inventory: s.inventory,
    Shadow: s.shadow,
    'PII Detected': s.pii_detected,
    'Threat: High':   s.threat_high   ?? '—',
    'Threat: Medium': s.threat_medium ?? '—',
    'Threat: Low':    s.threat_low    ?? '—',
    'Threat: Info':   s.threat_info   ?? '—',
    'Avg Risk Score': s.risk_score_avg ?? '—',
    'Max Risk Score': s.risk_score_max ?? '—',
    Zombie: s.zombie ?? '—',
    Unauthenticated: s.unauthenticated ?? '—',
    Vulnerable: s.vulnerable ?? '—',
  });
  const statsRows = [
    ...(!view ? results.nsStats.map(overviewRow) : []),
    ...lbStats.map(overviewRow),
  ];
  if (statsRows.length > 0) {
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(statsRows), 'Overview');
  }

  // Helper to keep LB rows ordered the same way they appear on screen
  const lbOrder = new Map(lbStats.map((s, i) => [s.scope, i]));
  const byLbOrder = <T extends { lb: string }>(arr: T[]): T[] =>
    [...arr].sort((a, b) => (lbOrder.get(a.lb) ?? 0) - (lbOrder.get(b.lb) ?? 0));

  // Sheet 2: Discovered Schema (parsed swagger endpoints)
  if (swaggerEndpoints.length > 0) {
    const swaggerRows = byLbOrder(swaggerEndpoints).map((e) => ({
      Namespace: e.namespace,
      'Load Balancer': e.lbName,
      Scope: e.lb,
      FQDN: e.fqdn,
      'API Endpoint': e.path,
      Method: e.method,
      'Content Type': e.contentType,
      Summary: e.summary || '',
      Tags: e.tags || '',
    }));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(swaggerRows), 'Discovered Schema');
  }

  // Sheet 3: Detailed Endpoints
  if (endpointRows.length > 0) {
    const detailRows = byLbOrder(endpointRows).map((r) => {
      const row: Record<string, string | number | undefined> = {
        Namespace: r.namespace,
        'Load Balancer': r.lbName,
        Scope: r.lb,
      };
      for (const col of COLUMN_KEYS) {
        row[col] = r[col];
      }
      return row;
    });
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(detailRows), 'API Endpoints');
  }

  const buf = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
  const blob = new Blob([buf], {
    type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  });
  triggerDownload(blob, `${filenameStem}_api_discovery_report.xlsx`);
}

// ------------------------------------------------------------------
// 7b. PDF Export (Overview)
// ------------------------------------------------------------------

export async function exportOverviewAsPdf(
  results: ApiReportResults,
  view?: ReportView,
): Promise<void> {
  const [{ default: jsPDF }, autoTableModule] = await Promise.all([
    import('jspdf'),
    import('jspdf-autotable'),
  ]);
  const autoTable = (autoTableModule as { default: (doc: unknown, opts: unknown) => unknown }).default;

  const lbStats = view?.lbStats ?? results.lbStats;

  const doc = new jsPDF({ orientation: 'landscape', unit: 'pt', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const generated = new Date(results.generatedAt).toLocaleString();

  doc.setFontSize(16);
  doc.setTextColor(30, 30, 30);
  doc.text('API Discovery Report', 40, 40);

  const nsInView = Array.from(new Set(lbStats.map(s => s.namespace).filter(Boolean) as string[]));
  const nsLabel = nsInView.length > 0
    ? (nsInView.length === 1 ? nsInView[0] : `${nsInView.length} namespaces (${nsInView.slice(0, 3).join(', ')}${nsInView.length > 3 ? ', …' : ''})`)
    : results.namespaces.join(', ');

  doc.setFontSize(10);
  doc.setTextColor(100);
  doc.text(`Namespaces: ${nsLabel}`, 40, 58, { maxWidth: 480 });
  doc.text(`Time range: last ${results.timeRangeDays} days`, 40, 72);
  doc.text(`Generated: ${generated}`, 40, 86);
  doc.text(`Load balancers: ${lbStats.length}${view ? ` (filtered from ${results.lbStats.length})` : ''}`, pageWidth - 240, 58);
  if (view?.description) {
    doc.text(`View: ${view.description}`, pageWidth - 240, 72, { maxWidth: 220 });
  }

  // Aggregate across the visible subset (so totals match what user is looking at)
  const agg = lbStats.reduce((a, s) => ({
    total_endpoints: a.total_endpoints + s.total_endpoints,
    discovered: a.discovered + s.discovered,
    inventory: a.inventory + s.inventory,
    shadow: a.shadow + s.shadow,
    pii_detected: a.pii_detected + s.pii_detected,
    threat_high:   a.threat_high   + (s.threat_high   ?? 0),
    threat_medium: a.threat_medium + (s.threat_medium ?? 0),
    threat_low:    a.threat_low    + (s.threat_low    ?? 0),
  }), { total_endpoints: 0, discovered: 0, inventory: 0, shadow: 0, pii_detected: 0, threat_high: 0, threat_medium: 0, threat_low: 0 });

  doc.setFontSize(11);
  doc.setTextColor(30, 30, 30);
  doc.text(
    `Aggregate — Total: ${agg.total_endpoints}   Discovered: ${agg.discovered}   ` +
    `Inventory: ${agg.inventory}   Shadow: ${agg.shadow}   PII: ${agg.pii_detected}`,
    40, 110,
  );
  doc.text(
    `Threat — High: ${agg.threat_high}   Medium: ${agg.threat_medium}   Low: ${agg.threat_low}`,
    40, 126,
  );

  const showNsCol = nsInView.length > 1 || results.namespaces.length > 1;
  const head = [[
    ...(showNsCol ? ['Namespace'] : []),
    'Load Balancer', 'Total', 'Disc.', 'Inv.', 'Shadow', 'PII',
    'Threat ▲', 'Threat ◆', 'Threat ▼', 'Avg Risk', 'Max Risk', 'Vulnerable',
  ]];
  const body = lbStats.map((s) => [
    ...(showNsCol ? [s.namespace ?? '—'] : []),
    s.lbName ?? s.scope,
    s.total_endpoints,
    s.discovered,
    s.inventory,
    s.shadow,
    s.pii_detected,
    s.threat_high   ?? '—',
    s.threat_medium ?? '—',
    s.threat_low    ?? '—',
    s.risk_score_avg ?? '—',
    s.risk_score_max ?? '—',
    s.vulnerable ?? '—',
  ]);

  autoTable(doc, {
    startY: 146,
    head,
    body,
    theme: 'striped',
    headStyles: { fillColor: [37, 99, 235], textColor: 255, fontStyle: 'bold' },
    styles: { fontSize: 8, cellPadding: 4 },
    columnStyles: showNsCol
      ? { 0: { cellWidth: 110 }, 1: { cellWidth: 130 } }
      : { 0: { cellWidth: 170 } },
  });

  doc.setFontSize(8);
  doc.setTextColor(140);
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    const ph = doc.internal.pageSize.getHeight();
    doc.text(`Page ${i} of ${pageCount}`, pageWidth - 70, ph - 20);
    doc.text('F5 XC API Discovery — generated by XC App Store', 40, ph - 20);
  }

  const filename = nsInView.length === 1
    ? nsInView[0]
    : (results.namespaces.length === 1 ? results.namespaces[0] : `multi-ns-${results.namespaces.length}`);
  doc.save(`${filename}_api_discovery_overview.pdf`);
}

// ------------------------------------------------------------------
// Internal helpers
// ------------------------------------------------------------------

function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
