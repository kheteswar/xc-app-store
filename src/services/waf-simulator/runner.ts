// ═══════════════════════════════════════════════════════════════════════════
// WAF Attack Simulator — Execution Engine
//
// Composes each (path × payload × method) into a concrete HTTP request, stamps
// it with a unique correlation marker, fires it through the dev-server proxy
// (/api/proxy/request, which forwards arbitrary method/headers/body), and
// classifies the live response as blocked-by-WAF vs. passed-to-origin.
//
// The live verdict is a heuristic; the authoritative verdict in reconcile mode
// comes from XC security events (see log-reconciler.ts).
// ═══════════════════════════════════════════════════════════════════════════

import { payloadsForCategories } from './attack-library';
import type {
  AttackPayload,
  AttackResult,
  HttpMethod,
  LiveVerdict,
  SimProgress,
  SimRunConfig,
} from './types';

const PROXY = '/api/proxy/request';

interface ProxyResponse {
  status?: number;
  statusText?: string;
  headers?: Record<string, unknown>;
  body?: string;
  connectedIp?: string;
  error?: string;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Send one request through the proxy and time it client-side.
async function proxyFetch(req: {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}): Promise<{ resp: ProxyResponse; ms: number }> {
  const start = Date.now();
  try {
    const r = await fetch(PROXY, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    const data = (await r.json().catch(() => ({}))) as ProxyResponse;
    return { resp: data, ms: Date.now() - start };
  } catch (e) {
    return { resp: { error: (e as Error).message }, ms: Date.now() - start };
  }
}

// Detect the egress IP that XC will record as src_ip for our proxied requests.
// Hits a public echo service through the SAME proxy path the attacks take.
export async function detectSourceIp(): Promise<string | null> {
  const services = ['https://api.ipify.org?format=json', 'https://ifconfig.me/all.json'];
  for (const url of services) {
    const { resp } = await proxyFetch({ url, method: 'GET', headers: { Accept: 'application/json' } });
    if (resp.body) {
      try {
        const j = JSON.parse(resp.body);
        const ip = j.ip || j.ip_addr || j.address;
        if (typeof ip === 'string' && ip.trim()) return ip.trim();
      } catch {
        // ifconfig.me/all.json sometimes returns text; try a regex
        const m = resp.body.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/);
        if (m) return m[0];
      }
    }
  }
  return null;
}

// XC WAF block page markers — used for the heuristic live verdict.
const BLOCK_MARKERS = [/support[\s_-]?id/i, /sorry,\s*the\s*page/i, /request\s*(was\s*)?blocked/i, /your\s*request\s*has\s*been\s*blocked/i];

function parseSupportId(body: string): string | undefined {
  const m = body.match(/support[\s_-]?id[^0-9a-fx]*([0-9a-fx:-]{6,})/i);
  return m ? m[1] : undefined;
}

function classifyLive(resp: ProxyResponse): { verdict: LiveVerdict; supportId?: string } {
  if (resp.error || !resp.status) return { verdict: resp.error ? 'ERROR' : 'UNKNOWN' };
  const body = resp.body || '';
  const headerKeys = Object.keys(resp.headers || {}).map((k) => k.toLowerCase());
  const looksLikeXcBlock =
    BLOCK_MARKERS.some((re) => re.test(body)) || headerKeys.some((k) => k.startsWith('x-volterra'));
  if (resp.status === 403 || resp.status === 406) {
    return { verdict: 'BLOCKED', supportId: parseSupportId(body) };
  }
  if (looksLikeXcBlock) return { verdict: 'BLOCKED', supportId: parseSupportId(body) };
  return { verdict: 'PASSED_TO_ORIGIN' };
}

// Normalize a base path to start with '/' and not end with '/'.
function normPath(p: string): string {
  let s = p.trim();
  if (!s.startsWith('/')) s = '/' + s;
  if (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1);
  return s;
}

// Choose the method to fire a payload with, honoring user selection.
function pickMethods(payload: AttackPayload, selected: HttpMethod[]): HttpMethod[] {
  const inter = payload.methods.filter((m) => selected.includes(m));
  return inter.length > 0 ? inter : [payload.methods[0]];
}

// Build the concrete request for one payload/path/method.
function buildRequest(
  config: SimRunConfig,
  payload: AttackPayload,
  path: string,
  method: HttpMethod,
  marker: string
): { url: string; method: HttpMethod; headers: Record<string, string>; body?: string } {
  const { scheme, domain } = config.target;
  const value = config.fullStrength && payload.fullStrength ? payload.fullStrength : payload.prodSafe;
  const base = normPath(path);
  const origin = `${scheme}://${domain}`;
  const markerQ = `__wafsim=${encodeURIComponent(marker)}`;

  const headers: Record<string, string> = {
    Accept: '*/*',
    'X-WAF-Sim-Id': marker,
    'User-Agent': 'XC-WAF-AttackSim/1.0',
  };

  let url = `${origin}${base}`;
  let body: string | undefined;

  switch (payload.vector) {
    case 'QUERY': {
      const param = `${payload.paramName || 'q'}=${encodeURIComponent(value)}`;
      url = `${origin}${base}?${param}&${markerQ}`;
      break;
    }
    case 'PATH': {
      // value is already in path-safe / encoded form where needed
      const seg = value ? `/${value}` : '';
      url = `${origin}${base}${seg}?${markerQ}`;
      break;
    }
    case 'HEADER': {
      headers[payload.headerName || 'X-Attack'] = value;
      url = `${origin}${base}?${markerQ}`;
      break;
    }
    case 'COOKIE': {
      headers['Cookie'] = `${payload.paramName || 'session'}=${value}`;
      url = `${origin}${base}?${markerQ}`;
      break;
    }
    case 'BODY': {
      url = `${origin}${base}?${markerQ}`;
      if (payload.bodyType === 'json') {
        headers['Content-Type'] = 'application/json';
        // value may itself be JSON (mass-assignment / ssrf); else wrap it.
        body = value.trim().startsWith('{') || value.trim().startsWith('[') ? value : JSON.stringify({ [payload.paramName || 'data']: value });
      } else if (payload.bodyType === 'xml') {
        headers['Content-Type'] = 'application/xml';
        body = value;
      } else {
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
        body = `${payload.paramName || 'data'}=${encodeURIComponent(value)}`;
      }
      break;
    }
  }

  return { url, method, headers, body };
}

export interface RunHandle {
  shouldAbort: () => boolean;
}

// Fire all selected attacks. Returns the live AttackResult list.
export async function runAttacks(
  config: SimRunConfig,
  onProgress: (p: SimProgress) => void,
  handle: RunHandle
): Promise<AttackResult[]> {
  const payloads = payloadsForCategories(config.categoryIds);
  const runId = crypto.randomUUID().slice(0, 8);

  // Expand into concrete (payload × path × method) requests.
  type Job = { payload: AttackPayload; path: string; method: HttpMethod };
  const jobs: Job[] = [];
  for (const payload of payloads) {
    const methods = pickMethods(payload, config.methods);
    for (const path of config.target.paths) {
      for (const method of methods) jobs.push({ payload, path, method });
    }
  }

  const total = jobs.length;
  const results: AttackResult[] = [];
  let blocked = 0;
  let reachedOrigin = 0;

  for (let i = 0; i < jobs.length; i++) {
    if (handle.shouldAbort()) break;
    const { payload, path, method } = jobs[i];
    const seq = i + 1;
    const marker = `wafsim-${runId}-${seq}`;
    const built = buildRequest(config, payload, path, method, marker);

    const sentAt = new Date().toISOString();
    const { resp, ms } = await proxyFetch(built);
    const { verdict, supportId } = classifyLive(resp);
    if (verdict === 'BLOCKED') blocked++;
    else if (verdict === 'PASSED_TO_ORIGIN') reachedOrigin++;

    const cat = payload.categoryId;
    results.push({
      marker,
      seq,
      categoryId: cat,
      categoryName: cat,
      owasp: '',
      payloadId: payload.id,
      payloadName: payload.name,
      severity: payload.severity,
      vector: payload.vector,
      method,
      path,
      requestUrl: built.url,
      requestHeaders: built.headers,
      requestBody: built.body,
      expectedSignature: payload.expectedSignature,
      liveVerdict: verdict,
      statusCode: resp.status || 0,
      statusText: resp.statusText,
      responseTimeMs: ms,
      responseSnippet: (resp.body || resp.error || '').slice(0, 280),
      blockSupportId: supportId,
      error: resp.error,
      sentAt,
    });

    onProgress({
      phase: 'attacking',
      message: `Fired ${seq}/${total}: ${payload.name} (${method})`,
      progress: Math.round((seq / Math.max(total, 1)) * 100),
      sent: seq,
      total,
      blocked,
      reachedOrigin,
    });

    if (config.pacingMs > 0 && i < jobs.length - 1) await sleep(config.pacingMs);
  }

  return results;
}

// The runId embedded in markers (so reconciler can filter logs to this run).
export function markerRunId(results: AttackResult[]): string | null {
  const m = results[0]?.marker.match(/^wafsim-([0-9a-f]+)-/);
  return m ? m[1] : null;
}
