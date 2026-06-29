/**
 * Node API Caller — Direct HTTPS to F5 XC from Vite dev server
 *
 * Uses node:https to call the F5 XC API directly (no proxy hop).
 * Follows the same auth pattern as vite.config.ts makeF5XCRequest().
 */

import https from 'node:https';

export interface NodeApiCallerConfig {
  tenant: string;
  token: string;
}

interface ApiResponse {
  statusCode: number;
  body: string;
}

const REQUEST_TIMEOUT_MS = 60_000; // 60s — scroll payloads can be large

export class NodeApiCaller {
  private hostname: string;
  private token: string;

  constructor(config: NodeApiCallerConfig) {
    this.hostname = `${config.tenant}.console.ves.volterra.io`;
    this.token = config.token;
  }

  // ───── Core request ─────

  private request(method: string, path: string, body?: unknown): Promise<ApiResponse> {
    return new Promise((resolve, reject) => {
      const postData = body ? JSON.stringify(body) : undefined;
      const options: https.RequestOptions = {
        hostname: this.hostname,
        path: path.startsWith('/api') ? path : `/api${path}`,
        method,
        headers: {
          'Authorization': `APIToken ${this.token}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          ...(postData ? { 'Content-Length': Buffer.byteLength(postData) } : {}),
        },
      };

      const req = https.request(options, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 500,
            body: Buffer.concat(chunks).toString('utf-8'),
          });
        });
      });

      req.on('error', reject);
      req.setTimeout(REQUEST_TIMEOUT_MS, () => {
        req.destroy();
        reject(new Error(`Request timeout after ${REQUEST_TIMEOUT_MS}ms: ${method} ${path}`));
      });

      if (postData) req.write(postData);
      req.end();
    });
  }

  /** Typed request — parses JSON, throws on non-2xx */
  async fetch<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.request(method, path, body);

    if (res.statusCode === 429) {
      throw new Error(`429 Too Many Requests: ${method} ${path}`);
    }

    if (res.statusCode >= 400) {
      const detail = res.body.slice(0, 500);
      throw new Error(`HTTP ${res.statusCode}: ${method} ${path} — ${detail}`);
    }

    try {
      return JSON.parse(res.body) as T;
    } catch {
      throw new Error(`Invalid JSON response: ${method} ${path}`);
    }
  }

  // ───── Security Events ─────

  async fetchSecurityEventsPage(
    namespace: string,
    query: string,
    startTime: string,
    endTime: string,
    limit = 500,
  ): Promise<{ events?: unknown[]; scroll_id?: string; total_hits?: unknown }> {
    return this.fetch('POST', `/api/data/namespaces/${namespace}/app_security/events`, {
      query,
      namespace,
      start_time: startTime,
      end_time: endTime,
      scroll: true,
      limit,
    });
  }

  async scrollSecurityEvents(
    namespace: string,
    scrollId: string,
  ): Promise<{ events?: unknown[]; scroll_id?: string }> {
    return this.fetch('POST', `/api/data/namespaces/${namespace}/app_security/events/scroll`, {
      scroll_id: scrollId,
      namespace,
    });
  }

  /**
   * Server-side aggregation over security events (terms buckets, no raw rows).
   * Body mirrors F5 XC's aggregation schema: { aggs: { key: { field, topk } } }
   * → response { aggs: { key: { buckets: [{ key, count }] } } }.
   */
  async fetchSecurityEventsAggregation(
    namespace: string,
    query: string,
    startTime: string,
    endTime: string,
    aggs: Record<string, { field: string; topk: number }>,
  ): Promise<{ aggs?: Record<string, unknown> }> {
    return this.fetch('POST', `/api/data/namespaces/${namespace}/app_security/events/aggregation`, {
      namespace,
      query,
      start_time: startTime,
      end_time: endTime,
      aggs,
    });
  }

  // ───── Access Logs ─────

  async fetchAccessLogsPage(
    namespace: string,
    query: string,
    startTime: string,
    endTime: string,
    limit = 500,
  ): Promise<{ logs?: unknown[]; scroll_id?: string; total_hits?: unknown }> {
    return this.fetch('POST', `/api/data/namespaces/${namespace}/access_logs`, {
      query,
      namespace,
      start_time: startTime,
      end_time: endTime,
      scroll: true,
      limit,
    });
  }

  async scrollAccessLogs(
    namespace: string,
    scrollId: string,
  ): Promise<{ logs?: unknown[]; scroll_id?: string }> {
    return this.fetch('POST', `/api/data/namespaces/${namespace}/access_logs/scroll`, {
      scroll_id: scrollId,
      namespace,
    });
  }

  // ───── LB Config ─────

  async getLBConfig(
    namespace: string,
    lbName: string,
  ): Promise<Record<string, unknown>> {
    return this.fetch('GET', `/api/config/namespaces/${namespace}/http_loadbalancers/${lbName}`);
  }

  // ───── WAF Exclusion Policy CRUD ─────

  async listWafExclusionPolicies(
    namespace: string,
  ): Promise<{ items?: unknown[] }> {
    return this.fetch('GET', `/api/config/namespaces/${namespace}/waf_exclusion_policys`);
  }

  async getWafExclusionPolicy(
    namespace: string,
    name: string,
  ): Promise<Record<string, unknown>> {
    return this.fetch('GET', `/api/config/namespaces/${namespace}/waf_exclusion_policys/${name}`);
  }

  async createWafExclusionPolicy(
    namespace: string,
    body: unknown,
  ): Promise<Record<string, unknown>> {
    return this.fetch('POST', `/api/config/namespaces/${namespace}/waf_exclusion_policys`, body);
  }

  async replaceWafExclusionPolicy(
    namespace: string,
    name: string,
    body: unknown,
  ): Promise<Record<string, unknown>> {
    return this.fetch('PUT', `/api/config/namespaces/${namespace}/waf_exclusion_policys/${name}`, body);
  }

  async deleteWafExclusionPolicy(
    namespace: string,
    name: string,
  ): Promise<void> {
    await this.fetch('DELETE', `/api/config/namespaces/${namespace}/waf_exclusion_policys/${name}`);
  }
}
