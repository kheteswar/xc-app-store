// =============================================================================
// SOC Polling Engine — 4-Track Fetch Orchestrator
// =============================================================================

import { apiClient } from '../api';
import { AdaptiveConcurrencyController } from '../fp-analyzer/adaptive-concurrency';
import type {
  SOCRoomConfig, SOCAction, HeartbeatResult, AggregationResults,
  AlertEntry, AuditEntry, LatencyStats, EventFeedEntry, JA4Cluster,
  BotTrafficOverview, SyntheticHealthSummary, DNSHealthStatus,
  PollingCycleResult,
} from './types';
import { createEmptyLatencyStats } from './types';
import { buildAccessLogAggregations, buildSecurityEventAggregations, buildLBQuery } from './aggregation-builder';
import { parseAggregationResponse } from './metrics-calculator';
import { processRawLogs } from './raw-log-processor';
import { fetchActiveAlerts } from './alert-fetcher';
import { fetchRecentChanges } from './config-change-tracker';
import { fetchBotOverview } from './bot-defense-fetcher';
import { fetchSyntheticHealth } from './synthetic-fetcher';
import { fetchDNSHealth } from './dns-monitor';

type Dispatch = (action: SOCAction) => void;

const SOC_CONCURRENCY_CONFIG = {
  initialConcurrency: 2,
  minConcurrency: 1,
  maxConcurrency: 4,
  rampUpAfterSuccesses: 12,
  rampDownFactor: 0.5,
  yellowDelayMs: 500,
  redDelayMs: 3000,
  redCooldownMs: 15000,
};

export class PollingEngine {
  private room: SOCRoomConfig;
  private dispatch: Dispatch;
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private countdownId: ReturnType<typeof setInterval> | null = null;
  private controller: AdaptiveConcurrencyController;
  private cycleNumber = 0;
  private isRunning = false;
  private isPaused = false;
  private isDestroyed = false;
  private lastCycleTime = 0;
  private abortController: AbortController | null = null;

  constructor(room: SOCRoomConfig, dispatch: Dispatch) {
    this.room = room;
    this.dispatch = dispatch;
    this.controller = new AdaptiveConcurrencyController(SOC_CONCURRENCY_CONFIG);
  }

  start(): void {
    if (this.isRunning || this.isDestroyed) return;
    this.isRunning = true;
    this.isPaused = false;

    // Bootstrap: aggressive initial fetch to populate dashboard immediately.
    // Fetches last 5 min of ALL data types in parallel before showing anything.
    this.executeBootstrap().then(() => {
      if (this.isDestroyed) return;
      // After bootstrap, start regular polling cycles
      this.intervalId = setInterval(() => {
        if (!this.isPaused && !this.isDestroyed) {
          this.executeCycle();
        }
      }, this.room.pollingIntervalSec * 1000);
    });

    // Countdown timer (every second)
    this.countdownId = setInterval(() => {
      if (!this.isPaused && !this.isDestroyed) {
        this.dispatch({ type: 'COUNTDOWN_TICK' });
      }
    }, 1000);
  }

  /**
   * Bootstrap: aggressive initial data pull on room entry.
   * Fetches last 5 minutes of ALL log types, aggregations, alerts, etc.
   * in parallel with higher limits so the dashboard is fully populated
   * before the user sees it. No waiting for the first polling interval.
   */
  private async executeBootstrap(): Promise<void> {
    if (this.isDestroyed) return;

    this.dispatch({ type: 'ADD_EVENT', payload: {
      id: `bootstrap-${Date.now()}`,
      timestamp: new Date().toISOString(),
      type: 'config',
      severity: 'info',
      message: `Bootstrapping SOC room — loading last 5 min of data...`,
    }});

    const { namespace, loadBalancers, features } = this.room;
    const endTime = new Date().toISOString();
    // Always bootstrap with 5 min window for immediate data
    const bootstrapWindowMin = 5;
    const startTime = new Date(Date.now() - bootstrapWindowMin * 60 * 1000).toISOString();
    const query = buildLBQuery(loadBalancers);
    const windowSeconds = bootstrapWindowMin * 60;

    try {
      // Fire ALL tracks in parallel — no sequential Track 1 first.
      // Use higher raw log limits for bootstrap (up to 1000).
      const bootstrapLogLimit = 1000;

      const [heartbeatResult, aggregationResult, alertsResult, auditResult,
             accessResp, secResp, botResult, syntheticResult, dnsResult] =
        await Promise.all([
          // Track 1: Heartbeat
          this.executeTrack1(namespace, query, startTime, endTime, windowSeconds),
          // Track 2: All aggregations
          this.executeTrack2(namespace, loadBalancers, startTime, endTime),
          // Alerts
          this.fetchAlerts(namespace),
          // Audit logs
          this.fetchAuditLogs(namespace, startTime),
          // Track 3: Raw access logs (high limit)
          (async () => {
            try {
              await this.respectConcurrency();
              const r = await apiClient.post<Record<string, unknown>>(
                `/api/data/namespaces/${namespace}/access_logs`,
                { namespace, query, start_time: startTime, end_time: endTime, limit: bootstrapLogLimit, scroll: false, sort: 'DESCENDING' }
              );
              this.controller.recordSuccess();
              return r;
            } catch (err) { this.handleApiError(err); return {}; }
          })(),
          // Track 3: Raw security events (high limit)
          (async () => {
            try {
              await this.respectConcurrency();
              const r = await apiClient.post<Record<string, unknown>>(
                `/api/data/namespaces/${namespace}/app_security/events`,
                { namespace, query, start_time: startTime, end_time: endTime, limit: 500, scroll: false, sort: 'DESCENDING' }
              );
              this.controller.recordSuccess();
              return r;
            } catch (err) { this.handleApiError(err); return {}; }
          })(),
          // Feature: Bot
          features.botDefenseEnabled && loadBalancers[0]
            ? this.fetchBotData(namespace, loadBalancers[0]) : Promise.resolve(null),
          // Feature: Synthetic
          features.syntheticMonitorsEnabled
            ? this.fetchSyntheticData(namespace) : Promise.resolve(null),
          // Feature: DNS
          this.room.dnsLoadBalancers.length > 0
            ? this.fetchDnsData(namespace) : Promise.resolve(null),
        ]);

      if (this.isDestroyed) return;

      this.lastHeartbeatHits = heartbeatResult.totalHits;

      // Parse raw logs
      const accessLogs = extractLogs(accessResp as Record<string, unknown>);
      const secEvents = extractSecEvents(secResp as Record<string, unknown>);
      const rawLogData = processRawLogs(accessLogs, secEvents);

      // Suspicious user count
      let suspiciousUserCount = 0;
      try {
        const susResp = await apiClient.post<Record<string, unknown>>(
          `/api/data/namespaces/${namespace}/app_security/suspicious_user_logs/aggregation`,
          { namespace, query, start_time: startTime, end_time: endTime, aggs: { count_agg: { field: 'user', topk: 1 } } }
        );
        const buckets = parseAggregationResponse(susResp);
        suspiciousUserCount = buckets.reduce((sum, b) => sum + b.count, 0);
      } catch { /* ignore */ }

      // Dispatch everything at once
      const result: PollingCycleResult = {
        heartbeat: heartbeatResult,
        aggregation: aggregationResult,
        alerts: alertsResult,
        auditEntries: auditResult,
        incidents: [],
        suspiciousUserCount,
        rawLogs: rawLogData,
        botOverview: botResult,
        syntheticHealth: syntheticResult,
        dnsHealth: dnsResult,
      };

      this.cycleNumber = 1;
      this.lastCycleTime = Date.now();
      this.dispatch({ type: 'CYCLE_RESULT', payload: result });

      this.dispatch({ type: 'ADD_EVENT', payload: {
        id: `bootstrap-done-${Date.now()}`,
        timestamp: new Date().toISOString(),
        type: 'config',
        severity: 'info',
        message: `Bootstrap complete — ${heartbeatResult.totalHits} access logs, ${heartbeatResult.secEventHits} security events, ${alertsResult.length} alerts loaded`,
      }});

      console.log(`[SOC] Bootstrap complete: ${accessLogs.length} raw access logs, ${secEvents.length} raw sec events, ${heartbeatResult.totalHits} total hits`);

    } catch (err) {
      if (this.isDestroyed) return;
      const msg = err instanceof Error ? err.message : String(err);
      console.error('[SOC] Bootstrap error:', msg);
      this.dispatch({ type: 'POLLING_ERROR', payload: `Bootstrap failed: ${msg}` });
      // Fall through — regular polling will start anyway
    }
  }

  stop(): void {
    this.isRunning = false;
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    if (this.countdownId) {
      clearInterval(this.countdownId);
      this.countdownId = null;
    }
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
  }

  pause(): void {
    this.isPaused = true;
    this.dispatch({ type: 'POLLING_PAUSED' });
  }

  resume(): void {
    if (!this.isPaused) return;
    this.isPaused = false;
    this.dispatch({ type: 'POLLING_RESUMED' });

    // Catch-up: if significant time passed, run a cycle immediately
    const elapsed = Date.now() - this.lastCycleTime;
    if (elapsed > this.room.pollingIntervalSec * 1000 * 1.5) {
      this.executeCycle();
    }
  }

  destroy(): void {
    this.isDestroyed = true;
    this.stop();
  }

  updateRoom(room: SOCRoomConfig): void {
    this.room = room;
  }

  private async executeCycle(): Promise<void> {
    if (this.isDestroyed || this.isPaused) return;

    this.cycleNumber++;
    this.lastCycleTime = Date.now();
    this.abortController = new AbortController();

    this.dispatch({ type: 'CYCLE_START' });

    const { namespace, loadBalancers, dataWindowMinutes, features } = this.room;
    const endTime = new Date().toISOString();
    const startTime = new Date(Date.now() - dataWindowMinutes * 60 * 1000).toISOString();
    const query = buildLBQuery(loadBalancers);
    const windowSeconds = dataWindowMinutes * 60;

    try {
      // Execute Track 1 first so we have hit count for adaptive Track 3 limit
      const heartbeat = await this.executeTrack1(namespace, query, startTime, endTime, windowSeconds);
      this.lastHeartbeatHits = heartbeat.totalHits;

      // Execute remaining tracks in parallel
      const [aggregation, alerts, auditEntries, rawLogData, botOverview, syntheticHealth, dnsHealth] =
        await Promise.all([
          this.executeTrack2(namespace, loadBalancers, startTime, endTime),
          this.fetchAlerts(namespace),
          this.fetchAuditLogs(namespace, startTime),
          this.executeTrack3(namespace, query, startTime, endTime),
          features.botDefenseEnabled ? this.fetchBotData(namespace, loadBalancers[0]) : Promise.resolve(null),
          features.syntheticMonitorsEnabled ? this.fetchSyntheticData(namespace) : Promise.resolve(null),
          this.room.dnsLoadBalancers.length > 0 ? this.fetchDnsData(namespace) : Promise.resolve(null),
        ]);

      if (this.isDestroyed) return;

      // Fetch security incidents
      let suspiciousUserCount = 0;
      try {
        const susResp = await apiClient.post<Record<string, unknown>>(
          `/api/data/namespaces/${namespace}/app_security/suspicious_user_logs/aggregation`,
          { namespace, query, start_time: startTime, end_time: endTime, aggs: { count_agg: { field: 'user', topk: 1 } } }
        );
        const buckets = parseAggregationResponse(susResp);
        suspiciousUserCount = buckets.reduce((sum, b) => sum + b.count, 0);
      } catch { /* ignore */ }

      const result: PollingCycleResult = {
        heartbeat,
        aggregation,
        alerts,
        auditEntries,
        incidents: [],
        suspiciousUserCount,
        rawLogs: rawLogData,
        botOverview,
        syntheticHealth,
        dnsHealth,
      };

      this.dispatch({ type: 'CYCLE_RESULT', payload: result });

    } catch (err) {
      if (this.isDestroyed) return;
      const msg = err instanceof Error ? err.message : String(err);
      this.dispatch({ type: 'POLLING_ERROR', payload: msg });
    }
  }

  // ---- Track 1: Heartbeat (2 calls) ----
  private async executeTrack1(
    namespace: string, query: string, startTime: string, endTime: string, windowSeconds: number
  ): Promise<HeartbeatResult> {
    const [accessProbe, secProbe] = await Promise.all([
      this.probeEndpoint(namespace, 'access_logs', query, startTime, endTime),
      this.probeEndpoint(namespace, 'app_security/events', query, startTime, endTime),
    ]);

    return {
      totalHits: accessProbe,
      secEventHits: secProbe,
      rps: windowSeconds > 0 ? accessProbe / windowSeconds : 0,
      timestamp: new Date().toISOString(),
    };
  }

  private async probeEndpoint(
    namespace: string, logType: string, query: string, startTime: string, endTime: string
  ): Promise<number> {
    try {
      await this.respectConcurrency();
      const resp = await apiClient.post<Record<string, unknown>>(
        `/api/data/namespaces/${namespace}/${logType}`,
        { namespace, query, start_time: startTime, end_time: endTime, limit: 1, scroll: false }
      );
      this.controller.recordSuccess();
      const totalHits = (resp as { total_hits?: number })?.total_hits ?? 0;
      return totalHits;
    } catch (err) {
      this.handleApiError(err);
      return 0;
    }
  }

  // ---- Track 2: Aggregation (12-16 calls) ----
  private async executeTrack2(
    namespace: string, lbNames: string[], startTime: string, endTime: string
  ): Promise<AggregationResults> {
    const accessAggs = buildAccessLogAggregations(namespace, lbNames, startTime, endTime);
    const securityAggs = buildSecurityEventAggregations(namespace, lbNames, startTime, endTime);
    const allQueries = [...accessAggs, ...securityAggs];

    const results = new Map<string, import('./types').AggBucket[]>();

    // Execute with adaptive concurrency pool
    await this.adaptivePool(allQueries, async (q) => {
      try {
        await this.respectConcurrency();
        const resp = await apiClient.post<Record<string, unknown>>(q.endpoint, q.body);
        this.controller.recordSuccess();
        // Debug: log first aggregation response to help diagnose parsing
        if (q.id === 'A1' && this.cycleNumber <= 2) {
          console.log(`[SOC] Aggregation ${q.id} raw response:`, JSON.stringify(resp).slice(0, 500));
        }
        const buckets = parseAggregationResponse(resp);
        if (q.id === 'A1' && this.cycleNumber <= 2) {
          console.log(`[SOC] Aggregation ${q.id} parsed ${buckets.length} buckets:`, buckets.slice(0, 5));
        }
        results.set(q.id, buckets);
      } catch (err) {
        this.handleApiError(err);
        results.set(q.id, []);
      }
    });

    return {
      byRspCode: results.get('A1') ?? [],
      byRspCodeDetails: results.get('A2') ?? [],
      byCountry: results.get('A3') ?? [],
      byDstIp: results.get('A4') ?? [],
      byReqPath: results.get('A5') ?? [],
      byDomain: results.get('A6') ?? [],
      bySrcIp: results.get('A7') ?? [],
      byWafAction: results.get('A8') ?? [],
      secByEventName: results.get('S1') ?? [],
      secBySignatureId: results.get('S2') ?? [],
      secBySrcIp: results.get('S3') ?? [],
      secByCountry: results.get('S4') ?? [],
      secByViolation: results.get('S5') ?? [],
    };
  }

  // ---- Track 3: Raw log detail (adaptive fetch) ----
  // Adaptively decide how many logs to fetch: more for low traffic, fewer for high
  // to keep API load reasonable while maximizing data quality.
  private lastHeartbeatHits = 0;

  private computeAdaptiveLimit(): number {
    const base = this.room.fetchDepth === 'deep' ? 500 : this.room.fetchDepth === 'standard' ? 250 : 100;
    const rps = this.lastHeartbeatHits / (this.room.dataWindowMinutes * 60);
    // Low traffic (<10 rps): fetch more to get better stats
    if (rps < 10) return Math.min(base * 2, 1000);
    // Medium traffic (10-100 rps): use base limit
    if (rps < 100) return base;
    // High traffic (100-1000 rps): reduce to conserve API budget
    if (rps < 1000) return Math.min(base, 200);
    // Very high traffic (>1000 rps): minimum fetch, aggregation is the source of truth
    return Math.min(base, 100);
  }

  private async executeTrack3(
    namespace: string, query: string, startTime: string, endTime: string
  ): Promise<{ latencyStats: LatencyStats; eventFeed: EventFeedEntry[]; ja4Clusters: JA4Cluster[]; sampleRate: number }> {
    const limit = this.computeAdaptiveLimit();

    try {
      const [accessResp, secResp] = await Promise.all([
        (async () => {
          await this.respectConcurrency();
          const r = await apiClient.post<Record<string, unknown>>(
            `/api/data/namespaces/${namespace}/access_logs`,
            { namespace, query, start_time: startTime, end_time: endTime, limit, scroll: false, sort: 'DESCENDING' }
          );
          this.controller.recordSuccess();
          return r;
        })(),
        (async () => {
          await this.respectConcurrency();
          const r = await apiClient.post<Record<string, unknown>>(
            `/api/data/namespaces/${namespace}/app_security/events`,
            { namespace, query, start_time: startTime, end_time: endTime, limit: Math.min(limit, 200), scroll: false, sort: 'DESCENDING' }
          );
          this.controller.recordSuccess();
          return r;
        })(),
      ]);

      const accessLogs = extractLogs(accessResp);
      const secEvents = extractSecEvents(secResp);

      return processRawLogs(accessLogs, secEvents);
    } catch (err) {
      this.handleApiError(err);
      return { latencyStats: createEmptyLatencyStats(), eventFeed: [], ja4Clusters: [], sampleRate: 1 };
    }
  }

  // ---- Feature-conditional fetchers ----
  private async fetchAlerts(namespace: string): Promise<AlertEntry[]> {
    try {
      return await fetchActiveAlerts(namespace);
    } catch {
      return [];
    }
  }

  private async fetchAuditLogs(namespace: string, since: string): Promise<AuditEntry[]> {
    try {
      return await fetchRecentChanges(namespace, since);
    } catch {
      return [];
    }
  }

  private async fetchBotData(namespace: string, lbName: string): Promise<BotTrafficOverview | null> {
    try {
      return await fetchBotOverview(namespace, lbName);
    } catch {
      return null;
    }
  }

  private async fetchSyntheticData(namespace: string): Promise<SyntheticHealthSummary | null> {
    try {
      return await fetchSyntheticHealth(namespace);
    } catch {
      return null;
    }
  }

  private async fetchDnsData(namespace: string): Promise<DNSHealthStatus | null> {
    try {
      return await fetchDNSHealth(namespace, this.room.dnsLoadBalancers);
    } catch {
      return null;
    }
  }

  // ---- Adaptive concurrency helpers ----
  private async respectConcurrency(): Promise<void> {
    const delay = this.controller.getRequestDelay();
    if (delay > 0) {
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  private handleApiError(err: unknown): void {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('429') || msg.toLowerCase().includes('rate limit')) {
      this.controller.recordRateLimit();
    } else {
      this.controller.recordError();
    }
  }

  private async adaptivePool<T>(
    items: T[],
    worker: (item: T) => Promise<void>,
  ): Promise<void> {
    let index = 0;
    const total = items.length;

    const runNext = async (): Promise<void> => {
      while (index < total) {
        const currentIndex = index++;
        await worker(items[currentIndex]);
      }
    };

    // Run with current concurrency level
    const concurrency = Math.min(this.controller.concurrency, total);
    const workers = Array.from({ length: concurrency }, () => runNext());
    await Promise.all(workers);
  }

  // ---- Public accessors ----
  get running(): boolean { return this.isRunning; }
  get paused(): boolean { return this.isPaused; }
  get cycle(): number { return this.cycleNumber; }
  get rateState(): string { return this.controller.getState(); }
}

// ---- Helpers to extract logs from API response ----
// CRITICAL: F5 XC API returns log entries as JSON STRINGS, not objects.
// Each entry in the events array must be parsed from string → object.
function normalizeEntries(raw: unknown[]): Record<string, unknown>[] {
  if (!raw || raw.length === 0) return [];
  if (typeof raw[0] === 'string') {
    return raw.map(e => {
      try { return JSON.parse(e as string); }
      catch { return {}; }
    });
  }
  return raw as Record<string, unknown>[];
}

function extractLogs(resp: Record<string, unknown>): import('./types').AccessLogEntry[] {
  if (!resp) return [];
  const events = (resp as { events?: unknown[] }).events;
  if (!Array.isArray(events)) return [];
  return normalizeEntries(events) as import('./types').AccessLogEntry[];
}

function extractSecEvents(resp: Record<string, unknown>): import('./types').SecurityEventEntry[] {
  if (!resp) return [];
  const events = (resp as { events?: unknown[] }).events;
  if (!Array.isArray(events)) return [];
  return normalizeEntries(events) as import('./types').SecurityEventEntry[];
}
