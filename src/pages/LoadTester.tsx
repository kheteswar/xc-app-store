import { useState, useRef, useCallback, useMemo, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Zap, Play, Square, Plus, Trash2, ChevronDown, ChevronUp,
  Download, ArrowLeft, AlertCircle, Clock, Activity,
  Search, Shield, CheckCircle, XCircle, Wifi,
  Loader2, HelpCircle,
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, Cell,
} from 'recharts';
import { useApp } from '../context/AppContext';
import { apiClient } from '../services/api';

// ── Types ────────────────────────────────────────────────────────

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD';
type TestMode = 'duration' | 'count';
type LoadProfile = 'constant' | 'ramp' | 'step' | 'spike' | 'burst';
type ChartTab = 'response' | 'throughput' | 'histogram';

interface ThresholdRule { metric: string; op: string; value: number }
interface ThresholdResult extends ThresholdRule { actual: number; passed: boolean }

interface HeaderPair { key: string; value: string }

interface RequestResult {
  id: number;
  timestamp: number;       // ms since test start
  statusCode: number;
  responseTimeMs: number;
  bodySize: number;
  error?: string;
}

// ── Constants ────────────────────────────────────────────────────

const METHODS: HttpMethod[] = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'];
const PROFILES: { id: LoadProfile; label: string; desc: string }[] = [
  { id: 'constant', label: 'Constant', desc: 'Flat rate' },
  { id: 'ramp', label: 'Ramp', desc: 'Linear ramp-up' },
  { id: 'step', label: 'Step', desc: 'Staircase increase' },
  { id: 'spike', label: 'Spike', desc: 'Burst traffic' },
  { id: 'burst', label: 'Burst', desc: 'Fire N requests simultaneously every interval to hit an exact RPS' },
];
const THRESHOLD_METRICS = [
  { id: 'avg_response', label: 'Avg Response (ms)' },
  { id: 'p95_response', label: 'P95 Response (ms)' },
  { id: 'p99_response', label: 'P99 Response (ms)' },
  { id: 'max_response', label: 'Max Response (ms)' },
  { id: 'error_rate', label: 'Error Rate (%)' },
  { id: 'success_rate', label: 'Success Rate (%)' },
];
const NI = "px-2 py-1.5 bg-slate-700 border border-slate-600 rounded text-center font-mono text-sm [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none";

const METHOD_COLORS: Record<string, string> = {
  GET: '#10b981', POST: '#3b82f6', PUT: '#f59e0b',
  DELETE: '#ef4444', PATCH: '#8b5cf6', HEAD: '#6b7280',
};

const STATUS_LABELS: Record<number, string> = {
  200: 'OK', 201: 'Created', 204: 'No Content',
  301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
  404: 'Not Found', 405: 'Method Not Allowed', 408: 'Request Timeout',
  429: 'Too Many Requests',
  500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout',
};

// ── Component ────────────────────────────────────────────────────

export default function LoadTester() {
  const navigate = useNavigate();
  const { isConnected } = useApp();

  // Config
  const [url, setUrl] = useState('');
  const [method, setMethod] = useState<HttpMethod>('GET');
  const [customHeaders, setCustomHeaders] = useState<HeaderPair[]>([]);
  const [requestBody, setRequestBody] = useState('');
  const [rps, setRps] = useState(10);
  const [testMode, setTestMode] = useState<TestMode>('duration');
  const [duration, setDuration] = useState(10);
  const [totalRequests, setTotalRequests] = useState(100);
  const [concurrency, setConcurrency] = useState(50);
  const [showConfig, setShowConfig] = useState(false);

  // Load profile
  const [profile, setProfile] = useState<LoadProfile>('constant');
  const [rampFrom, setRampFrom] = useState(1);
  const [rampTo, setRampTo] = useState(50);
  const [stepSize, setStepSize] = useState(10);
  const [stepInterval, setStepInterval] = useState(5);
  const [spikeBase, setSpikeBase] = useState(5);
  const [spikePeak, setSpikePeak] = useState(100);
  const [spikeAt, setSpikeAt] = useState(50);
  const [spikeDur, setSpikeDur] = useState(10);
  // Burst: fire `burstSize` requests all at once, every `burstInterval` seconds → RPS = burstSize / burstInterval
  const [burstSize, setBurstSize] = useState(50);
  const [burstInterval, setBurstInterval] = useState(1);

  // Thresholds & Apdex
  const [thresholds, setThresholds] = useState<ThresholdRule[]>([]);
  const [apdexT, setApdexT] = useState(500);
  const [chartTab, setChartTab] = useState<ChartTab>('response');

  // Runtime
  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState<RequestResult[]>([]);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [sentCount, setSentCount] = useState(0);

  // F5 XC Log Analysis (optional)
  const [showLogAnalysis, setShowLogAnalysis] = useState(false);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [selectedNamespace, setSelectedNamespace] = useState('');
  const [loadBalancers, setLoadBalancers] = useState<string[]>([]);
  const [selectedLb, setSelectedLb] = useState('');
  const [clientIp, setClientIp] = useState('');
  const [isLoadingNs, setIsLoadingNs] = useState(false);
  const [isLoadingLbs, setIsLoadingLbs] = useState(false);
  const [isLoadingLogs, setIsLoadingLogs] = useState(false);
  const [logEntries, setLogEntries] = useState<any[]>([]);
  const [logError, setLogError] = useState('');

  // Refs
  const abortRef = useRef(false);
  const resultsRef = useRef<RequestResult[]>([]);
  const inFlightRef = useRef(0);
  const sentRef = useRef(0);
  const startTimeRef = useRef(0);
  const dispatchRef = useRef<ReturnType<typeof setInterval>>();
  const uiRef = useRef<ReturnType<typeof setInterval>>();
  const burstsDoneRef = useRef(0);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      abortRef.current = true;
      clearInterval(dispatchRef.current);
      clearInterval(uiRef.current);
    };
  }, []);

  // ── Load profile functions ─────────────────────────────────────

  const getTargetRps = useCallback((ms: number): number => {
    const totalMs = duration * 1000;
    const t = Math.min(ms / totalMs, 1);
    switch (profile) {
      case 'constant': return rps;
      case 'ramp': return rampFrom + (rampTo - rampFrom) * t;
      case 'step': {
        const stepDurMs = stepInterval * 1000;
        const stepIdx = Math.floor(ms / stepDurMs);
        return rps + stepIdx * stepSize;
      }
      case 'spike': {
        const spikeStartT = spikeAt / 100;
        const spikeEndT = spikeStartT + spikeDur / 100;
        if (t >= spikeStartT && t <= spikeEndT) return spikePeak;
        return spikeBase;
      }
      case 'burst': return burstSize / Math.max(1, burstInterval); // effective (average) RPS
      default: return rps;
    }
  }, [profile, rps, rampFrom, rampTo, stepSize, stepInterval, spikeBase, spikePeak, spikeAt, spikeDur, duration, burstSize, burstInterval]);

  const getExpectedAt = useCallback((ms: number): number => {
    let total = 0;
    const step = 50;
    for (let t = 0; t < ms; t += step) {
      total += getTargetRps(t) * Math.min(step, ms - t) / 1000;
    }
    return Math.floor(total);
  }, [getTargetRps]);

  // ── Stats ──────────────────────────────────────────────────────

  const stats = useMemo(() => {
    if (results.length === 0) return null;

    const success = results.filter(r => r.statusCode >= 200 && r.statusCode < 400 && !r.error).length;
    const clientErrors = results.filter(r => r.statusCode >= 400 && r.statusCode < 500).length;
    const serverErrors = results.filter(r => r.statusCode >= 500).length;
    const networkErrors = results.filter(r => !!r.error && r.statusCode === 0).length;

    const times = results
      .filter(r => r.responseTimeMs > 0)
      .map(r => r.responseTimeMs)
      .sort((a, b) => a - b);

    const avg = times.length > 0 ? times.reduce((s, t) => s + t, 0) / times.length : 0;
    const min = times.length > 0 ? times[0] : 0;
    const max = times.length > 0 ? times[times.length - 1] : 0;
    const p50 = times.length > 0 ? times[Math.floor(times.length * 0.5)] : 0;
    const p95 = times.length > 0 ? times[Math.floor(times.length * 0.95)] : 0;
    const p99 = times.length > 0 ? times[Math.floor(times.length * 0.99)] : 0;

    const statusDist = new Map<string, number>();
    for (const r of results) {
      const key = r.error && r.statusCode === 0 ? 'Error' : `${r.statusCode}`;
      statusDist.set(key, (statusDist.get(key) || 0) + 1);
    }

    // Actual RPS over last 3 seconds
    const recentWindow = 3000;
    const recent = results.filter(r => r.timestamp > elapsedMs - recentWindow);
    const windowSec = Math.min(recentWindow / 1000, elapsedMs / 1000);
    const currentRps = windowSec > 0 ? recent.length / windowSec : 0;

    // Blocked breakdown by status code
    const blockedByCode = new Map<number, number>();
    for (const r of results) {
      if (r.statusCode >= 400) {
        blockedByCode.set(r.statusCode, (blockedByCode.get(r.statusCode) || 0) + 1);
      }
    }

    return {
      total: results.length, success, clientErrors, serverErrors, networkErrors,
      avg, min, max, p50, p95, p99, statusDist, currentRps,
      totalBytes: results.reduce((s, r) => s + r.bodySize, 0),
      blockedByCode,
      allowed: success,
      blocked: clientErrors + serverErrors,
      errors: networkErrors,
    };
  }, [results, elapsedMs]);

  // ── Chart data ─────────────────────────────────────────────────

  const chartData = useMemo(() => {
    if (results.length === 0) return [];
    const buckets = new Map<number, RequestResult[]>();
    for (const r of results) {
      const sec = Math.floor(r.timestamp / 1000);
      if (!buckets.has(sec)) buckets.set(sec, []);
      buckets.get(sec)!.push(r);
    }
    return Array.from(buckets.entries())
      .sort(([a], [b]) => a - b)
      .map(([sec, reqs]) => {
        const times = reqs.filter(r => r.responseTimeMs > 0).map(r => r.responseTimeMs);
        const sorted = [...times].sort((a, b) => a - b);
        const errors = reqs.filter(r => r.statusCode >= 400 || !!r.error).length;
        return {
          time: `${sec}s`,
          avg: times.length > 0 ? Math.round(times.reduce((s, t) => s + t, 0) / times.length) : 0,
          max: times.length > 0 ? Math.round(Math.max(...times)) : 0,
          min: times.length > 0 ? Math.round(Math.min(...times)) : 0,
          p95: sorted.length > 0 ? Math.round(sorted[Math.floor(sorted.length * 0.95)] || 0) : 0,
          rps: reqs.length,
          errors,
          errorPct: reqs.length > 0 ? Math.round((errors / reqs.length) * 100) : 0,
        };
      });
  }, [results]);

  // ── Profile preview data ─────────────────────────────────────

  const profilePreview = useMemo(() => {
    const totalMs = duration * 1000;
    const points = 60;
    return Array.from({ length: points }, (_, i) => {
      const ms = (i / (points - 1)) * totalMs;
      return { time: `${(ms / 1000).toFixed(0)}s`, rps: Math.round(getTargetRps(ms) * 10) / 10 };
    });
  }, [duration, getTargetRps]);

  // ── Latency histogram ────────────────────────────────────────

  const histogramData = useMemo(() => {
    if (results.length === 0) return [];
    const times = results.filter(r => r.responseTimeMs > 0).map(r => r.responseTimeMs);
    if (times.length === 0) return [];
    const buckets = [
      { label: '0-10', min: 0, max: 10 },
      { label: '10-25', min: 10, max: 25 },
      { label: '25-50', min: 25, max: 50 },
      { label: '50-100', min: 50, max: 100 },
      { label: '100-250', min: 100, max: 250 },
      { label: '250-500', min: 250, max: 500 },
      { label: '500ms-1s', min: 500, max: 1000 },
      { label: '1-2.5s', min: 1000, max: 2500 },
      { label: '2.5-5s', min: 2500, max: 5000 },
      { label: '5s+', min: 5000, max: Infinity },
    ];
    return buckets.map(b => ({
      label: b.label,
      count: times.filter(t => t >= b.min && t < b.max).length,
      pct: Math.round((times.filter(t => t >= b.min && t < b.max).length / times.length) * 1000) / 10,
    })).filter(b => b.count > 0);
  }, [results]);

  // ── Apdex score ──────────────────────────────────────────────

  const apdex = useMemo(() => {
    const times = results.filter(r => r.responseTimeMs > 0 && !r.error).map(r => r.responseTimeMs);
    if (times.length === 0) return null;
    const satisfied = times.filter(t => t <= apdexT).length;
    const tolerating = times.filter(t => t > apdexT && t <= apdexT * 4).length;
    const score = (satisfied + tolerating / 2) / times.length;
    let rating: string, color: string;
    if (score >= 0.94) { rating = 'Excellent'; color = 'text-emerald-400'; }
    else if (score >= 0.85) { rating = 'Good'; color = 'text-blue-400'; }
    else if (score >= 0.70) { rating = 'Fair'; color = 'text-amber-400'; }
    else if (score >= 0.50) { rating = 'Poor'; color = 'text-orange-400'; }
    else { rating = 'Unacceptable'; color = 'text-red-400'; }
    return { score, rating, color, satisfied, tolerating, frustrated: times.length - satisfied - tolerating };
  }, [results, apdexT]);

  // ── Threshold evaluation ──────────────────────────────────────

  const thresholdResults = useMemo((): ThresholdResult[] => {
    if (!stats || thresholds.length === 0) return [];
    const getMetricValue = (metric: string): number => {
      switch (metric) {
        case 'avg_response': return stats.avg;
        case 'p95_response': return stats.p95;
        case 'p99_response': return stats.p99;
        case 'max_response': return stats.max;
        case 'error_rate': return stats.total > 0 ? ((stats.clientErrors + stats.serverErrors + stats.networkErrors) / stats.total) * 100 : 0;
        case 'success_rate': return stats.total > 0 ? (stats.success / stats.total) * 100 : 0;
        default: return 0;
      }
    };
    return thresholds.map(t => {
      const actual = getMetricValue(t.metric);
      const passed = t.op === '<' ? actual < t.value : t.op === '>' ? actual > t.value : actual <= t.value;
      return { ...t, actual, passed };
    });
  }, [stats, thresholds]);

  // ── Test execution ─────────────────────────────────────────────

  const startTest = useCallback(() => {
    if (!url.trim()) return;
    try { new URL(url); } catch { return; }

    // Reset
    resultsRef.current = [];
    sentRef.current = 0;
    inFlightRef.current = 0;
    burstsDoneRef.current = 0;
    abortRef.current = false;
    startTimeRef.current = Date.now();
    setResults([]);
    setElapsedMs(0);
    setSentCount(0);
    setIsRunning(true);

    const startTime = Date.now();
    const targetTotal = testMode === 'count' ? totalRequests : Infinity;
    const durationMs = testMode === 'duration' ? duration * 1000 : Infinity;

    // Build headers object
    const headerObj: Record<string, string> = {};
    for (const h of customHeaders) {
      if (h.key.trim()) headerObj[h.key.trim()] = h.value;
    }

    const sendOne = async () => {
      inFlightRef.current++;
      try {
        const resp = await fetch('/api/load-test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url,
            method,
            headers: headerObj,
            body: ['POST', 'PUT', 'PATCH'].includes(method) ? requestBody : undefined,
          }),
        });
        const data = await resp.json();
        resultsRef.current.push({
          id: resultsRef.current.length,
          timestamp: Date.now() - startTime,
          statusCode: data.statusCode || 0,
          responseTimeMs: data.responseTimeMs ?? 0,
          bodySize: data.bodySize || 0,
          error: data.error,
        });
      } catch (err: any) {
        resultsRef.current.push({
          id: resultsRef.current.length,
          timestamp: Date.now() - startTime,
          statusCode: 0,
          responseTimeMs: 0,
          bodySize: 0,
          error: err.message || 'Proxy error',
        });
      } finally {
        inFlightRef.current--;
      }
    };

    // Dispatch loop: 50ms ticks for accurate timing
    dispatchRef.current = setInterval(() => {
      const elapsed = Date.now() - startTime;

      if (abortRef.current || elapsed >= durationMs || sentRef.current >= targetTotal) {
        clearInterval(dispatchRef.current);
        // Wait for in-flight to drain
        const finishId = setInterval(() => {
          setResults([...resultsRef.current]);
          setElapsedMs(Date.now() - startTime);
          setSentCount(sentRef.current);
          if (inFlightRef.current === 0) {
            clearInterval(finishId);
            clearInterval(uiRef.current);
            setIsRunning(false);
          }
        }, 100);
        return;
      }

      if (profile === 'burst') {
        // Fire `burstSize` requests simultaneously at each interval boundary (t=0, T, 2T…).
        // Synchronous loop => all fetches are initiated in the same event-loop tick, i.e. truly
        // at once. Concurrency cap is intentionally bypassed — the burst IS the concurrency.
        const intervalMs = Math.max(1, burstInterval) * 1000;
        const dueBursts = Math.floor(elapsed / intervalMs) + 1;
        while (burstsDoneRef.current < dueBursts && sentRef.current < targetTotal) {
          for (let i = 0; i < burstSize && sentRef.current < targetTotal; i++) {
            sentRef.current++;
            sendOne();
          }
          burstsDoneRef.current++;
        }
      } else {
        // Calculate how many requests should have been sent by now
        const expected = Math.min(
          profile === 'constant' ? Math.floor(elapsed * rps / 1000) : getExpectedAt(elapsed),
          targetTotal
        );
        const toSend = expected - sentRef.current;
        for (let i = 0; i < toSend && inFlightRef.current < concurrency; i++) {
          sentRef.current++;
          sendOne();
        }
      }
    }, 50);

    // UI update loop: 200ms for smooth stats
    uiRef.current = setInterval(() => {
      setResults([...resultsRef.current]);
      setElapsedMs(Date.now() - startTime);
      setSentCount(sentRef.current);
    }, 200);

  }, [url, method, customHeaders, requestBody, rps, testMode, duration, totalRequests, concurrency, profile, getExpectedAt, burstSize, burstInterval]);

  const stopTest = useCallback(() => {
    abortRef.current = true;
    clearInterval(dispatchRef.current);
    clearInterval(uiRef.current);
    setIsRunning(false);
    setResults([...resultsRef.current]);
    setElapsedMs(Date.now() - startTimeRef.current);
    setSentCount(sentRef.current);
  }, []);

  // ── Export CSV ─────────────────────────────────────────────────

  const exportCsv = useCallback(() => {
    if (results.length === 0) return;
    const header = 'ID,Timestamp (ms),Status Code,Response Time (ms),Body Size (bytes),Error\n';
    const rows = results.map(r =>
      `${r.id},${r.timestamp},${r.statusCode},${r.responseTimeMs},${r.bodySize},"${(r.error || '').replace(/"/g, '""')}"`
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `load-test-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
  }, [results]);

  // ── Header handlers ────────────────────────────────────────────

  // ── URL parts for log analysis ──────────────────────────────────

  const urlParts = useMemo(() => {
    try {
      const u = new URL(url);
      return { domain: u.hostname, path: u.pathname };
    } catch { return { domain: '', path: '' }; }
  }, [url]);

  // ── F5 XC Log Analysis ────────────────────────────────────────

  const fetchNamespaces = useCallback(async () => {
    if (!isConnected) return;
    setIsLoadingNs(true);
    try {
      const data = await apiClient.getNamespaces();
      const items = (data as any)?.items || [];
      setNamespaces(items.map((ns: any) => ns.name || ns.metadata?.name).filter(Boolean));
    } catch { /* ignore */ } finally { setIsLoadingNs(false); }
  }, [isConnected]);

  const fetchLoadBalancers = useCallback(async (ns: string) => {
    if (!ns || !isConnected) return;
    setIsLoadingLbs(true);
    setLoadBalancers([]);
    setSelectedLb('');
    try {
      const data = await apiClient.getLoadBalancers(ns);
      const items = (data as any)?.items || [];
      setLoadBalancers(items.map((lb: any) => lb.name || lb.metadata?.name).filter(Boolean));
    } catch { /* ignore */ } finally { setIsLoadingLbs(false); }
  }, [isConnected]);

  // Fetch namespaces when log analysis is toggled on
  useEffect(() => {
    if (showLogAnalysis && isConnected && namespaces.length === 0) fetchNamespaces();
  }, [showLogAnalysis, isConnected, namespaces.length, fetchNamespaces]);

  // Fetch LBs when namespace changes
  useEffect(() => {
    if (selectedNamespace) fetchLoadBalancers(selectedNamespace);
  }, [selectedNamespace, fetchLoadBalancers]);

  const fetchLogs = useCallback(async () => {
    if (!selectedNamespace || !selectedLb || !isConnected) return;
    setIsLoadingLogs(true);
    setLogError('');
    setLogEntries([]);
    try {
      const filters: string[] = [`vh_name="ves-io-http-loadbalancer-${selectedLb}"`];
      if (clientIp.trim()) filters.push(`src_ip="${clientIp.trim()}"`);
      if (urlParts.domain) filters.push(`domain="${urlParts.domain}"`);
      const query = `{${filters.join(',')}}`;

      // Time range: cover the test window + buffer
      const endTime = new Date().toISOString();
      const windowMs = Math.max(elapsedMs + 120000, 600000); // at least 10 min
      const startTime = new Date(Date.now() - windowMs).toISOString();

      const data = await apiClient.getAccessLogs(selectedNamespace, {
        query, namespace: selectedNamespace, start_time: startTime, end_time: endTime, scroll: true, limit: 500,
      }) as any;

      let entries = data?.logs || [];
      if (entries.length > 0 && typeof entries[0] === 'string') {
        entries = entries.map((e: string) => { try { return JSON.parse(e); } catch { return null; } }).filter(Boolean);
      }

      // Scroll for more pages (up to 2000)
      let scrollId = data?.scroll_id;
      while (scrollId && entries.length < 2000) {
        const scrollData = await apiClient.post<any>(
          `/api/data/namespaces/${selectedNamespace}/access_logs/scroll`,
          { scroll_id: scrollId, namespace: selectedNamespace },
        );
        let page = scrollData?.logs || [];
        if (page.length === 0) break;
        if (typeof page[0] === 'string') {
          page = page.map((e: string) => { try { return JSON.parse(e); } catch { return null; } }).filter(Boolean);
        }
        entries = [...entries, ...page];
        scrollId = scrollData?.scroll_id;
      }

      setLogEntries(entries);
      if (entries.length === 0) {
        setLogError('No matching log entries found. Logs may take a few minutes to appear — try again shortly.');
      }
    } catch (err: any) {
      setLogError(err.message || 'Failed to fetch logs');
    } finally { setIsLoadingLogs(false); }
  }, [selectedNamespace, selectedLb, isConnected, clientIp, urlParts, elapsedMs]);

  // ── Log analysis memo ─────────────────────────────────────────

  const logAnalysis = useMemo(() => {
    if (logEntries.length === 0) return null;

    const allowed = logEntries.filter(l => {
      const code = parseInt(l.rsp_code || '0');
      return code >= 200 && code < 400;
    });
    const blocked = logEntries.filter(l => {
      const code = parseInt(l.rsp_code || '0');
      return code >= 400 || l.waf_action === 'BLOCK';
    });

    // Group blocked by response code
    const blockedByCode = new Map<string, number>();
    for (const entry of blocked) {
      const code = entry.rsp_code || 'Unknown';
      blockedByCode.set(code, (blockedByCode.get(code) || 0) + 1);
    }

    // WAF action distribution
    const wafActions = new Map<string, number>();
    for (const entry of logEntries) {
      const action = entry.waf_action || 'NONE';
      wafActions.set(action, (wafActions.get(action) || 0) + 1);
    }

    // Block reasons
    const reasonMap = new Map<string, number>();
    for (const entry of blocked) {
      let reason: string;
      if (entry.waf_action === 'BLOCK') {
        reason = 'WAF Block';
      } else if (entry.rsp_code_details) {
        reason = entry.rsp_code_details;
      } else {
        const code = parseInt(entry.rsp_code || '0');
        if (code === 429) reason = 'Rate Limited';
        else if (code === 403) reason = 'Forbidden';
        else if (code >= 500) reason = 'Server Error';
        else reason = `HTTP ${entry.rsp_code}`;
      }
      reasonMap.set(reason, (reasonMap.get(reason) || 0) + 1);
    }
    const blockReasons = Array.from(reasonMap.entries())
      .map(([reason, count]) => ({ reason, count }))
      .sort((a, b) => b.count - a.count);

    return {
      total: logEntries.length,
      allowed: allowed.length,
      blocked: blocked.length,
      blockedByCode,
      wafActions,
      blockReasons,
    };
  }, [logEntries]);

  // ── Header handlers ────────────────────────────────────────────

  const addHeader = () => setCustomHeaders(h => [...h, { key: '', value: '' }]);
  const removeHeader = (i: number) => setCustomHeaders(h => h.filter((_, idx) => idx !== i));
  const updateHeader = (i: number, field: 'key' | 'value', val: string) => {
    setCustomHeaders(h => h.map((item, idx) => idx === i ? { ...item, [field]: val } : item));
  };

  // ── Progress ───────────────────────────────────────────────────

  const progress = useMemo(() => {
    if (!isRunning && results.length === 0) return 0;
    if (testMode === 'duration') return Math.min(100, (elapsedMs / (duration * 1000)) * 100);
    return Math.min(100, (sentCount / totalRequests) * 100);
  }, [isRunning, results.length, testMode, elapsedMs, duration, sentCount, totalRequests]);

  // ── Helpers ────────────────────────────────────────────────────

  const statusColor = (code: number) => {
    if (code === 0) return 'text-slate-400';
    if (code < 300) return 'text-emerald-400';
    if (code < 400) return 'text-blue-400';
    if (code < 500) return 'text-amber-400';
    return 'text-red-400';
  };

  const formatBytes = (b: number) => {
    if (b < 1024) return `${b} B`;
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
    return `${(b / 1024 / 1024).toFixed(1)} MB`;
  };

  const urlValid = useMemo(() => {
    if (!url.trim()) return true;
    try { new URL(url); return true; } catch { return false; }
  }, [url]);

  // ── Render ─────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
      {/* Header */}
      <div className="border-b border-slate-700/50 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center gap-4">
            <button onClick={() => navigate('/')} className="p-2 hover:bg-slate-800 rounded-lg transition-colors">
              <ArrowLeft className="w-5 h-5 text-slate-400" />
            </button>
            <div className="w-10 h-10 rounded-xl bg-yellow-500/10 flex items-center justify-center">
              <Zap className="w-5 h-5 text-yellow-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold">Load Tester</h1>
              <p className="text-sm text-slate-400">Stress test endpoints with configurable request rates and real-time metrics</p>
            </div>
            <Link to="/explainer/load-tester" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
              <HelpCircle className="w-3.5 h-3.5" /> How does this work?
            </Link>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        {/* ── Config Section ──────────────────────────── */}
        <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5 space-y-4">
          {/* URL Bar */}
          <div className="flex gap-2">
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value as HttpMethod)}
              disabled={isRunning}
              className="px-3 py-2.5 bg-slate-700 border border-slate-600 rounded-lg text-sm font-mono font-bold cursor-pointer"
              style={{ color: METHOD_COLORS[method] }}
            >
              {METHODS.map(m => <option key={m} value={m}>{m}</option>)}
            </select>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={isRunning}
              placeholder="https://example.com/api/endpoint"
              className={`flex-1 px-4 py-2.5 bg-slate-700 border rounded-lg text-sm font-mono placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500 ${
                !urlValid ? 'border-red-500' : 'border-slate-600'
              }`}
            />
            {isRunning ? (
              <button
                onClick={stopTest}
                className="px-6 py-2.5 bg-red-600 hover:bg-red-500 rounded-lg text-sm font-semibold flex items-center gap-2 transition-colors"
              >
                <Square className="w-4 h-4" /> Stop
              </button>
            ) : (
              <button
                onClick={startTest}
                disabled={!url.trim() || !urlValid}
                className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg text-sm font-semibold flex items-center gap-2 transition-colors"
              >
                <Play className="w-4 h-4" /> Start
              </button>
            )}
          </div>

          {!urlValid && url.trim() && (
            <p className="text-xs text-red-400">Invalid URL format — must include protocol (https://)</p>
          )}

          {/* Settings Row */}
          <div className="flex flex-wrap items-center gap-4 text-sm">
            {/* Load Profile */}
            <div className="flex items-center gap-2">
              <label className="text-slate-400">Profile:</label>
              <div className="flex bg-slate-700 rounded border border-slate-600 overflow-hidden">
                {PROFILES.map(p => (
                  <button
                    key={p.id}
                    onClick={() => setProfile(p.id)}
                    disabled={isRunning}
                    title={p.desc}
                    className={`px-2.5 py-1.5 text-xs font-medium transition-colors ${
                      profile === p.id
                        ? 'bg-blue-600 text-white'
                        : 'text-slate-400 hover:text-white hover:bg-slate-600'
                    } disabled:opacity-50`}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="w-px h-6 bg-slate-600" />

            {/* Profile-specific config */}
            {profile === 'constant' && (
              <div className="flex items-center gap-2">
                <label className="text-slate-400">RPS:</label>
                <input type="number" value={rps} onChange={(e) => setRps(Math.max(1, parseInt(e.target.value) || 1))} disabled={isRunning} className={`w-20 ${NI}`} min={1} max={1000} />
              </div>
            )}
            {profile === 'ramp' && (
              <div className="flex items-center gap-1.5">
                <label className="text-slate-400">From:</label>
                <input type="number" value={rampFrom} onChange={(e) => setRampFrom(Math.max(1, parseInt(e.target.value) || 1))} disabled={isRunning} className={`w-16 ${NI}`} min={1} />
                <label className="text-slate-400">To:</label>
                <input type="number" value={rampTo} onChange={(e) => setRampTo(Math.max(1, parseInt(e.target.value) || 1))} disabled={isRunning} className={`w-16 ${NI}`} min={1} />
                <span className="text-slate-500 text-xs">RPS</span>
              </div>
            )}
            {profile === 'step' && (
              <div className="flex items-center gap-1.5">
                <label className="text-slate-400">Base:</label>
                <input type="number" value={rps} onChange={(e) => setRps(Math.max(1, parseInt(e.target.value) || 1))} disabled={isRunning} className={`w-16 ${NI}`} min={1} />
                <label className="text-slate-400">+</label>
                <input type="number" value={stepSize} onChange={(e) => setStepSize(Math.max(1, parseInt(e.target.value) || 1))} disabled={isRunning} className={`w-14 ${NI}`} min={1} />
                <label className="text-slate-400">every</label>
                <input type="number" value={stepInterval} onChange={(e) => setStepInterval(Math.max(1, parseInt(e.target.value) || 1))} disabled={isRunning} className={`w-14 ${NI}`} min={1} />
                <span className="text-slate-500 text-xs">sec</span>
              </div>
            )}
            {profile === 'spike' && (
              <div className="flex items-center gap-1.5">
                <label className="text-slate-400">Base:</label>
                <input type="number" value={spikeBase} onChange={(e) => setSpikeBase(Math.max(1, parseInt(e.target.value) || 1))} disabled={isRunning} className={`w-14 ${NI}`} min={1} />
                <label className="text-slate-400">Peak:</label>
                <input type="number" value={spikePeak} onChange={(e) => setSpikePeak(Math.max(1, parseInt(e.target.value) || 1))} disabled={isRunning} className={`w-16 ${NI}`} min={1} />
                <label className="text-slate-400">at</label>
                <input type="number" value={spikeAt} onChange={(e) => setSpikeAt(Math.max(0, Math.min(100, parseInt(e.target.value) || 0)))} disabled={isRunning} className={`w-14 ${NI}`} min={0} max={100} />
                <label className="text-slate-400">dur:</label>
                <input type="number" value={spikeDur} onChange={(e) => setSpikeDur(Math.max(1, Math.min(100, parseInt(e.target.value) || 1)))} disabled={isRunning} className={`w-14 ${NI}`} min={1} max={100} />
                <span className="text-slate-500 text-xs">%</span>
              </div>
            )}
            {profile === 'burst' && (
              <div className="flex items-center gap-1.5">
                <label className="text-slate-400">Requests:</label>
                <input type="number" value={burstSize} onChange={(e) => setBurstSize(Math.max(1, parseInt(e.target.value) || 1))} disabled={isRunning} className={`w-20 ${NI}`} min={1} max={5000} title="Number of requests fired simultaneously in each burst" />
                <label className="text-slate-400">every</label>
                <input type="number" value={burstInterval} onChange={(e) => setBurstInterval(Math.max(1, parseInt(e.target.value) || 1))} disabled={isRunning} className={`w-14 ${NI}`} min={1} />
                <span className="text-slate-500 text-xs">sec → ~{Math.round(burstSize / Math.max(1, burstInterval))} RPS</span>
              </div>
            )}

            <div className="w-px h-6 bg-slate-600" />

            <div className="flex items-center gap-2">
              <select value={testMode} onChange={(e) => setTestMode(e.target.value as TestMode)} disabled={isRunning} className="px-2 py-1.5 bg-slate-700 border border-slate-600 rounded text-slate-300 text-sm cursor-pointer">
                <option value="duration">Duration</option>
                <option value="count">Count</option>
              </select>
              {testMode === 'duration' ? (
                <div className="flex items-center gap-1">
                  <input type="number" value={duration} onChange={(e) => setDuration(Math.max(1, parseInt(e.target.value) || 1))} disabled={isRunning} className={`w-16 ${NI}`} min={1} />
                  <span className="text-slate-500">sec</span>
                </div>
              ) : (
                <div className="flex items-center gap-1">
                  <input type="number" value={totalRequests} onChange={(e) => setTotalRequests(Math.max(1, parseInt(e.target.value) || 1))} disabled={isRunning} className={`w-20 ${NI}`} min={1} />
                  <span className="text-slate-500">reqs</span>
                </div>
              )}
            </div>

            <div className="w-px h-6 bg-slate-600" />

            <div className="flex items-center gap-2">
              <label className="text-slate-400">Concurrency:</label>
              <input
                type="number"
                value={profile === 'burst' ? burstSize : concurrency}
                onChange={(e) => setConcurrency(Math.max(1, parseInt(e.target.value) || 1))}
                disabled={isRunning || profile === 'burst'}
                className={`w-20 ${NI} ${profile === 'burst' ? 'opacity-40' : ''}`}
                min={1} max={2000}
                title="Max requests allowed in-flight at once. If it's lower than your target RPS and the endpoint is slow, it caps the achievable RPS. Use the Burst profile to fire N requests simultaneously regardless of this cap."
              />
              {profile === 'burst'
                ? <span className="text-[10px] text-slate-500">= burst size (all fire at once)</span>
                : profile === 'constant' && concurrency < rps
                  ? <span className="text-[10px] text-amber-400">⚠ below target {rps} RPS — may cap throughput</span>
                  : null}
            </div>

            <div className="flex-1" />

            <button onClick={() => setShowConfig(!showConfig)} disabled={isRunning} className="flex items-center gap-1 text-slate-400 hover:text-white transition-colors text-sm">
              Headers & Body
              {showConfig ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </div>

          {/* Profile Preview Sparkline */}
          {profile !== 'constant' && testMode === 'duration' && (
            <div className="bg-slate-900/50 rounded-lg p-3 border border-slate-700/30">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">RPS Profile Preview</span>
                <span className="text-[10px] text-slate-500">{duration}s total</span>
              </div>
              <ResponsiveContainer width="100%" height={50}>
                <AreaChart data={profilePreview}>
                  <Area dataKey="rps" fill="#3b82f6" fillOpacity={0.15} stroke="#3b82f6" strokeWidth={1.5} />
                  <XAxis dataKey="time" hide />
                  <YAxis hide />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Expandable Headers & Body */}
          {showConfig && (
            <div className="border-t border-slate-700 pt-4 space-y-4">
              {/* Headers */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-sm font-medium text-slate-300">Custom Headers</label>
                  <button onClick={addHeader} disabled={isRunning}
                    className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 disabled:opacity-40">
                    <Plus className="w-3 h-3" /> Add Header
                  </button>
                </div>
                {customHeaders.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">No custom headers configured</p>
                ) : (
                  <div className="space-y-2">
                    {customHeaders.map((h, i) => (
                      <div key={i} className="flex gap-2 items-center">
                        <input
                          value={h.key}
                          onChange={(e) => updateHeader(i, 'key', e.target.value)}
                          placeholder="Header name"
                          disabled={isRunning}
                          className="flex-1 px-3 py-1.5 bg-slate-700 border border-slate-600 rounded text-sm font-mono"
                        />
                        <input
                          value={h.value}
                          onChange={(e) => updateHeader(i, 'value', e.target.value)}
                          placeholder="Value"
                          disabled={isRunning}
                          className="flex-1 px-3 py-1.5 bg-slate-700 border border-slate-600 rounded text-sm font-mono"
                        />
                        <button onClick={() => removeHeader(i)} disabled={isRunning}
                          className="p-1.5 text-slate-500 hover:text-red-400 disabled:opacity-40">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Body */}
              {['POST', 'PUT', 'PATCH'].includes(method) && (
                <div>
                  <label className="text-sm font-medium text-slate-300 mb-2 block">Request Body</label>
                  <textarea
                    value={requestBody}
                    onChange={(e) => setRequestBody(e.target.value)}
                    disabled={isRunning}
                    placeholder='{"key": "value"}'
                    className="w-full h-24 px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm font-mono resize-y"
                  />
                </div>
              )}
            </div>
          )}
        </div>

        {/* ── Progress Bar ─────────────────────────────── */}
        {(isRunning || results.length > 0) && (
          <div className="space-y-1">
            <div className="flex justify-between text-xs text-slate-400">
              <span>
                {isRunning ? 'Running...' : 'Completed'} — {sentCount} sent, {results.length} completed
              </span>
              <span>{(elapsedMs / 1000).toFixed(1)}s elapsed</span>
            </div>
            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-200 ${isRunning ? 'bg-blue-500' : 'bg-emerald-500'}`}
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

        {/* ── Stats Cards ──────────────────────────────── */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            {[
              { label: 'Total Requests', value: stats.total, sub: `${sentCount} sent`, color: 'text-white' },
              { label: 'Success (2xx/3xx)', value: stats.success, sub: `${stats.total > 0 ? ((stats.success / stats.total) * 100).toFixed(1) : 0}%`, color: 'text-emerald-400' },
              { label: 'Errors', value: stats.clientErrors + stats.serverErrors + stats.networkErrors, sub: `${stats.clientErrors} 4xx · ${stats.serverErrors} 5xx · ${stats.networkErrors} net`, color: 'text-red-400' },
              { label: 'Avg Response', value: `${Math.round(stats.avg)}ms`, sub: `min ${Math.round(stats.min)}ms`, color: 'text-blue-400' },
              { label: 'P95 Response', value: `${Math.round(stats.p95)}ms`, sub: `max ${Math.round(stats.max)}ms`, color: 'text-amber-400' },
              { label: 'Actual RPS', value: stats.currentRps.toFixed(1), sub: `target ${profile === 'constant' ? `${rps}/s` : profile === 'burst' ? `${burstSize}×/${burstInterval}s` : profile}`, color: 'text-purple-400' },
            ].map((card, i) => (
              <div key={i} className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-4">
                <p className="text-xs text-slate-500 mb-1">{card.label}</p>
                <p className={`text-2xl font-bold font-mono ${card.color}`}>{card.value}</p>
                <p className="text-[11px] text-slate-500 mt-0.5 truncate">{card.sub}</p>
              </div>
            ))}
            {/* Apdex card */}
            {apdex && (
              <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-4">
                <div className="flex items-center justify-between mb-1">
                  <p className="text-xs text-slate-500">Apdex Score</p>
                  <div className="flex items-center gap-1">
                    <span className="text-[10px] text-slate-600">T=</span>
                    <input
                      type="number"
                      value={apdexT}
                      onChange={(e) => setApdexT(Math.max(1, parseInt(e.target.value) || 500))}
                      className="w-12 px-1 py-0 bg-transparent border-b border-slate-600 text-[10px] font-mono text-slate-400 text-center [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
                    />
                    <span className="text-[10px] text-slate-600">ms</span>
                  </div>
                </div>
                <p className={`text-2xl font-bold font-mono ${apdex.color}`}>{apdex.score.toFixed(2)}</p>
                <p className={`text-[11px] mt-0.5 ${apdex.color}`}>{apdex.rating}</p>
              </div>
            )}
          </div>
        )}

        {/* ── Threshold Config & Results ──────────────── */}
        {stats && (
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-slate-300">Pass / Fail Thresholds (SLA)</h3>
              <button
                onClick={() => setThresholds(t => [...t, { metric: 'p95_response', op: '<', value: 500 }])}
                className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300"
              >
                <Plus className="w-3 h-3" /> Add Rule
              </button>
            </div>
            {thresholds.length === 0 ? (
              <p className="text-xs text-slate-500 italic">No thresholds configured. Add rules to validate SLA targets.</p>
            ) : (
              <div className="space-y-2">
                {thresholds.map((t, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <select
                      value={t.metric}
                      onChange={(e) => setThresholds(prev => prev.map((r, idx) => idx === i ? { ...r, metric: e.target.value } : r))}
                      className="px-2 py-1.5 bg-slate-700 border border-slate-600 rounded text-sm text-slate-300 flex-1"
                    >
                      {THRESHOLD_METRICS.map(m => <option key={m.id} value={m.id}>{m.label}</option>)}
                    </select>
                    <select
                      value={t.op}
                      onChange={(e) => setThresholds(prev => prev.map((r, idx) => idx === i ? { ...r, op: e.target.value } : r))}
                      className="px-2 py-1.5 bg-slate-700 border border-slate-600 rounded text-sm font-mono text-slate-300 w-14"
                    >
                      <option value="<">&lt;</option>
                      <option value=">">&gt;</option>
                      <option value="<=">&le;</option>
                    </select>
                    <input
                      type="number"
                      value={t.value}
                      onChange={(e) => setThresholds(prev => prev.map((r, idx) => idx === i ? { ...r, value: parseFloat(e.target.value) || 0 } : r))}
                      className={`w-24 ${NI}`}
                    />
                    <button onClick={() => setThresholds(prev => prev.filter((_, idx) => idx !== i))} className="p-1.5 text-slate-500 hover:text-red-400">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                    {/* Result badge */}
                    {thresholdResults[i] && (
                      <span className={`flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold ${
                        thresholdResults[i].passed
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-red-500/10 text-red-400 border border-red-500/20'
                      }`}>
                        {thresholdResults[i].passed ? <CheckCircle className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                        {Math.round(thresholdResults[i].actual * 10) / 10}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
            {/* Overall verdict */}
            {thresholdResults.length > 0 && !isRunning && (
              <div className={`mt-3 flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-semibold ${
                thresholdResults.every(t => t.passed)
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  : 'bg-red-500/10 text-red-400 border border-red-500/20'
              }`}>
                {thresholdResults.every(t => t.passed)
                  ? <><CheckCircle className="w-4 h-4" /> All thresholds passed</>
                  : <><XCircle className="w-4 h-4" /> {thresholdResults.filter(t => !t.passed).length} of {thresholdResults.length} thresholds failed</>}
              </div>
            )}
          </div>
        )}

        {/* ── Tabbed Charts ────────────────────────────── */}
        {chartData.length > 1 && (
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5">
            {/* Chart Tabs */}
            <div className="flex items-center gap-1 mb-4">
              {([
                { id: 'response' as ChartTab, label: 'Response Time' },
                { id: 'throughput' as ChartTab, label: 'Throughput & Errors' },
                { id: 'histogram' as ChartTab, label: 'Latency Distribution' },
              ]).map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setChartTab(tab.id)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                    chartTab === tab.id
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-white hover:bg-slate-700'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Response Time Chart */}
            {chartTab === 'response' && (
              <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} />
                  <YAxis stroke="#64748b" fontSize={10} tickFormatter={(v) => `${v}ms`} />
                  <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} labelStyle={{ color: '#94a3b8' }} />
                  <Area dataKey="max" name="Max" fill="#ef4444" fillOpacity={0.06} stroke="#ef4444" strokeWidth={1} strokeDasharray="3 3" />
                  <Area dataKey="p95" name="P95" fill="#f59e0b" fillOpacity={0.06} stroke="#f59e0b" strokeWidth={1} strokeDasharray="2 2" />
                  <Area dataKey="avg" name="Avg" fill="#3b82f6" fillOpacity={0.15} stroke="#3b82f6" strokeWidth={2} />
                  <Area dataKey="min" name="Min" fill="#10b981" fillOpacity={0.06} stroke="#10b981" strokeWidth={1} strokeDasharray="3 3" />
                </AreaChart>
              </ResponsiveContainer>
            )}

            {/* Throughput & Errors Chart */}
            {chartTab === 'throughput' && (
              <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} />
                  <YAxis yAxisId="rps" stroke="#64748b" fontSize={10} tickFormatter={(v) => `${v}`} />
                  <YAxis yAxisId="pct" orientation="right" stroke="#64748b" fontSize={10} tickFormatter={(v) => `${v}%`} domain={[0, 100]} />
                  <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} labelStyle={{ color: '#94a3b8' }} />
                  <Area yAxisId="rps" dataKey="rps" name="RPS" fill="#8b5cf6" fillOpacity={0.15} stroke="#8b5cf6" strokeWidth={2} />
                  <Area yAxisId="rps" dataKey="errors" name="Errors" fill="#ef4444" fillOpacity={0.15} stroke="#ef4444" strokeWidth={1.5} />
                  <Area yAxisId="pct" dataKey="errorPct" name="Error %" fill="none" stroke="#f59e0b" strokeWidth={1} strokeDasharray="4 2" />
                </AreaChart>
              </ResponsiveContainer>
            )}

            {/* Latency Histogram */}
            {chartTab === 'histogram' && histogramData.length > 0 && (
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={histogramData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="label" stroke="#64748b" fontSize={10} />
                  <YAxis stroke="#64748b" fontSize={10} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }}
                    labelStyle={{ color: '#94a3b8' }}
                  />
                  <Bar dataKey="count" name="Requests" radius={[4, 4, 0, 0]}>
                    {histogramData.map((_, i) => (
                      <Cell key={i} fill={i < 4 ? '#10b981' : i < 6 ? '#f59e0b' : '#ef4444'} fillOpacity={0.7} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        )}

        {/* ── Status Distribution + Percentiles ────────── */}
        {stats && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Status Distribution */}
            <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-3">Status Code Distribution</h3>
              <div className="space-y-2">
                {Array.from(stats.statusDist.entries())
                  .sort(([a], [b]) => a.localeCompare(b))
                  .map(([code, count]) => {
                    const pct = (count / stats.total) * 100;
                    const codeNum = parseInt(code);
                    let barColor = '#64748b';
                    if (codeNum >= 200 && codeNum < 300) barColor = '#10b981';
                    else if (codeNum >= 300 && codeNum < 400) barColor = '#3b82f6';
                    else if (codeNum >= 400 && codeNum < 500) barColor = '#f59e0b';
                    else if (codeNum >= 500) barColor = '#ef4444';
                    else if (code === 'Error') barColor = '#94a3b8';
                    return (
                      <div key={code} className="flex items-center gap-3">
                        <span className="w-12 text-xs font-mono text-slate-300 text-right">{code}</span>
                        <div className="flex-1 h-5 bg-slate-700 rounded overflow-hidden">
                          <div
                            className="h-full rounded transition-all duration-300"
                            style={{ width: `${Math.max(pct, 1)}%`, backgroundColor: barColor }}
                          />
                        </div>
                        <span className="text-xs text-slate-400 w-24 text-right font-mono">{count} ({pct.toFixed(1)}%)</span>
                      </div>
                    );
                  })}
              </div>
            </div>

            {/* Percentile Table */}
            <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-slate-300">Response Time Percentiles</h3>
                {results.length > 0 && (
                  <button onClick={exportCsv} className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300">
                    <Download className="w-3 h-3" /> Export CSV
                  </button>
                )}
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-slate-500 text-xs">
                    <th className="text-left py-1.5">Metric</th>
                    <th className="text-right py-1.5">Response Time</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    { label: 'Minimum', value: stats.min },
                    { label: 'P50 (Median)', value: stats.p50 },
                    { label: 'Average', value: stats.avg },
                    { label: 'P95', value: stats.p95 },
                    { label: 'P99', value: stats.p99 },
                    { label: 'Maximum', value: stats.max },
                  ].map(row => (
                    <tr key={row.label} className="border-t border-slate-700/50">
                      <td className="py-2 text-slate-300">{row.label}</td>
                      <td className="py-2 text-right font-mono text-slate-200">{Math.round(row.value)} ms</td>
                    </tr>
                  ))}
                  <tr className="border-t border-slate-700/50">
                    <td className="py-2 text-slate-300">Total Data Transferred</td>
                    <td className="py-2 text-right font-mono text-slate-200">{formatBytes(stats.totalBytes)}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Test Report: Allowed vs Blocked ────────── */}
        {stats && stats.total > 0 && (
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">Test Report — Allowed vs Blocked</h3>

            {/* 3 summary cards */}
            <div className="grid grid-cols-3 gap-3 mb-5">
              <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-4 text-center">
                <CheckCircle className="w-5 h-5 text-emerald-400 mx-auto mb-1" />
                <p className="text-2xl font-bold font-mono text-emerald-400">{stats.allowed}</p>
                <p className="text-xs text-emerald-400/70">Allowed ({stats.total > 0 ? ((stats.allowed / stats.total) * 100).toFixed(1) : 0}%)</p>
                <p className="text-[10px] text-slate-500 mt-0.5">2xx / 3xx responses</p>
              </div>
              <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-4 text-center">
                <XCircle className="w-5 h-5 text-red-400 mx-auto mb-1" />
                <p className="text-2xl font-bold font-mono text-red-400">{stats.blocked}</p>
                <p className="text-xs text-red-400/70">Blocked ({stats.total > 0 ? ((stats.blocked / stats.total) * 100).toFixed(1) : 0}%)</p>
                <p className="text-[10px] text-slate-500 mt-0.5">4xx / 5xx responses</p>
              </div>
              <div className="bg-slate-500/5 border border-slate-500/20 rounded-lg p-4 text-center">
                <Wifi className="w-5 h-5 text-slate-400 mx-auto mb-1" />
                <p className="text-2xl font-bold font-mono text-slate-400">{stats.errors}</p>
                <p className="text-xs text-slate-400/70">Network Errors ({stats.total > 0 ? ((stats.errors / stats.total) * 100).toFixed(1) : 0}%)</p>
                <p className="text-[10px] text-slate-500 mt-0.5">Timeout / connection failed</p>
              </div>
            </div>

            {/* Blocked breakdown by status code */}
            {stats.blocked > 0 && (
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Blocked Requests by Status Code</h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-slate-500 text-xs border-b border-slate-700">
                        <th className="text-left py-2 px-3">Status Code</th>
                        <th className="text-left py-2 px-3">Description</th>
                        <th className="text-right py-2 px-3">Count</th>
                        <th className="text-right py-2 px-3">% of Blocked</th>
                        <th className="text-right py-2 px-3">% of Total</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Array.from(stats.blockedByCode.entries())
                        .sort(([, a], [, b]) => b - a)
                        .map(([code, count]) => (
                          <tr key={code} className="border-t border-slate-700/30 hover:bg-slate-700/20">
                            <td className={`py-2 px-3 font-mono font-bold ${code >= 500 ? 'text-red-400' : 'text-amber-400'}`}>{code}</td>
                            <td className="py-2 px-3 text-slate-300">{STATUS_LABELS[code] || 'Unknown'}</td>
                            <td className="py-2 px-3 text-right font-mono text-slate-200">{count}</td>
                            <td className="py-2 px-3 text-right font-mono text-slate-400">{((count / stats.blocked) * 100).toFixed(1)}%</td>
                            <td className="py-2 px-3 text-right font-mono text-slate-500">{((count / stats.total) * 100).toFixed(1)}%</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Request Log ──────────────────────────────── */}
        {results.length > 0 && (
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-slate-300">
                Request Log <span className="text-slate-500 font-normal">(last 50)</span>
              </h3>
              <span className="text-xs text-slate-500">{results.length} total</span>
            </div>
            <div className="overflow-x-auto max-h-72 overflow-y-auto">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-slate-800">
                  <tr className="text-slate-500 border-b border-slate-700">
                    <th className="text-left py-2 px-2 w-12">#</th>
                    <th className="text-left py-2 px-2">Time</th>
                    <th className="text-left py-2 px-2">Status</th>
                    <th className="text-right py-2 px-2">Response Time</th>
                    <th className="text-right py-2 px-2">Size</th>
                    <th className="text-left py-2 px-2">Error</th>
                  </tr>
                </thead>
                <tbody>
                  {results.slice(-50).reverse().map(r => (
                    <tr key={r.id} className="border-t border-slate-700/30 hover:bg-slate-700/20">
                      <td className="py-1.5 px-2 font-mono text-slate-500">{r.id + 1}</td>
                      <td className="py-1.5 px-2 font-mono text-slate-400">{(r.timestamp / 1000).toFixed(2)}s</td>
                      <td className={`py-1.5 px-2 font-mono font-bold ${statusColor(r.statusCode)}`}>
                        {r.statusCode || '—'}
                      </td>
                      <td className="py-1.5 px-2 font-mono text-slate-300 text-right">{Math.round(r.responseTimeMs)} ms</td>
                      <td className="py-1.5 px-2 font-mono text-slate-400 text-right">{formatBytes(r.bodySize)}</td>
                      <td className="py-1.5 px-2 text-red-400 truncate max-w-[200px]">{r.error || ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── F5 XC Log Analysis (Optional) ────────────── */}
        {results.length > 0 && (
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 overflow-hidden">
            <button
              onClick={() => setShowLogAnalysis(!showLogAnalysis)}
              className="w-full flex items-center justify-between px-5 py-4 hover:bg-slate-700/20 transition-colors"
            >
              <div className="flex items-center gap-3">
                <Shield className="w-5 h-5 text-blue-400" />
                <div className="text-left">
                  <p className="text-sm font-semibold text-slate-200">F5 XC Log Analysis</p>
                  <p className="text-xs text-slate-500">Optional — Correlate test results with server-side access logs and WAF actions</p>
                </div>
              </div>
              {showLogAnalysis ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
            </button>

            {showLogAnalysis && (
              <div className="px-5 pb-5 border-t border-slate-700/50 pt-4 space-y-4">
                {!isConnected ? (
                  <div className="text-center py-8 text-slate-500">
                    <AlertCircle className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">Connect to an F5 XC tenant first</p>
                    <p className="text-xs mt-1">Use the connection panel on the home page to connect, then return here.</p>
                  </div>
                ) : (
                  <>
                    {/* Config row */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                      <div>
                        <label className="text-xs text-slate-400 mb-1 block">Namespace</label>
                        <select
                          value={selectedNamespace}
                          onChange={(e) => setSelectedNamespace(e.target.value)}
                          disabled={isLoadingNs}
                          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm"
                        >
                          <option value="">Select namespace...</option>
                          {namespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
                        </select>
                      </div>
                      <div>
                        <label className="text-xs text-slate-400 mb-1 block">Load Balancer</label>
                        <select
                          value={selectedLb}
                          onChange={(e) => setSelectedLb(e.target.value)}
                          disabled={!selectedNamespace || isLoadingLbs}
                          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm"
                        >
                          <option value="">{isLoadingLbs ? 'Loading...' : 'Select LB...'}</option>
                          {loadBalancers.map(lb => <option key={lb} value={lb}>{lb}</option>)}
                        </select>
                      </div>
                      <div>
                        <label className="text-xs text-slate-400 mb-1 block">Client IP (your IP)</label>
                        <input
                          type="text"
                          value={clientIp}
                          onChange={(e) => setClientIp(e.target.value)}
                          placeholder="e.g. 203.0.113.42"
                          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm font-mono"
                        />
                      </div>
                      <div>
                        <label className="text-xs text-slate-400 mb-1 block">Domain (from URL)</label>
                        <input
                          type="text"
                          value={urlParts.domain}
                          readOnly
                          className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-sm font-mono text-slate-400"
                        />
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <button
                        onClick={fetchLogs}
                        disabled={!selectedNamespace || !selectedLb || isLoadingLogs}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg text-sm font-medium flex items-center gap-2 transition-colors"
                      >
                        {isLoadingLogs ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                        {isLoadingLogs ? 'Fetching Logs...' : 'Fetch & Analyze Logs'}
                      </button>
                      {urlParts.path && (
                        <span className="text-xs text-slate-500">Path filter: <code className="text-slate-400">{urlParts.path}</code></span>
                      )}
                    </div>

                    {/* Error */}
                    {logError && (
                      <div className="flex items-center gap-2 px-4 py-3 bg-amber-500/10 border border-amber-500/20 rounded-lg">
                        <AlertCircle className="w-4 h-4 text-amber-400 flex-shrink-0" />
                        <p className="text-sm text-amber-300">{logError}</p>
                      </div>
                    )}

                    {/* Log Analysis Results */}
                    {logAnalysis && (
                      <div className="space-y-4">
                        <p className="text-sm text-slate-300">
                          Found <span className="font-bold text-white">{logAnalysis.total}</span> matching log entries
                        </p>

                        {/* Allowed vs Blocked from server logs */}
                        <div className="grid grid-cols-2 gap-3">
                          <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-3 flex items-center gap-3">
                            <CheckCircle className="w-5 h-5 text-emerald-400" />
                            <div>
                              <p className="text-lg font-bold font-mono text-emerald-400">{logAnalysis.allowed}</p>
                              <p className="text-xs text-emerald-400/70">Allowed ({logAnalysis.total > 0 ? ((logAnalysis.allowed / logAnalysis.total) * 100).toFixed(1) : 0}%)</p>
                            </div>
                          </div>
                          <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-3 flex items-center gap-3">
                            <XCircle className="w-5 h-5 text-red-400" />
                            <div>
                              <p className="text-lg font-bold font-mono text-red-400">{logAnalysis.blocked}</p>
                              <p className="text-xs text-red-400/70">Blocked ({logAnalysis.total > 0 ? ((logAnalysis.blocked / logAnalysis.total) * 100).toFixed(1) : 0}%)</p>
                            </div>
                          </div>
                        </div>

                        {/* Block Reasons */}
                        {logAnalysis.blockReasons.length > 0 && (
                          <div>
                            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Block Reasons</h4>
                            <div className="space-y-1.5">
                              {logAnalysis.blockReasons.map(({ reason, count }) => (
                                <div key={reason} className="flex items-center gap-3">
                                  <span className="text-xs text-slate-300 flex-1">{reason}</span>
                                  <span className="text-xs font-mono text-red-400">{count}</span>
                                  <div className="w-24 h-3 bg-slate-700 rounded overflow-hidden">
                                    <div
                                      className="h-full bg-red-500/60 rounded"
                                      style={{ width: `${(count / logAnalysis.blocked) * 100}%` }}
                                    />
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* WAF Actions */}
                        {logAnalysis.wafActions.size > 0 && (
                          <div>
                            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">WAF Actions</h4>
                            <div className="flex flex-wrap gap-2">
                              {Array.from(logAnalysis.wafActions.entries()).map(([action, count]) => (
                                <span key={action} className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium ${
                                  action === 'BLOCK' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                                  action === 'ALLOW' || action === 'NONE' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                                  'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                }`}>
                                  {action} <span className="font-mono">{count}</span>
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Blocked by status code from server logs */}
                        {logAnalysis.blockedByCode.size > 0 && (
                          <div>
                            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Server-Side Blocked by Status Code</h4>
                            <div className="space-y-1.5">
                              {Array.from(logAnalysis.blockedByCode.entries())
                                .sort(([, a], [, b]) => b - a)
                                .map(([code, count]) => {
                                  const codeNum = parseInt(code);
                                  return (
                                    <div key={code} className="flex items-center gap-3">
                                      <span className={`w-10 text-xs font-mono font-bold text-right ${codeNum >= 500 ? 'text-red-400' : 'text-amber-400'}`}>{code}</span>
                                      <span className="text-xs text-slate-400 w-28">{STATUS_LABELS[codeNum] || 'Unknown'}</span>
                                      <div className="flex-1 h-4 bg-slate-700 rounded overflow-hidden">
                                        <div
                                          className="h-full rounded"
                                          style={{
                                            width: `${(count / logAnalysis.blocked) * 100}%`,
                                            backgroundColor: codeNum >= 500 ? '#ef4444' : '#f59e0b',
                                            opacity: 0.6,
                                          }}
                                        />
                                      </div>
                                      <span className="text-xs font-mono text-slate-300 w-12 text-right">{count}</span>
                                    </div>
                                  );
                                })}
                            </div>
                          </div>
                        )}

                        {/* Log entries table */}
                        <div>
                          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                            Log Entries <span className="text-slate-500 font-normal">(last 50)</span>
                          </h4>
                          <div className="overflow-x-auto max-h-64 overflow-y-auto">
                            <table className="w-full text-xs">
                              <thead className="sticky top-0 bg-slate-800">
                                <tr className="text-slate-500 border-b border-slate-700">
                                  <th className="text-left py-2 px-2">Time</th>
                                  <th className="text-left py-2 px-2">Method</th>
                                  <th className="text-left py-2 px-2">Path</th>
                                  <th className="text-left py-2 px-2">Status</th>
                                  <th className="text-left py-2 px-2">WAF</th>
                                  <th className="text-left py-2 px-2">Source IP</th>
                                  <th className="text-left py-2 px-2">Detail</th>
                                </tr>
                              </thead>
                              <tbody>
                                {logEntries.slice(-50).reverse().map((entry, i) => {
                                  const code = parseInt(entry.rsp_code || '0');
                                  const isBlocked = code >= 400 || entry.waf_action === 'BLOCK';
                                  return (
                                    <tr key={i} className={`border-t border-slate-700/30 ${isBlocked ? 'bg-red-500/5' : 'hover:bg-slate-700/20'}`}>
                                      <td className="py-1.5 px-2 font-mono text-slate-400 whitespace-nowrap">
                                        {entry['@timestamp'] ? new Date(entry['@timestamp']).toLocaleTimeString() : '—'}
                                      </td>
                                      <td className="py-1.5 px-2 font-mono text-slate-300">{entry.method || '—'}</td>
                                      <td className="py-1.5 px-2 font-mono text-slate-400 truncate max-w-[150px]">{entry.req_path || '—'}</td>
                                      <td className={`py-1.5 px-2 font-mono font-bold ${code >= 500 ? 'text-red-400' : code >= 400 ? 'text-amber-400' : 'text-emerald-400'}`}>
                                        {entry.rsp_code || '—'}
                                      </td>
                                      <td className={`py-1.5 px-2 text-xs ${entry.waf_action === 'BLOCK' ? 'text-red-400 font-bold' : 'text-slate-500'}`}>
                                        {entry.waf_action || '—'}
                                      </td>
                                      <td className="py-1.5 px-2 font-mono text-slate-400">{entry.src_ip || '—'}</td>
                                      <td className="py-1.5 px-2 text-slate-500 truncate max-w-[150px]">{entry.rsp_code_details || '—'}</td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        )}

        {/* ── Empty state ──────────────────────────────── */}
        {!isRunning && results.length === 0 && (
          <div className="text-center py-20 text-slate-500">
            <Zap className="w-12 h-12 mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium text-slate-400 mb-2">Configure and start a load test</p>
            <p className="text-sm max-w-md mx-auto">
              Enter a target URL, set the request rate and duration, then click Start to begin
              sending requests. Real-time metrics will appear here.
            </p>
            <div className="mt-6 flex items-center justify-center gap-6 text-xs text-slate-600">
              <div className="flex items-center gap-1.5"><Activity className="w-3.5 h-3.5" /> Response time tracking</div>
              <div className="flex items-center gap-1.5"><Clock className="w-3.5 h-3.5" /> Configurable RPS</div>
              <div className="flex items-center gap-1.5"><AlertCircle className="w-3.5 h-3.5" /> Status code analysis</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
