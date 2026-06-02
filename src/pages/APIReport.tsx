// ═══════════════════════════════════════════════════════════════════════════
// API Discovery Report Dashboard
//   1) Overview        — high-level stats per LB, Excel + PDF export
//   2) Schema Download — original F5 XC swagger_spec ZIP, per LB or bulk
//   3) Schema Details  — per-LB schema navigator (dropdown + prev/next)
// ═══════════════════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowLeft, BarChart2, Loader2, Play, Search,
  ChevronDown, ChevronUp, ChevronLeft, ChevronRight, ArrowUpDown,
  FileSpreadsheet, FileText, Filter, Download,
  Globe, Layers, Database, Eye, EyeOff, CheckSquare, Square, HelpCircle,
  ListTree, FileArchive, Tag, Lock, ShieldAlert, AlertTriangle, ShieldCheck,
} from 'lucide-react';
import { apiClient } from '../services/api';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { ConnectionPanel } from '../components/ConnectionPanel';
import type { Namespace, LoadBalancer } from '../types';
import {
  runFullReport,
  exportAsExcel,
  exportOverviewAsPdf,
  downloadLBOpenApiSpec,
  downloadRawSchemaZip,
} from '../services/api-report';
import type {
  ApiReportResults,
  ApiEndpointStats,
  FetchProgress,
  SwaggerSpec,
  SwaggerOperation,
  LBSelection,
} from '../services/api-report';

// Composite identifier for an LB across namespaces
const lbKey = (ns: string, lb: string) => `${ns}::${lb}`;
const parseKey = (k: string): [string, string] => {
  const idx = k.indexOf('::');
  return idx < 0 ? ['', k] : [k.slice(0, idx), k.slice(idx + 2)];
};

/**
 * Worker-pool runner — keeps `limit` promises in flight at any time. Used to
 * cap concurrent calls against F5 XC so multi-namespace selection doesn't
 * trigger the proxy's 30-second timeout under load.
 */
async function withConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
  shouldStop?: () => boolean,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let nextIdx = 0;
  const worker = async () => {
    while (true) {
      if (shouldStop?.()) return;
      const i = nextIdx++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  };
  const workers = Array.from({ length: Math.min(limit, items.length) }, worker);
  await Promise.all(workers);
  return results;
}

// Concurrency caps tuned to match the Vite proxy's single-socket-per-request
// budget without triggering its 30s timeout.
const NS_FETCH_CONCURRENCY = 3;        // namespaces resolving their LB list at once
const APID_DETECT_CONCURRENCY = 6;     // per-LB getLoadBalancer calls in flight per ns

// ─── Stat Card ───────────────────────────────────────────────────────────────

function StatCard({ label, value, icon: Icon, color, onClick, active, disabled }: {
  label: string; value: number | string; icon: typeof Globe; color: string;
  onClick?: () => void; active?: boolean; disabled?: boolean;
}) {
  const colorMap: Record<string, string> = {
    blue: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
    emerald: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    amber: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
    red: 'bg-red-500/10 border-red-500/30 text-red-400',
    violet: 'bg-violet-500/10 border-violet-500/30 text-violet-400',
    cyan: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
  };
  const activeRing: Record<string, string> = {
    blue: 'ring-2 ring-blue-400 shadow-blue-500/20 shadow-lg',
    emerald: 'ring-2 ring-emerald-400 shadow-emerald-500/20 shadow-lg',
    amber: 'ring-2 ring-amber-400 shadow-amber-500/20 shadow-lg',
    red: 'ring-2 ring-red-400 shadow-red-500/20 shadow-lg',
    violet: 'ring-2 ring-violet-400 shadow-violet-500/20 shadow-lg',
    cyan: 'ring-2 ring-cyan-400 shadow-cyan-500/20 shadow-lg',
  };
  const base = `px-4 py-3 rounded-xl border ${colorMap[color] || colorMap.blue} ${active ? (activeRing[color] || activeRing.blue) : ''}`;

  if (!onClick) {
    return (
      <div className={base}>
        <div className="flex items-center gap-2 mb-1">
          <Icon className="w-4 h-4" />
          <span className="text-xs font-medium text-slate-400">{label}</span>
        </div>
        <div className="text-2xl font-bold">{value}</div>
      </div>
    );
  }

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={active ? `Click to clear filter on ${label}` : `Filter to load balancers with non-zero ${label}`}
      className={`${base} text-left transition-all hover:brightness-125 ${active ? '' : 'hover:scale-[1.01]'} disabled:opacity-50 disabled:cursor-not-allowed`}
    >
      <div className="flex items-center justify-between gap-2 mb-1">
        <div className="flex items-center gap-2">
          <Icon className="w-4 h-4" />
          <span className="text-xs font-medium text-slate-400">{label}</span>
        </div>
        {active && <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-current/15 text-current">filter</span>}
      </div>
      <div className="text-2xl font-bold">{value}</div>
    </button>
  );
}

// ─── Sorting helpers ─────────────────────────────────────────────────────────

type SortDir = 'asc' | 'desc';

function useSort<F extends string>(initialField: F | null = null, initialDir: SortDir = 'asc') {
  const [sortField, setSortField] = useState<F | null>(initialField);
  const [sortDir, setSortDir] = useState<SortDir>(initialDir);
  const onSort = useCallback((field: F) => {
    setSortField(prev => {
      if (prev === field) {
        setSortDir(d => (d === 'asc' ? 'desc' : 'asc'));
        return prev;
      }
      setSortDir('asc');
      return field;
    });
  }, []);
  return { sortField, sortDir, onSort };
}

function isZeroish(v: unknown): boolean {
  if (v === undefined || v === null) return true;
  if (typeof v === 'number') return v === 0;
  if (typeof v === 'string') {
    const t = v.trim();
    if (t === '' || t === '—' || t === '-' || t === '0') return true;
    const n = Number(t);
    if (!Number.isNaN(n) && n === 0) return true;
    return false;
  }
  if (Array.isArray(v)) return v.length === 0;
  return false;
}

function compareCell(a: unknown, b: unknown, dir: SortDir): number {
  const dash = (v: unknown) => v === undefined || v === null || v === '—' || v === '-';
  if (dash(a) && dash(b)) return 0;
  if (dash(a)) return 1;            // empties always at the bottom
  if (dash(b)) return -1;
  if (typeof a === 'number' && typeof b === 'number') {
    return dir === 'asc' ? a - b : b - a;
  }
  const aNum = Number(a), bNum = Number(b);
  if (!Number.isNaN(aNum) && !Number.isNaN(bNum) && a !== '' && b !== '') {
    return dir === 'asc' ? aNum - bNum : bNum - aNum;
  }
  const as = String(a).toLowerCase();
  const bs = String(b).toLowerCase();
  return dir === 'asc' ? as.localeCompare(bs) : bs.localeCompare(as);
}

function sortBy<T, F extends string>(rows: T[], field: F | null, dir: SortDir, accessor: (row: T, f: F) => unknown): T[] {
  if (!field) return rows;
  return [...rows].sort((a, b) => compareCell(accessor(a, field), accessor(b, field), dir));
}

function SortableTh<F extends string>({ field, label, sortField, sortDir, onSort, align = 'left', className = '' }: {
  field: F;
  label: string;
  sortField: F | null;
  sortDir: SortDir;
  onSort: (f: F) => void;
  align?: 'left' | 'right';
  className?: string;
}) {
  const active = sortField === field;
  return (
    <th
      onClick={() => onSort(field)}
      className={`px-4 py-3 text-${align} text-xs font-medium uppercase cursor-pointer select-none transition-colors ${active ? 'text-blue-300' : 'text-slate-400 hover:text-slate-200'} ${className}`}
    >
      <span className={`inline-flex items-center gap-1 ${align === 'right' ? 'justify-end' : ''}`}>
        {label}
        {active
          ? (sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />)
          : <ArrowUpDown className="w-3 h-3 opacity-30" />}
      </span>
    </th>
  );
}

function FilterInput({ value, onChange, placeholder = 'Filter…', width = 'w-56' }: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  width?: string;
}) {
  return (
    <div className="relative">
      <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={`pl-8 pr-3 py-1.5 bg-slate-700/50 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-slate-500 ${width}`}
        placeholder={placeholder}
      />
    </div>
  );
}

// ─── Time Range Options ──────────────────────────────────────────────────────

const TIME_RANGES = [
  { label: '7 days', value: 7 },
  { label: '14 days', value: 14 },
  { label: '30 days', value: 30 },
  { label: '60 days', value: 60 },
  { label: '90 days', value: 90 },
];

// ─── Main Component ──────────────────────────────────────────────────────────

type Tab = 'overview' | 'download' | 'details';

export function APIReport() {
  const { isConnected } = useApp();
  const toast = useToast();

  // Step 1: Configuration
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [selectedNamespaces, setSelectedNamespaces] = useState<Set<string>>(new Set());
  const [nsFilter, setNsFilter] = useState('');
  const [lbsByNs, setLbsByNs] = useState<Map<string, LoadBalancer[]>>(new Map());
  const [loadingNsLBs, setLoadingNsLBs] = useState<Set<string>>(new Set()); // ns currently fetching LBs
  const [selectedLBs, setSelectedLBs] = useState<Set<string>>(new Set()); // composite keys ns::lb
  const [lbSearch, setLbSearch] = useState('');
  const [timeRange, setTimeRange] = useState(30);
  const [loadingNs, setLoadingNs] = useState(false);

  // API Discovery detection: composite ns::lb key -> true (enabled) | false (disabled) | undefined (detecting)
  const [apidStatus, setApidStatus] = useState<Map<string, boolean>>(new Map());
  const [detectingNs, setDetectingNs] = useState<Set<string>>(new Set());
  const [apidOnlyFilter, setApidOnlyFilter] = useState(false);

  // Step 2: Running
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<FetchProgress | null>(null);
  const cancelledRef = useRef(false);

  // Step 3: Results & UI
  const [results, setResults] = useState<ApiReportResults | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [exporting, setExporting] = useState(false);
  const [pdfExporting, setPdfExporting] = useState(false);

  // Schema Download tab state
  const [downloadingZip, setDownloadingZip] = useState<string | null>(null);
  const [bulkProgress, setBulkProgress] = useState<{ current: number; total: number; lb: string; ok: number; fail: number } | null>(null);
  const bulkCancelRef = useRef(false);

  // Schema Details tab state
  const [detailIndex, setDetailIndex] = useState(0);
  const [opFilter, setOpFilter] = useState('');

  // ─── Load namespaces ─────────────────────────────────────────────────────
  useEffect(() => {
    if (!isConnected) return;
    setLoadingNs(true);
    apiClient.getNamespaces()
      .then(res => setNamespaces(res.items || []))
      .catch(() => toast.error('Failed to load namespaces'))
      .finally(() => setLoadingNs(false));
  }, [isConnected]);

  // ─── Load LBs for each newly selected namespace ──────────────────────────
  // Fan out per-namespace in parallel. Every fetch is keyed by a generation
  // token so a re-selected namespace can never have an older fetch's result
  // overwrite the new one's bookkeeping. APID detection commits once per
  // namespace (at the end) so the badges don't flicker 6-at-a-time.
  const fetchTokenRef = useRef<Map<string, number>>(new Map());
  const tokenCounterRef = useRef(0);
  const lbsByNsRef = useRef<Map<string, LoadBalancer[]>>(new Map());
  useEffect(() => { lbsByNsRef.current = lbsByNs; }, [lbsByNs]);

  useEffect(() => {
    const selected = selectedNamespaces;
    const tokens = fetchTokenRef.current;

    // 1) Drop bookkeeping for namespaces the user just de-selected. In-flight
    //    fetches will see their token replaced/missing and short-circuit.
    for (const ns of [...tokens.keys()]) if (!selected.has(ns)) tokens.delete(ns);

    setLbsByNs(prev => {
      let changed = false;
      const next = new Map(prev);
      for (const ns of next.keys()) if (!selected.has(ns)) { next.delete(ns); changed = true; }
      return changed ? next : prev;
    });
    setSelectedLBs(prev => {
      const next = new Set<string>();
      let changed = false;
      for (const k of prev) {
        const [ns] = parseKey(k);
        if (selected.has(ns)) next.add(k);
        else changed = true;
      }
      return changed ? next : prev;
    });
    setApidStatus(prev => {
      let changed = false;
      const next = new Map(prev);
      for (const k of next.keys()) {
        const [ns] = parseKey(k);
        if (!selected.has(ns)) { next.delete(k); changed = true; }
      }
      return changed ? next : prev;
    });
    setLoadingNsLBs(prev => {
      let changed = false;
      const next = new Set(prev);
      for (const ns of next) if (!selected.has(ns)) { next.delete(ns); changed = true; }
      return changed ? next : prev;
    });
    setDetectingNs(prev => {
      let changed = false;
      const next = new Set(prev);
      for (const ns of next) if (!selected.has(ns)) { next.delete(ns); changed = true; }
      return changed ? next : prev;
    });

    // 2) Plan the fetches for namespaces that aren't cached or already in flight.
    const toFetch: Array<{ ns: string; token: number }> = [];
    for (const ns of selected) {
      if (lbsByNsRef.current.has(ns)) continue;
      if (tokens.has(ns)) continue;
      const token = ++tokenCounterRef.current;
      tokens.set(ns, token);
      toFetch.push({ ns, token });
    }
    if (toFetch.length === 0) return;

    // 3) Render skeleton + "detecting" state for every new namespace upfront so
    //    cards appear immediately, even before the network call returns.
    setLoadingNsLBs(prev => {
      const next = new Set(prev);
      for (const { ns } of toFetch) next.add(ns);
      return next;
    });
    setDetectingNs(prev => {
      const next = new Set(prev);
      for (const { ns } of toFetch) next.add(ns);
      return next;
    });

    // 4) Fan out across namespaces with a concurrency cap so the proxy
    //    doesn't get hit with N+8N parallel sockets.
    const dropDetecting = (ns: string) => setDetectingNs(prev => {
      if (!prev.has(ns)) return prev;
      const next = new Set(prev); next.delete(ns); return next;
    });
    const dropLoading = (ns: string) => setLoadingNsLBs(prev => {
      if (!prev.has(ns)) return prev;
      const next = new Set(prev); next.delete(ns); return next;
    });

    void withConcurrency(toFetch, NS_FETCH_CONCURRENCY, async ({ ns, token }) => {
      const stillMine = () => tokens.get(ns) === token;
      try {
        const res = await apiClient.getLoadBalancers(ns);
        if (!stillMine()) return;

        const items = (res.items || [])
          .slice()
          .sort((a, b) => (a.metadata?.name || a.name).localeCompare(b.metadata?.name || b.name));
        setLbsByNs(prev => new Map(prev).set(ns, items));
        dropLoading(ns);

        if (items.length === 0) { dropDetecting(ns); return; }

        // APID detection: capped concurrency, all results committed once at
        // the end so badges flip in a single transition.
        const names = items.map(lb => lb.metadata?.name || lb.name).filter(Boolean) as string[];
        const detected = await withConcurrency(
          names,
          APID_DETECT_CONCURRENCY,
          async (name) => {
            try {
              const full = await apiClient.getLoadBalancer(ns, name) as unknown as Record<string, unknown>;
              const spec = (full.spec || full.get_spec || full) as Record<string, unknown>;
              const enabled = spec?.enable_api_discovery !== undefined && spec?.enable_api_discovery !== null;
              const disabled = spec?.disable_api_discovery !== undefined && spec?.disable_api_discovery !== null;
              return [name, enabled && !disabled] as const;
            } catch {
              return [name, false] as const;
            }
          },
          () => !stillMine(),
        );

        if (!stillMine() || detected.length === 0) return;
        setApidStatus(prev => {
          const next = new Map(prev);
          for (const item of detected) {
            if (!item) continue; // skipped slots when stillMine() flipped
            const [n, v] = item;
            next.set(lbKey(ns, n), v);
          }
          return next;
        });
      } catch (err) {
        if (stillMine()) {
          console.error(`[APIReport] getLoadBalancers(${ns}) failed:`, err);
          toast.error(`Failed to load LBs for namespace ${ns}`);
        }
        dropLoading(ns);
      } finally {
        if (stillMine()) {
          tokens.delete(ns);
          dropDetecting(ns);
        }
      }
    });
  }, [selectedNamespaces]);

  // ─── Namespace + LB selection helpers ────────────────────────────────────
  const toggleNamespace = useCallback((name: string) => {
    setSelectedNamespaces(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  }, []);
  const filteredNs = useMemo(() => {
    const f = nsFilter.trim().toLowerCase();
    return f ? namespaces.filter(n => n.name.toLowerCase().includes(f)) : namespaces;
  }, [namespaces, nsFilter]);
  const selectAllNamespaces = useCallback(() => {
    setSelectedNamespaces(new Set(filteredNs.map(n => n.name)));
  }, [filteredNs]);
  const clearNamespaces = useCallback(() => setSelectedNamespaces(new Set()), []);

  const toggleLB = useCallback((key: string) => {
    setSelectedLBs(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }, []);

  // Build the visible LB grouping. Each group corresponds to one selected namespace.
  // Groups are rendered alphabetically so their position is stable as parallel
  // loads finish in arrival order.
  const lbSearchLower = lbSearch.trim().toLowerCase();
  const lbGroups = useMemo(() => {
    return Array.from(selectedNamespaces)
      .slice()
      .sort((a, b) => a.localeCompare(b))
      .map(ns => {
        const items = lbsByNs.get(ns) || [];
        let filtered = items;
        if (lbSearchLower) {
          filtered = filtered.filter(lb => (lb.metadata?.name || lb.name).toLowerCase().includes(lbSearchLower));
        }
        if (apidOnlyFilter) {
          filtered = filtered.filter(lb => apidStatus.get(lbKey(ns, lb.metadata?.name || lb.name)) === true);
        }
        return { ns, items, filtered };
      });
  }, [selectedNamespaces, lbsByNs, lbSearchLower, apidOnlyFilter, apidStatus]);

  const totalLBCount = useMemo(() => lbGroups.reduce((a, g) => a + g.items.length, 0), [lbGroups]);
  const visibleLBCount = useMemo(() => lbGroups.reduce((a, g) => a + g.filtered.length, 0), [lbGroups]);
  const apidEnabledCount = useMemo(() => {
    let n = 0;
    for (const [, v] of apidStatus) if (v) n++;
    return n;
  }, [apidStatus]);
  const detectingApid = detectingNs.size > 0;

  const selectAll = useCallback(() => {
    setSelectedLBs(prev => {
      const next = new Set(prev);
      for (const g of lbGroups) {
        for (const lb of g.filtered) next.add(lbKey(g.ns, lb.metadata?.name || lb.name));
      }
      return next;
    });
  }, [lbGroups]);
  const deselectAll = useCallback(() => setSelectedLBs(new Set()), []);

  // ─── Run Report ──────────────────────────────────────────────────────────
  const handleRun = useCallback(async () => {
    if (selectedLBs.size === 0) return;
    setRunning(true);
    setResults(null);
    setDetailIndex(0);
    cancelledRef.current = false;

    try {
      const selections: LBSelection[] = Array.from(selectedLBs).map(k => {
        const [ns, lb] = parseKey(k);
        return { namespace: ns, lbName: lb };
      });
      const report = await runFullReport(selections, timeRange, (p) => {
        if (!cancelledRef.current) setProgress(p);
      });
      if (!cancelledRef.current) {
        setResults(report);
        const nsCount = new Set(selections.map(s => s.namespace)).size;
        toast.success(`Report generated for ${selections.length} load balancer(s) across ${nsCount} namespace(s)`);
      }
    } catch (err: unknown) {
      toast.error(`Report failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setRunning(false);
      setProgress(null);
    }
  }, [selectedLBs, timeRange, toast]);

  // ─── Exports ─────────────────────────────────────────────────────────────
  const handleExportExcel = useCallback(async (view?: { lbStats: ApiEndpointStats[]; description?: string }) => {
    if (!results) return;
    setExporting(true);
    try {
      const stem = results.namespaces.length === 1
        ? results.namespaces[0]
        : `multi-ns-${results.namespaces.length}`;
      await exportAsExcel(results, stem, view);
      toast.success('Excel report downloaded');
    } catch {
      toast.error('Excel export failed');
    } finally {
      setExporting(false);
    }
  }, [results, toast]);

  const handleExportPdf = useCallback(async (view?: { lbStats: ApiEndpointStats[]; description?: string }) => {
    if (!results) return;
    setPdfExporting(true);
    try {
      await exportOverviewAsPdf(results, view);
      toast.success('PDF report downloaded');
    } catch (err) {
      console.error(err);
      toast.error('PDF export failed');
    } finally {
      setPdfExporting(false);
    }
  }, [results, toast]);

  // ─── Per-LB raw ZIP download ─────────────────────────────────────────────
  const handleDownloadZip = useCallback(async (scope: string, namespace: string, lbName: string) => {
    setDownloadingZip(scope);
    try {
      const r = await downloadRawSchemaZip(namespace, lbName);
      if (r.ok) toast.success(`Schema ZIP downloaded for ${scope}`);
      else toast.error(r.reason || 'Schema download failed');
    } finally {
      setDownloadingZip(null);
    }
  }, [toast]);

  /** Bulk-download the swagger ZIPs for the given (scope, ns, lb) triples — sequentially. */
  const handleBulkDownload = useCallback(async (
    targets?: Array<{ scope: string; namespace: string; lbName: string }>,
  ) => {
    if (!results) return;
    const list = targets && targets.length > 0
      ? targets
      : results.lbStats.map(s => ({ scope: s.scope, namespace: s.namespace || '', lbName: s.lbName || s.scope }));
    if (list.length === 0) return;

    bulkCancelRef.current = false;
    setBulkProgress({ current: 0, total: list.length, lb: list[0].scope, ok: 0, fail: 0 });

    let ok = 0;
    let fail = 0;
    try {
      for (let i = 0; i < list.length; i++) {
        if (bulkCancelRef.current) break;
        const t = list[i];
        setBulkProgress({ current: i + 1, total: list.length, lb: t.scope, ok, fail });

        const r = await downloadRawSchemaZip(t.namespace, t.lbName);
        if (r.ok) ok++; else fail++;

        setBulkProgress({ current: i + 1, total: list.length, lb: t.scope, ok, fail });

        if (i < list.length - 1) await new Promise(r => setTimeout(r, 350));
      }
      const cancelled = bulkCancelRef.current;
      if (ok > 0) toast.success(`${cancelled ? 'Stopped — ' : ''}Downloaded ${ok} schema ZIP(s)${fail ? `, ${fail} failed` : ''}`);
      else if (cancelled) toast.error('Bulk download cancelled');
      else toast.error('No schema ZIPs could be downloaded');
    } finally {
      setBulkProgress(null);
    }
  }, [results, toast]);

  const cancelBulkDownload = useCallback(() => {
    bulkCancelRef.current = true;
  }, []);

  // ─── Progress stats ──────────────────────────────────────────────────────
  const totalPhases = selectedLBs.size * 3;
  const currentPhaseOffset = progress
    ? (progress.phase === 'stats' ? 0 : progress.phase === 'swagger' ? selectedLBs.size : selectedLBs.size * 2)
    : 0;
  const progressPercent = progress
    ? Math.round(((currentPhaseOffset + progress.current) / totalPhases) * 100)
    : 0;

  // ─── Schema Details navigation ───────────────────────────────────────────
  const lbList = useMemo(() => results?.lbStats.map(s => s.scope) ?? [], [results]);
  const currentLB = lbList[detailIndex] || '';
  const currentSpecs: SwaggerSpec[] = useMemo(
    () => results?.swaggerSpecs.filter(s => s.lb === currentLB) ?? [],
    [results, currentLB],
  );
  const currentRows = useMemo(
    () => results?.endpointRows.filter(r => r.lb === currentLB) ?? [],
    [results, currentLB],
  );
  const currentLbStats = useMemo(
    () => results?.lbStats.find(s => s.scope === currentLB),
    [results, currentLB],
  );

  const goPrev = () => setDetailIndex(i => Math.max(0, i - 1));
  const goNext = () => setDetailIndex(i => Math.min(lbList.length - 1, i + 1));

  // ─── RENDER ──────────────────────────────────────────────────────────────

  if (!isConnected) {
    return (
      <div className="max-w-7xl mx-auto px-6 py-8">
        <ConnectionPanel />
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link to="/" className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div className="flex items-center gap-3">
          <div className="p-2 bg-violet-500/15 rounded-lg">
            <BarChart2 className="w-5 h-5 text-violet-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100">API Discovery Report Dashboard</h1>
            <p className="text-sm text-slate-400">Per-LB API Discovery overview, schema downloads, and detailed schema inspection</p>
          </div>
        </div>
        <Link to="/explainer/api-report" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
          <HelpCircle className="w-3.5 h-3.5" /> How does this work?
        </Link>
      </div>

      {/* Step 1: Configuration */}
      <section className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 space-y-5">
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Configuration</h2>

        {/* Time Range + Run */}
        <div className="flex items-end justify-between gap-4 flex-wrap">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Time Range</label>
            <div className="flex gap-1">
              {TIME_RANGES.map(t => (
                <button
                  key={t.value}
                  onClick={() => setTimeRange(t.value)}
                  disabled={running}
                  className={`px-3 py-2 text-xs rounded-lg border transition-colors disabled:opacity-50 ${
                    timeRange === t.value
                      ? 'bg-blue-500/20 border-blue-500/40 text-blue-400'
                      : 'bg-slate-800 border-slate-600 text-slate-400 hover:border-slate-500'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>
          <button
            onClick={handleRun}
            disabled={running || selectedLBs.size === 0}
            className="flex items-center gap-2 px-5 py-2 bg-blue-500 hover:bg-blue-600 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {running ? 'Running...' : `Generate Report (${selectedLBs.size} LB across ${selectedNamespaces.size} ns)`}
          </button>
        </div>

        {/* Namespaces multi-select */}
        <div>
          <div className="flex items-center justify-between mb-2 gap-3 flex-wrap">
            <label className="text-xs font-medium text-slate-400">
              Namespaces {loadingNs
                ? '(loading...)'
                : `(${selectedNamespaces.size}/${filteredNs.length} selected${nsFilter ? `, filtered from ${namespaces.length}` : ''})`}
            </label>
            <div className="flex items-center gap-3">
              <FilterInput value={nsFilter} onChange={setNsFilter} placeholder="Filter namespaces…" width="w-48" />
              <div className="flex gap-2">
                <button onClick={selectAllNamespaces} disabled={running || loadingNs} className="text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50">Select All</button>
                <span className="text-slate-600">|</span>
                <button onClick={clearNamespaces} disabled={running || loadingNs} className="text-xs text-slate-400 hover:text-slate-300 disabled:opacity-50">Clear</button>
              </div>
            </div>
          </div>

          {loadingNs ? (
            <div className="flex items-center gap-2 py-4 text-slate-500 text-sm">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading namespaces...
            </div>
          ) : filteredNs.length === 0 ? (
            <div className="py-4 text-center text-sm text-slate-500">
              {namespaces.length === 0 ? 'No namespaces found' : 'No namespaces match the filter'}
            </div>
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-1.5 max-h-44 overflow-y-auto pr-1">
              {filteredNs.map(n => {
                const selected = selectedNamespaces.has(n.name);
                const loading = loadingNsLBs.has(n.name);
                return (
                  <button
                    key={n.name}
                    onClick={() => toggleNamespace(n.name)}
                    disabled={running}
                    className={`flex items-center gap-2 px-2.5 py-1.5 rounded-md border text-left text-xs transition-colors disabled:opacity-50 ${
                      selected
                        ? 'bg-violet-500/10 border-violet-500/40 text-violet-300'
                        : 'bg-slate-800/50 border-slate-700 text-slate-400 hover:border-slate-600'
                    }`}
                  >
                    {selected
                      ? <CheckSquare className="w-3.5 h-3.5 text-violet-400 shrink-0" />
                      : <Square className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                    }
                    <span className="truncate flex-1">{n.name}</span>
                    {selected && loading && <Loader2 className="w-3 h-3 animate-spin text-slate-500" />}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* LB selection grouped by namespace */}
        {selectedNamespaces.size > 0 && (
          <div>
            <div className="flex items-center justify-between mb-2 gap-3 flex-wrap">
              <label className="text-xs font-medium text-slate-400">
                Load Balancers{' '}
                <span>({selectedLBs.size}/{visibleLBCount} selected{apidOnlyFilter || lbSearchLower ? `, filtered from ${totalLBCount}` : ''})</span>
                {totalLBCount > 0 && (
                  <span className="ml-2 text-emerald-400">
                    {detectingApid
                      ? `· detecting API Discovery…`
                      : `· ${apidEnabledCount} with API Discovery enabled`}
                  </span>
                )}
              </label>
              <div className="flex items-center gap-3 flex-wrap">
                <FilterInput value={lbSearch} onChange={setLbSearch} placeholder="Filter LB names…" width="w-48" />
                <button
                  onClick={() => setApidOnlyFilter(v => !v)}
                  disabled={running}
                  title="Show only load balancers with API Discovery enabled"
                  className={`flex items-center gap-1.5 px-2 py-1 rounded-md border text-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
                    apidOnlyFilter
                      ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                      : 'bg-slate-800 border-slate-600 text-slate-400 hover:border-slate-500'
                  }`}
                >
                  <Filter className="w-3 h-3" />
                  API Discovery only
                  {detectingApid && <Loader2 className="w-3 h-3 animate-spin" />}
                </button>
                <div className="flex gap-2">
                  <button onClick={selectAll} disabled={running} className="text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50">Select All</button>
                  <span className="text-slate-600">|</span>
                  <button onClick={deselectAll} disabled={running} className="text-xs text-slate-400 hover:text-slate-300 disabled:opacity-50">Clear</button>
                </div>
              </div>
            </div>

            <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
              {lbGroups.map(g => {
                const groupKeys = g.filtered.map(lb => lbKey(g.ns, lb.metadata?.name || lb.name));
                const allSelected = groupKeys.length > 0 && groupKeys.every(k => selectedLBs.has(k));
                const someSelected = groupKeys.some(k => selectedLBs.has(k));
                const toggleGroup = () => {
                  setSelectedLBs(prev => {
                    const next = new Set(prev);
                    if (allSelected) for (const k of groupKeys) next.delete(k);
                    else for (const k of groupKeys) next.add(k);
                    return next;
                  });
                };
                return (
                  <div key={g.ns} className="bg-slate-900/40 border border-slate-700 rounded-lg">
                    <div className="flex items-center justify-between px-3 py-2 border-b border-slate-700">
                      <div className="flex items-center gap-2 text-xs">
                        <button
                          onClick={toggleGroup}
                          disabled={running || groupKeys.length === 0}
                          className="text-slate-400 hover:text-slate-200 disabled:opacity-40"
                        >
                          {allSelected ? <CheckSquare className="w-4 h-4 text-violet-400" /> : someSelected ? <CheckSquare className="w-4 h-4 text-violet-400/40" /> : <Square className="w-4 h-4 text-slate-600" />}
                        </button>
                        <span className="font-mono text-slate-300">{g.ns}</span>
                        <span className="text-slate-500">
                          {loadingNsLBs.has(g.ns) ? <Loader2 className="w-3 h-3 animate-spin inline" /> : `${g.filtered.length}/${g.items.length} LBs`}
                        </span>
                      </div>
                    </div>
                    {loadingNsLBs.has(g.ns) ? (
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 p-3">
                        {Array.from({ length: 6 }).map((_, i) => (
                          <div key={i} className="flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-700 bg-slate-800/40 animate-pulse">
                            <Square className="w-4 h-4 text-slate-700 shrink-0" />
                            <div className="h-3 bg-slate-700/60 rounded flex-1" />
                            <div className="h-3 w-10 bg-slate-700/40 rounded" />
                          </div>
                        ))}
                      </div>
                    ) : g.items.length === 0 ? (
                      <div className="px-3 py-3 text-xs text-slate-500">No HTTP load balancers in this namespace</div>
                    ) : g.filtered.length === 0 ? (
                      <div className="px-3 py-3 text-xs text-slate-500">No load balancers match the current filter</div>
                    ) : (
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 p-3">
                        {g.filtered.map(lb => {
                          const name = lb.metadata?.name || lb.name;
                          const k = lbKey(g.ns, name);
                          const selected = selectedLBs.has(k);
                          const apid = apidStatus.get(k);
                          const apidKnown = apidStatus.has(k);
                          return (
                            <button
                              key={k}
                              onClick={() => toggleLB(k)}
                              disabled={running}
                              className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-left text-sm transition-colors disabled:opacity-50 ${
                                selected
                                  ? 'bg-blue-500/10 border-blue-500/40 text-blue-300'
                                  : 'bg-slate-800/50 border-slate-700 text-slate-400 hover:border-slate-600'
                              }`}
                            >
                              {selected
                                ? <CheckSquare className="w-4 h-4 text-blue-400 shrink-0" />
                                : <Square className="w-4 h-4 text-slate-600 shrink-0" />
                              }
                              <span className="truncate flex-1">{name}</span>
                              {!apidKnown ? (
                                <span className="px-1.5 py-0.5 text-[10px] rounded bg-slate-700/50 text-slate-500 border border-slate-600 shrink-0 flex items-center gap-1">
                                  <Loader2 className="w-2.5 h-2.5 animate-spin" />
                                </span>
                              ) : apid ? (
                                <span className="px-1.5 py-0.5 text-[10px] rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 shrink-0">APID</span>
                              ) : (
                                <span className="px-1.5 py-0.5 text-[10px] rounded bg-slate-700/50 text-slate-500 border border-slate-600 shrink-0">No APID</span>
                              )}
                            </button>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </section>

      {/* Progress */}
      {running && progress && (
        <section className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2 text-sm text-slate-300">
              <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
              {progress.message}
            </div>
            <span className="text-xs text-slate-500">{progressPercent}%</span>
          </div>
          <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-blue-500 to-cyan-500 transition-all duration-300"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </section>
      )}

      {/* Results */}
      {results && (
        <>
          {/* Tabs */}
          <section className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-700 px-4">
              <div className="flex">
                {([
                  { key: 'overview' as const, label: 'Overview',        icon: BarChart2,    count: results.lbStats.length },
                  { key: 'download' as const, label: 'Schema Download', icon: FileArchive,  count: results.lbStats.length },
                  { key: 'details'  as const, label: 'Schema Details',  icon: ListTree,     count: results.swaggerSpecs.length },
                ]).map(tab => {
                  const Icon = tab.icon;
                  return (
                    <button
                      key={tab.key}
                      onClick={() => setActiveTab(tab.key)}
                      className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                        activeTab === tab.key
                          ? 'border-blue-400 text-blue-400'
                          : 'border-transparent text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                      {tab.label}
                      <span className="ml-1 px-1.5 py-0.5 rounded text-[10px] bg-slate-700 text-slate-400">{tab.count}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {activeTab === 'overview' && <OverviewTab
              results={results}
              onExportExcel={handleExportExcel}
              onExportPdf={handleExportPdf}
              exporting={exporting}
              pdfExporting={pdfExporting}
            />}

            {activeTab === 'download' && <DownloadTab
              results={results}
              onDownload={handleDownloadZip}
              downloadingZip={downloadingZip}
              onBulkDownload={handleBulkDownload}
              onCancelBulk={cancelBulkDownload}
              bulkProgress={bulkProgress}
              onDownloadOpenApi={(scope) => {
                const r = downloadLBOpenApiSpec(scope, results.swaggerEndpoints);
                if (r.ok) toast.success(`OpenAPI spec downloaded for ${scope}`);
                else toast.error(r.reason || 'No spec available');
              }}
            />}

            {activeTab === 'details' && <DetailsTab
              lbList={lbList}
              detailIndex={detailIndex}
              setDetailIndex={setDetailIndex}
              goPrev={goPrev}
              goNext={goNext}
              currentLB={currentLB}
              currentSpecs={currentSpecs}
              currentRows={currentRows}
              currentLbStats={currentLbStats}
              opFilter={opFilter}
              setOpFilter={setOpFilter}
            />}
          </section>
        </>
      )}
    </div>
  );
}

// ─── Overview Tab ────────────────────────────────────────────────────────────

type OverviewSortField =
  | 'scope' | 'namespace' | 'lbName'
  | 'total_endpoints' | 'discovered' | 'inventory' | 'shadow'
  | 'pii_detected' | 'threat_high' | 'threat_medium' | 'threat_low'
  | 'risk_score_avg' | 'risk_score_max' | 'vulnerable';

function OverviewTab({ results, onExportExcel, onExportPdf, exporting, pdfExporting }: {
  results: ApiReportResults;
  onExportExcel: (view?: { lbStats: ApiEndpointStats[]; description?: string }) => void;
  onExportPdf:   (view?: { lbStats: ApiEndpointStats[]; description?: string }) => void;
  exporting: boolean;
  pdfExporting: boolean;
}) {
  const [filter, setFilter] = useState('');
  const [nsFilter, setNsFilter] = useState('');
  const [nonZeroOnly, setNonZeroOnly] = useState(false);
  const [cardFilters, setCardFilters] = useState<Set<keyof ApiEndpointStats>>(new Set());
  const [exportScope, setExportScope] = useState<'view' | 'all'>('view');
  const { sortField, sortDir, onSort } = useSort<OverviewSortField>('total_endpoints', 'desc');
  const showNsCol = results.namespaces.length > 1;

  const toggleCardFilter = useCallback((field: keyof ApiEndpointStats) => {
    setCardFilters(prev => {
      const next = new Set(prev);
      if (next.has(field)) next.delete(field); else next.add(field);
      return next;
    });
  }, []);
  const clearCardFilters = useCallback(() => setCardFilters(new Set()), []);
  const isCardActive = (f: keyof ApiEndpointStats) => cardFilters.has(f);

  const filtered = useMemo(() => {
    let out = results.lbStats;
    const f = filter.trim().toLowerCase();
    if (f) out = out.filter(s => (s.lbName || s.scope).toLowerCase().includes(f) || s.scope.toLowerCase().includes(f));
    const fns = nsFilter.trim().toLowerCase();
    if (fns) out = out.filter(s => (s.namespace || '').toLowerCase().includes(fns));
    if (nonZeroOnly && sortField && sortField !== 'scope' && sortField !== 'namespace' && sortField !== 'lbName') {
      out = out.filter(s => !isZeroish((s as unknown as Record<string, unknown>)[sortField]));
    }
    // Stat-card filters: keep only LBs with non-zero values for ALL active cards (AND).
    if (cardFilters.size > 0) {
      out = out.filter(s => {
        const rec = s as unknown as Record<string, unknown>;
        for (const f of cardFilters) if (isZeroish(rec[f])) return false;
        return true;
      });
    }
    return out;
  }, [results.lbStats, filter, nsFilter, nonZeroOnly, sortField, cardFilters]);

  const sorted = useMemo(
    () => sortBy(filtered, sortField, sortDir, (s, f) => (s as unknown as Record<string, unknown>)[f]),
    [filtered, sortField, sortDir],
  );

  // What gets shipped to the export functions — kept identical to what's on screen
  const viewDescription = useMemo(() => {
    const parts: string[] = [];
    if (sortField) parts.push(`sorted by ${sortField} (${sortDir})`);
    if (filter.trim()) parts.push(`filter: "${filter.trim()}"`);
    if (nsFilter.trim()) parts.push(`ns: "${nsFilter.trim()}"`);
    if (nonZeroOnly && sortField && sortField !== 'scope' && sortField !== 'namespace' && sortField !== 'lbName') {
      parts.push(`non-zero ${sortField} only`);
    }
    if (cardFilters.size > 0) {
      parts.push(`cards: ${Array.from(cardFilters).join(' & ')}`);
    }
    return parts.join(' · ');
  }, [sortField, sortDir, filter, nsFilter, nonZeroOnly, cardFilters]);

  const exportView = useMemo(
    () => exportScope === 'view'
      ? { lbStats: sorted, description: viewDescription || 'current view' }
      : undefined,
    [exportScope, sorted, viewDescription],
  );

  const agg = sorted.reduce((a, s) => ({
    total_endpoints: a.total_endpoints + s.total_endpoints,
    discovered: a.discovered + s.discovered,
    inventory: a.inventory + s.inventory,
    shadow: a.shadow + s.shadow,
    pii_detected: a.pii_detected + s.pii_detected,
    threat_high:   a.threat_high   + (s.threat_high   ?? 0),
    threat_medium: a.threat_medium + (s.threat_medium ?? 0),
    threat_low:    a.threat_low    + (s.threat_low    ?? 0),
    risk_score_max: Math.max(a.risk_score_max, s.risk_score_max ?? 0),
  }), { total_endpoints: 0, discovered: 0, inventory: 0, shadow: 0, pii_detected: 0, threat_high: 0, threat_medium: 0, threat_low: 0, risk_score_max: 0 });

  return (
    <div className="p-6 space-y-5">
      {/* Header with export buttons */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h3 className="text-base font-semibold text-slate-100">Per-Load-Balancer Overview</h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Generated {new Date(results.generatedAt).toLocaleString()} · last {results.timeRangeDays} days ·{' '}
            {results.namespaces.length === 1
              ? <>namespace <span className="text-slate-300 font-mono">{results.namespaces[0]}</span></>
              : <>{results.namespaces.length} namespaces <span className="text-slate-300 font-mono">{results.namespaces.slice(0, 3).join(', ')}{results.namespaces.length > 3 ? ', …' : ''}</span></>
            }
          </p>
        </div>
        <div className="flex flex-col items-end gap-1.5">
          <div className="flex items-center gap-1 bg-slate-800/60 border border-slate-600 rounded-lg p-0.5">
            <button
              onClick={() => setExportScope('view')}
              className={`px-2.5 py-1 text-[11px] rounded-md transition-colors ${
                exportScope === 'view' ? 'bg-blue-500/30 text-blue-200' : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Export only what is currently displayed (sort + filter applied)"
            >
              Current view ({sorted.length})
            </button>
            <button
              onClick={() => setExportScope('all')}
              className={`px-2.5 py-1 text-[11px] rounded-md transition-colors ${
                exportScope === 'all' ? 'bg-blue-500/30 text-blue-200' : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Export every load balancer in the report, in original order"
            >
              Full report ({results.lbStats.length})
            </button>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onExportExcel(exportView)}
              disabled={exporting}
              className="flex items-center gap-2 px-3 py-2 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 text-sm font-medium rounded-lg border border-emerald-500/30 transition-colors disabled:opacity-50"
            >
              {exporting ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileSpreadsheet className="w-4 h-4" />}
              Export Excel
            </button>
            <button
              onClick={() => onExportPdf(exportView)}
              disabled={pdfExporting}
              className="flex items-center gap-2 px-3 py-2 bg-rose-500/20 hover:bg-rose-500/30 text-rose-400 text-sm font-medium rounded-lg border border-rose-500/30 transition-colors disabled:opacity-50"
            >
              {pdfExporting ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4" />}
              Export PDF
            </button>
          </div>
        </div>
      </div>

      {/* Aggregate cards — clickable: toggle a non-zero filter on the
          underlying field. Multiple cards stack with AND semantics. */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <StatCard label="Total Endpoints" value={agg.total_endpoints} icon={Globe}    color="blue"
                  onClick={() => toggleCardFilter('total_endpoints')} active={isCardActive('total_endpoints')} />
        <StatCard label="Discovered"      value={agg.discovered}      icon={Eye}      color="emerald"
                  onClick={() => toggleCardFilter('discovered')}      active={isCardActive('discovered')} />
        <StatCard label="Inventory"       value={agg.inventory}       icon={Database} color="cyan"
                  onClick={() => toggleCardFilter('inventory')}       active={isCardActive('inventory')} />
        <StatCard label="Shadow"          value={agg.shadow}          icon={EyeOff}   color="amber"
                  onClick={() => toggleCardFilter('shadow')}          active={isCardActive('shadow')} />
        <StatCard label="PII Detected"    value={agg.pii_detected}    icon={Layers}   color="red"
                  onClick={() => toggleCardFilter('pii_detected')}    active={isCardActive('pii_detected')} />
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Threat: High"   value={agg.threat_high}   icon={ShieldAlert}   color="red"
                  onClick={() => toggleCardFilter('threat_high')}   active={isCardActive('threat_high')} />
        <StatCard label="Threat: Medium" value={agg.threat_medium} icon={AlertTriangle} color="amber"
                  onClick={() => toggleCardFilter('threat_medium')} active={isCardActive('threat_medium')} />
        <StatCard label="Threat: Low"    value={agg.threat_low}    icon={ShieldCheck}   color="emerald"
                  onClick={() => toggleCardFilter('threat_low')}    active={isCardActive('threat_low')} />
        <StatCard label="Max Risk Score" value={agg.risk_score_max || '—'} icon={Layers} color="violet"
                  onClick={() => toggleCardFilter('risk_score_max')} active={isCardActive('risk_score_max')} />
      </div>

      {/* Active card-filter pill */}
      {cardFilters.size > 0 && (
        <div className="flex items-center gap-2 flex-wrap text-xs">
          <span className="text-slate-500">Card filters:</span>
          {Array.from(cardFilters).map(f => (
            <button
              key={String(f)}
              onClick={() => toggleCardFilter(f)}
              className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-blue-500/15 border border-blue-500/30 text-blue-300 hover:bg-blue-500/25 transition-colors"
              title="Click to remove this filter"
            >
              <span>{String(f)}</span>
              <span className="text-blue-200">×</span>
            </button>
          ))}
          <button onClick={clearCardFilters} className="text-slate-400 hover:text-slate-200 underline">clear all</button>
        </div>
      )}

      {/* Filter + result count */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="text-xs text-slate-500">
          Showing <span className="text-slate-300">{sorted.length}</span> of {results.lbStats.length} load balancers
          {sortField && <span className="ml-2">· sorted by <span className="text-slate-300">{sortField}</span> ({sortDir})</span>}
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => setNonZeroOnly(v => !v)}
            disabled={!sortField || sortField === 'scope' || sortField === 'namespace' || sortField === 'lbName'}
            title={(sortField === 'scope' || sortField === 'namespace' || sortField === 'lbName') ? 'Pick a numeric column first' : `Hide load balancers where ${sortField || 'sorted column'} is zero`}
            className={`flex items-center gap-1.5 px-2 py-1.5 rounded-md border text-xs transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
              nonZeroOnly && sortField && sortField !== 'scope' && sortField !== 'namespace' && sortField !== 'lbName'
                ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                : 'bg-slate-800 border-slate-600 text-slate-400 hover:border-slate-500'
            }`}
          >
            <Filter className="w-3 h-3" />
            Non-zero only
          </button>
          {showNsCol && <FilterInput value={nsFilter} onChange={setNsFilter} placeholder="Filter namespace…" width="w-40" />}
          <FilterInput value={filter} onChange={setFilter} placeholder="Filter load balancer…" />
        </div>
      </div>

      {/* Per-LB stats table */}
      <div className="overflow-x-auto -mx-6">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-slate-700/30">
              {showNsCol && <SortableTh<OverviewSortField> field="namespace"  label="Namespace"     sortField={sortField} sortDir={sortDir} onSort={onSort} />}
              <SortableTh<OverviewSortField> field="lbName"           label="Load Balancer" sortField={sortField} sortDir={sortDir} onSort={onSort} />
              <SortableTh<OverviewSortField> field="total_endpoints"  label="Total"         sortField={sortField} sortDir={sortDir} onSort={onSort} align="right" />
              <SortableTh<OverviewSortField> field="discovered"       label="Discovered"    sortField={sortField} sortDir={sortDir} onSort={onSort} align="right" />
              <SortableTh<OverviewSortField> field="inventory"        label="Inventory"     sortField={sortField} sortDir={sortDir} onSort={onSort} align="right" />
              <SortableTh<OverviewSortField> field="shadow"           label="Shadow"        sortField={sortField} sortDir={sortDir} onSort={onSort} align="right" />
              <SortableTh<OverviewSortField> field="pii_detected"     label="PII"           sortField={sortField} sortDir={sortDir} onSort={onSort} align="right" />
              <SortableTh<OverviewSortField> field="threat_high"      label="Threat ▲"      sortField={sortField} sortDir={sortDir} onSort={onSort} align="right" />
              <SortableTh<OverviewSortField> field="threat_medium"    label="Threat ◆"      sortField={sortField} sortDir={sortDir} onSort={onSort} align="right" />
              <SortableTh<OverviewSortField> field="threat_low"       label="Threat ▼"      sortField={sortField} sortDir={sortDir} onSort={onSort} align="right" />
              <SortableTh<OverviewSortField> field="risk_score_avg"   label="Avg Risk"      sortField={sortField} sortDir={sortDir} onSort={onSort} align="right" />
              <SortableTh<OverviewSortField> field="risk_score_max"   label="Max Risk"      sortField={sortField} sortDir={sortDir} onSort={onSort} align="right" />
              <SortableTh<OverviewSortField> field="vulnerable"       label="Vulnerable"    sortField={sortField} sortDir={sortDir} onSort={onSort} align="right" />
            </tr>
          </thead>
          <tbody>
            {sorted.map((s, i) => (
              <tr key={i} className="border-t border-slate-700/50 hover:bg-slate-700/20">
                {showNsCol && <td className="px-4 py-3 text-violet-300 font-mono text-xs">{s.namespace || '—'}</td>}
                <td className="px-4 py-3 text-slate-200 font-mono text-xs">{s.lbName || s.scope}</td>
                <td className="px-4 py-3 text-right text-slate-300">{s.total_endpoints}</td>
                <td className="px-4 py-3 text-right text-emerald-400">{s.discovered}</td>
                <td className="px-4 py-3 text-right text-cyan-400">{s.inventory}</td>
                <td className="px-4 py-3 text-right text-amber-400">{s.shadow}</td>
                <td className="px-4 py-3 text-right text-red-400">{s.pii_detected}</td>
                <td className="px-4 py-3 text-right text-red-400 font-medium">{s.threat_high   ?? '—'}</td>
                <td className="px-4 py-3 text-right text-amber-400 font-medium">{s.threat_medium ?? '—'}</td>
                <td className="px-4 py-3 text-right text-emerald-400 font-medium">{s.threat_low    ?? '—'}</td>
                <td className="px-4 py-3 text-right text-violet-400">{s.risk_score_avg ?? '—'}</td>
                <td className="px-4 py-3 text-right text-violet-400">{s.risk_score_max ?? '—'}</td>
                <td className="px-4 py-3 text-right text-slate-400">{s.vulnerable ?? '—'}</td>
              </tr>
            ))}
            {sorted.length === 0 && (
              <tr><td colSpan={showNsCol ? 13 : 12} className="px-4 py-8 text-center text-slate-500">
                {results.lbStats.length === 0 ? 'No stats available' : 'No matches for current filter'}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Schema Download Tab ─────────────────────────────────────────────────────

type DownloadSortField = 'scope' | 'namespace' | 'lbName' | 'opCount';

interface BulkProgress { current: number; total: number; lb: string; ok: number; fail: number }

interface DownloadTarget { scope: string; namespace: string; lbName: string }

function DownloadTab({
  results, onDownload, downloadingZip, onBulkDownload, onCancelBulk, bulkProgress, onDownloadOpenApi,
}: {
  results: ApiReportResults;
  onDownload: (scope: string, namespace: string, lbName: string) => void;
  downloadingZip: string | null;
  onBulkDownload: (targets?: DownloadTarget[]) => void;
  onCancelBulk: () => void;
  bulkProgress: BulkProgress | null;
  onDownloadOpenApi: (scope: string) => void;
}) {
  const bulkDownloading = bulkProgress !== null;
  const [filter, setFilter] = useState('');
  const [nsFilter, setNsFilter] = useState('');
  const [hasOpsOnly, setHasOpsOnly] = useState(false);
  const { sortField, sortDir, onSort } = useSort<DownloadSortField>('opCount', 'desc');
  const showNsCol = results.namespaces.length > 1;

  const specCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of results.swaggerEndpoints) {
      if (!e.path || e.method === '-' || /^No discovered APIs$/i.test(e.path) || /^Error/i.test(e.path)) continue;
      m.set(e.lb, (m.get(e.lb) || 0) + 1);
    }
    return m;
  }, [results]);

  const rows = useMemo(() => {
    let out = results.lbStats.map(s => ({
      scope: s.scope,
      namespace: s.namespace || '',
      lbName: s.lbName || s.scope,
      opCount: specCounts.get(s.scope) || 0,
    }));
    const f = filter.trim().toLowerCase();
    if (f) out = out.filter(r => r.scope.toLowerCase().includes(f) || r.lbName.toLowerCase().includes(f));
    const fns = nsFilter.trim().toLowerCase();
    if (fns) out = out.filter(r => r.namespace.toLowerCase().includes(fns));
    if (hasOpsOnly) out = out.filter(r => r.opCount > 0);
    return sortBy(out, sortField, sortDir, (r, fld) => (r as unknown as Record<string, unknown>)[fld]);
  }, [results.lbStats, specCounts, filter, nsFilter, hasOpsOnly, sortField, sortDir]);

  const filteredTargets: DownloadTarget[] = rows.map(r => ({ scope: r.scope, namespace: r.namespace, lbName: r.lbName }));
  const allHasOpsTargets: DownloadTarget[] = results.lbStats
    .filter(s => (specCounts.get(s.scope) || 0) > 0)
    .map(s => ({ scope: s.scope, namespace: s.namespace || '', lbName: s.lbName || s.scope }));
  const isFilterActive = filter.trim() !== '' || nsFilter.trim() !== '' || hasOpsOnly;
  const progressPct = bulkProgress
    ? Math.round((bulkProgress.current / bulkProgress.total) * 100)
    : 0;

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h3 className="text-base font-semibold text-slate-100">Schema Download</h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Download the original swagger_spec ZIP per load balancer — same content as the F5 XC console "Download Schema" option. Files save one after another in the order shown below.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {isFilterActive && (
            <button
              onClick={() => onBulkDownload(filteredTargets)}
              disabled={bulkDownloading || filteredTargets.length === 0}
              title={`Download the ${filteredTargets.length} load balancers currently shown`}
              className="flex items-center gap-2 px-3 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 text-sm font-medium rounded-lg border border-cyan-500/30 transition-colors disabled:opacity-50"
            >
              <Download className="w-4 h-4" />
              Download Filtered ({filteredTargets.length})
            </button>
          )}
          <button
            onClick={() => onBulkDownload(allHasOpsTargets)}
            disabled={bulkDownloading || allHasOpsTargets.length === 0}
            title="Skip load balancers with zero discovered operations"
            className="flex items-center gap-2 px-3 py-2 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 text-sm font-medium rounded-lg border border-emerald-500/30 transition-colors disabled:opacity-50"
          >
            <Download className="w-4 h-4" />
            Download With Ops ({allHasOpsTargets.length})
          </button>
          <button
            onClick={() => onBulkDownload()}
            disabled={bulkDownloading || results.lbStats.length === 0}
            className="flex items-center gap-2 px-3 py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 text-sm font-medium rounded-lg border border-blue-500/30 transition-colors disabled:opacity-50"
          >
            {bulkDownloading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            {bulkDownloading ? 'Downloading…' : `Download All (${results.lbStats.length})`}
          </button>
          {bulkDownloading && (
            <button
              onClick={onCancelBulk}
              className="flex items-center gap-2 px-3 py-2 bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 text-sm font-medium rounded-lg border border-rose-500/30 transition-colors"
            >
              Stop
            </button>
          )}
        </div>
      </div>

      {/* Bulk progress */}
      {bulkProgress && (
        <div className="bg-slate-900/40 border border-slate-700 rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2 text-slate-200">
              <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
              <span>
                Downloading <span className="font-mono text-slate-100">{bulkProgress.lb}</span>
                <span className="text-slate-500"> · {bulkProgress.current} of {bulkProgress.total}</span>
              </span>
            </div>
            <div className="text-xs text-slate-400">
              <span className="text-emerald-400">{bulkProgress.ok} ok</span>
              {bulkProgress.fail > 0 && <span className="text-rose-400 ml-2">{bulkProgress.fail} failed</span>}
              <span className="ml-2 text-slate-500">{progressPct}%</span>
            </div>
          </div>
          <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-blue-500 to-cyan-500 transition-all duration-300"
              style={{ width: `${progressPct}%` }}
            />
          </div>
          <p className="text-[11px] text-slate-500">
            Tip: your browser may ask permission to download multiple files — allow it once and the rest save automatically.
          </p>
        </div>
      )}

      {/* Filter row */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setHasOpsOnly(v => !v)}
            className={`flex items-center gap-1.5 px-2 py-1 rounded-md border text-xs transition-colors ${
              hasOpsOnly
                ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                : 'bg-slate-800 border-slate-600 text-slate-400 hover:border-slate-500'
            }`}
          >
            <Filter className="w-3 h-3" />
            With discovered ops only
          </button>
          <div className="text-xs text-slate-500">
            Showing <span className="text-slate-300">{rows.length}</span> of {results.lbStats.length}
            <span className="ml-2">across {results.namespaces.length} ns</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {showNsCol && <FilterInput value={nsFilter} onChange={setNsFilter} placeholder="Filter namespace…" width="w-40" />}
          <FilterInput value={filter} onChange={setFilter} placeholder="Filter load balancer…" />
        </div>
      </div>

      <div className="overflow-x-auto -mx-6">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-slate-700/30">
              {showNsCol && <SortableTh<DownloadSortField> field="namespace" label="Namespace"     sortField={sortField} sortDir={sortDir} onSort={onSort} />}
              <SortableTh<DownloadSortField> field="lbName"  label="Load Balancer"  sortField={sortField} sortDir={sortDir} onSort={onSort} />
              <SortableTh<DownloadSortField> field="opCount" label="Discovered Ops" sortField={sortField} sortDir={sortDir} onSort={onSort} align="right" />
              <th className="px-4 py-3 text-right text-xs font-medium text-slate-400 uppercase">Raw Schema (F5 XC)</th>
              <th className="px-4 py-3 text-right text-xs font-medium text-slate-400 uppercase">OpenAPI 3.0 (synthesized)</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const isDownloading = downloadingZip === r.scope;
              return (
                <tr key={r.scope} className="border-t border-slate-700/50 hover:bg-slate-700/20">
                  {showNsCol && <td className="px-4 py-3 text-violet-300 font-mono text-xs">{r.namespace || '—'}</td>}
                  <td className="px-4 py-3 text-slate-200 font-mono text-xs">{r.lbName}</td>
                  <td className="px-4 py-3 text-right text-slate-300">{r.opCount}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => onDownload(r.scope, r.namespace, r.lbName)}
                      disabled={isDownloading || bulkDownloading}
                      title="Download original swagger_spec ZIP from F5 XC"
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-md border bg-violet-500/10 hover:bg-violet-500/20 text-violet-300 border-violet-500/30 disabled:bg-slate-800 disabled:text-slate-600 disabled:border-slate-700 disabled:cursor-not-allowed transition-colors"
                    >
                      {isDownloading ? <Loader2 className="w-3 h-3 animate-spin" /> : <FileArchive className="w-3 h-3" />}
                      ZIP
                    </button>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => onDownloadOpenApi(r.scope)}
                      disabled={r.opCount === 0}
                      title={r.opCount === 0 ? 'No discovered APIs to export' : `Download synthesized OpenAPI 3.0 spec (${r.opCount} operations)`}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-md border bg-blue-500/10 hover:bg-blue-500/20 text-blue-300 border-blue-500/30 disabled:bg-slate-800 disabled:text-slate-600 disabled:border-slate-700 disabled:cursor-not-allowed transition-colors"
                    >
                      <Download className="w-3 h-3" />
                      {r.opCount > 0 ? `JSON (${r.opCount})` : 'No spec'}
                    </button>
                  </td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr><td colSpan={showNsCol ? 5 : 4} className="px-4 py-8 text-center text-slate-500">
                {results.lbStats.length === 0 ? 'No load balancers in report' : 'No matches for current filter'}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Schema Details Tab ──────────────────────────────────────────────────────

type OpSortField = 'method' | 'path' | 'tags' | 'operationId' | 'fqdn';
type RowSortField = string;

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'];

function DetailsTab({
  lbList, detailIndex, setDetailIndex, goPrev, goNext,
  currentLB, currentSpecs, currentRows, currentLbStats,
  opFilter, setOpFilter,
}: {
  lbList: string[];
  detailIndex: number;
  setDetailIndex: (i: number) => void;
  goPrev: () => void;
  goNext: () => void;
  currentLB: string;
  currentSpecs: SwaggerSpec[];
  currentRows: Array<Record<string, string | number | undefined>>;
  currentLbStats: { total_endpoints: number; discovered: number; inventory: number; shadow: number; pii_detected: number } | undefined;
  opFilter: string;
  setOpFilter: (s: string) => void;
}) {
  const [methodFilter, setMethodFilter] = useState<Set<string>>(new Set());
  const opSort = useSort<OpSortField>('path', 'asc');
  const [rowFilter, setRowFilter] = useState('');
  const [rowNonZeroOnly, setRowNonZeroOnly] = useState(false);
  const rowSort = useSort<RowSortField>(null, 'asc');

  if (lbList.length === 0) {
    return <div className="p-8 text-center text-sm text-slate-500">No load balancers in this report</div>;
  }

  const allOps: Array<SwaggerOperation & { fqdn: string; specTitle?: string }> = [];
  for (const spec of currentSpecs) {
    for (const op of spec.endpoints) {
      allOps.push({ ...op, fqdn: spec.fqdn, specTitle: spec.title });
    }
  }
  let filteredOps = allOps;
  if (opFilter) {
    const f = opFilter.toLowerCase();
    filteredOps = filteredOps.filter(op =>
      op.path.toLowerCase().includes(f) ||
      op.method.toLowerCase().includes(f) ||
      (op.summary || '').toLowerCase().includes(f) ||
      (op.operationId || '').toLowerCase().includes(f) ||
      (op.tags || []).some(t => t.toLowerCase().includes(f))
    );
  }
  if (methodFilter.size > 0) {
    filteredOps = filteredOps.filter(op => methodFilter.has(op.method.toUpperCase()));
  }
  filteredOps = sortBy(filteredOps, opSort.sortField, opSort.sortDir, (op, fld) => {
    const o = op as unknown as Record<string, unknown>;
    const v = o[fld];
    return Array.isArray(v) ? v.join(',') : v;
  });

  const filteredRows = (() => {
    let out = currentRows;
    if (rowFilter.trim()) {
      const f = rowFilter.toLowerCase();
      out = out.filter(r =>
        Object.values(r).some(v => String(v ?? '').toLowerCase().includes(f))
      );
    }
    if (rowNonZeroOnly && rowSort.sortField) {
      out = out.filter(r => !isZeroish((r as Record<string, unknown>)[rowSort.sortField as string]));
    }
    return sortBy(out, rowSort.sortField, rowSort.sortDir, (r, fld) => (r as Record<string, unknown>)[fld]);
  })();

  const toggleMethod = (m: string) => {
    setMethodFilter(prev => {
      const next = new Set(prev);
      if (next.has(m)) next.delete(m); else next.add(m);
      return next;
    });
  };

  return (
    <div className="p-6 space-y-5">
      {/* Navigator */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h3 className="text-base font-semibold text-slate-100">Schema Details</h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Showing load balancer <span className="text-slate-300 font-mono">{currentLB}</span> ({detailIndex + 1} of {lbList.length})
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={goPrev}
            disabled={detailIndex <= 0}
            className="flex items-center gap-1 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm rounded-lg border border-slate-600 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronLeft className="w-4 h-4" /> Prev
          </button>
          <select
            value={currentLB}
            onChange={(e) => setDetailIndex(lbList.indexOf(e.target.value))}
            className="px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-200 outline-none focus:border-slate-500 max-w-xs"
          >
            {lbList.map(name => (
              <option key={name} value={name}>{name}</option>
            ))}
          </select>
          <button
            onClick={goNext}
            disabled={detailIndex >= lbList.length - 1}
            className="flex items-center gap-1 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm rounded-lg border border-slate-600 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Next <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* LB summary */}
      {currentLbStats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <StatCard label="Total" value={currentLbStats.total_endpoints} icon={Globe} color="blue" />
          <StatCard label="Discovered" value={currentLbStats.discovered} icon={Eye} color="emerald" />
          <StatCard label="Inventory" value={currentLbStats.inventory} icon={Database} color="cyan" />
          <StatCard label="Shadow" value={currentLbStats.shadow} icon={EyeOff} color="amber" />
          <StatCard label="PII" value={currentLbStats.pii_detected} icon={Layers} color="red" />
        </div>
      )}

      {/* Spec metadata */}
      {currentSpecs.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {currentSpecs.map((spec, i) => (
            <div key={i} className="p-3 bg-slate-900/40 border border-slate-700 rounded-lg">
              <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
                <Globe className="w-3 h-3" />
                <span className="truncate">{spec.fqdn || '(no FQDN)'}</span>
              </div>
              <div className="text-sm text-slate-200 font-medium">{spec.title || spec.filename}</div>
              <div className="text-[11px] text-slate-500 mt-1">
                {spec.openapi && <span className="mr-2">OpenAPI {spec.openapi}</span>}
                {spec.version && <span className="mr-2">v{spec.version}</span>}
                <span>{spec.endpoints.length} operations</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Operation filter + sort */}
      {allOps.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <h4 className="text-sm font-semibold text-slate-300">Operations ({filteredOps.length} of {allOps.length})</h4>
            <div className="flex items-center gap-2 flex-wrap">
              <select
                value={opSort.sortField || ''}
                onChange={(e) => e.target.value && opSort.onSort(e.target.value as OpSortField)}
                className="px-2 py-1.5 bg-slate-800 border border-slate-600 rounded-lg text-xs text-slate-200 outline-none focus:border-slate-500"
                title="Sort by"
              >
                <option value="path">Sort: Path</option>
                <option value="method">Sort: Method</option>
                <option value="operationId">Sort: Operation ID</option>
                <option value="tags">Sort: Tags</option>
                <option value="fqdn">Sort: FQDN</option>
              </select>
              <button
                onClick={() => opSort.onSort(opSort.sortField || 'path')}
                className="p-1.5 bg-slate-800 border border-slate-600 rounded-lg text-slate-300 hover:border-slate-500"
                title={opSort.sortDir === 'asc' ? 'Ascending — click for descending' : 'Descending — click for ascending'}
              >
                {opSort.sortDir === 'asc' ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
              <FilterInput value={opFilter} onChange={setOpFilter} placeholder="Filter path, method, tag, opId…" />
            </div>
          </div>
          {/* Method chip filter */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[11px] text-slate-500 mr-1">Method:</span>
            {HTTP_METHODS.map(m => {
              const active = methodFilter.has(m);
              return (
                <button
                  key={m}
                  onClick={() => toggleMethod(m)}
                  className={`px-2 py-0.5 text-[10px] font-medium rounded border transition-colors ${
                    active
                      ? 'bg-blue-500/20 border-blue-500/40 text-blue-300'
                      : 'bg-slate-800 border-slate-600 text-slate-500 hover:text-slate-300 hover:border-slate-500'
                  }`}
                >
                  {m}
                </button>
              );
            })}
            {methodFilter.size > 0 && (
              <button onClick={() => setMethodFilter(new Set())} className="text-[10px] text-slate-400 hover:text-slate-200 underline ml-1">clear</button>
            )}
          </div>
        </div>
      )}

      {/* Operation list */}
      {allOps.length === 0 ? (
        <div className="p-6 text-center text-sm text-slate-500 border border-dashed border-slate-700 rounded-lg">
          No discovered operations for this load balancer.
        </div>
      ) : (
        <div className="space-y-2">
          {filteredOps.map((op, i) => (
            <OperationRow key={`${op.path}-${op.method}-${i}`} op={op} />
          ))}
        </div>
      )}

      {/* Endpoint detail rows (raw) */}
      {currentRows.length > 0 && (
        <details className="bg-slate-900/40 border border-slate-700 rounded-lg" open>
          <summary className="px-4 py-3 cursor-pointer text-sm font-medium text-slate-300 hover:text-slate-100">
            Discovered Endpoint Detail ({filteredRows.length} of {currentRows.length} rows)
          </summary>
          <div className="px-4 py-3 border-t border-slate-700 flex items-center justify-between gap-3 flex-wrap">
            <div className="text-xs text-slate-500">
              {rowSort.sortField
                ? <>Sorted by <span className="text-slate-300">{rowSort.sortField}</span> ({rowSort.sortDir}) · click any column header to change</>
                : <>Click any column header to sort</>}
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <button
                onClick={() => setRowNonZeroOnly(v => !v)}
                disabled={!rowSort.sortField}
                title={!rowSort.sortField ? 'Pick a column first' : `Hide rows where ${rowSort.sortField} is zero/empty`}
                className={`flex items-center gap-1.5 px-2 py-1.5 rounded-md border text-xs transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
                  rowNonZeroOnly && rowSort.sortField
                    ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                    : 'bg-slate-800 border-slate-600 text-slate-400 hover:border-slate-500'
                }`}
              >
                <Filter className="w-3 h-3" />
                Non-zero only
              </button>
              <FilterInput value={rowFilter} onChange={setRowFilter} placeholder="Filter rows…" />
            </div>
          </div>
          <div className="overflow-x-auto border-t border-slate-700">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-slate-700/30">
                  {Object.keys(currentRows[0]).filter(k => k !== 'lb').map(col => (
                    <SortableTh<RowSortField>
                      key={col}
                      field={col}
                      label={col}
                      sortField={rowSort.sortField}
                      sortDir={rowSort.sortDir}
                      onSort={rowSort.onSort}
                      className="whitespace-nowrap"
                    />
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredRows.slice(0, 500).map((row, i) => (
                  <tr key={i} className="border-t border-slate-700/50 hover:bg-slate-700/20">
                    {Object.entries(row).filter(([k]) => k !== 'lb').map(([col, val]) => (
                      <td key={col} className="px-3 py-2 text-slate-300 text-xs max-w-[200px] truncate" title={String(val ?? '')}>
                        {col === 'Method' ? <MethodBadge method={String(val ?? '-')} /> : String(val ?? '—')}
                      </td>
                    ))}
                  </tr>
                ))}
                {filteredRows.length === 0 && (
                  <tr><td colSpan={Object.keys(currentRows[0]).length - 1} className="px-4 py-6 text-center text-xs text-slate-500">
                    No rows match the current filter
                  </td></tr>
                )}
                {filteredRows.length > 500 && (
                  <tr><td colSpan={Object.keys(currentRows[0]).length - 1} className="px-4 py-3 text-center text-xs text-slate-500">
                    Showing 500 of {filteredRows.length} rows. Export Excel from the Overview tab for the full dataset.
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </div>
  );
}

function OperationRow({ op }: { op: SwaggerOperation & { fqdn: string; specTitle?: string } }) {
  const [open, setOpen] = useState(false);
  const hasDetail = (op.parameters && op.parameters.length > 0) || op.requestBody || (op.responses && op.responses.length > 0) || op.description;
  return (
    <div className="bg-slate-900/40 border border-slate-700 rounded-lg overflow-hidden">
      <button
        onClick={() => hasDetail && setOpen(o => !o)}
        className={`w-full flex items-center gap-3 px-4 py-2.5 text-left ${hasDetail ? 'hover:bg-slate-800/60 cursor-pointer' : 'cursor-default'}`}
      >
        <MethodBadge method={op.method} />
        <span className="text-sm text-slate-100 font-mono truncate flex-1">{op.path}</span>
        {op.deprecated && (
          <span className="px-1.5 py-0.5 text-[10px] rounded bg-amber-500/15 text-amber-400 border border-amber-500/30">deprecated</span>
        )}
        {op.tags && op.tags.length > 0 && (
          <span className="hidden md:flex items-center gap-1 text-[11px] text-slate-500">
            <Tag className="w-3 h-3" />
            {op.tags.slice(0, 3).join(', ')}
          </span>
        )}
        {op.security && op.security.length > 0 && (
          <span className="flex items-center gap-1 text-[11px] text-emerald-400/80">
            <Lock className="w-3 h-3" />
            {op.security.join(', ')}
          </span>
        )}
        {op.contentType && op.contentType !== '-' && (
          <span className="hidden lg:inline text-[11px] text-slate-500 font-mono truncate max-w-[180px]">{op.contentType}</span>
        )}
        {hasDetail && <ChevronDown className={`w-4 h-4 text-slate-500 transition-transform ${open ? 'rotate-180' : ''}`} />}
      </button>

      {open && hasDetail && (
        <div className="border-t border-slate-700 px-4 py-3 space-y-3 bg-slate-900/60">
          {op.summary && <div className="text-sm text-slate-200">{op.summary}</div>}
          {op.description && <div className="text-xs text-slate-400 whitespace-pre-wrap">{op.description}</div>}
          {op.fqdn && (
            <div className="text-[11px] text-slate-500">
              <span className="text-slate-400">Server: </span>
              <span className="font-mono">{op.fqdn}</span>
            </div>
          )}

          {op.parameters && op.parameters.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-slate-300 mb-1.5">Parameters</div>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-slate-500 uppercase">
                    <th className="text-left font-medium pb-1">Name</th>
                    <th className="text-left font-medium pb-1">In</th>
                    <th className="text-left font-medium pb-1">Type</th>
                    <th className="text-left font-medium pb-1">Required</th>
                    <th className="text-left font-medium pb-1">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {op.parameters.map((p, i) => (
                    <tr key={i} className="border-t border-slate-700/50">
                      <td className="py-1 text-slate-200 font-mono">{p.name}</td>
                      <td className="py-1 text-slate-400">{p.in}</td>
                      <td className="py-1 text-cyan-400 font-mono">{p.type || '—'}</td>
                      <td className="py-1 text-slate-400">{p.required ? 'yes' : 'no'}</td>
                      <td className="py-1 text-slate-400">{p.description || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {op.requestBody && (
            <div>
              <div className="text-xs font-semibold text-slate-300 mb-1.5">Request Body</div>
              <div className="text-xs text-slate-400">
                <div>
                  <span className="text-slate-500">Content-Type: </span>
                  <span className="font-mono text-slate-200">{op.requestBody.contentTypes.join(', ')}</span>
                  {op.requestBody.required && <span className="ml-2 text-amber-400">required</span>}
                </div>
                {op.requestBody.schemaSummary && (
                  <div className="mt-1">
                    <span className="text-slate-500">Schema: </span>
                    <span className="font-mono text-cyan-400">{op.requestBody.schemaSummary}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {op.responses && op.responses.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-slate-300 mb-1.5">Responses</div>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-slate-500 uppercase">
                    <th className="text-left font-medium pb-1">Code</th>
                    <th className="text-left font-medium pb-1">Description</th>
                    <th className="text-left font-medium pb-1">Content Type(s)</th>
                  </tr>
                </thead>
                <tbody>
                  {op.responses.map((r, i) => (
                    <tr key={i} className="border-t border-slate-700/50">
                      <td className="py-1 font-mono text-slate-200">{r.code}</td>
                      <td className="py-1 text-slate-400">{r.description || '—'}</td>
                      <td className="py-1 text-slate-400 font-mono">{r.contentTypes?.join(', ') || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── HTTP Method Badge ───────────────────────────────────────────────────────

function MethodBadge({ method }: { method: string }) {
  const m = method.toUpperCase();
  const colorMap: Record<string, string> = {
    GET: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    POST: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
    PUT: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    DELETE: 'bg-red-500/15 text-red-400 border-red-500/30',
    PATCH: 'bg-violet-500/15 text-violet-400 border-violet-500/30',
  };
  const cls = colorMap[m] || 'bg-slate-700 text-slate-400 border-slate-600';
  return (
    <span className={`px-1.5 py-0.5 text-[10px] font-medium rounded border ${cls} shrink-0 min-w-[44px] text-center`}>{m}</span>
  );
}
