// ═══════════════════════════════════════════════════════════════════════════
// WAF Attack Simulator Page
//
// Setup wizard → fire curated OWASP WAF/API attacks at a selected XC endpoint →
// (optionally) pull XC security + access logs and reconcile what was BLOCKED vs.
// what REACHED ORIGIN. Authorized WAF-efficacy validation only.
// ═══════════════════════════════════════════════════════════════════════════

import { useState, useEffect, useRef, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Swords,
  ArrowLeft,
  Play,
  Square,
  ShieldCheck,
  ShieldAlert,
  Loader2,
  Download,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Search,
  AlertTriangle,
  Globe,
  Crosshair,
  ListChecks,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { apiClient } from '../services/api';
import type { Namespace } from '../types';
import {
  ATTACK_CATEGORIES,
  payloadsForCategories,
  runAttacks,
  detectSourceIp,
  reconcile,
  liveOnly,
  buildReport,
  exportSimReportCSV,
  SEVERITY_META,
  VERDICT_META,
  SEVERITY_ORDER,
} from '../services/waf-simulator';
import type {
  HttpMethod,
  SimRunConfig,
  SimProgress,
  SimReport,
  ReconciledVerdict,
  Severity,
} from '../services/waf-simulator';

const ALL_METHODS: HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'];

export function WafAttackSimulator() {
  const { isConnected } = useApp();
  const navigate = useNavigate();
  const toast = useToast();
  const abortRef = useRef(false);

  const [step, setStep] = useState<'config' | 'running' | 'results'>('config');

  // ── Target selection ──
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [namespace, setNamespace] = useState('');
  const [loadBalancers, setLoadBalancers] = useState<Array<{ name: string; domains: string[]; paths: string[] }>>([]);
  const [loadBalancer, setLoadBalancer] = useState('');
  const [domain, setDomain] = useState('');
  const [scheme, setScheme] = useState<'https' | 'http'>('https');
  const [pathsText, setPathsText] = useState('/');
  const [methods, setMethods] = useState<Set<HttpMethod>>(new Set<HttpMethod>(['GET', 'POST']));

  // ── Attack selection ──
  const [categoryIds, setCategoryIds] = useState<Set<string>>(
    () => new Set(ATTACK_CATEGORIES.filter((c) => c.defaultEnabled).map((c) => c.id))
  );

  // ── Mode / safety ──
  const [mode, setMode] = useState<'attack-only' | 'reconcile'>('reconcile');
  const [fullStrength, setFullStrength] = useState(false);
  const [nonProdAck, setNonProdAck] = useState(false);
  const [authorizedAck, setAuthorizedAck] = useState(false);

  // ── Tuning ──
  const [pacingMs, setPacingMs] = useState(250);
  const [ingestionWaitSec, setIngestionWaitSec] = useState(45);
  const [pollAttempts, setPollAttempts] = useState(4);
  const [pollIntervalSec, setPollIntervalSec] = useState(20);
  const [sourceIp, setSourceIp] = useState('');

  // ── Run state ──
  const [progress, setProgress] = useState<SimProgress | null>(null);
  const [report, setReport] = useState<SimReport | null>(null);

  // ── Results filtering ──
  const [filterVerdict, setFilterVerdict] = useState<ReconciledVerdict | 'ALL'>('ALL');
  const [filterSeverity, setFilterSeverity] = useState<Severity | 'ALL'>('ALL');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!isConnected) navigate('/');
  }, [isConnected, navigate]);

  useEffect(() => {
    (async () => {
      try {
        const resp = await apiClient.getNamespaces();
        setNamespaces(resp.items || []);
      } catch {
        toast.error('Failed to load namespaces');
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Load load balancers when namespace changes.
  useEffect(() => {
    if (!namespace) {
      setLoadBalancers([]);
      return;
    }
    (async () => {
      try {
        const resp = await apiClient.getLoadBalancers(namespace);
        const items = (resp.items || []) as Array<Record<string, any>>;
        const lbs = await Promise.all(
          items.map(async (it) => {
            const name = it.metadata?.name || it.name;
            let full: any = it;
            try {
              full = await apiClient.getLoadBalancer(namespace, name);
            } catch {
              /* keep list item */
            }
            const spec = full?.spec || full?.get_spec || full || {};
            const domains: string[] = Array.isArray(spec.domains) ? spec.domains.map(String) : [];
            const paths = extractPaths(spec);
            return { name, domains, paths };
          })
        );
        setLoadBalancers(lbs);
      } catch {
        toast.error('Failed to load load balancers');
        setLoadBalancers([]);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [namespace]);

  // When LB chosen, prefill domain + suggested paths.
  useEffect(() => {
    const lb = loadBalancers.find((l) => l.name === loadBalancer);
    if (!lb) return;
    if (lb.domains[0]) setDomain(lb.domains[0]);
    if (lb.paths.length) setPathsText(lb.paths.join('\n'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loadBalancer]);

  const selectedPayloadCount = useMemo(() => {
    const payloads = payloadsForCategories([...categoryIds]);
    const pathCount = parsePaths(pathsText).length || 1;
    // Approximate: each payload runs once per path (method intersection ≈ 1+).
    return payloads.length * pathCount;
  }, [categoryIds, pathsText]);

  const paths = parsePaths(pathsText);
  const canRun =
    !!namespace &&
    !!domain.trim() &&
    paths.length > 0 &&
    categoryIds.size > 0 &&
    methods.size > 0 &&
    authorizedAck &&
    (!fullStrength || nonProdAck);

  const toggleMethod = (m: HttpMethod) => {
    setMethods((prev) => {
      const next = new Set(prev);
      next.has(m) ? next.delete(m) : next.add(m);
      return next;
    });
  };

  const toggleCategory = (id: string) => {
    setCategoryIds((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const startRun = async () => {
    if (!canRun) {
      toast.error('Complete the required fields and confirm authorization first');
      return;
    }
    abortRef.current = false;
    setReport(null);
    setStep('running');

    const cfg: SimRunConfig = {
      namespace,
      loadBalancer: loadBalancer || '(manual)',
      target: { scheme, domain: domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, ''), paths },
      methods: [...methods],
      categoryIds: [...categoryIds],
      fullStrength,
      mode,
      pacingMs,
      ingestionWaitSec,
      pollAttempts,
      pollIntervalSec,
      sourceIp: sourceIp.trim(),
    };

    const started = Date.now();
    try {
      // Detect egress IP for reconcile mode if not supplied.
      if (cfg.mode === 'reconcile' && !cfg.sourceIp) {
        setProgress({ phase: 'detecting-ip', message: 'Detecting source IP as XC sees it…', progress: 0 });
        const ip = await detectSourceIp();
        if (ip) {
          cfg.sourceIp = ip;
          setSourceIp(ip);
        } else {
          toast.warning('Could not auto-detect source IP — reconciliation may be incomplete');
        }
      }

      const live = await runAttacks(cfg, (p) => setProgress(p), { shouldAbort: () => abortRef.current });

      if (abortRef.current) {
        toast.info('Run aborted');
        setStep('config');
        return;
      }

      let rep: SimReport;
      if (cfg.mode === 'reconcile' && cfg.sourceIp) {
        const { reconciled, notes } = await reconcile(cfg, live, (p) => setProgress(p), () => abortRef.current);
        rep = buildReport(cfg, reconciled, Date.now() - started, true, notes);
      } else {
        const notes =
          cfg.mode === 'reconcile'
            ? ['Reconciliation skipped: no source IP available. Verdicts are from live responses only.']
            : ['Attack-only mode: verdicts derived from live HTTP responses (XC logs not consulted).'];
        rep = buildReport(cfg, liveOnly(live), Date.now() - started, false, notes);
      }

      setProgress({ phase: 'complete', message: 'Done', progress: 100 });
      setReport(rep);
      setStep('results');
      toast.success(`Simulation complete — ${rep.summary.blocked} blocked, ${rep.summary.reachedOrigin} reached origin`);
    } catch (e) {
      toast.error(`Run failed: ${(e as Error).message}`);
      setStep('config');
    }
  };

  const filteredResults = useMemo(() => {
    if (!report) return [];
    const q = search.toLowerCase();
    return report.results.filter((r) => {
      if (filterVerdict !== 'ALL' && r.verdict !== filterVerdict) return false;
      if (filterSeverity !== 'ALL' && r.severity !== filterSeverity) return false;
      if (q && !`${r.payloadName} ${r.categoryName} ${r.owasp} ${r.path} ${r.method}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [report, filterVerdict, filterSeverity, search]);

  // ───────────────────────────────────────────────────────────────────────────
  return (
    <main className="max-w-7xl mx-auto px-6 py-8">
      <div className="flex items-center justify-between mb-6">
        <Link to="/" className="text-slate-400 hover:text-slate-200 flex items-center gap-2">
          <ArrowLeft className="w-4 h-4" /> Back to Toolbox
        </Link>
        {step === 'results' && report && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => exportSimReportCSV(report)}
              className="flex items-center gap-2 px-3 py-1.5 text-sm rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-100"
            >
              <Download className="w-4 h-4" /> Export CSV
            </button>
            <button
              onClick={() => setStep('config')}
              className="flex items-center gap-2 px-3 py-1.5 text-sm rounded-lg bg-blue-600 hover:bg-blue-500 text-white"
            >
              <RefreshCw className="w-4 h-4" /> New Run
            </button>
          </div>
        )}
      </div>

      <header className="flex items-start gap-4 mb-8">
        <div className="w-12 h-12 rounded-xl bg-rose-500/15 text-rose-400 flex items-center justify-center">
          <Swords className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-slate-100">WAF Attack Simulator</h1>
          <p className="text-slate-400 text-sm mt-1 max-w-3xl">
            Fire curated OWASP WAF Top 10 + API Top 10 attack signatures at one of your XC-protected endpoints, then
            reconcile against XC security &amp; access logs to see what the WAF blocked and what reached origin.
          </p>
        </div>
      </header>

      {step === 'config' && renderConfig()}
      {step === 'running' && renderRunning()}
      {step === 'results' && report && renderResults()}
    </main>
  );

  // ── CONFIG ──
  function renderConfig() {
    return (
      <div className="space-y-6">
        {/* Authorization banner */}
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
            <div className="text-sm text-amber-100/90">
              <p className="font-semibold text-amber-300">Authorized testing only</p>
              <p className="mt-1">
                This tool sends real attack-pattern requests to the endpoint you specify. Only run it against systems you
                own or are explicitly authorized to test. Default payloads are signature-triggering but non-destructive.
              </p>
              <label className="flex items-center gap-2 mt-3 cursor-pointer">
                <input type="checkbox" checked={authorizedAck} onChange={(e) => setAuthorizedAck(e.target.checked)} className="accent-amber-500" />
                <span>I am authorized to test the target endpoint.</span>
              </label>
            </div>
          </div>
        </div>

        <div className="grid lg:grid-cols-2 gap-6">
          {/* Target */}
          <section className="rounded-xl border border-slate-700 bg-slate-800/40 p-5">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2 mb-4">
              <Crosshair className="w-4 h-4 text-rose-400" /> Target
            </h2>
            <div className="space-y-4">
              <Field label="Namespace">
                <select value={namespace} onChange={(e) => setNamespace(e.target.value)} className={inputCls}>
                  <option value="">Select namespace…</option>
                  {namespaces.map((ns) => (
                    <option key={ns.name} value={ns.name}>{ns.name}</option>
                  ))}
                </select>
              </Field>

              <Field label="Load Balancer">
                <select value={loadBalancer} onChange={(e) => setLoadBalancer(e.target.value)} className={inputCls} disabled={!namespace}>
                  <option value="">{namespace ? 'Select load balancer…' : 'Select a namespace first'}</option>
                  {loadBalancers.map((lb) => (
                    <option key={lb.name} value={lb.name}>{lb.name}</option>
                  ))}
                </select>
              </Field>

              <Field label="Domain">
                <div className="flex gap-2">
                  <select value={scheme} onChange={(e) => setScheme(e.target.value as 'https' | 'http')} className={`${inputCls} w-28`}>
                    <option value="https">https://</option>
                    <option value="http">http://</option>
                  </select>
                  <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="app.example.com" className={inputCls} />
                </div>
              </Field>

              <Field label="Endpoint path(s) — one per line">
                <textarea
                  value={pathsText}
                  onChange={(e) => setPathsText(e.target.value)}
                  rows={4}
                  placeholder={'/\n/api/v1/users\n/login'}
                  className={`${inputCls} font-mono text-xs`}
                />
              </Field>

              <Field label="HTTP methods">
                <div className="flex flex-wrap gap-2">
                  {ALL_METHODS.map((m) => (
                    <button
                      key={m}
                      onClick={() => toggleMethod(m)}
                      className={`px-2.5 py-1 text-xs rounded-md border ${
                        methods.has(m) ? 'border-rose-500 bg-rose-500/20 text-rose-200' : 'border-slate-600 text-slate-400 hover:border-slate-500'
                      }`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </Field>
            </div>
          </section>

          {/* Mode & safety */}
          <section className="rounded-xl border border-slate-700 bg-slate-800/40 p-5">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2 mb-4">
              <ShieldCheck className="w-4 h-4 text-emerald-400" /> Mode &amp; Safety
            </h2>
            <div className="space-y-4">
              <Field label="Run mode">
                <div className="grid grid-cols-1 gap-2">
                  <ModeOption
                    active={mode === 'reconcile'}
                    onClick={() => setMode('reconcile')}
                    title="Attack + reconcile with XC logs"
                    desc="Fire attacks, wait for ingestion, pull security + access logs, and report blocked vs. reached-origin."
                  />
                  <ModeOption
                    active={mode === 'attack-only'}
                    onClick={() => setMode('attack-only')}
                    title="Attack only (no XC logs)"
                    desc="Fire attacks and classify from live HTTP responses only. No log access required."
                  />
                </div>
              </Field>

              <Field label="Payload strength">
                <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
                  <input type="checkbox" checked={fullStrength} onChange={(e) => { setFullStrength(e.target.checked); if (!e.target.checked) setNonProdAck(false); }} className="accent-rose-500" />
                  Use full-strength exploit payloads (non-prod targets only)
                </label>
                {fullStrength && (
                  <label className="flex items-center gap-2 mt-2 text-xs text-rose-200 cursor-pointer">
                    <input type="checkbox" checked={nonProdAck} onChange={(e) => setNonProdAck(e.target.checked)} className="accent-rose-500" />
                    I confirm the target is NOT production and I accept full-strength payloads.
                  </label>
                )}
                {!fullStrength && <p className="text-xs text-slate-500 mt-1">Default: prod-safe signatures (trip WAF rules, harmless at origin).</p>}
              </Field>

              {mode === 'reconcile' && (
                <>
                  <Field label="Source IP (auto-detected if blank)">
                    <input value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} placeholder="auto-detect at run start" className={`${inputCls} font-mono text-xs`} />
                  </Field>
                  <div className="grid grid-cols-3 gap-2">
                    <NumField label="Ingest wait (s)" value={ingestionWaitSec} onChange={setIngestionWaitSec} />
                    <NumField label="Poll tries" value={pollAttempts} onChange={setPollAttempts} />
                    <NumField label="Poll gap (s)" value={pollIntervalSec} onChange={setPollIntervalSec} />
                  </div>
                </>
              )}
              <NumField label="Pacing between requests (ms)" value={pacingMs} onChange={setPacingMs} />
            </div>
          </section>
        </div>

        {/* Attack categories */}
        <section className="rounded-xl border border-slate-700 bg-slate-800/40 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <ListChecks className="w-4 h-4 text-violet-400" /> Attack Categories
            </h2>
            <div className="flex gap-2 text-xs">
              <button onClick={() => setCategoryIds(new Set(ATTACK_CATEGORIES.map((c) => c.id)))} className="text-blue-400 hover:underline">Select all</button>
              <button onClick={() => setCategoryIds(new Set())} className="text-slate-400 hover:underline">Clear</button>
            </div>
          </div>
          <div className="grid md:grid-cols-2 gap-x-6 gap-y-2">
            {(['WAF', 'API'] as const).map((fam) => (
              <div key={fam}>
                <p className="text-xs uppercase tracking-wide text-slate-500 mb-2">{fam === 'WAF' ? 'OWASP Web / WAF Top 10' : 'OWASP API Security Top 10'}</p>
                <div className="space-y-1.5">
                  {ATTACK_CATEGORIES.filter((c) => c.family === fam).map((c) => {
                    const count = payloadsForCategories([c.id]).length;
                    return (
                      <label key={c.id} className="flex items-start gap-2 p-2 rounded-md hover:bg-slate-700/40 cursor-pointer">
                        <input type="checkbox" checked={categoryIds.has(c.id)} onChange={() => toggleCategory(c.id)} className="mt-0.5 accent-violet-500" />
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm text-slate-200">{c.name}</span>
                            <span className="text-[10px] text-slate-500">{count} payloads</span>
                          </div>
                          <p className="text-xs text-slate-500">{c.owasp}</p>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Run bar */}
        <div className="flex items-center justify-between rounded-xl border border-slate-700 bg-slate-800/60 p-4 sticky bottom-4">
          <div className="text-sm text-slate-400">
            <span className="text-slate-200 font-semibold">{selectedPayloadCount}</span> requests will be sent
            {fullStrength && <span className="ml-2 text-rose-300">· full-strength</span>}
            <span className="ml-2">· {mode === 'reconcile' ? 'with log reconciliation' : 'attack-only'}</span>
          </div>
          <button
            onClick={startRun}
            disabled={!canRun}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-lg font-semibold ${
              canRun ? 'bg-rose-600 hover:bg-rose-500 text-white' : 'bg-slate-700 text-slate-500 cursor-not-allowed'
            }`}
          >
            <Play className="w-4 h-4" /> Launch Simulation
          </button>
        </div>
      </div>
    );
  }

  // ── RUNNING ──
  function renderRunning() {
    const p = progress;
    return (
      <div className="rounded-xl border border-slate-700 bg-slate-800/40 p-8">
        <div className="flex items-center gap-3 mb-6">
          <Loader2 className="w-6 h-6 text-rose-400 animate-spin" />
          <div>
            <h2 className="text-lg font-semibold text-slate-100">{phaseLabel(p?.phase)}</h2>
            <p className="text-sm text-slate-400">{p?.message}</p>
          </div>
        </div>
        <div className="w-full h-2 rounded-full bg-slate-700 overflow-hidden mb-4">
          <div className="h-full bg-rose-500 transition-all" style={{ width: `${p?.progress || 0}%` }} />
        </div>
        {p && (p.sent !== undefined) && (
          <div className="flex gap-6 text-sm text-slate-300">
            <span>Sent: <b>{p.sent}</b>/{p.total}</span>
            <span className="text-emerald-400">Blocked (live): <b>{p.blocked ?? 0}</b></span>
            <span className="text-red-400">Reached origin (live): <b>{p.reachedOrigin ?? 0}</b></span>
          </div>
        )}
        <button
          onClick={() => { abortRef.current = true; }}
          className="mt-6 flex items-center gap-2 px-4 py-2 text-sm rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-100"
        >
          <Square className="w-4 h-4" /> Abort
        </button>
      </div>
    );
  }

  // ── RESULTS ──
  function renderResults() {
    if (!report) return null;
    const s = report.summary;
    return (
      <div className="space-y-6">
        {report.notes.length > 0 && (
          <div className="rounded-lg border border-slate-600 bg-slate-800/60 p-3 text-xs text-slate-400 space-y-1">
            {report.notes.map((n, i) => (
              <p key={i} className="flex gap-2"><span className="text-slate-500">ℹ</span>{n}</p>
            ))}
          </div>
        )}

        {/* Summary cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <StatCard label="Block rate" value={`${s.blockRate}%`} sub={report.reconciled ? 'from XC logs' : 'live only'} tone={s.blockRate >= 90 ? 'good' : s.blockRate >= 60 ? 'warn' : 'bad'} />
          <StatCard label="Total sent" value={s.total} />
          <StatCard label="Blocked" value={s.blocked} tone="good" />
          <StatCard label="Reached origin" value={s.reachedOrigin} tone={s.reachedOrigin > 0 ? 'bad' : 'good'} />
          <StatCard label="Inconclusive" value={s.inconclusive} tone="muted" />
        </div>

        {/* Gaps callout */}
        {s.reachedOrigin > 0 && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 flex items-start gap-3">
            <ShieldAlert className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div className="text-sm text-red-100/90">
              <p className="font-semibold text-red-300">{s.reachedOrigin} attack request(s) reached origin</p>
              <p className="mt-1">These payloads were not blocked by the WAF. Review the categories below and consider tightening the WAF policy or adding signatures.</p>
            </div>
          </div>
        )}

        {/* Category rollup */}
        <section className="rounded-xl border border-slate-700 bg-slate-800/40 p-5">
          <h2 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2"><Globe className="w-4 h-4 text-violet-400" /> By Category</h2>
          <div className="space-y-2">
            {s.byCategory.map((c) => {
              const conclusive = c.blocked + c.reachedOrigin;
              const pct = conclusive > 0 ? Math.round((c.blocked / conclusive) * 100) : 0;
              return (
                <div key={c.categoryId} className="flex items-center gap-3 text-sm">
                  <div className="w-56 flex-shrink-0">
                    <div className="text-slate-200">{c.categoryName}</div>
                    <div className="text-[10px] text-slate-500">{c.owasp}</div>
                  </div>
                  <div className="flex-1 h-5 rounded bg-slate-700 overflow-hidden flex">
                    {c.blocked > 0 && <div className="h-full bg-emerald-500/70" style={{ width: `${(c.blocked / c.total) * 100}%` }} title={`${c.blocked} blocked`} />}
                    {c.reachedOrigin > 0 && <div className="h-full bg-red-500/70" style={{ width: `${(c.reachedOrigin / c.total) * 100}%` }} title={`${c.reachedOrigin} reached origin`} />}
                    {c.inconclusive > 0 && <div className="h-full bg-slate-500/50" style={{ width: `${(c.inconclusive / c.total) * 100}%` }} title={`${c.inconclusive} inconclusive`} />}
                  </div>
                  <div className="w-32 text-right text-xs text-slate-400">
                    <span className="text-emerald-400">{c.blocked}</span> / <span className="text-red-400">{c.reachedOrigin}</span> / <span className="text-slate-500">{c.inconclusive}</span>
                    <span className="ml-2 text-slate-300">{pct}%</span>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search payloads, paths, OWASP…" className={`${inputCls} pl-9`} />
          </div>
          <select value={filterVerdict} onChange={(e) => setFilterVerdict(e.target.value as any)} className={`${inputCls} w-44`}>
            <option value="ALL">All verdicts</option>
            <option value="BLOCKED">Blocked</option>
            <option value="REACHED_ORIGIN">Reached origin</option>
            <option value="INCONCLUSIVE">Inconclusive</option>
          </select>
          <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value as any)} className={`${inputCls} w-36`}>
            <option value="ALL">All severities</option>
            {SEVERITY_ORDER.map((sv) => <option key={sv} value={sv}>{SEVERITY_META[sv].label}</option>)}
          </select>
        </div>

        {/* Results list */}
        <div className="space-y-2">
          {filteredResults.map((r) => {
            const vm = VERDICT_META[r.verdict];
            const sm = SEVERITY_META[r.severity];
            const isOpen = expanded.has(r.marker);
            return (
              <div key={r.marker} className="rounded-lg border border-slate-700 bg-slate-800/40 overflow-hidden">
                <button
                  onClick={() => setExpanded((prev) => { const n = new Set(prev); n.has(r.marker) ? n.delete(r.marker) : n.add(r.marker); return n; })}
                  className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-slate-700/30"
                >
                  {isOpen ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${vm.bg} ${vm.color}`}>{vm.icon} {vm.label}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${sm.bg} ${sm.color}`}>{sm.label}</span>
                  <span className="text-sm text-slate-200">{r.payloadName}</span>
                  <span className="text-xs text-slate-500">{r.categoryName} · {r.owasp}</span>
                  <span className="ml-auto text-xs font-mono text-slate-500">{r.method} {r.statusCode || '—'}</span>
                </button>
                {isOpen && (
                  <div className="px-4 pb-4 pt-1 text-xs space-y-2 border-t border-slate-700/60">
                    <KV k="Request">{r.method} <span className="font-mono text-slate-300 break-all">{r.requestUrl}</span></KV>
                    {r.requestBody && <KV k="Body"><span className="font-mono text-slate-300 break-all">{r.requestBody}</span></KV>}
                    <KV k="Expected signature">{r.expectedSignature}</KV>
                    <KV k="Live response">{r.statusCode} {r.statusText} · {r.responseTimeMs}ms · {r.liveVerdict}{r.blockSupportId ? ` · support-id ${r.blockSupportId}` : ''}</KV>
                    {r.responseSnippet && <KV k="Response snippet"><span className="font-mono text-slate-400 break-all">{r.responseSnippet}</span></KV>}
                    {r.matchedSecurityEvent && (
                      <KV k="XC security event">
                        action=<b className="text-slate-200">{r.matchedSecurityEvent.action}</b>
                        {r.matchedSecurityEvent.secEventName ? ` · ${r.matchedSecurityEvent.secEventName}` : ''}
                        {r.matchedSecurityEvent.wafMode ? ` · mode=${r.matchedSecurityEvent.wafMode}` : ''}
                        {r.matchedSecurityEvent.reqId ? ` · req_id=${r.matchedSecurityEvent.reqId}` : ''}
                      </KV>
                    )}
                    {r.matchedAccessLog && (
                      <KV k="XC access log">rsp_code={r.matchedAccessLog.rspCode}{r.matchedAccessLog.reqId ? ` · req_id=${r.matchedAccessLog.reqId}` : ''}</KV>
                    )}
                    {r.error && <KV k="Error"><span className="text-red-300">{r.error}</span></KV>}
                  </div>
                )}
              </div>
            );
          })}
          {filteredResults.length === 0 && <p className="text-center text-slate-500 py-8 text-sm">No results match the filters.</p>}
        </div>
      </div>
    );
  }
}

// ── helpers / small components ──
const inputCls = 'w-full bg-slate-900/60 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-rose-500';

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-400 mb-1.5">{label}</label>
      {children}
    </div>
  );
}

function NumField({ label, value, onChange }: { label: string; value: number; onChange: (n: number) => void }) {
  return (
    <Field label={label}>
      <input type="number" value={value} min={0} onChange={(e) => onChange(Math.max(0, parseInt(e.target.value || '0', 10)))} className={inputCls} />
    </Field>
  );
}

function ModeOption({ active, onClick, title, desc }: { active: boolean; onClick: () => void; title: string; desc: string }) {
  return (
    <button onClick={onClick} className={`text-left p-3 rounded-lg border ${active ? 'border-emerald-500 bg-emerald-500/10' : 'border-slate-600 hover:border-slate-500'}`}>
      <div className="text-sm font-medium text-slate-200">{title}</div>
      <div className="text-xs text-slate-500 mt-0.5">{desc}</div>
    </button>
  );
}

function StatCard({ label, value, sub, tone = 'default' }: { label: string; value: React.ReactNode; sub?: string; tone?: 'good' | 'bad' | 'warn' | 'muted' | 'default' }) {
  const toneCls = {
    good: 'text-emerald-400',
    bad: 'text-red-400',
    warn: 'text-amber-400',
    muted: 'text-slate-400',
    default: 'text-slate-100',
  }[tone];
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-800/40 p-4">
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`text-2xl font-bold ${toneCls}`}>{value}</div>
      {sub && <div className="text-[10px] text-slate-500 mt-0.5">{sub}</div>}
    </div>
  );
}

function KV({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-2">
      <span className="text-slate-500 w-36 flex-shrink-0">{k}</span>
      <span className="text-slate-300 min-w-0">{children}</span>
    </div>
  );
}

function phaseLabel(phase?: SimProgress['phase']): string {
  switch (phase) {
    case 'detecting-ip': return 'Detecting source IP';
    case 'attacking': return 'Firing attacks';
    case 'waiting': return 'Waiting for log ingestion';
    case 'pulling-logs': return 'Pulling XC logs';
    case 'reconciling': return 'Reconciling';
    case 'complete': return 'Complete';
    default: return 'Working';
  }
}

// Parse the textarea into a clean path list.
function parsePaths(text: string): string[] {
  return text
    .split('\n')
    .map((p) => p.trim())
    .filter(Boolean);
}

// Extract candidate paths from an LB spec's routes.
function extractPaths(spec: Record<string, any>): string[] {
  const out = new Set<string>(['/']);
  const routes = Array.isArray(spec.routes) ? spec.routes : [];
  for (const r of routes) {
    const sr = r?.simple_route;
    const p = sr?.path;
    if (!p) continue;
    const val = p.prefix || p.path || p.regex;
    if (typeof val === 'string' && val) out.add(val);
  }
  return [...out].slice(0, 10);
}
