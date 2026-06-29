import { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  Gauge, Play, ChevronDown, ChevronRight, Shield,
  BarChart3, Settings, Copy, Check, Download, AlertTriangle,
  FileJson, Users, Target, Zap, SlidersHorizontal, HelpCircle,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { apiClient } from '../services/api';
import type { LoadBalancer, Namespace } from '../types';
import { collectUnified } from '../services/rate-limit-advisor/unified-collector';
import { analyzeUnified, simulateUnifiedImpact } from '../services/rate-limit-advisor/unified-analyzer';
import type { UnifiedProgress, UnifiedCollection } from '../services/rate-limit-advisor/unified-collector';
import type { UnifiedResult, UnifiedImpactResult, AlgorithmOption } from '../services/rate-limit-advisor/unified-analyzer';

// ═══════════════════════════════════════════════════════════════════
function SearchableSelect({ value, onChange, options, placeholder, disabled }: {
  value: string; onChange: (v: string) => void;
  options: Array<{ value: string; label: string }>; placeholder: string; disabled?: boolean;
}) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const filtered = options.filter(o => o.label.toLowerCase().includes(query.toLowerCase()));
  const selected = options.find(o => o.value === value);
  return (
    <div className="relative">
      <button onClick={() => !disabled && setOpen(p => !p)} disabled={disabled}
        className="w-full flex items-center justify-between px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-100 disabled:opacity-50 hover:border-slate-600">
        <span className={selected ? '' : 'text-slate-400'}>{selected?.label ?? placeholder}</span>
        <ChevronDown className="w-4 h-4 text-slate-400" />
      </button>
      {open && (
        <div className="absolute z-50 w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg shadow-xl max-h-64 overflow-hidden flex flex-col">
          <div className="p-2 border-b border-slate-700"><input autoFocus value={query} onChange={e => setQuery(e.target.value)} placeholder="Search..." className="w-full px-2 py-1 bg-slate-900 border border-slate-700 rounded text-sm text-slate-100 placeholder-slate-500 focus:outline-none" /></div>
          <div className="overflow-y-auto">{filtered.map(o => (
            <button key={o.value} onClick={() => { onChange(o.value); setOpen(false); setQuery(''); }} className={`w-full text-left px-3 py-2 text-sm hover:bg-slate-700 ${o.value === value ? 'text-blue-400 bg-blue-500/10' : 'text-slate-200'}`}>{o.label}</button>
          ))}{filtered.length === 0 && <div className="px-3 py-2 text-sm text-slate-400">No results</div>}</div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
export function RateLimitAdvisor() {
  const { isConnected } = useApp();
  const navigate = useNavigate();
  const toast = useToast();

  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [selectedNamespace, setSelectedNamespace] = useState('');
  const [loadBalancers, setLoadBalancers] = useState<LoadBalancer[]>([]);
  const [selectedLB, setSelectedLB] = useState('');
  const [windowHours, setWindowHours] = useState(4);

  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState<UnifiedProgress | null>(null);
  const [result, setResult] = useState<UnifiedResult | null>(null);
  const [collection, setCollection] = useState<UnifiedCollection | null>(null);

  const [sliderValue, setSliderValue] = useState(100);
  const [burstMultiplier, setBurstMultiplier] = useState(2);
  const [selectedAlgoId, setSelectedAlgoId] = useState('balanced');
  const [showBurstExplainer, setShowBurstExplainer] = useState(false);
  const [copiedField, setCopiedField] = useState('');
  const [sections, setSections] = useState<Record<string, boolean>>({
    overview: true, stats: true, recommendation: true, simulator: true, config: false,
  });

  useEffect(() => { if (!isConnected) navigate('/'); }, [isConnected, navigate]);
  useEffect(() => { if (isConnected) apiClient.getNamespaces().then(r => setNamespaces((r.items || []).sort((a, b) => (a.name || '').localeCompare(b.name || '')))).catch(() => toast.error('Failed to load namespaces')); }, [isConnected]);
  useEffect(() => { if (selectedNamespace) { setSelectedLB(''); setResult(null); apiClient.getLoadBalancers(selectedNamespace).then(r => setLoadBalancers(r.items || [])).catch(() => toast.error('Failed to load LBs')); } }, [selectedNamespace]);

  const toggle = (k: string) => setSections(p => ({ ...p, [k]: !p[k] }));
  const selectAlgo = useCallback((a: AlgorithmOption) => { setSelectedAlgoId(a.id); setSliderValue(a.n); setBurstMultiplier(a.b); }, []);
  const copy = useCallback(async (text: string, label: string) => { await navigator.clipboard.writeText(text); setCopiedField(label); setTimeout(() => setCopiedField(''), 2000); }, []);

  const impact = useMemo<UnifiedImpactResult | null>(() => {
    if (!collection) return null;
    return simulateUnifiedImpact(collection.userMinuteCounts, sliderValue, burstMultiplier);
  }, [collection, sliderValue, burstMultiplier]);

  const runAnalysis = async () => {
    if (!selectedNamespace || !selectedLB) { toast.error('Select namespace and load balancer'); return; }
    setIsRunning(true); setResult(null); setCollection(null);
    try {
      const col = await collectUnified(selectedNamespace, selectedLB, windowHours, setProgress);
      setCollection(col);
      const res = analyzeUnified(col);
      setResult(res);
      setSliderValue(res.recommendation.numberOfRequests);
      setBurstMultiplier(res.recommendation.burstMultiplier);
      setSelectedAlgoId('balanced');
      toast.success(`Analysis complete — ${res.apiCallsUsed} API calls in ${res.runtimeSeconds}s`);
    } catch (err) {
      toast.error(`Analysis failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally { setIsRunning(false); }
  };

  return (
    <main className="max-w-7xl mx-auto px-6 py-8">
      <div className="mb-8 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-blue-500/15 rounded-xl flex items-center justify-center"><Gauge className="w-5 h-5 text-blue-400" /></div>
          <div><h1 className="text-2xl font-bold text-slate-100">Rate Limit Advisor</h1>
            <p className="text-sm text-slate-400">7-day baseline + deep per-user scan → industry-standard recommendation</p></div>
        </div>
        <Link to="/rate-limit-explainer"
          className="flex items-center gap-1.5 px-4 py-2 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-300 hover:text-blue-400 rounded-lg text-sm transition-colors">
          <HelpCircle className="w-4 h-4" /> How does this work?
        </Link>
      </div>

      {/* Configuration */}
      <Section title="Configuration" icon={Settings} open>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div><label className="block text-xs font-medium text-slate-400 mb-1">Namespace</label>
            <SearchableSelect value={selectedNamespace} onChange={setSelectedNamespace} options={namespaces.map(n => ({ value: n.name || '', label: n.name || '' }))} placeholder="Select namespace" disabled={isRunning} /></div>
          <div><label className="block text-xs font-medium text-slate-400 mb-1">Load Balancer</label>
            <SearchableSelect value={selectedLB} onChange={setSelectedLB} options={loadBalancers.map(lb => ({ value: lb.name || '', label: lb.name || '' }))} placeholder="Select LB" disabled={isRunning || !selectedNamespace} /></div>
          <div><label className="block text-xs font-medium text-slate-400 mb-1">Deep Scan Window</label>
            <select value={windowHours} onChange={e => setWindowHours(Number(e.target.value))} disabled={isRunning}
              className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-100 disabled:opacity-50">
              <option value={1}>Last 1 hour</option><option value={4}>Last 4 hours</option>
              <option value={12}>Last 12 hours</option><option value={24}>Last 24 hours</option>
              <option value={48}>Last 48 hours</option><option value={168}>Last 7 days</option>
            </select>
            <p className="text-[10px] text-slate-500 mt-1">7-day baseline always runs for weekly context. Longer deep scans capture more peaks but take longer (more API calls).</p></div>
        </div>
        <div className="flex items-center gap-4">
          <button onClick={runAnalysis} disabled={isRunning || !selectedLB}
            className="flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg text-sm font-medium">
            {isRunning ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />Analyzing...</> : <><Play className="w-4 h-4" />Analyze</>}
          </button>
          {isRunning && progress && (
            <div className="flex-1">
              <div className="flex justify-between text-xs text-slate-400 mb-1">
                <span className="capitalize">{progress.phase === 'baseline' ? 'Phase 1: Weekly Baseline' : progress.phase === 'deep' ? 'Phase 2: Deep Scan' : progress.phase === 'processing' ? 'Processing' : 'Complete'} — {progress.message}</span>
                <span>{progress.apiCalls} calls</span>
              </div>
              <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden"><div className={`h-full rounded-full transition-all ${progress.phase === 'baseline' ? 'bg-blue-500' : 'bg-emerald-500'}`} style={{ width: `${progress.progress}%` }} /></div>
            </div>
          )}
        </div>
      </Section>

      {result && (
        <>
          {/* Traffic Overview */}
          <Section title="Traffic Overview" icon={BarChart3} collapsible open={sections.overview} onToggle={() => toggle('overview')}
            badge={`${result.totalRequests7d.toLocaleString()} / 7d`}>
            <TrafficOverview result={result} />
          </Section>

          {/* Recommendation */}
          <Section title="Recommendation" icon={Target} collapsible open={sections.recommendation} onToggle={() => toggle('recommendation')}>
            <RecommendationDisplay result={result} selectedAlgoId={selectedAlgoId} onSelect={selectAlgo} />
          </Section>

          {/* Per-User Statistics */}
          <Section title="Per-User Statistics" icon={Users} collapsible open={sections.stats} onToggle={() => toggle('stats')}
            badge={`${result.recommendation.stats.usersAnalyzed} users`}>
            <UserStats result={result} />
          </Section>

          {/* Impact Simulator */}
          <Section title="Impact Simulator" icon={SlidersHorizontal} collapsible open={sections.simulator} onToggle={() => toggle('simulator')}>
            <ImpactSim impact={impact} rec={result.recommendation}
              sliderValue={sliderValue} onSlider={setSliderValue}
              burst={burstMultiplier} onBurst={setBurstMultiplier}
              showExplainer={showBurstExplainer} onToggleExplainer={() => setShowBurstExplainer(p => !p)} />
          </Section>

          {/* Config */}
          <Section title="Configuration Output" icon={FileJson} collapsible open={sections.config} onToggle={() => toggle('config')}>
            <ConfigOut result={result} n={sliderValue} b={burstMultiplier} onCopy={copy} copiedField={copiedField} />
          </Section>
        </>
      )}
    </main>
  );
}

// ═══════════════════════════════════════════════════════════════════
function Section({ title, icon: Icon, children, collapsible, open, onToggle, badge }: {
  title: string; icon: React.ElementType; children: React.ReactNode;
  collapsible?: boolean; open?: boolean; onToggle?: () => void; badge?: string;
}) {
  const isOpen = open ?? true;
  return (
    <div className="mb-6">
      <button onClick={collapsible ? onToggle : undefined}
        className="w-full flex items-center justify-between p-4 bg-slate-800/70 border border-slate-700 rounded-xl hover:border-slate-600">
        <div className="flex items-center gap-3"><Icon className="w-5 h-5 text-blue-400" /><span className="font-semibold text-slate-100">{title}</span>
          {badge && <span className="px-2 py-0.5 bg-slate-700 text-slate-300 text-xs rounded-full">{badge}</span>}</div>
        {collapsible && (isOpen ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />)}
      </button>
      {isOpen && <div className="border border-t-0 border-slate-700 rounded-b-xl p-6 bg-slate-800/30">{children}</div>}
    </div>
  );
}

function Stat({ label, value, sub, color }: { label: string; value: string; sub?: string; color?: string }) {
  return (<div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
    <div className="text-xs text-slate-400 mb-1">{label}</div>
    <div className={`text-xl font-bold ${color || 'text-slate-100'}`}>{value}</div>
    {sub && <div className="text-[10px] text-slate-500 mt-0.5">{sub}</div>}
  </div>);
}

// ═══════════════════════════════════════════════════════════════════
function TrafficOverview({ result }: { result: UnifiedResult }) {
  const fb7d = result.filterBreakdown7d;
  const fbDeep = result.filterBreakdownDeep;
  const fetchPct = result.deepTotalExpected > 0 ? Math.round((result.deepTotalFetched / result.deepTotalExpected) * 100) : 100;

  const filterRows = [
    { label: 'WAF Blocked', v7d: fb7d.waf_block, vDeep: fbDeep.waf_block, icon: Shield },
    { label: 'Bot Malicious', v7d: fb7d.bot_malicious, vDeep: fbDeep.bot_malicious, icon: Zap },
    { label: 'Good Bots (crawlers)', v7d: fb7d.good_bot ?? 0, vDeep: fbDeep.good_bot ?? 0, icon: Zap },
    { label: 'Policy Deny', v7d: fb7d.policy_deny ?? 0, vDeep: fbDeep.policy_deny, icon: AlertTriangle },
    { label: 'MUM Action', v7d: fb7d.mum_action ?? 0, vDeep: fbDeep.mum_action, icon: Users },
    { label: 'IP High Risk', v7d: fb7d.ip_high_risk, vDeep: fbDeep.ip_high_risk, icon: AlertTriangle },
    { label: 'Already Rate-Limited (429)', v7d: fb7d.rate_limited ?? 0, vDeep: fbDeep.rate_limited ?? 0, icon: Gauge },
  ].filter(r => r.v7d > 0 || r.vDeep > 0);

  return (
    <div>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
        <Stat label="7-Day Total" value={result.totalRequests7d.toLocaleString()} sub="Weekly baseline" />
        <Stat label="7-Day Filtered" value={fb7d.total.toLocaleString()} sub={result.totalRequests7d > 0 ? `${((fb7d.total / result.totalRequests7d) * 100).toFixed(1)}%` : ''} color="text-red-400" />
        <Stat label={`Deep Scan (${result.deepWindowHours}h)`} value={result.deepTotalFetched.toLocaleString()} sub={`${fetchPct}% of ${result.deepTotalExpected.toLocaleString()} expected`} />
        <Stat label="Deep Clean" value={result.deepCleanLogs.toLocaleString()} color="text-emerald-400" sub={`${result.recommendation.stats.usersAnalyzed} users`} />
        <Stat label="Runtime" value={`${result.runtimeSeconds}s`} sub={`${result.apiCallsUsed} API calls`} />
      </div>

      {filterRows.length > 0 && (
        <div className="bg-slate-800/50 rounded-lg overflow-hidden mb-4">
          <table className="w-full text-sm"><thead><tr className="border-b border-slate-700">
            <th className="text-left px-4 py-2 text-slate-400 font-medium">Filter</th>
            <th className="text-right px-4 py-2 text-slate-400 font-medium">7-Day (agg)</th>
            <th className="text-right px-4 py-2 text-slate-400 font-medium">Deep (exact)</th>
          </tr></thead><tbody>{filterRows.map(r => (
            <tr key={r.label} className="border-b border-slate-700/50">
              <td className="px-4 py-2 text-slate-300 flex items-center gap-2"><r.icon className="w-3.5 h-3.5 text-slate-500" />{r.label}</td>
              <td className="text-right px-4 py-2 text-slate-400 font-mono">{r.v7d.toLocaleString()}</td>
              <td className="text-right px-4 py-2 text-slate-100 font-mono">{r.vDeep.toLocaleString()}</td>
            </tr>
          ))}</tbody></table>
        </div>
      )}

      {/* Daily shape */}
      {result.dailyShape.length > 0 && (
        <div className="mb-4">
          <h4 className="text-sm font-semibold text-slate-200 mb-2">7-Day Traffic Shape</h4>
          <div className="flex items-end gap-1 h-20">{result.dailyShape.map((d, i) => {
            const max = Math.max(...result.dailyShape.map(x => x.count), 1);
            const h = Math.max(4, (d.count / max) * 100);
            const dayLabel = new Date(d.dayStart).toLocaleDateString('en', { weekday: 'short' });
            return (<div key={i} className="flex-1 flex flex-col items-center gap-1">
              <div className="w-full bg-blue-500/30 rounded-t" style={{ height: `${h}%` }} title={`${dayLabel}: ${d.count.toLocaleString()}`} />
              <span className="text-[9px] text-slate-500">{dayLabel}</span>
            </div>);
          })}</div>
        </div>
      )}

      {result.warnings.length > 0 && (
        <div className="space-y-2">{result.warnings.map((w, i) => (
          <div key={i} className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-sm text-amber-300 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />{w}
          </div>
        ))}</div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
function RecommendationDisplay({ result, selectedAlgoId, onSelect }: {
  result: UnifiedResult; selectedAlgoId: string; onSelect: (a: AlgorithmOption) => void;
}) {
  const rec = result.recommendation;
  const algos = result.algorithms ?? [];
  const selected = algos.find(a => a.id === selectedAlgoId) ?? algos[0] ?? {
    id: 'balanced', label: 'Balanced', formula: '', n: rec.numberOfRequests, b: rec.burstMultiplier,
    effectiveLimit: rec.effectiveLimit, description: '',
  } as AlgorithmOption;
  const confColors: Record<string, string> = { high: 'text-emerald-400 bg-emerald-500/20', medium: 'text-amber-400 bg-amber-500/20', low: 'text-red-400 bg-red-500/20' };
  return (
    <div>
      {/* Algorithm selector */}
      {algos.length > 0 && (
        <div className="mb-4">
          <div className="text-xs text-slate-400 mb-2">Choose an algorithm — the limit, simulator and config below update to match:</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {algos.map(a => {
              const active = a.id === selected.id;
              return (
                <button key={a.id} onClick={() => onSelect(a)}
                  className={`text-left p-3 rounded-lg border transition-colors ${active ? 'bg-blue-500/15 border-blue-500/60' : 'bg-slate-800/50 border-slate-700 hover:border-slate-600'}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-xs font-semibold ${active ? 'text-blue-300' : 'text-slate-200'}`}>{a.label}</span>
                    {a.recommended && <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold uppercase">Rec</span>}
                  </div>
                  <div className="text-lg font-bold text-slate-100">{a.n}<span className="text-xs text-slate-400 font-normal"> × {a.b} = {a.effectiveLimit}/min</span></div>
                  <div className="text-[10px] text-slate-500 mt-0.5 font-mono">{a.formula}</div>
                </button>
              );
            })}
          </div>
        </div>
      )}

      <div className="bg-gradient-to-b from-blue-500/10 to-slate-800/50 border border-blue-500/40 rounded-xl p-6 mb-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-slate-100">{selected.label}</h3>
          <span className={`px-2 py-0.5 text-xs font-bold rounded uppercase ${confColors[rec.confidence] || confColors.low}`}>{rec.confidence} confidence</span>
        </div>
        <div className="grid grid-cols-3 gap-6 mb-4">
          <div><div className="text-xs text-slate-400 mb-1">Number (N)</div><div className="text-4xl font-bold text-slate-100">{selected.n}</div><div className="text-sm text-slate-400">req/min</div></div>
          <div><div className="text-xs text-slate-400 mb-1">Burst (B)</div><div className="text-4xl font-bold text-slate-100">{selected.b}×</div></div>
          <div><div className="text-xs text-slate-400 mb-1">Effective Limit</div><div className="text-4xl font-bold text-emerald-400">{selected.effectiveLimit}</div><div className="text-sm text-slate-400">req/min peak</div></div>
        </div>
        {selected.description && <p className="text-sm text-slate-300 leading-relaxed mb-3">{selected.description}</p>}
        {selected.id === 'balanced' ? (
          <div className="text-sm text-slate-300 leading-relaxed space-y-3 border-t border-slate-700/50 pt-3">
            {rec.rationale.split('\n\n').map((p, i) => <p key={i}>{p}</p>)}
          </div>
        ) : (
          <p className="text-xs text-slate-500 border-t border-slate-700/50 pt-3">Switch to <span className="text-blue-400">Balanced</span> for the full per-user statistical breakdown. Use the Impact Simulator below to see exactly who this limit would affect.</p>
        )}
      </div>
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 text-xs">
        <h4 className="text-slate-200 font-semibold mb-2">How to apply in F5 XC Console</h4>
        <ol className="list-decimal list-inside text-slate-400 space-y-1">
          <li>HTTP Load Balancer → <code className="text-slate-300">{result.lbName}</code> → Rate Limiting → Custom Rate Limiting Parameters</li>
          <li>Number = <code className="text-blue-300">{selected.n}</code>, Per Period = <code className="text-blue-300">Minutes</code>, Periods = <code className="text-blue-300">1</code>, Burst = <code className="text-blue-300">{selected.b}</code></li>
          <li>Mitigation Action = <code className="text-amber-300">None</code> (alert-only for first week)</li>
        </ol>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
function UserStats({ result }: { result: UnifiedResult }) {
  const s = result.recommendation.stats;
  const rows = [
    { label: 'P50 (median)', value: s.p50Peaks },
    { label: 'P75', value: s.p75Peaks },
    { label: 'P90', value: s.p90Peaks },
    { label: 'P95 (baseline)', value: s.p95Peaks, highlight: true },
    { label: 'P99', value: s.p99Peaks },
    { label: 'P99.9 (absolute)', value: s.p999Peaks },
    { label: 'P95 Medians (typical)', value: s.p95Medians },
  ];
  return (
    <div>
      <p className="text-[11px] text-slate-500 mb-2">Peak = max requests in any rolling 60-second window per user (token-bucket view; bursts that cross a clock-minute boundary are not undercounted). Counts are de-sampled.</p>
      <div className="bg-slate-800/50 rounded-lg overflow-hidden mb-4">
        <table className="w-full text-sm"><thead><tr className="border-b border-slate-700">
          <th className="text-left px-4 py-2 text-slate-400 font-medium">Percentile</th>
          <th className="text-right px-4 py-2 text-slate-400 font-medium">Per-User Peak (rolling 60s)</th>
        </tr></thead><tbody>{rows.map(r => (
          <tr key={r.label} className={`border-b border-slate-700/50 ${r.highlight ? 'bg-blue-500/5' : ''}`}>
            <td className={`px-4 py-2 font-medium ${r.highlight ? 'text-blue-400' : 'text-slate-200'}`}>{r.label}</td>
            <td className={`text-right px-4 py-2 font-mono text-lg font-bold ${r.highlight ? 'text-blue-300' : 'text-slate-100'}`}>{Math.round(r.value)}</td>
          </tr>
        ))}</tbody></table>
      </div>
      <p className="text-xs text-slate-500 mb-4">{s.usersAnalyzed} users. {s.outliersTrimmed > 0 ? `${s.outliersTrimmed} outlier(s) trimmed (3×IQR).` : 'No outliers trimmed.'} Safety factor: {s.safetyFactor}×.</p>

      {result.userPeaks.length > 0 && (<div>
        <h4 className="text-sm font-semibold text-slate-200 mb-2">Top Users by Peak RPM</h4>
        <div className="bg-slate-800/50 rounded-lg overflow-x-auto">
          <table className="w-full text-sm"><thead><tr className="border-b border-slate-700">
            <th className="text-left px-4 py-2 text-slate-400 font-medium">User</th>
            <th className="text-right px-4 py-2 text-slate-400 font-medium">Peak</th>
            <th className="text-right px-4 py-2 text-slate-400 font-medium">Median</th>
            <th className="text-right px-4 py-2 text-slate-400 font-medium">Active Min</th>
            <th className="text-right px-4 py-2 text-slate-400 font-medium">Total Reqs</th>
          </tr></thead><tbody>{result.userPeaks.slice(0, 20).map((u, i) => (
            <tr key={u.userId} className="border-b border-slate-700/50">
              <td className="px-4 py-2 font-mono text-slate-200 text-xs">{i === 0 && <span className="mr-1 text-amber-400">★</span>}{u.userId}</td>
              <td className="text-right px-4 py-2 font-mono font-semibold text-slate-100">{u.peakRpm}</td>
              <td className="text-right px-4 py-2 font-mono text-slate-400">{u.medianRpm.toFixed(1)}</td>
              <td className="text-right px-4 py-2 text-slate-400">{u.activeMinutes}</td>
              <td className="text-right px-4 py-2 text-slate-400">{u.totalRequests.toLocaleString()}</td>
            </tr>
          ))}</tbody></table>
        </div>
      </div>)}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
function ImpactSim({ impact, rec, sliderValue, onSlider, burst, onBurst, showExplainer, onToggleExplainer }: {
  impact: UnifiedImpactResult | null; rec: { numberOfRequests: number; burstMultiplier: number };
  sliderValue: number; onSlider: (v: number) => void; burst: number; onBurst: (v: number) => void;
  showExplainer: boolean; onToggleExplainer: () => void;
}) {
  const sliderMax = Math.max(rec.numberOfRequests * 3, sliderValue, 500);
  const isClean = impact ? impact.usersAffected === 0 : true;
  return (
    <div>
      <div className="bg-slate-800/80 border border-blue-500/30 rounded-xl p-6 mb-6">
        <div className="mb-4">
          <div className="flex items-center justify-between mb-2">
            <label className="text-sm text-slate-300">Rate Limit: <span className="text-white font-bold text-lg">{sliderValue}</span> <span className="text-slate-400">req/min</span></label>
            <input type="number" value={sliderValue} min={1} max={8192} onChange={e => onSlider(Math.max(1, Math.min(8192, Number(e.target.value))))} className="w-24 bg-slate-700 border border-slate-600 rounded px-2 py-1 text-sm text-slate-100 text-right" />
          </div>
          <input type="range" value={sliderValue} min={1} max={sliderMax} step={1} onChange={e => onSlider(Number(e.target.value))} className="w-full h-2 bg-slate-700 rounded-full appearance-none cursor-pointer accent-blue-500" />
          <div className="flex justify-between text-xs text-slate-500 mt-1"><span>1</span><span className="text-emerald-400">Recommended: {rec.numberOfRequests}</span><span>{sliderMax}</span></div>
        </div>
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-sm text-slate-300 flex items-center gap-1.5">Burst: <span className="text-white font-bold">{burst}×</span>
              <span className="text-slate-400 text-xs ml-1">(effective: {sliderValue * burst})</span>
              <button onClick={onToggleExplainer} className="ml-1 text-blue-400 hover:text-blue-300"><HelpCircle className="w-3.5 h-3.5" /></button></label>
          </div>
          <input type="range" value={burst} min={1} max={5} step={1} onChange={e => onBurst(Number(e.target.value))} className="w-full h-2 bg-slate-700 rounded-full appearance-none cursor-pointer accent-amber-500" />
          {showExplainer && (
            <div className="mt-3 bg-slate-900/80 border border-slate-700 rounded-lg p-4 text-xs text-slate-400">
              <p className="mb-2"><span className="text-slate-200 font-medium">Rate limit</span> = sustained ceiling (token refill rate). <span className="text-slate-200 font-medium">Burst</span> = bucket capacity (temporary headroom).</p>
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-3"><div className="text-emerald-400 font-semibold">40/min × 2 burst</div><div className="text-[11px]">Attacker at 60/min → blocked after ~4 min</div></div>
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3"><div className="text-red-400 font-semibold">80/min × 1 burst</div><div className="text-[11px]">Attacker at 60/min → never blocked</div></div>
              </div>
            </div>
          )}
        </div>
      </div>

      {impact && (
        <div className={`rounded-xl border p-6 ${isClean ? 'bg-emerald-500/5 border-emerald-500/30' : impact.usersAffectedPct > 10 ? 'bg-red-500/5 border-red-500/30' : 'bg-amber-500/5 border-amber-500/30'}`}>
          <h4 className="text-sm font-semibold mb-4 flex items-center gap-2">
            {isClean ? <><Check className="w-4 h-4 text-emerald-400" /><span className="text-emerald-400">No users would be affected</span></>
              : <><AlertTriangle className="w-4 h-4 text-amber-400" /><span className="text-amber-400">{impact.usersAffected} user(s) affected ({impact.usersAffectedPct}%)</span></>}
          </h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <div><div className="text-xs text-slate-400">Users Affected</div><div className="text-2xl font-bold text-slate-100">{impact.usersAffected}<span className="text-sm font-normal text-slate-400">/{impact.totalUsers}</span></div></div>
            <div><div className="text-xs text-slate-400">Requests Blocked</div><div className="text-2xl font-bold text-slate-100">{impact.requestsBlocked.toLocaleString()}</div><div className="text-xs text-slate-500">{impact.requestsBlockedPct}%</div></div>
            <div><div className="text-xs text-slate-400">Total Analysed</div><div className="text-2xl font-bold text-slate-100">{impact.totalRequests.toLocaleString()}</div></div>
            <div><div className="text-xs text-slate-400">Effective Limit</div><div className="text-2xl font-bold text-slate-100">{impact.effectiveLimit} <span className="text-sm font-normal text-slate-400">req/min</span></div></div>
          </div>
          {impact.affectedUsers.length > 0 && (
            <div className="bg-slate-900/50 rounded-lg overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b border-slate-700">
              <th className="text-left px-3 py-1.5 text-slate-400 font-medium text-xs">User</th>
              <th className="text-right px-3 py-1.5 text-slate-400 font-medium text-xs">Peak</th>
              <th className="text-right px-3 py-1.5 text-slate-400 font-medium text-xs">Median</th>
              <th className="text-right px-3 py-1.5 text-slate-400 font-medium text-xs">Min Blocked</th>
              <th className="text-right px-3 py-1.5 text-slate-400 font-medium text-xs">Reqs Blocked</th>
            </tr></thead><tbody>{impact.affectedUsers.map(u => (
              <tr key={u.userId} className="border-b border-slate-700/50">
                <td className="px-3 py-1.5 font-mono text-slate-200 text-xs">{u.userId}</td>
                <td className="text-right px-3 py-1.5 font-mono text-amber-400">{u.peakRpm}</td>
                <td className="text-right px-3 py-1.5 font-mono text-slate-400">{u.medianRpm.toFixed(1)}</td>
                <td className="text-right px-3 py-1.5 text-slate-300">{u.minutesBlocked}</td>
                <td className="text-right px-3 py-1.5 text-red-400">{u.requestsBlocked.toLocaleString()}</td>
              </tr>
            ))}</tbody></table></div>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
function ConfigOut({ result, n, b, onCopy, copiedField }: {
  result: UnifiedResult; n: number; b: number;
  onCopy: (t: string, l: string) => Promise<void>; copiedField: string;
}) {
  const [isPdfGenerating, setIsPdfGenerating] = useState(false);
  const json = JSON.stringify({ rate_limit: { rate_limiter: { unit: 'MINUTE', total_number: n, burst_multiplier: b, period_multiplier: 1 }, no_ip_allowed_list: {} } }, null, 2);
  const report = JSON.stringify({
    advisor_version: 'unified-v1', lb_name: result.lbName, namespace: result.namespace,
    baseline_window: `${result.baselineStart} → ${result.baselineEnd}`,
    deep_window: `${result.deepStart} → ${result.deepEnd} (${result.deepWindowHours}h)`,
    total_requests_7d: result.totalRequests7d, deep_fetched: result.deepTotalFetched, deep_clean: result.deepCleanLogs,
    recommendation: result.recommendation, warnings: result.warnings,
    selected: { rate_limit: n, burst_multiplier: b, effective: n * b },
  }, null, 2);

  const downloadPdf = async () => {
    setIsPdfGenerating(true);
    try {
      const { jsPDF } = await import('jspdf');
      const doc = new jsPDF();
      const rec = result.recommendation;
      const s = rec.stats;
      const lm = 14; // left margin
      let y = 20;

      const addLine = (text: string, size = 11, bold = false) => {
        if (y > 270) { doc.addPage(); y = 20; }
        doc.setFontSize(size);
        doc.setFont('helvetica', bold ? 'bold' : 'normal');
        const lines = doc.splitTextToSize(text, 180);
        doc.text(lines, lm, y);
        y += lines.length * (size * 0.45) + 2;
      };

      const addGap = (px = 4) => { y += px; };

      // Title
      addLine(`F5 XC Rate Limit Advisor Report`, 18, true);
      addGap(2);
      addLine(`Load Balancer: ${result.lbName}`, 12);
      addLine(`Namespace: ${result.namespace}`, 10);
      addLine(`Generated: ${new Date().toLocaleString()}`, 10);
      addGap(6);

      // Recommendation
      addLine('RECOMMENDATION', 14, true);
      addGap(2);
      addLine(`Number (N):        ${rec.numberOfRequests} req/min`);
      addLine(`Burst (B):         ${rec.burstMultiplier}×`);
      addLine(`Effective Limit:   ${rec.effectiveLimit} req/min`);
      addLine(`Confidence:        ${rec.confidence}`);
      addGap(4);

      // Rationale
      addLine('RATIONALE', 14, true);
      addGap(2);
      for (const para of rec.rationale.split('\n\n')) {
        addLine(para, 9);
        addGap(2);
      }

      // Traffic Summary
      addLine('TRAFFIC SUMMARY', 14, true);
      addGap(2);
      addLine(`7-Day Total Requests:     ${result.totalRequests7d.toLocaleString()}`);
      addLine(`7-Day Filtered (blocked): ${result.filterBreakdown7d.total.toLocaleString()}`);
      addLine(`Deep Scan Window:         ${result.deepWindowHours}h (${result.deepStart.slice(0, 16)} → ${result.deepEnd.slice(0, 16)})`);
      addLine(`Deep Logs Fetched:        ${result.deepTotalFetched.toLocaleString()} / ${result.deepTotalExpected.toLocaleString()} expected`);
      addLine(`Deep Clean Logs:          ${result.deepCleanLogs.toLocaleString()}`);
      addLine(`Users Analysed:           ${s.usersAnalyzed}`);
      addLine(`Outliers Trimmed:         ${s.outliersTrimmed}`);
      addGap(4);

      // Percentile Table
      addLine('PER-USER PEAK DISTRIBUTION', 14, true);
      addGap(2);
      const pctRows = [
        ['P50', s.p50Peaks], ['P75', s.p75Peaks], ['P90', s.p90Peaks],
        ['P95 (baseline)', s.p95Peaks], ['P99', s.p99Peaks], ['P99.9 (absolute)', s.p999Peaks],
        ['P95 Medians (typical)', s.p95Medians],
      ] as const;
      for (const [label, val] of pctRows) {
        addLine(`${label.padEnd(25)} ${Math.round(val)} req/min`, 10);
      }
      addGap(4);

      // Top Users
      if (result.userPeaks.length > 0) {
        addLine('TOP USERS BY PEAK RPM', 14, true);
        addGap(2);
        addLine('User                              Peak    Median  Active Min', 9, true);
        for (const u of result.userPeaks.slice(0, 15)) {
          addLine(`${u.userId.padEnd(34)} ${String(u.peakRpm).padStart(6)}  ${u.medianRpm.toFixed(1).padStart(7)}  ${String(u.activeMinutes).padStart(10)}`, 8);
        }
        addGap(4);
      }

      // Selected config
      addLine('SELECTED CONFIGURATION', 14, true);
      addGap(2);
      addLine(`Rate Limit: ${n} req/min × ${b} burst = ${n * b} effective`);
      addGap(2);
      addLine(json, 8);
      addGap(4);

      // Warnings
      if (result.warnings.length > 0) {
        addLine('WARNINGS', 14, true);
        addGap(2);
        for (const w of result.warnings) { addLine(`⚠ ${w}`, 9); addGap(1); }
        addGap(4);
      }

      // Rollout
      addLine('ROLLOUT GUIDANCE', 14, true);
      addGap(2);
      addLine('Week 1: Deploy with Mitigation Action = None (alert-only). Monitor access logs.', 9);
      addLine('Week 2: Review who triggers the limit. Adjust N if legitimate users are flagged.', 9);
      addLine('Week 3: Switch to Block with 5-minute duration. Monitor for complaints.', 9);
      addLine('Monthly: Re-run the advisor. Update if recommended N shifts >20%.', 9);

      doc.save(`rate-limit-advisor-${result.lbName}-${new Date().toISOString().split('T')[0]}.pdf`);
    } catch (err) {
      console.error('PDF generation failed:', err);
    } finally {
      setIsPdfGenerating(false);
    }
  };

  return (<div>
    <div className="border border-blue-500/30 rounded-xl p-4 bg-blue-500/5 mb-4">
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-sm font-semibold text-slate-200">{n} req/min × {b} burst = {n * b} effective</h4>
        <button onClick={() => onCopy(json, 'config')} className="flex items-center gap-1 px-3 py-1 text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg">
          {copiedField === 'config' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}{copiedField === 'config' ? 'Copied!' : 'Copy'}</button>
      </div>
      <pre className="bg-slate-950 border border-slate-700 rounded-lg p-4 text-sm text-green-400 overflow-x-auto font-mono">{json}</pre>
    </div>
    <div className="flex gap-3 flex-wrap">
      <button onClick={() => {
        const blob = new Blob([report], { type: 'application/json' }); const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url; a.download = `rate-limit-advisor-${result.lbName}-${new Date().toISOString().split('T')[0]}.json`;
        a.click(); URL.revokeObjectURL(url);
      }} className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm">
        <Download className="w-4 h-4" />Download JSON Report</button>
      <button onClick={downloadPdf} disabled={isPdfGenerating}
        className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg text-sm">
        {isPdfGenerating ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />Generating...</>
          : <><FileJson className="w-4 h-4" />Download PDF Report</>}</button>
    </div>
  </div>);
}
