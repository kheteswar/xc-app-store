import { useState, useEffect, useRef, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ShieldAlert, Play, ChevronDown, ChevronRight, AlertTriangle,
  Globe, Target, Lock, Check, XCircle,
  ArrowLeft, ArrowRight, Zap, BarChart3,
  Download, FileSpreadsheet, HelpCircle,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { apiClient } from '../services/api';
import type { LoadBalancer, Namespace } from '../types';
import {
  classifyMatchingInfo,
  generateFPAnalysisPDF,
  generateFPAnalysisExcel,
  generatePerPathExclusions,
  generateViolationPerPathExclusions,
  buildWafExclusionPolicy,
  cleanPolicyForExport,
} from '../services/fp-analyzer';
import type {
  AnalysisScope, AnalysisMode, FPVerdict, QuickVerdict, ConfidenceLevel,
  SignatureAnalysisUnit,
  ViolationAnalysisUnit,
  ThreatMeshAnalysisUnit,
  ThreatMeshEnrichmentResult,
  SignatureSummary, SummaryResult,
  ProgressiveJobProgress,
  WafExclusionRule,
  WafExclusionPolicyObject,
} from '../services/fp-analyzer';

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

const VERDICT_CONFIG: Record<FPVerdict, { label: string; bg: string; text: string }> = {
  highly_likely_fp: { label: 'Highly Likely FP', bg: 'bg-red-500/20', text: 'text-red-400' },
  likely_fp: { label: 'Likely FP', bg: 'bg-orange-500/20', text: 'text-orange-400' },
  ambiguous: { label: 'Ambiguous', bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  likely_tp: { label: 'Likely TP', bg: 'bg-emerald-500/20', text: 'text-emerald-400' },
  confirmed_tp: { label: 'Confirmed TP', bg: 'bg-green-500/20', text: 'text-green-400' },
};

const QUICK_VERDICT_CONFIG: Record<QuickVerdict, { label: string; bg: string; text: string; icon: string }> = {
  likely_fp: { label: 'Likely FP', bg: 'bg-red-500/20', text: 'text-red-400', icon: '●' },
  investigate: { label: 'Investigate', bg: 'bg-yellow-500/20', text: 'text-yellow-400', icon: '?' },
  likely_tp: { label: 'Likely TP', bg: 'bg-emerald-500/20', text: 'text-emerald-400', icon: '✗' },
};

const CONFIDENCE_CONFIG: Record<ConfidenceLevel, { label: string; dots: string }> = {
  high: { label: 'HIGH', dots: '●●●●' },
  medium: { label: 'MED', dots: '●●●○' },
  low: { label: 'LOW', dots: '●●○○' },
};

function VerdictBadge({ verdict }: { verdict: FPVerdict }) {
  const cfg = VERDICT_CONFIG[verdict];
  return <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${cfg.bg} ${cfg.text}`}>{cfg.label}</span>;
}

function QuickVerdictBadge({ verdict, confidence }: { verdict: QuickVerdict; confidence: ConfidenceLevel }) {
  const vCfg = QUICK_VERDICT_CONFIG[verdict];
  const cCfg = CONFIDENCE_CONFIG[confidence];
  return (
    <div className="flex items-center gap-1.5">
      <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${vCfg.bg} ${vCfg.text}`}>{vCfg.label}</span>
      <span className="text-[10px] text-slate-500" title={`Confidence: ${cCfg.label}`}>{cCfg.dots}</span>
    </div>
  );
}

function SignalBar({ label, score, reason, weight }: { label: string; score: number; reason: string; weight?: string }) {
  const barColor = score > 75 ? 'bg-red-500' : score > 55 ? 'bg-orange-500' : score > 35 ? 'bg-yellow-500' : score > 15 ? 'bg-emerald-500' : 'bg-green-500';
  return (
    <div className="mb-2">
      <div className="flex justify-between text-xs mb-0.5">
        <span className="text-slate-300">{label} {weight && <span className="text-slate-500">({weight})</span>}</span>
        <span className="text-slate-400">{score}</span>
      </div>
      <div className="w-full bg-slate-700 rounded-full h-1.5">
        <div className={`h-1.5 rounded-full ${barColor} transition-all`} style={{ width: `${score}%` }} />
      </div>
      <div className="text-[10px] text-slate-500 mt-0.5">{reason}</div>
    </div>
  );
}

function MatchingInfoValue({ value }: { value: string }) {
  const result = classifyMatchingInfo(value);
  const colorClass = result.classification === 'clearly_malicious' ? 'text-red-400'
    : result.classification === 'clearly_benign' ? 'text-emerald-400'
    : 'text-yellow-400';
  return (
    <div className="flex items-center gap-1.5" title={result.reason}>
      <span className={`w-1.5 h-1.5 rounded-full ${
        result.classification === 'clearly_malicious' ? 'bg-red-400'
        : result.classification === 'clearly_benign' ? 'bg-emerald-400'
        : 'bg-yellow-400'
      }`} />
      <span className={`text-xs font-mono truncate ${colorClass}`}>{value}</span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SEARCHABLE SELECT
// ═══════════════════════════════════════════════════════════════

function SearchableSelect({
  value, onChange, options, placeholder, disabled,
}: {
  value: string;
  onChange: (val: string) => void;
  options: { value: string; label: string }[];
  placeholder: string;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = search
    ? options.filter(o => o.label.toLowerCase().includes(search.toLowerCase()))
    : options;
  const selectedLabel = options.find(o => o.value === value)?.label || '';

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false); setSearch('');
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  return (
    <div ref={containerRef} className="relative">
      <input
        ref={inputRef}
        type="text"
        value={open ? search : selectedLabel}
        placeholder={placeholder}
        disabled={disabled}
        className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
        onFocus={() => { setOpen(true); setSearch(''); }}
        onChange={e => setSearch(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Escape') { setOpen(false); setSearch(''); inputRef.current?.blur(); }
          if (e.key === 'Enter' && filtered.length === 1) { onChange(filtered[0].value); setOpen(false); setSearch(''); inputRef.current?.blur(); }
        }}
      />
      <ChevronDown className={`absolute right-2 top-2.5 w-4 h-4 text-slate-400 pointer-events-none transition-transform ${open ? 'rotate-180' : ''}`} />
      {open && filtered.length > 0 && (
        <div className="absolute z-50 w-full mt-1 bg-slate-800 border border-slate-600 rounded-lg shadow-xl max-h-60 overflow-y-auto">
          {filtered.map(o => (
            <button key={o.value} onClick={() => { onChange(o.value); setOpen(false); setSearch(''); }}
              className={`w-full text-left px-3 py-2 text-sm hover:bg-slate-700 transition-colors ${o.value === value ? 'text-blue-400 bg-slate-700/50' : 'text-slate-200'}`}
            >{o.label}</button>
          ))}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// COLLAPSIBLE SECTION
// ═══════════════════════════════════════════════════════════════

function Section({ title, icon: Icon, expanded, onToggle, badge, children }: {
  title: string;
  icon: React.ElementType;
  expanded: boolean;
  onToggle: () => void;
  badge?: string | number;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-xl mb-4">
      <button onClick={onToggle} className="w-full flex items-center justify-between px-5 py-3 text-left hover:bg-slate-700/30 transition-colors">
        <div className="flex items-center gap-3">
          <Icon className="w-4 h-4 text-blue-400" />
          <span className="text-sm font-semibold text-slate-200">{title}</span>
          {badge != null && <span className="px-2 py-0.5 text-xs bg-blue-500/20 text-blue-400 rounded-full">{badge}</span>}
        </div>
        {expanded ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
      </button>
      {expanded && <div className="px-5 pb-5">{children}</div>}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SIGNATURE DETAIL VIEW
// ═══════════════════════════════════════════════════════════════

function SignatureDetailView({ unit, onEnrich, enriching, onBack, onPrev, onNext, currentIdx, totalCount, onMarkFP, onMarkTP }: {
  unit: SignatureAnalysisUnit;
  onEnrich: (paths: string[]) => void;
  enriching: boolean;
  onBack: () => void;
  onPrev: () => void;
  onNext: () => void;
  currentIdx: number;
  totalCount: number;
  onMarkFP: () => void;
  onMarkTP: () => void;
}) {
  const signals = unit.signals;

  const signalList = [
    { label: 'User Breadth', weight: '20%', score: signals.userBreadth.score, reason: signals.userBreadth.reason },
    { label: 'Request Breadth', weight: '15%', score: signals.requestBreadth.score, reason: signals.requestBreadth.reason },
    { label: 'Path Breadth', weight: '15%', score: signals.pathBreadth.score, reason: signals.pathBreadth.reason },
    { label: 'Context Analysis', weight: '15%', score: signals.contextAnalysis.score, reason: signals.contextAnalysis.reason },
    { label: 'Client Profile', weight: '10%', score: signals.clientProfile.score, reason: signals.clientProfile.reason },
    { label: 'Temporal Pattern', weight: '10%', score: signals.temporalPattern.score, reason: signals.temporalPattern.reason },
    { label: 'Signature Accuracy', weight: '15%', score: signals.signatureAccuracy.score, reason: signals.signatureAccuracy.reason },
  ];

  // Fix: use pathCounts directly instead of re-counting rawPaths
  const topPaths = Object.entries(unit.pathCounts || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20);

  const topIPs = Object.entries(unit.ipCounts || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15);

  const exclusionRules = unit.pathAnalyses ? generatePerPathExclusions(unit) : [];
  const fpPaths = unit.pathAnalyses?.filter(pa => pa.verdict === 'highly_likely_fp' || pa.verdict === 'likely_fp') || [];
  const tpPaths = unit.pathAnalyses?.filter(pa => pa.verdict === 'likely_tp' || pa.verdict === 'confirmed_tp') || [];

  return (
    <div>
      {/* Navigation header */}
      <div className="flex items-center justify-between mb-4">
        <button onClick={onBack} className="flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300">
          <ArrowLeft className="w-4 h-4" /> Back to Summary
        </button>
        <div className="flex items-center gap-3 text-sm text-slate-400">
          <span>Sig {currentIdx + 1} of {totalCount}</span>
          <button onClick={onPrev} disabled={currentIdx === 0} className="p-1 hover:bg-slate-700 rounded disabled:opacity-30">
            <ArrowLeft className="w-4 h-4" />
          </button>
          <button onClick={onNext} disabled={currentIdx >= totalCount - 1} className="p-1 hover:bg-slate-700 rounded disabled:opacity-30">
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Signature header */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
        <div className="flex items-start justify-between mb-3">
          <div>
            <h3 className="text-lg font-bold text-slate-100">
              {unit.signatureId} — "{unit.signatureName}"
            </h3>
            <div className="flex gap-2 mt-1 text-xs text-slate-400">
              <span>Accuracy: <span className="text-slate-300">{unit.accuracy}</span></span>
              <span>|</span>
              <span>Attack: <span className="text-slate-300">{unit.attackType}</span></span>
              <span>|</span>
              <span>Context: <span className="text-slate-300">{unit.contextType} "{unit.contextName}"</span></span>
              {unit.autoSuppressed && <span className="text-yellow-400 ml-2">AutoSuppressed</span>}
              {unit.enriched && <span className="text-blue-400 ml-2">Enriched with access logs</span>}
            </div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-slate-100">{signals.compositeScore}%</div>
            <VerdictBadge verdict={signals.verdict} />
          </div>
        </div>

        {/* Quick stats */}
        <div className="grid grid-cols-5 gap-3 mt-4">
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{unit.flaggedUsers.toLocaleString()}</div>
            <div className="text-xs text-slate-400">Users{unit.enriched && unit.totalUsersOnPath > 0 ? ` / ${unit.totalUsersOnPath.toLocaleString()}` : ''}</div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{unit.eventCount.toLocaleString()}</div>
            <div className="text-xs text-slate-400">Events</div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{unit.pathCount}</div>
            <div className="text-xs text-slate-400">Paths</div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{unit.flaggedIPs.toLocaleString()}</div>
            <div className="text-xs text-slate-400">IPs</div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{Object.keys(unit.rspCodes).length > 0 ? Object.entries(unit.rspCodes).sort((a, b) => b[1] - a[1])[0][0] : '-'}</div>
            <div className="text-xs text-slate-400">Top Rsp Code</div>
          </div>
        </div>
      </div>

      {/* Signals */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
        <h4 className="text-sm font-semibold text-slate-200 mb-3">
          {unit.enriched ? 'Deep Mode Signals' : 'Quick Mode Signals'} (from security events)
        </h4>
        {signalList.map((s, i) => <SignalBar key={i} label={s.label} score={s.score} reason={s.reason} weight={s.weight} />)}
      </div>

      {/* Per-path FP/TP Analysis */}
      {unit.pathAnalyses && unit.pathAnalyses.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-slate-200 mb-1">Per-Path FP/TP Analysis</h4>
          <p className="text-[10px] text-slate-500 mb-3">
            {fpPaths.length} FP path(s), {tpPaths.length} TP path(s), {(unit.pathAnalyses.length - fpPaths.length - tpPaths.length)} ambiguous
          </p>
          <table className="w-full text-xs">
            <thead><tr className="text-slate-400 border-b border-slate-700">
              <th className="text-left py-1 pr-2">Path</th>
              <th className="text-right py-1 pr-2 w-16">Events</th>
              <th className="text-right py-1 pr-2 w-14">Users</th>
              <th className="text-right py-1 pr-2 w-14">IPs</th>
              <th className="text-center py-1 pr-2 w-16">Methods</th>
              <th className="text-right py-1 pr-2 w-16">FP Score</th>
              <th className="text-center py-1 w-28">Verdict</th>
            </tr></thead>
            <tbody>
              {unit.pathAnalyses.slice(0, 20).map((pa, i) => {
                const vCfg = VERDICT_CONFIG[pa.verdict];
                return (
                  <tr key={i} className={`border-b border-slate-700/50 ${
                    pa.verdict === 'highly_likely_fp' || pa.verdict === 'likely_fp' ? 'bg-red-500/5' :
                    pa.verdict === 'likely_tp' || pa.verdict === 'confirmed_tp' ? 'bg-emerald-500/5' : ''
                  }`}>
                    <td className="py-1.5 pr-2 text-slate-300 font-mono truncate max-w-xs" title={pa.path}>{pa.path}</td>
                    <td className="py-1.5 pr-2 text-right text-slate-300">{pa.eventCount.toLocaleString()}</td>
                    <td className="py-1.5 pr-2 text-right text-slate-300">{pa.uniqueUsers}</td>
                    <td className="py-1.5 pr-2 text-right text-slate-300">{pa.uniqueIPs}</td>
                    <td className="py-1.5 pr-2 text-center text-slate-400 text-[10px]">{Object.keys(pa.methods).join(', ')}</td>
                    <td className={`py-1.5 pr-2 text-right font-medium ${vCfg.text}`}>{pa.fpScore}%</td>
                    <td className="py-1.5 text-center"><span className={`px-1.5 py-0.5 text-[10px] font-medium rounded-full ${vCfg.bg} ${vCfg.text}`}>{vCfg.label}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {/* Per-path reasons (expandable) */}
          {unit.pathAnalyses.slice(0, 5).map((pa, i) => (
            <div key={i} className="mt-2 text-[10px]">
              <span className="text-slate-400 font-mono">{pa.path.length > 40 ? pa.path.slice(0, 40) + '...' : pa.path}:</span>
              <span className="text-slate-500 ml-1">{pa.reasons.join('; ')}</span>
            </div>
          ))}
        </div>
      )}

      {/* Path breakdown (event counts) */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
        <h4 className="text-sm font-semibold text-slate-200 mb-3">Path Event Counts</h4>
        <table className="w-full text-xs">
          <thead><tr className="text-slate-400 border-b border-slate-700">
            <th className="text-left py-1 pr-2">Path</th>
            <th className="text-right py-1 w-20">Events</th>
          </tr></thead>
          <tbody>
            {topPaths.map(([path, count], i) => (
              <tr key={i} className="border-b border-slate-700/50">
                <td className="py-1 pr-2 text-slate-300 font-mono truncate max-w-xs">{path}</td>
                <td className="py-1 text-right text-slate-400">{count.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Top Source IPs */}
      {topIPs.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-slate-200 mb-3">Top Source IPs</h4>
          <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead><tr className="text-slate-400 border-b border-slate-700">
              <th className="text-left py-1 pr-2">#</th>
              <th className="text-left py-1 pr-2">IP Address</th>
              <th className="text-left py-1 pr-2">Country</th>
              <th className="text-left py-1 pr-2">City</th>
              <th className="text-left py-1 pr-2">AS Org</th>
              <th className="text-left py-1 pr-2 max-w-[200px]">User Agent</th>
              <th className="text-right py-1 pr-2 w-16">Events</th>
              <th className="text-right py-1 w-16">%</th>
            </tr></thead>
            <tbody>
              {topIPs.map(([ip, count], i) => {
                const ipInfo = unit.ipDetails?.[ip];
                return (
                <tr key={i} className="border-b border-slate-700/50">
                  <td className="py-1.5 pr-2 text-slate-500">{i + 1}</td>
                  <td className="py-1.5 pr-2 text-slate-300 font-mono">{ip}</td>
                  <td className="py-1.5 pr-2 text-slate-300">{ipInfo?.country || '-'}</td>
                  <td className="py-1.5 pr-2 text-slate-400">{ipInfo?.city || '-'}</td>
                  <td className="py-1.5 pr-2 text-slate-400 truncate max-w-[150px]">{ipInfo?.asOrg || '-'}</td>
                  <td className="py-1.5 pr-2 text-slate-500 truncate max-w-[200px]" title={ipInfo?.userAgent}>{ipInfo?.userAgent || '-'}</td>
                  <td className="py-1.5 pr-2 text-right text-slate-400">{count.toLocaleString()}</td>
                  <td className="py-1.5 text-right text-slate-400">{unit.eventCount > 0 ? ((count / unit.eventCount) * 100).toFixed(1) : 0}%</td>
                </tr>
                );
              })}
            </tbody>
          </table>
          </div>
        </div>
      )}

      {/* Client Profile */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
        <h4 className="text-sm font-semibold text-slate-200 mb-3">Client Profile</h4>
        <div className="grid grid-cols-3 gap-4 text-xs">
          <div>
            <h5 className="text-slate-400 mb-1">Top User Agents</h5>
            {Object.entries(unit.userAgents).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ua, count], i) => (
              <div key={i} className="text-slate-300 truncate">{ua} <span className="text-slate-500">({count})</span></div>
            ))}
          </div>
          <div>
            <h5 className="text-slate-400 mb-1">Countries</h5>
            {Object.entries(unit.countries).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([c, count], i) => (
              <div key={i} className="text-slate-300">{c} <span className="text-slate-500">({count})</span></div>
            ))}
          </div>
          <div>
            <h5 className="text-slate-400 mb-1">Methods</h5>
            {Object.entries(unit.methods).sort((a, b) => b[1] - a[1]).map(([m, count], i) => (
              <div key={i} className="text-slate-300">{m} <span className="text-slate-500">({count})</span></div>
            ))}
          </div>
          <div>
            <h5 className="text-slate-400 mb-1">Response Codes</h5>
            {Object.entries(unit.rspCodes).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([code, count], i) => (
              <div key={i} className="text-slate-300">{code} <span className="text-slate-500">({count})</span></div>
            ))}
          </div>
          {Object.keys(unit.botClassifications).length > 0 && (
            <div>
              <h5 className="text-slate-400 mb-1">Bot Classifications</h5>
              {Object.entries(unit.botClassifications).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([cls, count], i) => (
                <div key={i} className="text-slate-300">{cls} <span className="text-slate-500">({count})</span></div>
              ))}
            </div>
          )}
          {unit.trustScores.length > 0 && (
            <div>
              <h5 className="text-slate-400 mb-1">Trust Score Distribution</h5>
              <div className="text-slate-300">Min: {Math.min(...unit.trustScores)}</div>
              <div className="text-slate-300">Max: {Math.max(...unit.trustScores)}</div>
              <div className="text-slate-300">Avg: {(unit.trustScores.reduce((a, b) => a + b, 0) / unit.trustScores.length).toFixed(0)}</div>
            </div>
          )}
        </div>
        {/* Additional metadata */}
        <div className="mt-3 pt-3 border-t border-slate-700/50 flex flex-wrap gap-3 text-[10px]">
          {unit.aiConfirmed && <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded-full">AI Confirmed Malicious</span>}
          {unit.autoSuppressed && <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-400 rounded-full">Auto Suppressed</span>}
          {unit.sigState && <span className="text-slate-500">Sig State: <span className="text-slate-400">{unit.sigState}</span></span>}
          {unit.originAcceptedCount > 0 && <span className="text-slate-500">Origin Accepted: <span className="text-slate-400">{unit.originAcceptedCount.toLocaleString()}</span></span>}
          {unit.reqRiskReasons.length > 0 && <span className="text-slate-500">Risk Reasons: <span className="text-slate-400">{unit.reqRiskReasons.slice(0, 3).join(', ')}</span></span>}
        </div>
      </div>

      {/* Matching info samples */}
      {unit.sampleMatchingInfos.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-slate-200 mb-3">Sample Matching Values</h4>
          <div className="space-y-1.5">
            {unit.sampleMatchingInfos.slice(0, 10).map((v, i) => <MatchingInfoValue key={i} value={v} />)}
          </div>
        </div>
      )}

      {/* WAF Exclusion Recommendation */}
      {fpPaths.length > 0 && (
        <div className="bg-slate-800/50 border border-blue-700/50 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-blue-300 mb-2">WAF Exclusion Recommendation</h4>
          <p className="text-xs text-slate-400 mb-3">
            {fpPaths.length} path(s) identified as false positive can be excluded.
            {tpPaths.length > 0 && <span className="text-amber-400"> {tpPaths.length} path(s) appear to be true positive and will NOT be excluded.</span>}
          </p>
          {exclusionRules.length > 0 && (
            <div className="mb-3">
              <div className="text-xs text-slate-400 mb-1">{exclusionRules.length} exclusion rule(s) generated:</div>
              <div className="bg-slate-900/80 rounded-lg p-3 max-h-48 overflow-auto">
                <pre className="text-[10px] text-slate-300 whitespace-pre-wrap font-mono">
                  {JSON.stringify(exclusionRules, null, 2)}
                </pre>
              </div>
            </div>
          )}
          <button
            onClick={() => {
              navigator.clipboard.writeText(JSON.stringify(exclusionRules, null, 2));
            }}
            className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 rounded-lg text-xs border border-blue-600/30 transition-colors"
          >
            Copy Rules to Clipboard
          </button>
        </div>
      )}

      {/* Enrich with access logs */}
      {!unit.enriched && (
        <div className="bg-slate-800/50 border border-blue-700/50 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-blue-300 mb-2">Optional: Load Access Logs for Precision</h4>
          <p className="text-xs text-slate-400 mb-3">
            Fetch access logs for the {unit.pathCount} paths where this signature triggers
            to compute exact ratios (% of users affected).
          </p>
          <button
            onClick={() => onEnrich(unit.rawPaths.slice(0, 15))}
            disabled={enriching}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-600 text-white rounded-lg text-sm transition-colors"
          >
            {enriching ? 'Loading Access Logs...' : 'Load Access Logs for This Signature'}
          </button>
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-3 mt-4">
        <button onClick={onMarkFP} className="px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg text-sm border border-red-600/30 transition-colors">
          <Check className="w-3.5 h-3.5 inline mr-1" /> Confirm FP
        </button>
        <button onClick={onMarkTP} className="px-4 py-2 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 rounded-lg text-sm border border-emerald-600/30 transition-colors">
          <XCircle className="w-3.5 h-3.5 inline mr-1" /> Confirm TP
        </button>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// VIOLATION DETAIL VIEW
// ═══════════════════════════════════════════════════════════════

function ViolationDetailView({ unit, onBack, onPrev, onNext, currentIdx, totalCount }: {
  unit: ViolationAnalysisUnit;
  onBack: () => void;
  onPrev: () => void;
  onNext: () => void;
  currentIdx: number;
  totalCount: number;
}) {
  const signals = unit.signals;

  const signalList = [
    { label: 'User Breadth', weight: '30%', score: signals.userBreadth.score, reason: signals.userBreadth.reason },
    { label: 'Request Breadth', weight: '20%', score: signals.requestBreadth.score, reason: signals.requestBreadth.reason },
    { label: 'Path Breadth', weight: '20%', score: signals.pathBreadth.score, reason: signals.pathBreadth.reason },
    { label: 'Context Analysis', weight: '15%', score: signals.contextAnalysis.score, reason: signals.contextAnalysis.reason },
    { label: 'Client Profile', weight: '15%', score: signals.clientProfile.score, reason: signals.clientProfile.reason },
  ];

  const topPaths = Object.entries(unit.pathCounts || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20);

  const topIPs = Object.entries(unit.ipCounts || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15);

  const exclusionRules = unit.pathAnalyses ? generateViolationPerPathExclusions(unit) : [];
  const fpPaths = unit.pathAnalyses?.filter(pa => pa.verdict === 'highly_likely_fp' || pa.verdict === 'likely_fp') || [];
  const tpPaths = unit.pathAnalyses?.filter(pa => pa.verdict === 'likely_tp' || pa.verdict === 'confirmed_tp') || [];

  return (
    <div>
      {/* Navigation header */}
      <div className="flex items-center justify-between mb-4">
        <button onClick={onBack} className="flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300">
          <ArrowLeft className="w-4 h-4" /> Back to Summary
        </button>
        <div className="flex items-center gap-3 text-sm text-slate-400">
          <span>Violation {currentIdx + 1} of {totalCount}</span>
          <button onClick={onPrev} disabled={currentIdx === 0} className="p-1 hover:bg-slate-700 rounded disabled:opacity-30">
            <ArrowLeft className="w-4 h-4" />
          </button>
          <button onClick={onNext} disabled={currentIdx >= totalCount - 1} className="p-1 hover:bg-slate-700 rounded disabled:opacity-30">
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Violation header */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
        <div className="flex items-start justify-between mb-3">
          <div>
            <h3 className="text-lg font-bold text-slate-100">{unit.violationName}</h3>
            <div className="flex gap-2 mt-1 text-xs text-slate-400">
              <span>Attack Type: <span className="text-slate-300">{unit.attackType || 'N/A'}</span></span>
            </div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-slate-100">{signals.compositeScore}%</div>
            <VerdictBadge verdict={signals.verdict} />
          </div>
        </div>

        {/* Quick stats */}
        <div className="grid grid-cols-5 gap-3 mt-4">
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{unit.flaggedUsers.toLocaleString()}</div>
            <div className="text-xs text-slate-400">Users</div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{unit.eventCount.toLocaleString()}</div>
            <div className="text-xs text-slate-400">Events</div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{unit.pathCount}</div>
            <div className="text-xs text-slate-400">Paths</div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{unit.flaggedIPs.toLocaleString()}</div>
            <div className="text-xs text-slate-400">IPs</div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{Object.keys(unit.methods).length > 0 ? Object.entries(unit.methods).sort((a, b) => b[1] - a[1])[0][0] : '-'}</div>
            <div className="text-xs text-slate-400">Top Method</div>
          </div>
        </div>
      </div>

      {/* Signals */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
        <h4 className="text-sm font-semibold text-slate-200 mb-3">Analysis Signals</h4>
        {signalList.map((s, i) => <SignalBar key={i} label={s.label} score={s.score} reason={s.reason} weight={s.weight} />)}
      </div>

      {/* Per-path FP/TP Analysis */}
      {unit.pathAnalyses && unit.pathAnalyses.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-slate-200 mb-1">Per-Path FP/TP Analysis</h4>
          <p className="text-[10px] text-slate-500 mb-3">
            {fpPaths.length} FP path(s), {tpPaths.length} TP path(s), {(unit.pathAnalyses.length - fpPaths.length - tpPaths.length)} ambiguous
          </p>
          <table className="w-full text-xs">
            <thead><tr className="text-slate-400 border-b border-slate-700">
              <th className="text-left py-1 pr-2">Path</th>
              <th className="text-right py-1 pr-2 w-16">Events</th>
              <th className="text-right py-1 pr-2 w-14">Users</th>
              <th className="text-right py-1 pr-2 w-14">IPs</th>
              <th className="text-center py-1 pr-2 w-16">Methods</th>
              <th className="text-right py-1 pr-2 w-16">FP Score</th>
              <th className="text-center py-1 w-28">Verdict</th>
            </tr></thead>
            <tbody>
              {unit.pathAnalyses.slice(0, 20).map((pa, i) => {
                const vCfg = VERDICT_CONFIG[pa.verdict];
                return (
                  <tr key={i} className={`border-b border-slate-700/50 ${
                    pa.verdict === 'highly_likely_fp' || pa.verdict === 'likely_fp' ? 'bg-red-500/5' :
                    pa.verdict === 'likely_tp' || pa.verdict === 'confirmed_tp' ? 'bg-emerald-500/5' : ''
                  }`}>
                    <td className="py-1.5 pr-2 text-slate-300 font-mono truncate max-w-xs" title={pa.path}>{pa.path}</td>
                    <td className="py-1.5 pr-2 text-right text-slate-300">{pa.eventCount.toLocaleString()}</td>
                    <td className="py-1.5 pr-2 text-right text-slate-300">{pa.uniqueUsers}</td>
                    <td className="py-1.5 pr-2 text-right text-slate-300">{pa.uniqueIPs}</td>
                    <td className="py-1.5 pr-2 text-center text-slate-400 text-[10px]">{Object.keys(pa.methods).join(', ')}</td>
                    <td className={`py-1.5 pr-2 text-right font-medium ${vCfg.text}`}>{pa.fpScore}%</td>
                    <td className="py-1.5 text-center"><span className={`px-1.5 py-0.5 text-[10px] font-medium rounded-full ${vCfg.bg} ${vCfg.text}`}>{vCfg.label}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {unit.pathAnalyses.slice(0, 5).map((pa, i) => (
            <div key={i} className="mt-2 text-[10px]">
              <span className="text-slate-400 font-mono">{pa.path.length > 40 ? pa.path.slice(0, 40) + '...' : pa.path}:</span>
              <span className="text-slate-500 ml-1">{pa.reasons.join('; ')}</span>
            </div>
          ))}
        </div>
      )}

      {/* Top IPs */}
      {topIPs.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-slate-200 mb-3">Top Source IPs</h4>
          <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead><tr className="text-slate-400 border-b border-slate-700">
              <th className="text-left py-1 pr-2">#</th>
              <th className="text-left py-1 pr-2">IP Address</th>
              <th className="text-left py-1 pr-2">Country</th>
              <th className="text-left py-1 pr-2">City</th>
              <th className="text-left py-1 pr-2">AS Org</th>
              <th className="text-left py-1 pr-2 max-w-[200px]">User Agent</th>
              <th className="text-right py-1 pr-2 w-16">Events</th>
              <th className="text-right py-1 w-16">%</th>
            </tr></thead>
            <tbody>
              {topIPs.map(([ip, count], i) => {
                const ipInfo = unit.ipDetails?.[ip];
                return (
                <tr key={i} className="border-b border-slate-700/50">
                  <td className="py-1.5 pr-2 text-slate-500">{i + 1}</td>
                  <td className="py-1.5 pr-2 text-slate-300 font-mono">{ip}</td>
                  <td className="py-1.5 pr-2 text-slate-300">{ipInfo?.country || '-'}</td>
                  <td className="py-1.5 pr-2 text-slate-400">{ipInfo?.city || '-'}</td>
                  <td className="py-1.5 pr-2 text-slate-400 truncate max-w-[150px]">{ipInfo?.asOrg || '-'}</td>
                  <td className="py-1.5 pr-2 text-slate-500 truncate max-w-[200px]" title={ipInfo?.userAgent}>{ipInfo?.userAgent || '-'}</td>
                  <td className="py-1.5 pr-2 text-right text-slate-400">{count.toLocaleString()}</td>
                  <td className="py-1.5 text-right text-slate-400">{unit.eventCount > 0 ? ((count / unit.eventCount) * 100).toFixed(1) : 0}%</td>
                </tr>
                );
              })}
            </tbody>
          </table>
          </div>
        </div>
      )}

      {/* Path breakdown */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
        <h4 className="text-sm font-semibold text-slate-200 mb-3">Path Event Counts</h4>
        <table className="w-full text-xs">
          <thead><tr className="text-slate-400 border-b border-slate-700">
            <th className="text-left py-1 pr-2">Path</th>
            <th className="text-right py-1 w-20">Events</th>
          </tr></thead>
          <tbody>
            {topPaths.map(([path, count], i) => (
              <tr key={i} className="border-b border-slate-700/50">
                <td className="py-1 pr-2 text-slate-300 font-mono truncate max-w-xs">{path}</td>
                <td className="py-1 text-right text-slate-400">{count.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Client Profile */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
        <h4 className="text-sm font-semibold text-slate-200 mb-3">Client Profile</h4>
        <div className="grid grid-cols-2 gap-4 text-xs">
          <div>
            <h5 className="text-slate-400 mb-1">Top User Agents</h5>
            {Object.entries(unit.userAgents).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ua, count], i) => (
              <div key={i} className="text-slate-300 truncate">{ua} <span className="text-slate-500">({count})</span></div>
            ))}
          </div>
          <div>
            <h5 className="text-slate-400 mb-1">Countries</h5>
            {Object.entries(unit.countries).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([c, count], i) => (
              <div key={i} className="text-slate-300">{c} <span className="text-slate-500">({count})</span></div>
            ))}
          </div>
          <div>
            <h5 className="text-slate-400 mb-1">Methods</h5>
            {Object.entries(unit.methods).sort((a, b) => b[1] - a[1]).map(([m, count], i) => (
              <div key={i} className="text-slate-300">{m} <span className="text-slate-500">({count})</span></div>
            ))}
          </div>
        </div>
      </div>

      {/* Matching info samples */}
      {unit.sampleMatchingInfos.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-slate-200 mb-3">Sample Matching Values</h4>
          <div className="space-y-1.5">
            {unit.sampleMatchingInfos.slice(0, 10).map((v, i) => <MatchingInfoValue key={i} value={v} />)}
          </div>
        </div>
      )}

      {/* WAF Exclusion Recommendation */}
      {fpPaths.length > 0 && (
        <div className="bg-slate-800/50 border border-blue-700/50 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-blue-300 mb-2">WAF Exclusion Recommendation</h4>
          <p className="text-xs text-slate-400 mb-3">
            {fpPaths.length} path(s) identified as false positive can be excluded.
            {tpPaths.length > 0 && <span className="text-amber-400"> {tpPaths.length} path(s) appear to be true positive and will NOT be excluded.</span>}
          </p>
          {exclusionRules.length > 0 && (
            <div className="mb-3">
              <div className="text-xs text-slate-400 mb-1">{exclusionRules.length} exclusion rule(s) generated:</div>
              <div className="bg-slate-900/80 rounded-lg p-3 max-h-48 overflow-auto">
                <pre className="text-[10px] text-slate-300 whitespace-pre-wrap font-mono">
                  {JSON.stringify(exclusionRules, null, 2)}
                </pre>
              </div>
            </div>
          )}
          <button
            onClick={() => { navigator.clipboard.writeText(JSON.stringify(exclusionRules, null, 2)); }}
            className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 rounded-lg text-xs border border-blue-600/30 transition-colors"
          >
            Copy Rules to Clipboard
          </button>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// THREAT MESH DETAIL VIEW
// ═══════════════════════════════════════════════════════════════

function ThreatMeshDetailView({ unit, onEnrich, enriching, enrichResult, onBack, onPrev, onNext, currentIdx, totalCount }: {
  unit: ThreatMeshAnalysisUnit;
  onEnrich: () => void;
  enriching: boolean;
  enrichResult: ThreatMeshEnrichmentResult | null;
  onBack: () => void;
  onPrev: () => void;
  onNext: () => void;
  currentIdx: number;
  totalCount: number;
}) {
  const topPaths = Object.entries(unit.pathsAccessed || {}).sort((a, b) => b[1] - a[1]).slice(0, 15);
  const topRspCodes = Object.entries(unit.rspCodes || {}).sort((a, b) => b[1] - a[1]);

  return (
    <div>
      {/* Navigation */}
      <div className="flex items-center justify-between mb-4">
        <button onClick={onBack} className="flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300">
          <ArrowLeft className="w-4 h-4" /> Back to Summary
        </button>
        <div className="flex items-center gap-3 text-sm text-slate-400">
          <span>IP {currentIdx + 1} of {totalCount}</span>
          <button onClick={onPrev} disabled={currentIdx === 0} className="p-1 hover:bg-slate-700 rounded disabled:opacity-30"><ArrowLeft className="w-4 h-4" /></button>
          <button onClick={onNext} disabled={currentIdx >= totalCount - 1} className="p-1 hover:bg-slate-700 rounded disabled:opacity-30"><ArrowRight className="w-4 h-4" /></button>
        </div>
      </div>

      {/* IP Header */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
        <div className="flex items-start justify-between mb-3">
          <div>
            <h3 className="text-lg font-bold text-slate-100 font-mono">{unit.srcIp}</h3>
            <div className="flex flex-wrap gap-3 mt-1 text-xs text-slate-400">
              {unit.country && <span>Country: <span className="text-slate-300">{unit.country}</span></span>}
              {unit.asOrg && <span>AS Org: <span className="text-slate-300">{unit.asOrg}</span></span>}
              {unit.user && <span>User: <span className="text-slate-300">{unit.user}</span></span>}
              {unit.userAgent && <span>UA: <span className="text-slate-300 truncate max-w-[200px] inline-block align-bottom">{unit.userAgent}</span></span>}
            </div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-slate-100">{unit.fpScore}</div>
            <VerdictBadge verdict={unit.verdict} />
          </div>
        </div>
        <div className="grid grid-cols-4 gap-3 mt-4">
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{(unit.totalRequestsOnApp || 0).toLocaleString()}</div>
            <div className="text-xs text-slate-400">Total Requests</div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{unit.wafEventsFromThisIP || 0}</div>
            <div className="text-xs text-slate-400">WAF Events</div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{Object.keys(unit.pathsAccessed || {}).length}</div>
            <div className="text-xs text-slate-400">Paths</div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-slate-100">{unit.threatDetails?.tenantCount || 0}</div>
            <div className="text-xs text-slate-400">Tenants</div>
          </div>
        </div>
      </div>

      {/* Why Blocked */}
      {unit.threatDetails && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-slate-200 mb-3">Why Blocked</h4>
          <div className="space-y-2 text-xs">
            <div><span className="text-slate-400">Description:</span> <span className="text-slate-300">{unit.threatDetails.description || '-'}</span></div>
            <div><span className="text-slate-400">Attack Types:</span> <span className="text-slate-300">{(unit.threatDetails.attackTypes || []).join(', ') || '-'}</span></div>
            <div className="flex flex-wrap gap-4">
              <span><span className="text-slate-400">Tenant Count:</span> <span className="text-slate-300">{unit.threatDetails.tenantCount || 0}</span></span>
              <span><span className="text-slate-400">Global Events:</span> <span className="text-slate-300">{(unit.threatDetails.events || 0).toLocaleString()}</span></span>
              <span><span className="text-slate-400">High Accuracy Sigs:</span> <span className="text-slate-300">{unit.threatDetails.highAccuracySignatures || 0}</span></span>
              <span><span className="text-slate-400">TLS Events:</span> <span className="text-slate-300">{unit.threatDetails.tlsCount || 0}</span></span>
              <span><span className="text-slate-400">Malicious Bot Events:</span> <span className="text-slate-300">{unit.threatDetails.maliciousBotEvents || 0}</span></span>
            </div>
          </div>
        </div>
      )}

      {/* FP Assessment — Reasons */}
      {unit.reasons && unit.reasons.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-slate-200 mb-3">FP Assessment Signals</h4>
          <div className="space-y-1">
            {unit.reasons.map((reason, i) => {
              const isFP = reason.startsWith('+') || reason.toLowerCase().includes('benign') || reason.toLowerCase().includes('cdn') || reason.toLowerCase().includes('proxy');
              const isTP = reason.startsWith('-') || reason.toLowerCase().includes('exploit') || reason.toLowerCase().includes('malicious') || reason.toLowerCase().includes('scripting');
              return (
                <div key={i} className={`text-xs px-2 py-1 rounded ${isFP ? 'bg-red-500/10 text-red-400' : isTP ? 'bg-emerald-500/10 text-emerald-400' : 'text-slate-400'}`}>
                  {reason}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Paths Accessed */}
      {topPaths.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-slate-200 mb-3">Paths Accessed</h4>
          <table className="w-full text-xs">
            <thead><tr className="text-slate-400 border-b border-slate-700">
              <th className="text-left py-1 pr-2">Path</th>
              <th className="text-right py-1 w-20">Requests</th>
            </tr></thead>
            <tbody>
              {topPaths.map(([path, count], i) => (
                <tr key={i} className="border-b border-slate-700/50">
                  <td className="py-1 pr-2 text-slate-300 font-mono truncate max-w-md">{path}</td>
                  <td className="py-1 text-right text-slate-400">{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Response Codes */}
      {topRspCodes.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-slate-200 mb-3">Response Codes</h4>
          <div className="flex flex-wrap gap-2">
            {topRspCodes.map(([code, count]) => (
              <span key={code} className={`px-2 py-1 text-xs rounded ${
                code.startsWith('2') ? 'bg-emerald-500/20 text-emerald-400'
                : code.startsWith('3') ? 'bg-blue-500/20 text-blue-400'
                : code.startsWith('4') ? 'bg-yellow-500/20 text-yellow-400'
                : 'bg-red-500/20 text-red-400'
              }`}>{code}: {count}</span>
            ))}
          </div>
        </div>
      )}

      {/* Access Log Behavioral Analysis — auto-enriched or on-demand */}
      {(unit.totalRequestsOnApp > 0 || enrichResult) ? (
        <div className="bg-slate-800/50 border border-emerald-700/50 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-emerald-300 mb-3">Access Log Behavioral Analysis</h4>
          <div className="grid grid-cols-4 gap-3 mb-3">
            <div className="bg-slate-900/50 rounded-lg p-3 text-center">
              <div className="text-lg font-bold text-slate-100">
                {(enrichResult?.totalAccessLogRequests ?? unit.totalRequestsOnApp ?? 0).toLocaleString()}
              </div>
              <div className="text-xs text-slate-400">Total Requests</div>
            </div>
            <div className="bg-slate-900/50 rounded-lg p-3 text-center">
              <div className="text-lg font-bold text-slate-100">
                {enrichResult ? `${(enrichResult.successRate * 100).toFixed(1)}%` : '—'}
              </div>
              <div className="text-xs text-slate-400">Success Rate</div>
            </div>
            <div className="bg-slate-900/50 rounded-lg p-3 text-center">
              <div className="text-lg font-bold text-slate-100">
                {enrichResult ? enrichResult.avgRequestsPerHour.toFixed(1) : '—'}
              </div>
              <div className="text-xs text-slate-400">Avg Req/Hour</div>
            </div>
            <div className="bg-slate-900/50 rounded-lg p-3 text-center">
              <div className="text-lg font-bold text-slate-100">
                {enrichResult ? `${enrichResult.timeSpanHours.toFixed(1)}h` : '—'}
              </div>
              <div className="text-xs text-slate-400">Time Span</div>
            </div>
          </div>
          {enrichResult?.updatedReasons && enrichResult.updatedReasons.length > 0 && (
            <div className="space-y-1 mt-2">
              {enrichResult.updatedReasons.map((r, i) => (
                <div key={i} className="text-xs text-slate-400 px-2 py-1 bg-slate-900/30 rounded">{r}</div>
              ))}
            </div>
          )}
          {enrichResult && (
            <div className="mt-3 flex items-center gap-2">
              <span className="text-xs text-slate-400">Updated Verdict:</span>
              <VerdictBadge verdict={enrichResult.updatedVerdict} />
              <span className="text-xs text-slate-500 ml-2">Score: {enrichResult.updatedScore}</span>
            </div>
          )}
        </div>
      ) : (
        <div className="bg-slate-800/50 border border-blue-700/50 rounded-xl p-5 mb-4">
          <h4 className="text-sm font-semibold text-blue-300 mb-2">Load Access Logs for This IP</h4>
          <p className="text-xs text-slate-400 mb-3">
            Fetch access logs to analyze behavioral patterns — request rate, success rate, browsing patterns.
          </p>
          <button onClick={onEnrich} disabled={enriching}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-600 text-white rounded-lg text-sm transition-colors"
          >{enriching ? 'Loading Access Logs...' : 'Load Access Logs for This IP'}</button>
        </div>
      )}

      {/* Suggested Action */}
      {unit.suggestedAction && (
        <div className="bg-blue-600/10 border border-blue-600/30 rounded-xl p-4 mb-4">
          <span className="text-sm font-semibold text-blue-300">
            Suggested: {unit.suggestedAction === 'trusted_client' ? 'Add as Trusted Client' : 'No Action Needed'}
          </span>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// MAIN PAGE COMPONENT
// ═══════════════════════════════════════════════════════════════

type Phase = 'idle' | 'collecting' | 'summary' | 'detail' | 'viol-detail' | 'tm-detail';

export default function FPAnalyzer() {
  const navigate = useNavigate();
  const { tenant } = useApp();
  const toast = useToast();

  // ── Namespace + LB selection ──
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [selectedNs, setSelectedNs] = useState('');
  const [loadBalancers, setLoadBalancers] = useState<LoadBalancer[]>([]);
  const [selectedLb, setSelectedLb] = useState('');
  const [domains, setDomains] = useState<string[]>([]);

  // ── Analysis config ──
  const [hoursBack, setHoursBack] = useState(168);
  const [mode, setMode] = useState<AnalysisMode>('quick');
  const [scopes, setScopes] = useState<AnalysisScope[]>(['waf_signatures', 'waf_violations', 'threat_mesh', 'service_policy']);
  const [configExpanded, setConfigExpanded] = useState(true);

  // ── Job state ──
  const [phase, setPhase] = useState<Phase>('idle');
  const [jobId, setJobId] = useState<string | null>(null);
  const [progress, setProgress] = useState<ProgressiveJobProgress | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Summary + Detail ──
  const [summary, setSummary] = useState<SummaryResult | null>(null);
  const [selectedSigId, setSelectedSigId] = useState<string | null>(null);
  const [sigDetail, setSigDetail] = useState<SignatureAnalysisUnit | null>(null);
  const [enriching, setEnriching] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);

  // ── Violation Detail ──
  const [selectedViolName, setSelectedViolName] = useState<string | null>(null);
  const [violDetail, setViolDetail] = useState<ViolationAnalysisUnit | null>(null);
  const [violDetailLoading, setViolDetailLoading] = useState(false);

  // ── Threat Mesh Detail ──
  const [selectedTMIP, setSelectedTMIP] = useState<string | null>(null);
  const [tmDetail, setTmDetail] = useState<ThreatMeshAnalysisUnit | null>(null);
  const [tmDetailLoading, setTmDetailLoading] = useState(false);
  const [tmEnriching, setTmEnriching] = useState(false);
  const [tmEnrichResult, setTmEnrichResult] = useState<ThreatMeshEnrichmentResult | null>(null);

  // ── Export state ──
  const [exportingPdf, setExportingPdf] = useState(false);

  // ── Review state ──
  const [reviewStatus, setReviewStatus] = useState<Record<string, 'confirmed_fp' | 'confirmed_tp' | 'skipped'>>({});

  // ── Summary sorting ──
  const [sortField, setSortField] = useState<'events' | 'users' | 'paths' | 'verdict'>('verdict');

  // ── Export ──
  const [copied, setCopied] = useState(false);
  const [generatingPolicy, setGeneratingPolicy] = useState(false);

  // ── Section expansion ──
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    signatures: true,
    violations: true,
    threatMesh: true,
    policyRules: true,
  });
  const toggleSection = (key: string) => setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));

  // ── Fetch namespaces ──
  useEffect(() => {
    if (!tenant) return;
    apiClient.getNamespaces().then((data: { items: Namespace[] }) => {
      setNamespaces(data.items || []);
    }).catch(() => {});
  }, [tenant]);

  // ── Fetch LBs when namespace changes ──
  useEffect(() => {
    if (!selectedNs) { setLoadBalancers([]); return; }
    apiClient.getLoadBalancers(selectedNs).then((data: { items: LoadBalancer[] }) => {
      setLoadBalancers(data.items || []);
    }).catch(() => {});
  }, [selectedNs]);

  // ── Update domains when LB changes ──
  useEffect(() => {
    const lb = loadBalancers.find(l => l.name === selectedLb);
    setDomains(lb?.spec?.domains || []);
  }, [selectedLb, loadBalancers]);

  // ── Toggle scope ──
  const toggleScope = (scope: AnalysisScope) => {
    setScopes(prev => prev.includes(scope) ? prev.filter(s => s !== scope) : [...prev, scope]);
  };

  // ── Cleanup polling ──
  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  // ═══════════════════════════════════════════════════════════════
  // START ANALYSIS
  // ═══════════════════════════════════════════════════════════════

  const startAnalysis = useCallback(async () => {
    if (!selectedNs || !selectedLb) {
      toast.error('Select a namespace and load balancer');
      return;
    }

    const token = apiClient.getToken();
    const tenantName = tenant;
    if (!token || !tenantName) {
      toast.error('Not authenticated — set your API token first');
      return;
    }

    setPhase('collecting');
    setProgress(null);
    setSummary(null);
    setSelectedSigId(null);
    setSigDetail(null);
    setReviewStatus({});
    setConfigExpanded(false);

    try {
      const res = await fetch('/api/fp-analyzer/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tenant: tenantName,
          token,
          namespace: selectedNs,
          lbName: selectedLb,
          domains,
          scopes,
          hoursBack,
          mode,
        }),
      });
      const data = await res.json();
      if (!data.jobId) throw new Error(data.error || 'No jobId returned');

      setJobId(data.jobId);

      // Start polling
      let summaryFetched = false;
      pollRef.current = setInterval(async () => {
        try {
          const pRes = await fetch(`/api/fp-analyzer/progress/${data.jobId}`);
          const prog: ProgressiveJobProgress = await pRes.json();
          setProgress(prog);

          if ((prog.status === 'summary_ready' || prog.status === 'enriching' || prog.status === 'complete') && !summaryFetched) {
            // Summary is ready — fetch it and show to user
            summaryFetched = true;
            const sRes = await fetch(`/api/fp-analyzer/summary/${data.jobId}`);
            const summaryData: SummaryResult = await sRes.json();
            setSummary(summaryData);
            setPhase('summary');
          }

          // Check if any enrichment is still ongoing (hybrid or TM-only)
          const hybridEnriching = prog.hybridEnrichPhase && prog.hybridEnrichPhase !== 'complete';
          const tmEnriching = prog.tmEnrichTotal && prog.tmEnrichTotal > 0 && prog.tmEnrichCompleted !== undefined && prog.tmEnrichCompleted < prog.tmEnrichTotal;
          const anyEnriching = hybridEnriching || tmEnriching;

          // Re-fetch summary periodically during enrichment to show updated scores
          if (summaryFetched && anyEnriching) {
            const sRes = await fetch(`/api/fp-analyzer/summary/${data.jobId}`);
            const updatedSummary: SummaryResult = await sRes.json();
            setSummary(updatedSummary);
          }

          if (summaryFetched && !anyEnriching && prog.status === 'complete') {
            // Everything done — final re-fetch and stop polling
            if (pollRef.current) clearInterval(pollRef.current);
            pollRef.current = null;

            const sRes = await fetch(`/api/fp-analyzer/summary/${data.jobId}`);
            const updatedSummary: SummaryResult = await sRes.json();
            setSummary(updatedSummary);
          }

          if (prog.status === 'error') {
            if (pollRef.current) clearInterval(pollRef.current);
            pollRef.current = null;
            toast.error(prog.error || 'Analysis failed');
            setPhase('idle');
          }
        } catch {
          // Ignore polling errors
        }
      }, 2000);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to start analysis');
      setPhase('idle');
    }
  }, [selectedNs, selectedLb, tenant, domains, scopes, hoursBack, mode, toast]);

  // ═══════════════════════════════════════════════════════════════
  // SELECT SIGNATURE → LOAD DETAIL
  // ═══════════════════════════════════════════════════════════════

  const selectSignature = useCallback(async (sigId: string) => {
    if (!jobId) return;
    setSelectedSigId(sigId);
    setPhase('detail');
    setSigDetail(null);
    setDetailLoading(true);

    try {
      const res = await fetch(`/api/fp-analyzer/detail/${jobId}/signature/${sigId}`);
      const detail: SignatureAnalysisUnit = await res.json();
      setSigDetail(detail);
    } catch (err) {
      toast.error('Failed to load signature detail');
    } finally {
      setDetailLoading(false);
    }
  }, [jobId, toast]);

  // ═══════════════════════════════════════════════════════════════
  // ENRICH WITH ACCESS LOGS
  // ═══════════════════════════════════════════════════════════════

  const enrichSignature = useCallback(async (paths: string[]) => {
    if (!jobId || !selectedSigId) return;
    setEnriching(true);

    try {
      const res = await fetch(`/api/fp-analyzer/enrich/${jobId}/signature/${selectedSigId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ paths }),
      });
      await res.json(); // EnrichmentResult

      // Reload the detail
      const detRes = await fetch(`/api/fp-analyzer/detail/${jobId}/signature/${selectedSigId}`);
      const updated: SignatureAnalysisUnit = await detRes.json();
      setSigDetail(updated);
      toast.success('Access logs loaded — signals updated');
    } catch (err) {
      toast.error('Failed to load access logs');
    } finally {
      setEnriching(false);
    }
  }, [jobId, selectedSigId, toast]);

  // ═══════════════════════════════════════════════════════════════
  // SELECT VIOLATION → LOAD DETAIL
  // ═══════════════════════════════════════════════════════════════

  const selectViolation = useCallback(async (violName: string) => {
    if (!jobId) return;
    setSelectedViolName(violName);
    setPhase('viol-detail');
    setViolDetail(null);
    setViolDetailLoading(true);

    try {
      const res = await fetch(`/api/fp-analyzer/detail/${jobId}/violation/${encodeURIComponent(violName)}`);
      const detail: ViolationAnalysisUnit = await res.json();
      setViolDetail(detail);
    } catch (err) {
      toast.error('Failed to load violation detail');
    } finally {
      setViolDetailLoading(false);
    }
  }, [jobId, toast]);

  // ═══════════════════════════════════════════════════════════════
  // SELECT THREAT MESH IP → LOAD DETAIL
  // ═══════════════════════════════════════════════════════════════

  const selectThreatMeshIP = useCallback(async (srcIp: string) => {
    if (!jobId) return;
    setSelectedTMIP(srcIp);
    setPhase('tm-detail');
    setTmDetail(null);
    setTmEnrichResult(null);
    setTmDetailLoading(true);

    try {
      const res = await fetch(`/api/fp-analyzer/detail/${jobId}/threat-mesh/${encodeURIComponent(srcIp)}`);
      const detail: ThreatMeshAnalysisUnit = await res.json();
      setTmDetail(detail);
    } catch {
      toast.error('Failed to load threat mesh detail');
    } finally {
      setTmDetailLoading(false);
    }
  }, [jobId, toast]);

  const enrichThreatMeshIP = useCallback(async () => {
    if (!jobId || !selectedTMIP) return;
    setTmEnriching(true);

    try {
      const res = await fetch(`/api/fp-analyzer/enrich/${jobId}/threat-mesh/${encodeURIComponent(selectedTMIP)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      const result: ThreatMeshEnrichmentResult = await res.json();
      setTmEnrichResult(result);

      // Reload detail with updated data
      const detRes = await fetch(`/api/fp-analyzer/detail/${jobId}/threat-mesh/${encodeURIComponent(selectedTMIP)}`);
      const updated: ThreatMeshAnalysisUnit = await detRes.json();
      setTmDetail(updated);
      toast.success('Access logs loaded — verdict updated');
    } catch {
      toast.error('Failed to enrich threat mesh IP');
    } finally {
      setTmEnriching(false);
    }
  }, [jobId, selectedTMIP, toast]);

  // ═══════════════════════════════════════════════════════════════
  // EXPORT PDF / EXCEL
  // ═══════════════════════════════════════════════════════════════

  // Fetch all signature/violation details for reports
  const fetchAllDetails = useCallback(async () => {
    if (!jobId || !summary) return { sigDetails: [] as SignatureAnalysisUnit[], violDetails: [] as ViolationAnalysisUnit[], tmDetails: [] as ThreatMeshAnalysisUnit[] };

    const sigDetails: SignatureAnalysisUnit[] = [];
    const violDetails: ViolationAnalysisUnit[] = [];
    let tmDetails: ThreatMeshAnalysisUnit[] = [];

    if (scopes.includes('waf_signatures')) {
      const sigPromises = summary.signatures.slice(0, 30).map(async (sig) => {
        const res = await fetch(`/api/fp-analyzer/detail/${jobId}/signature/${encodeURIComponent(sig.sigId)}`);
        return res.json() as Promise<SignatureAnalysisUnit>;
      });
      sigDetails.push(...await Promise.all(sigPromises));
    }

    if (scopes.includes('waf_violations')) {
      const violPromises = summary.violations.slice(0, 30).map(async (v) => {
        const res = await fetch(`/api/fp-analyzer/detail/${jobId}/violation/${encodeURIComponent(v.violationName)}`);
        return res.json() as Promise<ViolationAnalysisUnit>;
      });
      violDetails.push(...await Promise.all(violPromises));
    }

    if (scopes.includes('threat_mesh') && summary.threatMeshIPs.length > 0) {
      const tmPromises = summary.threatMeshIPs.slice(0, 20).map(async (ip) => {
        const res = await fetch(`/api/fp-analyzer/detail/${jobId}/threat-mesh/${encodeURIComponent(ip.srcIp)}`);
        return res.json() as Promise<ThreatMeshAnalysisUnit>;
      });
      tmDetails = await Promise.all(tmPromises);
    }

    return { sigDetails, violDetails, tmDetails };
  }, [jobId, summary, scopes]);

  const buildExclusionPolicy = useCallback((sigDetails: SignatureAnalysisUnit[]) => {
    const allRules: WafExclusionRule[] = [];
    for (const unit of sigDetails) {
      if (unit.pathAnalyses) {
        allRules.push(...generatePerPathExclusions(unit));
      }
    }
    if (allRules.length === 0) return undefined;
    return buildWafExclusionPolicy(selectedLb, selectedNs, allRules);
  }, [selectedLb, selectedNs]);

  const downloadPDF = useCallback(async () => {
    if (!summary) return;
    setExportingPdf(true);
    try {
      const { sigDetails, violDetails, tmDetails } = await fetchAllDetails();
      const exclusionPolicy = buildExclusionPolicy(sigDetails);

      generateFPAnalysisPDF({
        summary,
        scopes,
        namespace: selectedNs,
        lbName: selectedLb,
        mode,
        threatMeshDetails: tmDetails,
        signatureDetails: sigDetails,
        violationDetails: violDetails,
        exclusionPolicy,
      });
      toast.success('PDF report downloaded');
    } catch (err) {
      toast.error('Failed to generate PDF');
    } finally {
      setExportingPdf(false);
    }
  }, [summary, scopes, selectedNs, selectedLb, mode, fetchAllDetails, buildExclusionPolicy, toast]);

  const downloadExcel = useCallback(async () => {
    if (!summary) return;
    try {
      const { sigDetails, violDetails, tmDetails } = await fetchAllDetails();
      const exclusionPolicy = buildExclusionPolicy(sigDetails);

      generateFPAnalysisExcel({
        summary,
        scopes,
        namespace: selectedNs,
        lbName: selectedLb,
        mode,
        threatMeshDetails: tmDetails,
        signatureDetails: sigDetails,
        violationDetails: violDetails,
        exclusionPolicy,
      });
      toast.success('Excel report downloaded');
    } catch {
      toast.error('Failed to generate Excel');
    }
  }, [summary, scopes, selectedNs, selectedLb, mode, fetchAllDetails, buildExclusionPolicy, toast]);

  const downloadExclusionPolicy = useCallback(async () => {
    if (!summary || !jobId) return;
    try {
      const { sigDetails } = await fetchAllDetails();
      const policy = buildExclusionPolicy(sigDetails);
      if (!policy) {
        toast.error('No FP paths found for exclusion rules');
        return;
      }
      const clean = cleanPolicyForExport(policy);
      const json = JSON.stringify(clean, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `waf-exclusion-policy-${selectedLb}-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success('WAF exclusion policy downloaded');
    } catch {
      toast.error('Failed to generate exclusion policy');
    }
  }, [summary, jobId, fetchAllDetails, buildExclusionPolicy, selectedLb, toast]);

  // ═══════════════════════════════════════════════════════════════
  // NAVIGATION
  // ═══════════════════════════════════════════════════════════════

  const sortedSignatures = summary ? getSortedSignatures(summary.signatures, sortField) : [];

  const currentSigIdx = selectedSigId ? sortedSignatures.findIndex(s => s.sigId === selectedSigId) : -1;

  const goToNext = useCallback(() => {
    if (currentSigIdx < sortedSignatures.length - 1) {
      selectSignature(sortedSignatures[currentSigIdx + 1].sigId);
    }
  }, [currentSigIdx, sortedSignatures, selectSignature]);

  const goToPrev = useCallback(() => {
    if (currentSigIdx > 0) {
      selectSignature(sortedSignatures[currentSigIdx - 1].sigId);
    }
  }, [currentSigIdx, sortedSignatures, selectSignature]);

  const violationsList = summary?.violations || [];
  const currentViolIdx = selectedViolName ? violationsList.findIndex(v => v.violationName === selectedViolName) : -1;

  const goToNextViol = useCallback(() => {
    if (currentViolIdx < violationsList.length - 1) selectViolation(violationsList[currentViolIdx + 1].violationName);
  }, [currentViolIdx, violationsList, selectViolation]);

  const goToPrevViol = useCallback(() => {
    if (currentViolIdx > 0) selectViolation(violationsList[currentViolIdx - 1].violationName);
  }, [currentViolIdx, violationsList, selectViolation]);

  const tmIPs = summary?.threatMeshIPs || [];
  const currentTMIdx = selectedTMIP ? tmIPs.findIndex(ip => ip.srcIp === selectedTMIP) : -1;

  const goToNextTM = useCallback(() => {
    if (currentTMIdx < tmIPs.length - 1) selectThreatMeshIP(tmIPs[currentTMIdx + 1].srcIp);
  }, [currentTMIdx, tmIPs, selectThreatMeshIP]);

  const goToPrevTM = useCallback(() => {
    if (currentTMIdx > 0) selectThreatMeshIP(tmIPs[currentTMIdx - 1].srcIp);
  }, [currentTMIdx, tmIPs, selectThreatMeshIP]);

  // ═══════════════════════════════════════════════════════════════
  // CANCEL
  // ═══════════════════════════════════════════════════════════════

  const cancelJob = useCallback(async () => {
    if (!jobId) return;
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    try { await fetch(`/api/fp-analyzer/cancel/${jobId}`, { method: 'POST' }); } catch {}
    setPhase('idle');
    toast.info('Analysis cancelled');
  }, [jobId, toast]);

  // ═══════════════════════════════════════════════════════════════
  // BATCH ACTIONS
  // ═══════════════════════════════════════════════════════════════

  const markAllHighFPAsConfirmed = () => {
    if (!summary) return;
    const updates: Record<string, 'confirmed_fp'> = {};
    for (const sig of summary.signatures) {
      if (sig.quickVerdict === 'likely_fp' && sig.quickConfidence === 'high') {
        updates[sig.sigId] = 'confirmed_fp';
      }
    }
    setReviewStatus(prev => ({ ...prev, ...updates }));
    toast.success(`Marked ${Object.keys(updates).length} signatures as confirmed FP`);
  };

  const generateExclusionPolicy = useCallback(async () => {
    if (!jobId) return;
    const confirmedFPIds = Object.entries(reviewStatus)
      .filter(([, status]) => status === 'confirmed_fp')
      .map(([sigId]) => sigId);

    if (confirmedFPIds.length === 0) {
      toast.error('No signatures marked as confirmed FP');
      return;
    }

    setGeneratingPolicy(true);
    try {
      const res = await fetch(`/api/fp-analyzer/exclusion/${jobId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sigIds: confirmedFPIds }),
      });
      const policy: WafExclusionPolicyObject = await res.json();
      const json = JSON.stringify(policy, null, 2);
      await navigator.clipboard.writeText(json);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      toast.success(`Exclusion policy copied (${policy.spec.waf_exclusion_rules.length} rules)`);
    } catch (err) {
      toast.error('Failed to generate exclusion policy');
    } finally {
      setGeneratingPolicy(false);
    }
  }, [jobId, reviewStatus, toast]);

  // ═══════════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════════

  const confirmedFPCount = Object.values(reviewStatus).filter(v => v === 'confirmed_fp').length;
  const confirmedTPCount = Object.values(reviewStatus).filter(v => v === 'confirmed_tp').length;
  const unreviewed = (summary?.signatures.length || 0) - confirmedFPCount - confirmedTPCount;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-6 h-6 text-blue-400" />
          <div>
            <h1 className="text-xl font-bold text-slate-100">FP Analyzer</h1>
            <p className="text-xs text-slate-400">Progressive False Positive Analysis</p>
          </div>
          <Link to="/explainer/fp-analyzer" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
            <HelpCircle className="w-3.5 h-3.5" /> How does this work?
          </Link>
        </div>
        <button onClick={() => navigate('/')} className="text-xs text-slate-400 hover:text-slate-200">
          &larr; Back to Apps
        </button>
      </div>

      {/* ── Configuration Section ── */}
      <Section title="Analysis Configuration" icon={Target} expanded={configExpanded} onToggle={() => setConfigExpanded(!configExpanded)}>
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Namespace</label>
            <SearchableSelect
              value={selectedNs} onChange={setSelectedNs}
              options={namespaces.map(n => ({ value: n.name, label: n.name }))}
              placeholder="Select namespace..."
              disabled={phase !== 'idle'}
            />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Load Balancer</label>
            <SearchableSelect
              value={selectedLb} onChange={setSelectedLb}
              options={loadBalancers.map(l => ({ value: l.name, label: l.name }))}
              placeholder="Select load balancer..."
              disabled={phase !== 'idle' || !selectedNs}
            />
          </div>
        </div>

        {/* Time range */}
        <div className="mb-4">
          <label className="block text-xs text-slate-400 mb-1">Time Range</label>
          <div className="flex gap-2">
            {[24, 48, 72, 168, 336].map(h => (
              <button key={h} onClick={() => setHoursBack(h)} disabled={phase !== 'idle'}
                className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${hoursBack === h
                  ? 'bg-blue-600/30 border-blue-500 text-blue-300'
                  : 'bg-slate-800 border-slate-600 text-slate-300 hover:border-slate-500'}`}
              >{h <= 72 ? `${h}h` : `${h / 24}d`}</button>
            ))}
          </div>
        </div>

        {/* Mode selector */}
        <div className="mb-4">
          <label className="block text-xs text-slate-400 mb-1">Analysis Mode</label>
          <div className="grid grid-cols-2 gap-3">
            {([
              { value: 'quick' as AnalysisMode, label: 'Quick Mode', desc: 'Security events only', time: '~30-120 sec', icon: Zap },
              { value: 'hybrid' as AnalysisMode, label: 'Hybrid Mode', desc: 'Security + access logs (background)', time: '~3-15 min', icon: BarChart3 },
            ]).map(m => (
              <button key={m.value} onClick={() => setMode(m.value)} disabled={phase !== 'idle'}
                className={`p-3 rounded-lg border text-left transition-colors ${mode === m.value
                  ? 'bg-blue-600/20 border-blue-500'
                  : 'bg-slate-800 border-slate-600 hover:border-slate-500'}`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <m.icon className="w-3.5 h-3.5 text-blue-400" />
                  <span className="text-sm font-medium text-slate-200">{m.label}</span>
                </div>
                <p className="text-[10px] text-slate-400">{m.desc}</p>
                <p className="text-[10px] text-slate-500 mt-0.5">{m.time}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Scopes */}
        <div className="mb-4">
          <label className="block text-xs text-slate-400 mb-1">Analysis Scope</label>
          <div className="flex flex-wrap gap-2">
            {([
              { scope: 'waf_signatures' as AnalysisScope, label: 'WAF Signatures' },
              { scope: 'waf_violations' as AnalysisScope, label: 'WAF Violations' },
              { scope: 'threat_mesh' as AnalysisScope, label: 'Threat Mesh' },
              { scope: 'service_policy' as AnalysisScope, label: 'Service Policy' },
              { scope: 'bot_defense' as AnalysisScope, label: 'Bot Defense' },
              { scope: 'api_security' as AnalysisScope, label: 'API Security' },
            ]).map(s => (
              <button key={s.scope} onClick={() => toggleScope(s.scope)} disabled={phase !== 'idle'}
                className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${scopes.includes(s.scope)
                  ? 'bg-blue-600/30 border-blue-500 text-blue-300'
                  : 'bg-slate-800 border-slate-600 text-slate-400 hover:border-slate-500'}`}
              >{s.label}</button>
            ))}
          </div>
        </div>

        {/* Start button */}
        <button onClick={startAnalysis} disabled={phase !== 'idle' || !selectedNs || !selectedLb}
          className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-600 disabled:text-slate-400 text-white rounded-lg font-medium text-sm transition-colors flex items-center justify-center gap-2"
        >
          <Play className="w-4 h-4" /> Start Progressive Analysis
        </button>
      </Section>

      {/* ── Collecting Phase ── */}
      {phase === 'collecting' && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
              <span className="text-sm text-slate-200">
                {progress?.currentPhaseLabel || 'Starting analysis...'}
              </span>
            </div>
            <button onClick={cancelJob} className="text-xs text-red-400 hover:text-red-300">Cancel</button>
          </div>
          {progress ? (
            <>
              {/* Progress bar — chunks downloaded vs total */}
              {progress.totalChunks > 0 && (
                <div className="mb-4">
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-slate-400">
                      Time chunks: {progress.chunksCompleted} / {progress.totalChunks} downloaded
                    </span>
                    <span className="text-slate-400">
                      {Math.round((progress.chunksCompleted / progress.totalChunks) * 100)}%
                    </span>
                  </div>
                  <div className="w-full bg-slate-700 rounded-full h-2">
                    <div
                      className="h-2 rounded-full bg-blue-500 transition-all duration-500"
                      style={{ width: `${(progress.chunksCompleted / progress.totalChunks) * 100}%` }}
                    />
                  </div>
                  {progress.estimatedRemainingMs > 0 && (
                    <div className="text-[10px] text-slate-500 mt-1">
                      ~{Math.ceil(progress.estimatedRemainingMs / 1000)}s remaining
                    </div>
                  )}
                </div>
              )}

              {/* Stats grid */}
              <div className="grid grid-cols-4 gap-3 text-center">
                <div className="bg-slate-900/40 rounded-lg p-2.5">
                  <div className="text-lg font-bold text-slate-100">{progress.securityEventsCollected.toLocaleString()}</div>
                  <div className="text-[10px] text-slate-400">Events Downloaded</div>
                </div>
                <div className="bg-slate-900/40 rounded-lg p-2.5">
                  <div className="text-lg font-bold text-slate-100">{progress.chunksCompleted}/{progress.totalChunks}</div>
                  <div className="text-[10px] text-slate-400">Chunks Done</div>
                </div>
                <div className="bg-slate-900/40 rounded-lg p-2.5">
                  <div className="text-lg font-bold text-slate-100">{progress.signaturesFound}</div>
                  <div className="text-[10px] text-slate-400">Signatures</div>
                </div>
                <div className="bg-slate-900/40 rounded-lg p-2.5">
                  <div className="text-lg font-bold text-slate-100">{(progress.elapsedMs / 1000).toFixed(0)}s</div>
                  <div className="text-[10px] text-slate-400">Elapsed</div>
                </div>
              </div>

              {/* Adaptive state */}
              {progress.adaptiveState && (
                <div className="mt-3 flex items-center gap-2 text-xs">
                  <span className="text-slate-400">Concurrency:</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                    progress.adaptiveState === 'GREEN' ? 'bg-emerald-500/20 text-emerald-400'
                    : progress.adaptiveState === 'YELLOW' ? 'bg-yellow-500/20 text-yellow-400'
                    : 'bg-red-500/20 text-red-400'
                  }`}>{progress.adaptiveState}</span>
                  <span className="text-slate-500">{progress.adaptiveConcurrency} parallel workers</span>
                </div>
              )}
            </>
          ) : (
            <div className="mt-2">
              <div className="w-full bg-slate-700 rounded-full h-2 mb-2">
                <div className="h-2 rounded-full bg-blue-500/50 animate-pulse w-1/6" />
              </div>
              <div className="text-xs text-slate-400">Connecting to F5 XC API...</div>
            </div>
          )}
        </div>
      )}

      {/* ── Summary Phase ── */}
      {phase === 'summary' && summary && (
        <div>
          {/* Summary stats bar */}
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 mb-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4 text-xs">
                <span className="text-slate-400">{summary.totalEvents.toLocaleString()} events analyzed</span>
                {scopes.includes('waf_signatures') && summary.signatures.length > 0 && (<>
                  <span className="text-slate-600">|</span>
                  <span className="text-red-400">{summary.signatures.filter(s => s.quickVerdict === 'likely_fp').length} Likely FP</span>
                  <span className="text-yellow-400">{summary.signatures.filter(s => s.quickVerdict === 'investigate').length} Investigate</span>
                  <span className="text-emerald-400">{summary.signatures.filter(s => s.quickVerdict === 'likely_tp').length} Likely TP</span>
                </>)}
                {scopes.includes('waf_violations') && summary.violations.length > 0 && (
                  <span className="text-slate-400">{summary.violations.length} violations</span>
                )}
                {scopes.includes('threat_mesh') && summary.threatMeshIPs.length > 0 && (
                  <span className="text-slate-400">{summary.threatMeshIPs.length} threat mesh IPs</span>
                )}
                {scopes.includes('service_policy') && summary.policyRules.length > 0 && (
                  <span className="text-slate-400">{summary.policyRules.length} policy rules</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {scopes.includes('waf_signatures') && summary.signatures.length > 0 && (
                  <span className="text-xs text-slate-400 mr-2">Reviewed: {confirmedFPCount + confirmedTPCount}/{summary.signatures.length}</span>
                )}
                <button onClick={downloadPDF} disabled={exportingPdf}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 rounded-lg border border-blue-600/30 transition-colors disabled:opacity-40"
                ><Download className="w-3.5 h-3.5" />{exportingPdf ? 'Generating...' : 'PDF'}</button>
                <button onClick={downloadExcel}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 rounded-lg border border-emerald-600/30 transition-colors"
                ><FileSpreadsheet className="w-3.5 h-3.5" />Excel</button>
                <button onClick={downloadExclusionPolicy}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 rounded-lg border border-amber-600/30 transition-colors"
                  title="Download WAF Exclusion Policy JSON"
                ><Lock className="w-3.5 h-3.5" />WAF Policy</button>
              </div>
            </div>
          </div>

          {/* Enrichment progress banner */}
          {progress && progress.hybridEnrichPhase && progress.hybridEnrichPhase !== 'complete' && (
            <div className="bg-blue-900/30 border border-blue-700/50 rounded-xl p-3 mb-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-3.5 h-3.5 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
                <span className="text-xs text-blue-300">
                  {progress.hybridEnrichPhase === 'fetching_access_logs' && `Fetching access logs (${(progress.accessLogsCollected || 0).toLocaleString()} collected)...`}
                  {progress.hybridEnrichPhase === 'enriching_signatures' && `Enriching signatures (${progress.sigEnrichCompleted || 0}/${progress.sigEnrichTotal || 0})...`}
                  {progress.hybridEnrichPhase === 'enriching_violations' && `Enriching violations (${progress.violEnrichCompleted || 0}/${progress.violEnrichTotal || 0})...`}
                  {progress.hybridEnrichPhase === 'enriching_tm' && `Enriching threat mesh IPs (${progress.tmEnrichCompleted || 0}/${progress.tmEnrichTotal || 0})...`}
                </span>
                <span className="text-[10px] text-slate-500 ml-auto">You can browse results while enrichment continues</span>
              </div>
              {(() => {
                let pct = 0;
                if (progress.hybridEnrichPhase === 'fetching_access_logs') pct = 10;
                else if (progress.hybridEnrichPhase === 'enriching_signatures') pct = 25 + ((progress.sigEnrichCompleted || 0) / Math.max(progress.sigEnrichTotal || 1, 1)) * 25;
                else if (progress.hybridEnrichPhase === 'enriching_violations') pct = 50 + ((progress.violEnrichCompleted || 0) / Math.max(progress.violEnrichTotal || 1, 1)) * 20;
                else if (progress.hybridEnrichPhase === 'enriching_tm') pct = 70 + ((progress.tmEnrichCompleted || 0) / Math.max(progress.tmEnrichTotal || 1, 1)) * 30;
                return (
                  <div className="w-full bg-slate-700 rounded-full h-1.5">
                    <div className="h-1.5 rounded-full bg-blue-500 transition-all duration-500" style={{ width: `${pct}%` }} />
                  </div>
                );
              })()}
            </div>
          )}
          {/* TM-only enrichment (quick mode) */}
          {progress && !progress.hybridEnrichPhase && progress.tmEnrichTotal != null && progress.tmEnrichTotal > 0 && progress.tmEnrichCompleted != null && progress.tmEnrichCompleted < progress.tmEnrichTotal && (
            <div className="bg-blue-900/30 border border-blue-700/50 rounded-xl p-3 mb-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-3.5 h-3.5 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
                <span className="text-xs text-blue-300">
                  Enriching threat mesh IPs with access logs ({progress.tmEnrichCompleted}/{progress.tmEnrichTotal})...
                </span>
              </div>
              <div className="w-full bg-slate-700 rounded-full h-1.5">
                <div className="h-1.5 rounded-full bg-blue-500 transition-all duration-500"
                  style={{ width: `${(progress.tmEnrichCompleted / progress.tmEnrichTotal) * 100}%` }} />
              </div>
            </div>
          )}

          {/* Batch actions — only for WAF Signatures scope */}
          {scopes.includes('waf_signatures') && summary.signatures.length > 0 && (
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 mb-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <button onClick={markAllHighFPAsConfirmed}
                className="px-3 py-1.5 text-xs bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg border border-red-600/30 transition-colors"
              >Mark all "Likely FP (HIGH)" as Confirmed FP</button>
              <button onClick={generateExclusionPolicy} disabled={confirmedFPCount === 0 || generatingPolicy}
                className="px-3 py-1.5 text-xs bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 rounded-lg border border-blue-600/30 transition-colors disabled:opacity-40"
              >{copied ? 'Copied!' : `Generate Exclusion Policy (${confirmedFPCount} FPs)`}</button>
            </div>
            <div className="text-xs text-slate-500">
              {confirmedFPCount} FP, {confirmedTPCount} TP, {unreviewed} unreviewed
            </div>
          </div>
          )}

          {/* WAF Signatures section — only if scope selected */}
          {scopes.includes('waf_signatures') && (
            <Section title="WAF Signatures" icon={ShieldAlert} expanded={expandedSections.signatures} onToggle={() => toggleSection('signatures')} badge={summary.signatures.length}>
              {summary.signatures.length > 0 ? (<>
                {/* Sort controls */}
                <div className="flex items-center gap-2 mb-3 text-xs text-slate-400">
                  <span>Sort by:</span>
                  {([
                    { field: 'verdict' as const, label: 'Verdict' },
                    { field: 'events' as const, label: 'Events' },
                    { field: 'users' as const, label: 'Users' },
                    { field: 'paths' as const, label: 'Paths' },
                  ]).map(s => (
                    <button key={s.field} onClick={() => setSortField(s.field)}
                      className={`px-2 py-0.5 rounded ${sortField === s.field ? 'bg-blue-600/30 text-blue-300' : 'hover:bg-slate-700 text-slate-400'}`}
                    >{s.label}</button>
                  ))}
                </div>
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-slate-400 border-b border-slate-700">
                      <th className="text-left py-2 pr-2 w-8">#</th>
                      <th className="text-left py-2 pr-2 w-24">Sig ID</th>
                      <th className="text-left py-2 pr-2">Name</th>
                      <th className="text-right py-2 pr-2 w-16">Events</th>
                      <th className="text-right py-2 pr-2 w-16">Users</th>
                      <th className="text-right py-2 pr-2 w-16">Paths</th>
                      <th className="text-center py-2 pr-2 w-16">Accuracy</th>
                      <th className="text-right py-2 pr-2 w-16">FP Score</th>
                      <th className="text-center py-2 w-32">Verdict</th>
                      <th className="text-center py-2 w-20">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedSignatures.map((sig, idx) => {
                      const displayScore = sig.enrichedFpScore ?? sig.fpScore;
                      const displayVerdict = sig.enrichedFpVerdict ?? sig.fpVerdict;
                      const fpVCfg = VERDICT_CONFIG[displayVerdict];
                      const isEnriched = sig.enrichmentStatus === 'complete';
                      return (
                      <tr key={sig.sigId}
                        onClick={() => selectSignature(sig.sigId)}
                        className="border-b border-slate-700/50 cursor-pointer hover:bg-slate-700/30 transition-colors"
                      >
                        <td className="py-2 pr-2 text-slate-500">{idx + 1}</td>
                        <td className="py-2 pr-2 text-slate-300 font-mono">{sig.sigId}</td>
                        <td className="py-2 pr-2 text-slate-200 truncate max-w-xs">{sig.name}</td>
                        <td className="py-2 pr-2 text-right text-slate-300">{sig.totalEvents.toLocaleString()}</td>
                        <td className="py-2 pr-2 text-right text-slate-300">{sig.uniqueUsers.toLocaleString()}</td>
                        <td className="py-2 pr-2 text-right text-slate-300">{sig.uniquePaths}</td>
                        <td className="py-2 pr-2 text-center">
                          <span className={`text-[10px] ${sig.accuracy === 'high_accuracy' ? 'text-emerald-400' : sig.accuracy === 'low_accuracy' ? 'text-red-400' : 'text-yellow-400'}`}>
                            {sig.accuracy === 'high_accuracy' ? 'High' : sig.accuracy === 'low_accuracy' ? 'Low' : 'Med'}
                          </span>
                        </td>
                        <td className={`py-2 pr-2 text-right font-medium ${fpVCfg.text}`}>
                          {displayScore}%{isEnriched && <span className="text-[8px] text-blue-400 ml-0.5" title="Enriched with access logs">*</span>}
                        </td>
                        <td className="py-2 text-center">
                          <VerdictBadge verdict={displayVerdict} />
                        </td>
                        <td className="py-2 text-center">
                          {reviewStatus[sig.sigId] === 'confirmed_fp' && <span className="text-red-400 text-[10px]">FP</span>}
                          {reviewStatus[sig.sigId] === 'confirmed_tp' && <span className="text-emerald-400 text-[10px]">TP</span>}
                        </td>
                      </tr>
                      );
                    })}
                  </tbody>
                </table>
              </>) : (
                <p className="text-sm text-slate-500 py-3">No WAF signature events found in the analyzed data.</p>
              )}
            </Section>
          )}

          {/* Violations summary — only if scope selected */}
          {scopes.includes('waf_violations') && (
            <Section title="WAF Violations" icon={AlertTriangle} expanded={expandedSections.violations} onToggle={() => toggleSection('violations')} badge={summary.violations.length}>
              {summary.violations.length > 0 ? (
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-slate-400 border-b border-slate-700">
                      <th className="text-left py-2 pr-2">Violation</th>
                      <th className="text-right py-2 pr-2 w-16">Events</th>
                      <th className="text-right py-2 pr-2 w-16">Users</th>
                      <th className="text-right py-2 pr-2 w-16">FP Score</th>
                      <th className="text-center py-2 w-32">Verdict</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.violations.map(v => {
                      const vDisplayScore = v.enrichedFpScore ?? v.fpScore;
                      const vDisplayVerdict = v.enrichedFpVerdict ?? v.fpVerdict;
                      const vVCfg = VERDICT_CONFIG[vDisplayVerdict];
                      const vIsEnriched = v.enrichmentStatus === 'complete';
                      return (
                      <tr key={v.violationName}
                        onClick={() => selectViolation(v.violationName)}
                        className="border-b border-slate-700/50 cursor-pointer hover:bg-slate-700/30 transition-colors"
                      >
                        <td className="py-2 pr-2 text-slate-200">{v.violationName}</td>
                        <td className="py-2 pr-2 text-right text-slate-300">{v.totalEvents.toLocaleString()}</td>
                        <td className="py-2 pr-2 text-right text-slate-300">{v.uniqueUsers}</td>
                        <td className={`py-2 pr-2 text-right font-medium ${vVCfg.text}`}>
                          {vDisplayScore}%{vIsEnriched && <span className="text-[8px] text-blue-400 ml-0.5" title="Enriched with access logs">*</span>}
                        </td>
                        <td className="py-2 text-center">
                          <VerdictBadge verdict={vDisplayVerdict} />
                        </td>
                      </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <p className="text-sm text-slate-500 py-3">No WAF violation events found in the analyzed data.</p>
              )}
            </Section>
          )}

          {/* Threat Mesh summary — only if scope selected */}
          {scopes.includes('threat_mesh') && (
            <Section title="Threat Mesh IPs" icon={Globe} expanded={expandedSections.threatMesh} onToggle={() => toggleSection('threatMesh')} badge={summary.threatMeshIPs.length}>
              {summary.threatMeshIPs.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-slate-400 border-b border-slate-700">
                        <th className="text-left py-2 pr-2 w-8">#</th>
                        <th className="text-left py-2 pr-2">Source IP</th>
                        <th className="text-left py-2 pr-2 w-16">Country</th>
                        <th className="text-left py-2 pr-2">AS Org</th>
                        <th className="text-right py-2 pr-2 w-16">Sec Events</th>
                        <th className="text-right py-2 pr-2 w-16">Access Reqs</th>
                        <th className="text-right py-2 pr-2 w-16">Success%</th>
                        <th className="text-right py-2 pr-2 w-14">Paths</th>
                        <th className="text-right py-2 pr-2 w-14">Tenants</th>
                        <th className="text-center py-2 pr-2 w-16">Action</th>
                        <th className="text-left py-2 pr-2">User Agent</th>
                        <th className="text-center py-2 w-32">Verdict</th>
                      </tr>
                    </thead>
                    <tbody>
                      {summary.threatMeshIPs.map((ip, idx) => (
                        <tr key={ip.srcIp}
                          onClick={() => selectThreatMeshIP(ip.srcIp)}
                          className="border-b border-slate-700/50 cursor-pointer hover:bg-slate-700/30 transition-colors"
                        >
                          <td className="py-2 pr-2 text-slate-500">{idx + 1}</td>
                          <td className="py-2 pr-2 text-slate-300 font-mono">{ip.srcIp}</td>
                          <td className="py-2 pr-2 text-slate-300">{ip.country || '-'}</td>
                          <td className="py-2 pr-2 text-slate-400 truncate max-w-[150px]">{ip.asOrg || '-'}</td>
                          <td className="py-2 pr-2 text-right text-slate-300">{ip.eventCount.toLocaleString()}</td>
                          <td className="py-2 pr-2 text-right text-slate-300">
                            {ip.accessLogRequests != null ? ip.accessLogRequests.toLocaleString() : <span className="text-slate-600">—</span>}
                          </td>
                          <td className="py-2 pr-2 text-right">
                            {ip.successRate != null ? (
                              <span className={ip.successRate > 0.8 ? 'text-emerald-400' : ip.successRate < 0.3 ? 'text-red-400' : 'text-yellow-400'}>
                                {(ip.successRate * 100).toFixed(0)}%
                              </span>
                            ) : <span className="text-slate-600">—</span>}
                          </td>
                          <td className="py-2 pr-2 text-right text-slate-300">{ip.paths}</td>
                          <td className="py-2 pr-2 text-right text-slate-300">{ip.tenantCount || 0}</td>
                          <td className="py-2 pr-2 text-center">
                            <span className={`px-1.5 py-0.5 text-[10px] rounded ${
                              ip.action === 'block' ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400'
                            }`}>{ip.action || '-'}</span>
                          </td>
                          <td className="py-2 pr-2 text-slate-400 truncate max-w-[150px]">{ip.userAgent || '-'}</td>
                          <td className="py-2 text-center">
                            {ip.enrichedVerdict ? (
                              <VerdictBadge verdict={ip.enrichedVerdict} />
                            ) : (
                              <QuickVerdictBadge verdict={ip.quickVerdict} confidence={ip.quickConfidence} />
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-sm text-slate-500 py-3">No threat mesh events found in the analyzed data.</p>
              )}
            </Section>
          )}

          {/* Policy Rules summary — only if scope selected */}
          {scopes.includes('service_policy') && (
            <Section title="Service Policy Rules" icon={Lock} expanded={expandedSections.policyRules} onToggle={() => toggleSection('policyRules')} badge={summary.policyRules.length}>
              {summary.policyRules.length > 0 ? (
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-slate-400 border-b border-slate-700">
                      <th className="text-left py-2 pr-2">Rule</th>
                      <th className="text-left py-2 pr-2">Policy</th>
                      <th className="text-right py-2 pr-2 w-16">Blocked</th>
                      <th className="text-right py-2 w-16">IPs</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.policyRules.map(r => (
                      <tr key={r.ruleName} className="border-b border-slate-700/50">
                        <td className="py-2 pr-2 text-slate-200">{r.ruleName}</td>
                        <td className="py-2 pr-2 text-slate-400">{r.policyName}</td>
                        <td className="py-2 pr-2 text-right text-slate-300">{r.totalBlocked}</td>
                        <td className="py-2 text-right text-slate-300">{r.uniqueIPs}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="text-sm text-slate-500 py-3">No service policy events found in the analyzed data.</p>
              )}
            </Section>
          )}
        </div>
      )}

      {/* ── Signature Detail Phase ── */}
      {phase === 'detail' && (
        <div>
          {detailLoading && !sigDetail && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 text-center">
              <div className="w-6 h-6 border-2 border-blue-400 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
              <p className="text-sm text-slate-400">Loading signature detail...</p>
            </div>
          )}
          {sigDetail && (
            <SignatureDetailView
              unit={sigDetail}
              onEnrich={enrichSignature}
              enriching={enriching}
              onBack={() => setPhase('summary')}
              onPrev={goToPrev}
              onNext={goToNext}
              currentIdx={currentSigIdx}
              totalCount={sortedSignatures.length}
              onMarkFP={() => {
                setReviewStatus(prev => ({ ...prev, [sigDetail.signatureId]: 'confirmed_fp' }));
                toast.success(`Signature ${sigDetail.signatureId} marked as FP`);
              }}
              onMarkTP={() => {
                setReviewStatus(prev => ({ ...prev, [sigDetail.signatureId]: 'confirmed_tp' }));
                toast.info(`Signature ${sigDetail.signatureId} marked as TP`);
              }}
            />
          )}
        </div>
      )}

      {/* ── Violation Detail Phase ── */}
      {phase === 'viol-detail' && (
        <div>
          {violDetailLoading && !violDetail && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 text-center">
              <div className="w-6 h-6 border-2 border-blue-400 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
              <p className="text-sm text-slate-400">Loading violation detail...</p>
            </div>
          )}
          {violDetail && (
            <ViolationDetailView
              unit={violDetail}
              onBack={() => setPhase('summary')}
              onPrev={goToPrevViol}
              onNext={goToNextViol}
              currentIdx={currentViolIdx}
              totalCount={violationsList.length}
            />
          )}
        </div>
      )}

      {/* ── Threat Mesh Detail Phase ── */}
      {phase === 'tm-detail' && (
        <div>
          {tmDetailLoading && !tmDetail && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 text-center">
              <div className="w-6 h-6 border-2 border-blue-400 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
              <p className="text-sm text-slate-400">Loading threat mesh IP detail...</p>
            </div>
          )}
          {tmDetail && (
            <ThreatMeshDetailView
              unit={tmDetail}
              onEnrich={enrichThreatMeshIP}
              enriching={tmEnriching}
              enrichResult={tmEnrichResult}
              onBack={() => setPhase('summary')}
              onPrev={goToPrevTM}
              onNext={goToNextTM}
              currentIdx={currentTMIdx}
              totalCount={tmIPs.length}
            />
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SORTING HELPER
// ═══════════════════════════════════════════════════════════════

function getSortedSignatures(sigs: SignatureSummary[], sortField: string): SignatureSummary[] {
  const sorted = [...sigs];
  switch (sortField) {
    case 'events':
      sorted.sort((a, b) => b.totalEvents - a.totalEvents);
      break;
    case 'users':
      sorted.sort((a, b) => b.uniqueUsers - a.uniqueUsers);
      break;
    case 'paths':
      sorted.sort((a, b) => b.uniquePaths - a.uniquePaths);
      break;
    case 'verdict':
    default: {
      const priority: Record<string, number> = {
        highly_likely_fp: 0, likely_fp: 1, ambiguous: 2, likely_tp: 3, confirmed_tp: 4,
      };
      sorted.sort((a, b) => {
        const aVerdict = a.enrichedFpVerdict ?? a.fpVerdict;
        const bVerdict = b.enrichedFpVerdict ?? b.fpVerdict;
        const pA = priority[aVerdict] ?? 2;
        const pB = priority[bVerdict] ?? 2;
        if (pA !== pB) return pA - pB;
        // Within same verdict, sort by FP score descending (higher score = more FP)
        const aScore = a.enrichedFpScore ?? a.fpScore;
        const bScore = b.enrichedFpScore ?? b.fpScore;
        if (aScore !== bScore) return bScore - aScore;
        return b.totalEvents - a.totalEvents;
      });
      break;
    }
  }
  return sorted;
}
