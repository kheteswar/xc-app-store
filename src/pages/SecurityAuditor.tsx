// ═══════════════════════════════════════════════════════════════════════════
// Security Auditor Page Component
// Main UI for running security audits
// ═══════════════════════════════════════════════════════════════════════════

import { useState, useEffect, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield,
  ArrowLeft,
  Play,
  XCircle,
  CheckCircle,
  AlertTriangle,
  AlertCircle,
  Info,
  ChevronDown,
  ChevronRight,
  Download,
  RefreshCw,
  Filter,
  Search,
  ExternalLink,
  FileJson,
  FileText,
  FileSpreadsheet,
  FileSignature,
  Loader2,
  Clock,
  Database,
  Layers,
  HelpCircle,
  KeyRound,
  BarChart3,
  ListChecks,
  ChevronLeft,
  DollarSign,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { apiClient } from '../services/api';
import { AuditEngine } from '../services/security-auditor/audit-engine';
import { allRules, getRuleStats } from '../services/security-auditor/rules';
import {
  CATEGORY_INFO,
  SEVERITY_INFO,
  RISK_INFO,
  ENTITLEMENT_INFO,
} from '../services/security-auditor/types';
import type {
  AuditReport,
  AuditProgress,
  AuditFinding,
  RuleCategory,
  Severity,
  RiskLevel,
  Entitlement,
  AuditOptions,
} from '../services/security-auditor/types';
import {
  exportSecurityAuditCSV,
  exportSecurityAuditExcel,
  exportSecurityAuditPDF,
  exportSecurityAuditJSON,
} from '../services/security-auditor/export-utils';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import type { Namespace } from '../types';

// ═══════════════════════════════════════════════════════════════════════════
// COMPONENT
// ═══════════════════════════════════════════════════════════════════════════

export function SecurityAuditor() {
  const { isConnected } = useApp();
  const navigate = useNavigate();
  const toast = useToast();
  const engineRef = useRef<AuditEngine | null>(null);

  // State
  const [step, setStep] = useState<'config' | 'running' | 'results'>('config');
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [selectedNamespaces, setSelectedNamespaces] = useState<string[]>([]);
  const [isLoadingNamespaces, setIsLoadingNamespaces] = useState(true);

  // Granular check selection — individual rule IDs (default: all enabled)
  const [selectedRuleIds, setSelectedRuleIds] = useState<Set<string>>(
    () => new Set(allRules.map((r) => r.id))
  );
  const [expandedCategories, setExpandedCategories] = useState<Set<RuleCategory>>(new Set());

  // Progress and results
  const [progress, setProgress] = useState<AuditProgress | null>(null);
  const [report, setReport] = useState<AuditReport | null>(null);

  // Results filtering
  const [filterSeverity, setFilterSeverity] = useState<Severity | 'ALL'>('ALL');
  const [filterCategory, setFilterCategory] = useState<RuleCategory | 'ALL'>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [filterEntitlement, setFilterEntitlement] = useState<Entitlement | 'ALL'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const [resultsView, setResultsView] = useState<'overview' | 'bylb' | 'controls'>('overview');
  const [selectedLbKey, setSelectedLbKey] = useState<string>('');

  // Export menu
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const exportMenuRef = useRef<HTMLDivElement | null>(null);

  // ─────────────────────────────────────────────────────────────────────────
  // EFFECTS
  // ─────────────────────────────────────────────────────────────────────────

  useEffect(() => {
    if (!isConnected) {
      navigate('/');
    }
  }, [isConnected, navigate]);

  useEffect(() => {
    loadNamespaces();
  }, []);

  // Close the export menu on outside click
  useEffect(() => {
    if (!exportMenuOpen) return;
    const handler = (e: MouseEvent) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target as Node)) {
        setExportMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [exportMenuOpen]);

  // ─────────────────────────────────────────────────────────────────────────
  // LOAD NAMESPACES
  // ─────────────────────────────────────────────────────────────────────────

  const loadNamespaces = async () => {
    setIsLoadingNamespaces(true);
    try {
      const resp = await apiClient.getNamespaces();
      const nsList = resp.items || [];
      setNamespaces(nsList);

      // Auto-select 'default' if exists
      const hasDefault = nsList.some((ns) => ns.name === 'default');
      if (hasDefault) {
        setSelectedNamespaces(['default']);
      }
    } catch (err) {
      toast.error('Failed to load namespaces');
    } finally {
      setIsLoadingNamespaces(false);
    }
  };

  // ─────────────────────────────────────────────────────────────────────────
  // RUN AUDIT
  // ─────────────────────────────────────────────────────────────────────────

  const startAudit = async () => {
    if (selectedNamespaces.length === 0) {
      toast.error('Please select at least one namespace');
      return;
    }
    if (selectedRuleIds.size === 0) {
      toast.error('Please select at least one security check');
      return;
    }

    setStep('running');
    setProgress({ phase: 'fetching', message: 'Starting audit...', progress: 0 });
    setReport(null);

    const engine = new AuditEngine((p) => setProgress(p));
    engineRef.current = engine;

    const options: AuditOptions = {
      ruleIds: selectedRuleIds.size < allRules.length ? [...selectedRuleIds] : undefined,
    };

    try {
      const result = await engine.runAudit(selectedNamespaces, options);
      setReport(result);
      setStep('results');
      toast.success(`Audit complete! Score: ${result.score}/100`);
    } catch (err) {
      if ((err as Error).message === 'Audit aborted') {
        toast.info('Audit cancelled');
        setStep('config');
      } else {
        toast.error(`Audit failed: ${(err as Error).message}`);
        setStep('config');
      }
    } finally {
      engineRef.current = null;
    }
  };

  const cancelAudit = () => {
    if (engineRef.current) {
      engineRef.current.abort();
    }
  };

  // ─────────────────────────────────────────────────────────────────────────
  // NAMESPACE SELECTION HELPERS
  // ─────────────────────────────────────────────────────────────────────────

  const toggleNamespace = (ns: string) => {
    setSelectedNamespaces((prev) =>
      prev.includes(ns) ? prev.filter((n) => n !== ns) : [...prev, ns]
    );
  };

  const selectAllNamespacesFn = () => setSelectedNamespaces(namespaces.map((ns) => ns.name));
  const deselectAllNamespaces = () => setSelectedNamespaces([]);

  // ─────────────────────────────────────────────────────────────────────────
  // CHECK / CATEGORY SELECTION HELPERS (granular, per-rule)
  // ─────────────────────────────────────────────────────────────────────────

  // Rules grouped by category — only categories that actually have rules.
  const rulesByCategory = (() => {
    const map = new Map<RuleCategory, typeof allRules>();
    for (const rule of allRules) {
      if (!map.has(rule.category)) map.set(rule.category, []);
      map.get(rule.category)!.push(rule);
    }
    return [...map.entries()].sort((a, b) =>
      (CATEGORY_INFO[a[0]]?.label || a[0]).localeCompare(CATEGORY_INFO[b[0]]?.label || b[0])
    );
  })();

  const toggleRule = (id: string) => {
    setSelectedRuleIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const categorySelectedCount = (cat: RuleCategory) =>
    (rulesByCategory.find(([c]) => c === cat)?.[1] || []).filter((r) => selectedRuleIds.has(r.id)).length;

  const setCategoryRules = (cat: RuleCategory, enabled: boolean) => {
    const ids = (rulesByCategory.find(([c]) => c === cat)?.[1] || []).map((r) => r.id);
    setSelectedRuleIds((prev) => {
      const next = new Set(prev);
      for (const id of ids) {
        if (enabled) next.add(id);
        else next.delete(id);
      }
      return next;
    });
  };

  const toggleCategoryExpand = (cat: RuleCategory) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };

  const selectAllRules = () => setSelectedRuleIds(new Set(allRules.map((r) => r.id)));
  const deselectAllRules = () => setSelectedRuleIds(new Set());

  // ─────────────────────────────────────────────────────────────────────────
  // FILTER RESULTS
  // ─────────────────────────────────────────────────────────────────────────

  const filteredFindings = report?.findings.filter((f) => {
    if (filterSeverity !== 'ALL' && f.severity !== filterSeverity) return false;
    if (filterCategory !== 'ALL' && f.category !== filterCategory) return false;
    if (filterStatus !== 'ALL' && f.status !== filterStatus) return false;
    if (filterEntitlement !== 'ALL' && f.entitlement !== filterEntitlement) return false;
    if (searchTerm) {
      const search = searchTerm.toLowerCase();
      return (
        f.ruleName.toLowerCase().includes(search) ||
        f.objectName.toLowerCase().includes(search) ||
        f.namespace.toLowerCase().includes(search) ||
        f.ruleId.toLowerCase().includes(search)
      );
    }
    return true;
  }) || [];

  // Group filtered findings: namespace → object (objectType + objectName).
  const OBJECT_TYPE_LABELS: Record<string, string> = {
    http_loadbalancer: 'HTTP Load Balancer',
    origin_pool: 'Origin Pool',
    app_firewall: 'App Firewall (WAF)',
    service_policy: 'Service Policy',
    healthcheck: 'Health Check',
    user_identification: 'User Identification',
    alert_policy: 'Alert Policy',
    alert_receiver: 'Alert Receiver',
    certificate: 'Certificate',
    global_log_receiver: 'Global Log Receiver',
  };
  const objLabel = (t: string) => OBJECT_TYPE_LABELS[t] || t;

  const statusOrder: Record<string, number> = { FAIL: 0, WARN: 1, INFO: 2, ERROR: 3, PASS: 4, SKIP: 5 };

  // Special scopes (tenant-wide / unattached) sort after real load balancers.
  const lbSpecialRank = (lb: string) => (lb === '(unattached)' ? 1 : lb === '(tenant-wide)' ? 2 : 0);

  // Per-LB weighted score lookup (from the report rollup).
  const lbScoreMap = new Map(
    (report?.loadBalancerSummary || []).map((l) => [`${l.namespace}|${l.loadBalancer}`, l.score])
  );

  // All load-balancer scopes (UNFILTERED) for the per-LB selector + navigator.
  type LbScope = {
    key: string; ns: string; lb: string; title: string; special: boolean;
    findings: AuditFinding[]; pass: number; fail: number; warn: number; reviews: number; total: number; score: number; addOns: number;
  };
  const allScopes: LbScope[] = (() => {
    if (!report) return [];
    const map = new Map<string, LbScope>();
    for (const f of report.findings) {
      const key = `${f.namespace}|${f.loadBalancer}`;
      let g = map.get(key);
      if (!g) {
        const special = f.loadBalancer === '(tenant-wide)' || f.loadBalancer === '(unattached)';
        const title = f.loadBalancer === '(tenant-wide)' ? 'Tenant-Wide Checks' : f.loadBalancer === '(unattached)' ? 'Unattached Objects' : f.loadBalancer;
        g = { key, ns: f.namespace, lb: f.loadBalancer, title, special, findings: [], pass: 0, fail: 0, warn: 0, reviews: 0, total: 0, score: lbScoreMap.get(key) ?? 0, addOns: 0 };
        map.set(key, g);
      }
      g.findings.push(f);
      g.total++;
      if (f.status === 'PASS') g.pass++;
      else if (f.status === 'FAIL') g.fail++;
      else if (f.status === 'WARN') g.warn++;
      else if (f.status === 'INFO') g.reviews++;
      if (f.entitlement === 'Entitlement' && (f.status === 'FAIL' || f.status === 'WARN' || f.status === 'INFO')) g.addOns++;
    }
    return [...map.values()].sort(
      (a, b) => lbSpecialRank(a.lb) - lbSpecialRank(b.lb) || a.ns.localeCompare(b.ns) || a.lb.localeCompare(b.lb)
    );
  })();
  const selectedScope = allScopes.find((s) => s.key === selectedLbKey) || allScopes[0];
  const selectedIdx = selectedScope ? allScopes.findIndex((s) => s.key === selectedScope.key) : -1;
  const gotoLb = (key: string) => { setSelectedLbKey(key); setResultsView('bylb'); };
  const scoreColorCls = (s: number) => (s >= 80 ? 'text-green-400' : s >= 60 ? 'text-yellow-400' : s >= 40 ? 'text-orange-400' : 'text-red-400');

  // ─────────────────────────────────────────────────────────────────────────
  // DASHBOARD DATA (reflects the whole report, not the current filters)
  // ─────────────────────────────────────────────────────────────────────────

  const severityRank: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const riskRank: Record<string, number> = { High: 0, Med: 1, Low: 2 };

  const statusDonut = report
    ? [
        { name: 'Passed', value: report.summary.passed, color: '#22c55e' },
        { name: 'Critical', value: report.summary.critical, color: '#dc2626' },
        { name: 'High', value: report.summary.high, color: '#f97316' },
        { name: 'Medium', value: report.summary.medium, color: '#eab308' },
        { name: 'Low', value: report.summary.low, color: '#3b82f6' },
        { name: 'Warnings', value: report.summary.warnings, color: '#f59e0b' },
      ].filter((d) => d.value > 0)
    : [];

  const categoryBars = (() => {
    if (!report) return [] as { name: string; fails: number }[];
    const m = new Map<string, number>();
    for (const f of report.findings) {
      if (f.status !== 'FAIL') continue;
      const label = CATEGORY_INFO[f.category]?.label || f.category;
      m.set(label, (m.get(label) || 0) + 1);
    }
    return [...m.entries()].map(([name, fails]) => ({ name, fails })).sort((a, b) => b.fails - a.fails).slice(0, 8);
  })();

  const worstLBs = (report?.loadBalancerSummary || [])
    .filter((l) => l.loadBalancer !== '(tenant-wide)' && l.loadBalancer !== '(unattached)')
    .slice()
    .sort((a, b) => b.fail - a.fail || a.score - b.score)
    .slice(0, 8);

  const topPriorities = (report?.findings || [])
    .filter((f) => f.status === 'FAIL')
    .slice()
    .sort(
      (a, b) =>
        severityRank[a.severity] - severityRank[b.severity] ||
        (riskRank[a.risk] ?? 3) - (riskRank[b.risk] ?? 3) ||
        a.ruleId.localeCompare(b.ruleId)
    )
    .slice(0, 10);

  // ─────────────────────────────────────────────────────────────────────────
  // TOGGLE HELPERS
  // ─────────────────────────────────────────────────────────────────────────

  const toggleFinding = (key: string) => {
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  // ─────────────────────────────────────────────────────────────────────────
  // EXPORT FUNCTIONS
  // ─────────────────────────────────────────────────────────────────────────

  const handleExport = async (format: 'csv' | 'excel' | 'pdf' | 'json') => {
    if (!report) return;
    setExportMenuOpen(false);
    try {
      setIsExporting(true);
      switch (format) {
        case 'csv':
          exportSecurityAuditCSV(report);
          toast.success('CSV checklist exported');
          break;
        case 'excel':
          await exportSecurityAuditExcel(report);
          toast.success('Excel workbook exported');
          break;
        case 'pdf':
          await exportSecurityAuditPDF(report);
          toast.success('PDF report exported');
          break;
        case 'json':
          exportSecurityAuditJSON(report);
          toast.success('JSON exported');
          break;
      }
    } catch (err) {
      toast.error(`Export failed: ${(err as Error).message}`);
    } finally {
      setIsExporting(false);
    }
  };

  // ─────────────────────────────────────────────────────────────────────────
  // GET RULE STATS
  // ─────────────────────────────────────────────────────────────────────────

  const ruleStats = getRuleStats();

  // ─────────────────────────────────────────────────────────────────────────
  // RENDER SEVERITY BADGE
  // ─────────────────────────────────────────────────────────────────────────

  const SeverityBadge = ({ severity }: { severity: Severity }) => {
    const info = SEVERITY_INFO[severity];
    return (
      <span className={`px-2 py-0.5 rounded text-xs font-medium ${info.bgColor} ${info.color}`}>
        {info.label}
      </span>
    );
  };

  const RiskBadge = ({ risk }: { risk: RiskLevel }) => {
    const info = RISK_INFO[risk];
    return (
      <span className={`px-2 py-0.5 rounded text-xs font-medium ${info.bgColor} ${info.color}`}>
        {info.label} risk
      </span>
    );
  };

  const EntitlementBadge = ({ entitlement }: { entitlement: Entitlement }) => {
    const info = ENTITLEMENT_INFO[entitlement];
    return (
      <span
        title={info.description}
        className={`px-2 py-0.5 rounded text-xs font-medium ${info.bgColor} ${info.color}`}
      >
        {info.label}
      </span>
    );
  };

  // ─────────────────────────────────────────────────────────────────────────
  // RENDER STATUS ICON
  // ─────────────────────────────────────────────────────────────────────────

  const StatusIcon = ({ status }: { status: string }) => {
    switch (status) {
      case 'PASS':
        return <CheckCircle className="w-5 h-5 text-green-400" />;
      case 'FAIL':
        return <XCircle className="w-5 h-5 text-red-400" />;
      case 'WARN':
        return <AlertTriangle className="w-5 h-5 text-yellow-400" />;
      case 'INFO':
        return <Info className="w-5 h-5 text-sky-400" />;
      case 'ERROR':
        return <AlertCircle className="w-5 h-5 text-purple-400" />;
      default:
        return <Info className="w-5 h-5 text-slate-400" />;
    }
  };

  // Left accent color by status — gives each row a quick color-coded cue.
  const statusAccent = (status: string) =>
    status === 'PASS' ? 'border-l-green-500'
    : status === 'FAIL' ? 'border-l-red-500'
    : status === 'WARN' ? 'border-l-yellow-500'
    : status === 'INFO' ? 'border-l-sky-500'
    : status === 'ERROR' ? 'border-l-purple-500'
    : 'border-l-slate-600';

  // Reusable expandable finding card (shared by grouped + flat views).
  const renderFinding = (finding: AuditFinding, key: string) => {
    const isExpanded = expandedFindings.has(key);
    return (
      <div
        key={key}
        className={`bg-slate-800 rounded-lg border border-slate-700 border-l-4 ${statusAccent(finding.status)} overflow-hidden`}
      >
        <button
          onClick={() => toggleFinding(key)}
          className="w-full px-4 py-2.5 flex items-center gap-3 hover:bg-slate-700/50 transition-colors"
        >
          <StatusIcon status={finding.status} />
          <SeverityBadge severity={finding.severity} />
          <div className="flex-1 text-left min-w-0">
            <div className="font-medium text-slate-100 truncate">
              {finding.ruleId}: {finding.ruleName}
            </div>
            <div className="text-xs text-slate-400 truncate">{finding.message}</div>
          </div>
          <RiskBadge risk={finding.risk} />
          <EntitlementBadge entitlement={finding.entitlement} />
          {isExpanded ? (
            <ChevronDown className="w-5 h-5 text-slate-400 shrink-0" />
          ) : (
            <ChevronRight className="w-5 h-5 text-slate-400 shrink-0" />
          )}
        </button>

        {isExpanded && (
          <div className="px-4 pb-4 border-t border-slate-700">
            <div className="pt-4 space-y-4">
              <div>
                <div className="text-sm font-medium text-slate-400 mb-1">Finding</div>
                <div className="text-slate-200">{finding.message}</div>
              </div>
              {(finding.currentValue !== undefined || finding.expectedValue !== undefined) && (
                <div className="grid md:grid-cols-2 gap-4">
                  {finding.currentValue !== undefined && (
                    <div>
                      <div className="text-sm font-medium text-slate-400 mb-1">Current Value</div>
                      <div className="bg-slate-700/50 rounded-lg p-3 text-sm text-slate-300 font-mono overflow-x-auto">
                        {typeof finding.currentValue === 'object'
                          ? JSON.stringify(finding.currentValue, null, 2)
                          : String(finding.currentValue)}
                      </div>
                    </div>
                  )}
                  {finding.expectedValue !== undefined && (
                    <div>
                      <div className="text-sm font-medium text-slate-400 mb-1">Expected Value</div>
                      <div className="bg-slate-700/50 rounded-lg p-3 text-sm text-slate-300 font-mono overflow-x-auto">
                        {typeof finding.expectedValue === 'object'
                          ? JSON.stringify(finding.expectedValue, null, 2)
                          : String(finding.expectedValue)}
                      </div>
                    </div>
                  )}
                </div>
              )}
              <div>
                <div className="text-sm font-medium text-slate-400 mb-1">Remediation</div>
                <div className="bg-slate-700/50 rounded-lg p-3 text-sm text-slate-300 whitespace-pre-wrap">
                  {finding.remediation}
                </div>
              </div>
              {finding.referenceUrl && (
                <a
                  href={finding.referenceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 text-sm text-blue-400 hover:text-blue-300"
                >
                  <ExternalLink className="w-4 h-4" />
                  View Documentation
                </a>
              )}
            </div>
          </div>
        )}
      </div>
    );
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════════════════════

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header */}
      <header className="bg-slate-800 border-b border-slate-700 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/')}
              className="p-2 hover:bg-slate-700 rounded-lg transition-colors"
            >
              <ArrowLeft className="w-5 h-5 text-slate-400" />
            </button>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-emerald-500/20 rounded-lg">
                <Shield className="w-6 h-6 text-emerald-400" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-slate-100">Security Auditor</h1>
                <p className="text-sm text-slate-400">
                  Validate configurations against security best practices
                </p>
              </div>
            </div>
            <Link to="/explainer/security-auditor" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
              <HelpCircle className="w-3.5 h-3.5" /> How does this work?
            </Link>
          </div>

          {report && step === 'results' && (
            <div className="flex items-center gap-3">
              <button
                onClick={() => setStep('config')}
                className="flex items-center gap-2 px-4 py-2 text-slate-300 hover:bg-slate-700 rounded-lg transition-colors"
              >
                <RefreshCw className="w-4 h-4" />
                New Audit
              </button>

              <div className="relative" ref={exportMenuRef}>
                <button
                  onClick={() => setExportMenuOpen((o) => !o)}
                  disabled={isExporting}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:opacity-60 text-white rounded-lg transition-colors"
                >
                  {isExporting ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Download className="w-4 h-4" />
                  )}
                  Export
                  <ChevronDown className="w-4 h-4" />
                </button>

                {exportMenuOpen && (
                  <div className="absolute right-0 mt-2 w-64 bg-slate-800 border border-slate-700 rounded-lg shadow-xl z-20 overflow-hidden">
                    <button
                      onClick={() => handleExport('csv')}
                      className="w-full flex items-start gap-3 px-4 py-3 hover:bg-slate-700 transition-colors text-left"
                    >
                      <FileText className="w-4 h-4 text-emerald-400 mt-0.5" />
                      <div>
                        <div className="text-sm font-medium text-slate-100">CSV checklist</div>
                        <div className="text-xs text-slate-400">Customer review checkbook</div>
                      </div>
                    </button>
                    <button
                      onClick={() => handleExport('excel')}
                      className="w-full flex items-start gap-3 px-4 py-3 hover:bg-slate-700 transition-colors text-left border-t border-slate-700"
                    >
                      <FileSpreadsheet className="w-4 h-4 text-green-400 mt-0.5" />
                      <div>
                        <div className="text-sm font-medium text-slate-100">Excel workbook</div>
                        <div className="text-xs text-slate-400">Summary + per-namespace + legend</div>
                      </div>
                    </button>
                    <button
                      onClick={() => handleExport('pdf')}
                      className="w-full flex items-start gap-3 px-4 py-3 hover:bg-slate-700 transition-colors text-left border-t border-slate-700"
                    >
                      <FileSignature className="w-4 h-4 text-red-400 mt-0.5" />
                      <div>
                        <div className="text-sm font-medium text-slate-100">PDF report</div>
                        <div className="text-xs text-slate-400">Branded, color-coded summary</div>
                      </div>
                    </button>
                    <button
                      onClick={() => handleExport('json')}
                      className="w-full flex items-start gap-3 px-4 py-3 hover:bg-slate-700 transition-colors text-left border-t border-slate-700"
                    >
                      <FileJson className="w-4 h-4 text-blue-400 mt-0.5" />
                      <div>
                        <div className="text-sm font-medium text-slate-100">JSON</div>
                        <div className="text-xs text-slate-400">Machine-readable raw report</div>
                      </div>
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* ═══════════════════════════════════════════════════════════════════ */}
        {/* CONFIGURATION STEP */}
        {/* ═══════════════════════════════════════════════════════════════════ */}
        {step === 'config' && (
          <div className="space-y-8">
            {/* Rule Stats */}
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
              <h2 className="text-lg font-semibold text-slate-100 mb-4">Security Rules Overview</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-3xl font-bold text-blue-400">{ruleStats.total}</div>
                  <div className="text-sm text-slate-400">Total Rules</div>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-3xl font-bold text-red-400">{ruleStats.bySeverity.CRITICAL || 0}</div>
                  <div className="text-sm text-slate-400">Critical</div>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-3xl font-bold text-orange-400">{ruleStats.bySeverity.HIGH || 0}</div>
                  <div className="text-sm text-slate-400">High</div>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-3xl font-bold text-yellow-400">{ruleStats.bySeverity.MEDIUM || 0}</div>
                  <div className="text-sm text-slate-400">Medium</div>
                </div>
              </div>
            </div>

            {/* Namespace Selection */}
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-slate-100">
                  Select Namespaces
                  <span className="ml-2 text-sm font-normal text-slate-400">
                    ({selectedNamespaces.length}/{namespaces.length})
                  </span>
                </h2>
                <div className="flex gap-2">
                  <button onClick={selectAllNamespacesFn} className="text-sm text-blue-400 hover:text-blue-300">
                    Select All
                  </button>
                  <span className="text-slate-600">|</span>
                  <button onClick={deselectAllNamespaces} className="text-sm text-blue-400 hover:text-blue-300">
                    Deselect All
                  </button>
                </div>
              </div>

              {isLoadingNamespaces ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-6 h-6 text-blue-400 animate-spin" />
                </div>
              ) : (
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
                  {namespaces.map((ns) => (
                    <label
                      key={ns.name}
                      className={`flex items-center gap-2 p-3 rounded-lg cursor-pointer transition-colors ${
                        selectedNamespaces.includes(ns.name)
                          ? 'bg-blue-500/20 border border-blue-500/50'
                          : 'bg-slate-700/50 border border-transparent hover:bg-slate-700'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedNamespaces.includes(ns.name)}
                        onChange={() => toggleNamespace(ns.name)}
                        className="rounded border-slate-600 text-blue-500 focus:ring-blue-500"
                      />
                      <span className="text-sm text-slate-200 truncate">{ns.name}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            {/* Security Checks — granular per-category / per-rule selection */}
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-slate-100">
                  Security Checks
                  <span className="ml-2 text-sm font-normal text-slate-400">
                    ({selectedRuleIds.size}/{allRules.length} selected)
                  </span>
                </h2>
                <div className="flex gap-2">
                  <button onClick={selectAllRules} className="text-sm text-blue-400 hover:text-blue-300">
                    Select All
                  </button>
                  <span className="text-slate-600">|</span>
                  <button onClick={deselectAllRules} className="text-sm text-blue-400 hover:text-blue-300">
                    Deselect All
                  </button>
                </div>
              </div>
              <p className="text-xs text-slate-400 mb-4">
                Expand a category to enable or disable individual checks.
              </p>

              <div className="space-y-2">
                {rulesByCategory.map(([cat, rules]) => {
                  const info = CATEGORY_INFO[cat];
                  const selCount = categorySelectedCount(cat);
                  const all = selCount === rules.length;
                  const none = selCount === 0;
                  const expanded = expandedCategories.has(cat);
                  return (
                    <div key={cat} className="rounded-lg border border-slate-700 overflow-hidden">
                      {/* Category header row */}
                      <div
                        className={`flex items-center gap-3 px-3 py-2.5 ${
                          none ? 'bg-slate-700/30' : 'bg-emerald-500/10'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={all}
                          ref={(el) => {
                            if (el) el.indeterminate = !all && !none;
                          }}
                          onChange={() => setCategoryRules(cat, !all)}
                          className="rounded border-slate-600 text-emerald-500 focus:ring-emerald-500"
                        />
                        <span className="text-lg">{info?.icon}</span>
                        <button
                          onClick={() => toggleCategoryExpand(cat)}
                          className="flex-1 flex items-center gap-2 text-left"
                        >
                          <span className="text-sm font-medium text-slate-100">{info?.label || cat}</span>
                          <span className="text-xs text-slate-400">
                            {selCount}/{rules.length}
                          </span>
                          {expanded ? (
                            <ChevronDown className="w-4 h-4 text-slate-400 ml-auto" />
                          ) : (
                            <ChevronRight className="w-4 h-4 text-slate-400 ml-auto" />
                          )}
                        </button>
                      </div>

                      {/* Expanded per-rule list */}
                      {expanded && (
                        <div className="divide-y divide-slate-700/60 bg-slate-800">
                          {rules.map((rule) => (
                            <label
                              key={rule.id}
                              className="flex items-start gap-3 px-4 py-2.5 cursor-pointer hover:bg-slate-700/30"
                            >
                              <input
                                type="checkbox"
                                checked={selectedRuleIds.has(rule.id)}
                                onChange={() => toggleRule(rule.id)}
                                className="mt-0.5 rounded border-slate-600 text-emerald-500 focus:ring-emerald-500"
                              />
                              <div className="min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="text-xs font-mono text-slate-400">{rule.id}</span>
                                  <span className="text-sm font-medium text-slate-100">{rule.name}</span>
                                  <SeverityBadge severity={rule.severity} />
                                  <EntitlementBadge entitlement={rule.entitlement ?? 'Base'} />
                                </div>
                                <div className="text-xs text-slate-400 mt-0.5">{rule.description}</div>
                              </div>
                            </label>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Start Button */}
            <div className="flex justify-center">
              <button
                onClick={startAudit}
                disabled={selectedNamespaces.length === 0 || selectedRuleIds.size === 0}
                className="flex items-center gap-3 px-8 py-4 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-colors text-lg"
              >
                <Play className="w-6 h-6" />
                Start Security Audit
              </button>
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════════════════════════════════════ */}
        {/* RUNNING STEP */}
        {/* ═══════════════════════════════════════════════════════════════════ */}
        {step === 'running' && progress && (
          <div className="max-w-2xl mx-auto">
            <div className="bg-slate-800 rounded-xl p-8 border border-slate-700">
              <div className="text-center mb-8">
                <Loader2 className="w-16 h-16 text-emerald-400 animate-spin mx-auto mb-4" />
                <h2 className="text-2xl font-bold text-slate-100 mb-2">Running Security Audit</h2>
                <p className="text-slate-400">{progress.message}</p>
              </div>

              {/* Progress Bar */}
              <div className="mb-6">
                <div className="flex justify-between text-sm text-slate-400 mb-2">
                  <span>{progress.phase}</span>
                  <span>{progress.progress || 0}%</span>
                </div>
                <div className="h-3 bg-slate-700 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-emerald-500 transition-all duration-300"
                    style={{ width: `${progress.progress || 0}%` }}
                  />
                </div>
              </div>

              {/* Stats */}
              {progress.rulesChecked !== undefined && (
                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div className="bg-slate-700/50 rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-blue-400">
                      {progress.rulesChecked}/{progress.totalRules}
                    </div>
                    <div className="text-sm text-slate-400">Rules Checked</div>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-red-400">{progress.findingsCount || 0}</div>
                    <div className="text-sm text-slate-400">Issues Found</div>
                  </div>
                </div>
              )}

              {/* Cancel Button */}
              <div className="text-center">
                <button
                  onClick={cancelAudit}
                  className="px-6 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
                >
                  Cancel Audit
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════════════════════════════════════ */}
        {/* RESULTS STEP */}
        {/* ═══════════════════════════════════════════════════════════════════ */}
        {step === 'results' && report && (
          <div className="space-y-6">
            {/* ── Results tab bar ── */}
            <div className="flex items-center gap-1 bg-slate-800/60 border border-slate-700 rounded-xl p-1 w-fit">
              {([
                { id: 'overview', label: 'Overview & Summary', icon: BarChart3 },
                { id: 'bylb', label: `By Load Balancer (${allScopes.length})`, icon: Shield },
                { id: 'controls', label: `Controls (${allRules.length})`, icon: ListChecks },
              ] as const).map((t) => {
                const Icon = t.icon;
                const active = resultsView === t.id;
                return (
                  <button
                    key={t.id}
                    onClick={() => setResultsView(t.id)}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${active ? 'bg-blue-500 text-white shadow' : 'text-slate-300 hover:bg-slate-700/60'}`}
                  >
                    <Icon className="w-4 h-4" /> {t.label}
                  </button>
                );
              })}
            </div>

            {/* ════════════════════ OVERVIEW & SUMMARY ════════════════════ */}
            {resultsView === 'overview' && (
            <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
              {/* Score */}
              <div className="col-span-2 bg-slate-800 rounded-xl p-6 border border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm text-slate-400 mb-1">Security Score</div>
                    <div className={`text-4xl font-bold ${
                      report.score >= 80 ? 'text-green-400' :
                      report.score >= 60 ? 'text-yellow-400' :
                      report.score >= 40 ? 'text-orange-400' : 'text-red-400'
                    }`}>
                      {report.score}/100
                    </div>
                  </div>
                  <div className="relative w-20 h-20">
                    <svg className="w-full h-full -rotate-90">
                      <circle
                        cx="40"
                        cy="40"
                        r="35"
                        stroke="currentColor"
                        strokeWidth="8"
                        fill="none"
                        className="text-slate-700"
                      />
                      <circle
                        cx="40"
                        cy="40"
                        r="35"
                        stroke="currentColor"
                        strokeWidth="8"
                        fill="none"
                        strokeDasharray={`${(report.score / 100) * 220} 220`}
                        className={
                          report.score >= 80 ? 'text-green-400' :
                          report.score >= 60 ? 'text-yellow-400' :
                          report.score >= 40 ? 'text-orange-400' : 'text-red-400'
                        }
                      />
                    </svg>
                  </div>
                </div>
              </div>

              {/* Critical */}
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <div className="text-sm text-slate-400 mb-1">Critical</div>
                <div className="text-3xl font-bold text-red-400">{report.summary.critical}</div>
              </div>

              {/* High */}
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <div className="text-sm text-slate-400 mb-1">High</div>
                <div className="text-3xl font-bold text-orange-400">{report.summary.high}</div>
              </div>

              {/* Medium */}
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <div className="text-sm text-slate-400 mb-1">Medium</div>
                <div className="text-3xl font-bold text-yellow-400">{report.summary.medium}</div>
              </div>

              {/* Passed */}
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <div className="text-sm text-slate-400 mb-1">Passed</div>
                <div className="text-3xl font-bold text-green-400">{report.summary.passed}</div>
              </div>
            </div>

            {/* Dashboard: charts */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* Status / severity donut */}
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <h3 className="text-sm font-semibold text-slate-200 mb-2">Check Outcomes</h3>
                <div className="flex items-center">
                  <ResponsiveContainer width="55%" height={150}>
                    <PieChart>
                      <Pie data={statusDonut} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={38} outerRadius={62} paddingAngle={2} stroke="none">
                        {statusDonut.map((d) => (
                          <Cell key={d.name} fill={d.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                        itemStyle={{ color: '#e2e8f0' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="flex-1 space-y-1">
                    {statusDonut.map((d) => (
                      <div key={d.name} className="flex items-center gap-2 text-xs">
                        <span className="w-2.5 h-2.5 rounded-sm" style={{ background: d.color }} />
                        <span className="text-slate-300 flex-1">{d.name}</span>
                        <span className="text-slate-100 font-medium">{d.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Failures by category */}
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <h3 className="text-sm font-semibold text-slate-200 mb-2">Failures by Category</h3>
                {categoryBars.length > 0 ? (
                  <ResponsiveContainer width="100%" height={150}>
                    <BarChart data={categoryBars} layout="vertical" margin={{ left: 8, right: 16, top: 2, bottom: 2 }}>
                      <XAxis type="number" hide />
                      <YAxis type="category" dataKey="name" width={120} tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={false} tickLine={false} />
                      <Tooltip
                        cursor={{ fill: '#334155', opacity: 0.3 }}
                        contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                        itemStyle={{ color: '#e2e8f0' }}
                      />
                      <Bar dataKey="fails" fill="#ef4444" radius={[0, 4, 4, 0]} barSize={12} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-[150px] flex items-center justify-center text-sm text-green-400">
                    <CheckCircle className="w-5 h-5 mr-2" /> No failures
                  </div>
                )}
              </div>

              {/* Worst load balancers */}
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <h3 className="text-sm font-semibold text-slate-200 mb-2">Lowest-Scoring Load Balancers</h3>
                <div className="space-y-2">
                  {worstLBs.length === 0 && <div className="text-sm text-slate-400">No load balancers audited.</div>}
                  {worstLBs.map((l) => (
                    <div key={`${l.namespace}|${l.loadBalancer}`} className="text-xs">
                      <div className="flex items-center justify-between mb-0.5">
                        <span className="text-slate-300 truncate mr-2">{l.loadBalancer}</span>
                        <span className={`font-semibold ${l.score >= 80 ? 'text-green-400' : l.score >= 60 ? 'text-yellow-400' : l.score >= 40 ? 'text-orange-400' : 'text-red-400'}`}>
                          {l.score}%{l.fail > 0 ? ` · ${l.fail} fail` : ''}
                        </span>
                      </div>
                      <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${l.score >= 80 ? 'bg-green-500' : l.score >= 60 ? 'bg-yellow-500' : l.score >= 40 ? 'bg-orange-500' : 'bg-red-500'}`}
                          style={{ width: `${l.score}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Top Priorities */}
            {topPriorities.length > 0 && (
              <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-700 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  <h3 className="text-sm font-semibold text-slate-200">Top Priorities — fix these first</h3>
                </div>
                <div className="divide-y divide-slate-700/60">
                  {topPriorities.map((f, idx) => (
                    <div key={`prio-${f.ruleId}-${f.loadBalancer}-${idx}`} className="px-4 py-2.5 flex items-start gap-3">
                      <SeverityBadge severity={f.severity} />
                      <div className="flex-1 min-w-0">
                        <div className="text-sm text-slate-100">
                          {f.ruleId}: {f.ruleName}
                        </div>
                        <div className="text-xs text-slate-400 truncate">
                          {f.loadBalancer === '(tenant-wide)' ? 'Tenant-wide' : `${f.namespace} / ${f.loadBalancer}`}
                          {' · '}{objLabel(f.objectType)}{f.objectName ? ` (${f.objectName})` : ''}
                        </div>
                      </div>
                      <EntitlementBadge entitlement={f.entitlement} />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Audit Info */}
            <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
              <div className="flex flex-wrap items-center gap-6 text-sm text-slate-400">
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4" />
                  <span>Duration: {(report.durationMs / 1000).toFixed(1)}s</span>
                </div>
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4" />
                  <span>Namespaces: {report.namespaces.join(', ')}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Database className="w-4 h-4" />
                  <span>
                    {report.configSnapshot.loadBalancers} LBs, {report.configSnapshot.originPools} Pools,{' '}
                    {report.configSnapshot.wafPolicies} WAFs, {report.configSnapshot.certificates} Certs
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <KeyRound className="w-4 h-4" />
                  <span>
                    Failing gaps:{' '}
                    <span className="text-emerald-400 font-medium">
                      {report.entitlementSummary.baseFails + report.entitlementSummary.configFails} config/base
                    </span>{' '}
                    ·{' '}
                    <span className="text-amber-400 font-medium">
                      {report.entitlementSummary.entitlementFails} need add-on
                    </span>
                  </span>
                </div>
              </div>
            </div>

            {/* Per-Load-Balancer Summary — click a row to open that LB */}
            <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-700 flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                <h3 className="text-sm font-semibold text-slate-200">Per-Load-Balancer Summary</h3>
                <span className="text-xs text-slate-500">click a row to open the load balancer</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-slate-900/60 text-slate-400 text-xs uppercase tracking-wide">
                      <th className="text-left px-4 py-2 font-medium">Load Balancer</th>
                      <th className="text-left px-4 py-2 font-medium">Namespace</th>
                      <th className="text-center px-4 py-2 font-medium">Score</th>
                      <th className="text-center px-4 py-2 font-medium">Pass</th>
                      <th className="text-center px-4 py-2 font-medium">Fail</th>
                      <th className="text-center px-4 py-2 font-medium">Warn</th>
                      <th className="text-center px-4 py-2 font-medium">Review</th>
                      <th className="text-center px-4 py-2 font-medium">Add-on gaps</th>
                      <th className="px-4 py-2" />
                    </tr>
                  </thead>
                  <tbody>
                    {allScopes.map((s) => (
                      <tr key={s.key} onClick={() => gotoLb(s.key)} className="border-t border-slate-700/60 hover:bg-slate-700/30 cursor-pointer">
                        <td className="px-4 py-2.5 font-medium text-slate-100">{s.title}</td>
                        <td className="px-4 py-2.5 text-slate-400">{s.special ? '—' : s.ns}</td>
                        <td className={`px-4 py-2.5 text-center font-semibold ${s.special ? 'text-slate-500' : scoreColorCls(s.score)}`}>{s.special ? '—' : `${s.score}%`}</td>
                        <td className="px-4 py-2.5 text-center text-green-400">{s.pass}</td>
                        <td className="px-4 py-2.5 text-center text-red-400">{s.fail || ''}</td>
                        <td className="px-4 py-2.5 text-center text-yellow-400">{s.warn || ''}</td>
                        <td className="px-4 py-2.5 text-center text-sky-400">{s.reviews || ''}</td>
                        <td className="px-4 py-2.5 text-center">{s.addOns > 0 ? <span className="inline-flex items-center gap-1 text-amber-400"><DollarSign className="w-3 h-3" />{s.addOns}</span> : ''}</td>
                        <td className="px-4 py-2.5 text-right"><ChevronRight className="w-4 h-4 text-slate-500 inline" /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Licensing note */}
            <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-4">
              <div className="flex items-start gap-3">
                <DollarSign className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                <div className="text-sm text-slate-300">
                  <div className="font-semibold text-amber-300 mb-1">Licensing — confirm add-on entitlements with your F5 Account Team</div>
                  Some controls require an additional F5 subscription/SKU beyond the WAAP base bundle — notably <span className="text-slate-100">Bot Defense, Malware Protection, Client-Side Defense, Rate Limiting and API Testing</span>. Findings for these are tagged <span className="text-amber-400 font-medium">Add-on ($)</span>; treat them as "discuss with Account Team" rather than immediate config fixes. The exported Excel carries the same flag plus an Action/Remarks tracker per load balancer.
                </div>
              </div>
            </div>
            </div>
            )}

            {/* ════════════════════ BY LOAD BALANCER ════════════════════ */}
            {resultsView === 'bylb' && selectedScope && (
            <div className="space-y-5">
              {/* LB navigator + selected-LB header */}
              <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
                <div className="flex items-center gap-3 flex-wrap">
                  <button onClick={() => selectedIdx > 0 && setSelectedLbKey(allScopes[selectedIdx - 1].key)} disabled={selectedIdx <= 0} className="p-2 rounded-lg bg-slate-700/60 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed" title="Previous load balancer"><ChevronLeft className="w-4 h-4" /></button>
                  <select value={selectedScope.key} onChange={(e) => setSelectedLbKey(e.target.value)} className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-100 min-w-[280px]">
                    {allScopes.map((s) => (
                      <option key={s.key} value={s.key}>{s.title}{s.special ? '' : ` — ${s.ns}`}  ({s.fail} fail · {s.warn} warn)</option>
                    ))}
                  </select>
                  <button onClick={() => selectedIdx < allScopes.length - 1 && setSelectedLbKey(allScopes[selectedIdx + 1].key)} disabled={selectedIdx >= allScopes.length - 1} className="p-2 rounded-lg bg-slate-700/60 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed" title="Next load balancer"><ChevronRight className="w-4 h-4" /></button>
                  <span className="text-xs text-slate-500">{selectedIdx + 1} of {allScopes.length}</span>
                  <div className="ml-auto flex items-center gap-2">
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                      <input type="text" placeholder="Search this LB…" value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} className="w-44 pl-9 pr-3 py-1.5 bg-slate-700 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder-slate-400" />
                    </div>
                    <button onClick={() => setFilterStatus(filterStatus === 'FAIL' ? 'ALL' : 'FAIL')} className={`px-3 py-1.5 rounded-lg text-sm font-medium border ${filterStatus === 'FAIL' ? 'bg-red-500/20 text-red-300 border-red-500/40' : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'}`}>Failures only</button>
                  </div>
                </div>
                <div className="mt-4 flex items-center gap-6 flex-wrap">
                  <div className="min-w-0">
                    <div className="text-xs text-slate-400">{selectedScope.special ? 'Tenant-wide' : selectedScope.ns}</div>
                    <div className="text-lg font-bold text-slate-100 truncate">{selectedScope.title}</div>
                  </div>
                  {!selectedScope.special && (
                    <div className="text-center">
                      <div className="text-xs text-slate-400">Score</div>
                      <div className={`text-2xl font-bold ${scoreColorCls(selectedScope.score)}`}>{selectedScope.score}%</div>
                    </div>
                  )}
                  <div className="flex items-center gap-2 text-sm">
                    <span className="px-2.5 py-1 rounded-lg bg-red-500/15 text-red-300 font-medium">{selectedScope.fail} Fail</span>
                    <span className="px-2.5 py-1 rounded-lg bg-yellow-500/15 text-yellow-300 font-medium">{selectedScope.warn} Warn</span>
                    {selectedScope.reviews > 0 && <span className="px-2.5 py-1 rounded-lg bg-sky-500/15 text-sky-300 font-medium">{selectedScope.reviews} Review</span>}
                    <span className="px-2.5 py-1 rounded-lg bg-green-500/15 text-green-300 font-medium">{selectedScope.pass} Pass</span>
                  </div>
                  {selectedScope.addOns > 0 && (
                    <div className="flex items-center gap-1.5 text-sm text-amber-300 bg-amber-500/10 px-3 py-1.5 rounded-lg">
                      <DollarSign className="w-4 h-4" /> {selectedScope.addOns} add-on gap(s) — discuss with Account Team
                    </div>
                  )}
                </div>
              </div>

            {/* Findings filter bar (scoped to the selected LB) */}
            <div className="bg-slate-800 rounded-xl px-3 py-2.5 border border-slate-700 flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-2 text-sm text-slate-400"><Filter className="w-4 h-4" /> Filters:</div>
              <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-slate-200">
                <option value="ALL">All Status</option>
                <option value="FAIL">Failed</option>
                <option value="WARN">Warnings</option>
                <option value="INFO">Review</option>
                <option value="PASS">Passed</option>
              </select>
              <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value as Severity | 'ALL')} className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-slate-200">
                <option value="ALL">All Severities</option>
                {Object.entries(SEVERITY_INFO).map(([sev, info]) => (<option key={sev} value={sev}>{info.label}</option>))}
              </select>
              <select value={filterCategory} onChange={(e) => setFilterCategory(e.target.value as RuleCategory | 'ALL')} className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-slate-200">
                <option value="ALL">All Categories</option>
                {Object.entries(CATEGORY_INFO).map(([cat, info]) => (<option key={cat} value={cat}>{info.label}</option>))}
              </select>
              <select value={filterEntitlement} onChange={(e) => setFilterEntitlement(e.target.value as Entitlement | 'ALL')} className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-slate-200">
                <option value="ALL">All Entitlements</option>
                {Object.entries(ENTITLEMENT_INFO).map(([ent, info]) => (<option key={ent} value={ent}>{info.label}</option>))}
              </select>
            </div>

            {/* Findings for the selected load balancer, grouped by object */}
            {(() => {
              const scoped = filteredFindings.filter((f) => `${f.namespace}|${f.loadBalancer}` === selectedScope.key);
              const groups = new Map<string, AuditFinding[]>();
              for (const f of scoped) {
                const objKey = `${objLabel(f.objectType)} — ${f.objectName}`;
                if (!groups.has(objKey)) groups.set(objKey, []);
                groups.get(objKey)!.push(f);
              }
              if (scoped.length === 0) {
                return (
                  <div className="bg-slate-800 rounded-xl p-8 border border-slate-700 text-center">
                    <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-4" />
                    <div className="text-lg font-medium text-slate-200 mb-2">No findings match your filters</div>
                    <div className="text-slate-400">This load balancer has no checks under the current filter.</div>
                  </div>
                );
              }
              return (
                <div className="space-y-4">
                  {[...groups.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([objKey, objFindings]) => (
                    <div key={objKey} className="bg-slate-800/40 rounded-xl border border-slate-700 p-4">
                      <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-400 mb-3">
                        <Database className="w-3.5 h-3.5" /> {objKey}
                      </div>
                      <div className="space-y-2">
                        {objFindings
                          .slice()
                          .sort((a, b) => (statusOrder[a.status] ?? 5) - (statusOrder[b.status] ?? 5))
                          .map((finding, idx) => renderFinding(finding, `${selectedScope.key}-${objKey}-${finding.ruleId}-${idx}`))}
                      </div>
                    </div>
                  ))}
                </div>
              );
            })()}
            </div>
            )}

            {/* Security Checks catalog */}
            {resultsView === 'controls' && (
              <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="bg-slate-900/60 text-slate-400 text-xs uppercase tracking-wide">
                        <th className="text-left px-4 py-2 font-medium">ID</th>
                        <th className="text-left px-4 py-2 font-medium">Check</th>
                        <th className="text-left px-4 py-2 font-medium">What it verifies &amp; why</th>
                        <th className="text-left px-4 py-2 font-medium">Expected</th>
                        <th className="text-center px-4 py-2 font-medium">Risk</th>
                        <th className="text-center px-4 py-2 font-medium">Entitlement</th>
                      </tr>
                    </thead>
                    <tbody>
                      {allRules.map((rule) => {
                        const risk = rule.risk ?? (rule.severity === 'CRITICAL' || rule.severity === 'HIGH' ? 'High' : rule.severity === 'MEDIUM' ? 'Med' : 'Low');
                        const ent = rule.entitlement ?? 'Base';
                        return (
                          <tr key={rule.id} className="border-t border-slate-700/60 align-top hover:bg-slate-700/20">
                            <td className="px-4 py-2.5 text-slate-400 whitespace-nowrap font-mono text-xs">{rule.id}</td>
                            <td className="px-4 py-2.5">
                              <div className="font-medium text-slate-100">{rule.name}</div>
                              <div className="text-xs text-slate-500">{CATEGORY_INFO[rule.category]?.label || rule.category}</div>
                            </td>
                            <td className="px-4 py-2.5 text-slate-300 max-w-md">{rule.description}</td>
                            <td className="px-4 py-2.5 text-slate-300">{rule.expectedDisplay || '—'}</td>
                            <td className="px-4 py-2.5 text-center"><RiskBadge risk={risk} /></td>
                            <td className="px-4 py-2.5 text-center"><EntitlementBadge entitlement={ent} /></td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
