import { useState, useEffect, useCallback, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Search,
  Shield,
  ChevronRight,
  Check,
  Loader2,
  FileJson,
  Table,
  Eye,
  AlertTriangle,
  Server,
  Route,
  X,
  HelpCircle,
} from 'lucide-react';
import { apiClient } from '../services/api';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import type { Namespace, WAFScanRow, ScanStats, WAFPolicy } from '../types';

type Step = 1 | 2 | 3;
type Filter = 'all' | 'blocking' | 'monitoring' | 'nowaf';

interface LogEntry {
  time: string;
  message: string;
  type: 'info' | 'success' | 'warning' | 'error' | 'fetch' | 'waf' | 'route';
}

export function WAFScanner() {
  const { isConnected } = useApp();
  const navigate = useNavigate();
  const toast = useToast();

  const [step, setStep] = useState<Step>(1);
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [selectedNs, setSelectedNs] = useState<string[]>([]);
  const [includeRoutes, setIncludeRoutes] = useState(true);
  const [isLoadingNs, setIsLoadingNs] = useState(true);

  const [, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressText, setProgressText] = useState('');
  const [operation, setOperation] = useState({ title: '', subtitle: '' });
  const [eta, setEta] = useState('');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [stats, setStats] = useState<ScanStats>({ namespaces: 0, loadBalancers: 0, routes: 0, wafs: 0 });

  const [rows, setRows] = useState<WAFScanRow[]>([]);
  const [filter, setFilter] = useState<Filter>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const cancelledRef = useRef(false);
  const startTimeRef = useRef<number | null>(null);
  const wafCacheRef = useRef<Map<string, WAFPolicy>>(new Map());

  useEffect(() => {
    if (!isConnected) {
      navigate('/');
      return;
    }
    loadNamespaces();
  }, [isConnected, navigate]);

  const loadNamespaces = async () => {
    setIsLoadingNs(true);
    try {
      const resp = await apiClient.getNamespaces();
      setNamespaces(resp.items.sort((a, b) => a.name.localeCompare(b.name)));
    } catch (e) {
      toast.error('Failed to load namespaces');
    } finally {
      setIsLoadingNs(false);
    }
  };

  const logScan = useCallback((message: string, type: LogEntry['type'] = 'info') => {
    const time = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { time, message, type }]);
  }, []);

  const updateProgress = useCallback((percent: number, text: string) => {
    setProgress(percent);
    setProgressText(text);
    if (startTimeRef.current && percent > 5) {
      const elapsed = Date.now() - startTimeRef.current;
      const estimated = (elapsed / percent) * (100 - percent);
      const seconds = Math.round(estimated / 1000);
      setEta(seconds > 60 ? `${Math.round(seconds / 60)} min remaining` : `${seconds} sec remaining`);
    }
  }, []);

  const fetchWafPolicy = async (name: string, ns: string): Promise<WAFPolicy | null> => {
    const cacheKey = `${ns}/${name}`;
    if (wafCacheRef.current.has(cacheKey)) {
      return wafCacheRef.current.get(cacheKey) || null;
    }
    try {
      const waf = await apiClient.getWAFPolicy(ns, name);
      const policy = { ...waf, name, shared: false };
      wafCacheRef.current.set(cacheKey, policy);
      return policy;
    } catch {
      try {
        const waf = await apiClient.getWAFPolicy('shared', name);
        const policy = { ...waf, name, shared: true };
        wafCacheRef.current.set(`shared/${name}`, policy);
        return policy;
      } catch {
        return null;
      }
    }
  };

  const getWafMode = (waf: WAFPolicy | null): string => {
    if (!waf?.spec) return 'unknown';
    if (waf.spec.mode) {
      const m = waf.spec.mode.toUpperCase();
      if (m === 'BLOCKING') return 'blocking';
      if (m === 'MONITORING') return 'monitoring';
    }
    if (waf.spec.blocking) return 'blocking';
    // AI risk-based blocking is an active blocking enforcement posture (newer XC oneof member)
    if (waf.spec.ai_risk_based_blocking) return 'blocking';
    if (waf.spec.monitoring) return 'monitoring';
    return 'unknown';
  };

  const scanNamespace = async (ns: string, index: number, total: number): Promise<WAFScanRow[]> => {
    if (cancelledRef.current) return [];
    const results: WAFScanRow[] = [];

    setOperation({ title: `Scanning namespace: ${ns}`, subtitle: `Namespace ${index + 1} of ${total}` });
    logScan(`Scanning namespace: ${ns}`, 'info');
    setStats(prev => ({ ...prev, namespaces: prev.namespaces + 1 }));

    let lbs;
    try {
      const resp = await apiClient.getLoadBalancers(ns);
      lbs = resp.items || [];
      logScan(`Found ${lbs.length} HTTP Load Balancers in ${ns}`, 'success');
    } catch (err: unknown) {
      logScan(`Error fetching LBs from ${ns}: ${err instanceof Error ? err.message : 'Unknown error'}`, 'error');
      return results;
    }

    for (const lb of lbs) {
      if (cancelledRef.current) break;
      const lbName = lb.name;
      setStats(prev => ({ ...prev, loadBalancers: prev.loadBalancers + 1 }));
      setOperation({ title: `Analyzing: ${lbName}`, subtitle: `Namespace: ${ns}` });
      logScan(`Analyzing LB: ${lbName}`, 'fetch');

      let lbDetails;
      try {
        lbDetails = await apiClient.getLoadBalancer(ns, lbName);
      } catch (err: unknown) {
        logScan(`Error fetching ${lbName}: ${err instanceof Error ? err.message : 'Unknown error'}`, 'error');
        continue;
      }

      const spec = lbDetails.spec || {};
      let lbWafName = 'disabled';
      let lbWafMode = 'disabled';
      let wafDisplayName = 'N/A';

      if (!spec.disable_waf && spec.app_firewall?.name) {
        const wafName = spec.app_firewall.name;
        const wafNs = spec.app_firewall.namespace || ns;
        const wafPolicy = await fetchWafPolicy(wafName, wafNs);
        if (wafPolicy) {
          setStats(prev => ({ ...prev, wafs: prev.wafs + 1 }));
          lbWafName = wafPolicy.shared ? `${wafName} (shared)` : wafName;
          lbWafMode = getWafMode(wafPolicy);
          wafDisplayName = lbWafName;
        }
      }

      results.push({
        namespace: ns,
        lb_name: lbName,
        route: 'LB Default',
        waf_name: wafDisplayName,
        waf_mode: lbWafMode,
      });

      if (includeRoutes && spec.routes?.length) {
        for (const route of spec.routes) {
          if (cancelledRef.current) break;
          setStats(prev => ({ ...prev, routes: prev.routes + 1 }));

          let routePath = '/';
          if (route.simple_route?.path) {
            const p = route.simple_route.path;
            if (p.prefix) routePath = `prefix:${p.prefix}`;
            else if (p.regex) routePath = `regex:${p.regex}`;
            else if (p.path) routePath = `exact:${p.path}`;
          } else if (route.redirect_route?.path?.prefix) {
            routePath = `redirect:${route.redirect_route.path.prefix}`;
          } else if (route.direct_response_route) {
            routePath = 'direct-response';
          }

          const adv = route.simple_route?.advanced_options || {};
          let routeWafName = 'inherit';
          let routeWafMode = lbWafMode;

          if (adv.disable_waf) {
            routeWafName = 'disabled';
            routeWafMode = 'disabled';
          } else if (adv.app_firewall?.name) {
            const routeWafPolicyName = adv.app_firewall.name;
            const routeWafNs = adv.app_firewall.namespace || ns;
            const routeWafPolicy = await fetchWafPolicy(routeWafPolicyName, routeWafNs);
            if (routeWafPolicy) {
              routeWafName = routeWafPolicy.shared ? `${routeWafPolicyName} (shared)` : routeWafPolicyName;
              routeWafMode = getWafMode(routeWafPolicy);
            }
          }

          results.push({
            namespace: ns,
            lb_name: lbName,
            route: routePath,
            waf_name: routeWafName === 'inherit' ? wafDisplayName : routeWafName,
            waf_mode: routeWafMode,
            inherited: routeWafName === 'inherit',
          });
        }
      }
    }

    updateProgress(Math.round(((index + 1) / total) * 100), `Completed ${index + 1} of ${total} namespaces`);
    return results;
  };

  const startScan = async () => {
    if (selectedNs.length === 0) return;

    cancelledRef.current = false;
    wafCacheRef.current.clear();
    startTimeRef.current = Date.now();
    setRows([]);
    setLogs([]);
    setStats({ namespaces: 0, loadBalancers: 0, routes: 0, wafs: 0 });
    setProgress(0);
    setEta('');
    setStep(2);
    setIsScanning(true);

    logScan('Starting WAF Status Scan...', 'info');

    const allRows: WAFScanRow[] = [];
    for (let i = 0; i < selectedNs.length; i++) {
      if (cancelledRef.current) break;
      const nsRows = await scanNamespace(selectedNs[i], i, selectedNs.length);
      allRows.push(...nsRows);
    }

    setRows(allRows);
    setIsScanning(false);

    if (!cancelledRef.current) {
      logScan('Scan complete!', 'success');
      setStep(3);
    } else {
      logScan('Scan cancelled by user', 'warning');
    }
  };

  const cancelScan = () => {
    cancelledRef.current = true;
    setOperation({ title: 'Cancelling...', subtitle: 'Please wait' });
  };

  const filteredRows = rows.filter(r => {
    if (filter === 'blocking' && r.waf_mode !== 'blocking') return false;
    if (filter === 'monitoring' && r.waf_mode !== 'monitoring') return false;
    if (filter === 'nowaf' && r.waf_mode !== 'disabled') return false;

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        r.namespace.toLowerCase().includes(q) ||
        r.lb_name.toLowerCase().includes(q) ||
        r.route.toLowerCase().includes(q) ||
        r.waf_name.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const summaryStats = {
    blocking: rows.filter(r => r.waf_mode === 'blocking').length,
    monitoring: rows.filter(r => r.waf_mode === 'monitoring').length,
    disabled: rows.filter(r => r.waf_mode === 'disabled' || r.waf_mode === 'unknown').length,
  };

  const exportExcel = () => {
    if (!rows.length) {
      toast.warning('No data to export');
      return;
    }

    let tableRows = `<Row>
      <Cell><Data ss:Type="String">Namespace</Data></Cell>
      <Cell><Data ss:Type="String">Load Balancer</Data></Cell>
      <Cell><Data ss:Type="String">Route</Data></Cell>
      <Cell><Data ss:Type="String">WAF Policy</Data></Cell>
      <Cell><Data ss:Type="String">Mode</Data></Cell>
    </Row>`;

    rows.forEach(r => {
      tableRows += `<Row>
        <Cell><Data ss:Type="String">${r.namespace}</Data></Cell>
        <Cell><Data ss:Type="String">${r.lb_name}</Data></Cell>
        <Cell><Data ss:Type="String">${r.route}</Data></Cell>
        <Cell><Data ss:Type="String">${r.waf_name}</Data></Cell>
        <Cell><Data ss:Type="String">${r.waf_mode}</Data></Cell>
      </Row>`;
    });

    const xml = `<?xml version="1.0"?>
    <?mso-application progid="Excel.Sheet"?>
    <Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
     xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
     <Worksheet ss:Name="WAF Status Summary">
      <Table>${tableRows}</Table>
     </Worksheet>
    </Workbook>`;

    const blob = new Blob([xml], { type: 'application/vnd.ms-excel' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'waf-scan-results.xls';
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Excel file exported');
  };

  const exportJson = () => {
    if (!rows.length) {
      toast.warning('No data to export');
      return;
    }
    const report = {
      generated_at: new Date().toISOString(),
      tool: 'WAF Status Scanner',
      summary: stats,
      lb_status: rows,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'waf-status-report.json';
    a.click();
    URL.revokeObjectURL(url);
    toast.success('JSON report exported');
  };

  const toggleNs = (ns: string) => {
    setSelectedNs(prev => (prev.includes(ns) ? prev.filter(n => n !== ns) : [...prev, ns]));
  };

  const selectAll = () => setSelectedNs(namespaces.map(n => n.name));
  const deselectAll = () => setSelectedNs([]);

  const logIcons: Record<string, string> = {
    info: '📋',
    success: '✅',
    warning: '⚠️',
    error: '❌',
    fetch: '🔄',
    waf: '🛡️',
    route: '🔀',
  };

  return (
    <div className="min-h-screen bg-slate-900">
      <div className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link
              to="/"
              className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-violet-500/15 rounded-xl flex items-center justify-center text-violet-400">
                <Search className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-slate-100">WAF Status Scanner</h1>
                <p className="text-xs text-slate-500">Audit WAF configurations across your environment</p>
              </div>
            </div>
            <Link to="/explainer/waf-scanner" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
              <HelpCircle className="w-3.5 h-3.5" /> How does this work?
            </Link>
          </div>

          <div className="flex items-center gap-2">
            {[1, 2, 3].map(s => (
              <div key={s} className="flex items-center">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold transition-colors ${
                    step > s
                      ? 'bg-emerald-500 text-white'
                      : step === s
                      ? 'bg-blue-500 text-white'
                      : 'bg-slate-700 text-slate-400'
                  }`}
                >
                  {step > s ? <Check className="w-4 h-4" /> : s}
                </div>
                {s < 3 && (
                  <div className={`w-8 h-0.5 ${step > s ? 'bg-emerald-500' : 'bg-slate-700'}`} />
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {step === 1 && (
          <div className="space-y-6">
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-lg font-semibold text-slate-100 mb-1">Select Namespaces</h2>
                  <p className="text-sm text-slate-400">
                    Choose which namespaces to scan for WAF configurations
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={selectAll}
                    className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
                  >
                    Select All
                  </button>
                  <button
                    onClick={deselectAll}
                    className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
                  >
                    Deselect All
                  </button>
                </div>
              </div>

              {isLoadingNs ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
                </div>
              ) : (
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 max-h-80 overflow-y-auto">
                  {namespaces.map(ns => (
                    <label
                      key={ns.name}
                      className={`flex items-center gap-2 p-3 rounded-lg cursor-pointer transition-colors ${
                        selectedNs.includes(ns.name)
                          ? 'bg-blue-500/15 border border-blue-500/30'
                          : 'bg-slate-700/30 border border-transparent hover:bg-slate-700/50'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedNs.includes(ns.name)}
                        onChange={() => toggleNs(ns.name)}
                        className="sr-only"
                      />
                      <div
                        className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${
                          selectedNs.includes(ns.name)
                            ? 'bg-blue-500 border-blue-500'
                            : 'border-slate-500'
                        }`}
                      >
                        {selectedNs.includes(ns.name) && <Check className="w-3 h-3 text-white" />}
                      </div>
                      <span className="text-sm text-slate-300 truncate">{ns.name}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <h3 className="text-sm font-semibold text-slate-200 mb-4">Scan Options</h3>
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeRoutes}
                  onChange={e => setIncludeRoutes(e.target.checked)}
                  className="sr-only"
                />
                <div
                  className={`w-5 h-5 rounded border flex items-center justify-center transition-colors ${
                    includeRoutes ? 'bg-blue-500 border-blue-500' : 'border-slate-500'
                  }`}
                >
                  {includeRoutes && <Check className="w-3 h-3 text-white" />}
                </div>
                <span className="text-sm text-slate-300">Include route-level WAF overrides</span>
              </label>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-400">
                {selectedNs.length > 0
                  ? `Ready to scan ${selectedNs.length} namespace${selectedNs.length > 1 ? 's' : ''}`
                  : 'Select namespaces to continue'}
              </span>
              <button
                onClick={startScan}
                disabled={selectedNs.length === 0}
                className="flex items-center gap-2 px-6 py-3 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors"
              >
                Start Scan
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-6">
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-lg font-semibold text-slate-100">{operation.title}</h2>
                  <p className="text-sm text-slate-400">{operation.subtitle}</p>
                </div>
                <button
                  onClick={cancelScan}
                  className="flex items-center gap-2 px-4 py-2 text-red-400 hover:text-red-300 hover:bg-red-500/10 border border-red-500/30 rounded-lg transition-colors"
                >
                  <X className="w-4 h-4" />
                  Cancel
                </button>
              </div>

              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-slate-400">{progressText}</span>
                  <span className="text-sm font-semibold text-blue-400">{progress}%</span>
                </div>
                <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-blue-500 to-cyan-500 transition-all duration-300"
                    style={{ width: `${progress}%` }}
                  />
                </div>
                {eta && <p className="text-xs text-slate-500 mt-2">{eta}</p>}
              </div>

              <div className="grid grid-cols-4 gap-4">
                <div className="bg-slate-700/30 rounded-lg p-4 text-center">
                  <Server className="w-5 h-5 mx-auto mb-2 text-blue-400" />
                  <div className="text-2xl font-bold text-slate-100">{stats.namespaces}</div>
                  <div className="text-xs text-slate-500">Namespaces</div>
                </div>
                <div className="bg-slate-700/30 rounded-lg p-4 text-center">
                  <Server className="w-5 h-5 mx-auto mb-2 text-emerald-400" />
                  <div className="text-2xl font-bold text-slate-100">{stats.loadBalancers}</div>
                  <div className="text-xs text-slate-500">Load Balancers</div>
                </div>
                <div className="bg-slate-700/30 rounded-lg p-4 text-center">
                  <Route className="w-5 h-5 mx-auto mb-2 text-amber-400" />
                  <div className="text-2xl font-bold text-slate-100">{stats.routes}</div>
                  <div className="text-xs text-slate-500">Routes</div>
                </div>
                <div className="bg-slate-700/30 rounded-lg p-4 text-center">
                  <Shield className="w-5 h-5 mx-auto mb-2 text-violet-400" />
                  <div className="text-2xl font-bold text-slate-100">{stats.wafs}</div>
                  <div className="text-xs text-slate-500">WAF Policies</div>
                </div>
              </div>
            </div>

            <div className="bg-slate-800/50 border border-slate-700 rounded-xl">
              <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
                <span className="text-sm font-semibold text-slate-300">Scan Log</span>
                <span className="text-xs text-slate-500">{logs.length} entries</span>
              </div>
              <div className="h-64 overflow-y-auto p-4 font-mono text-xs space-y-1">
                {logs.map((log, i) => (
                  <div key={i} className="flex items-start gap-2">
                    <span className="text-slate-600">{log.time}</span>
                    <span>{logIcons[log.type]}</span>
                    <span
                      className={
                        log.type === 'error'
                          ? 'text-red-400'
                          : log.type === 'success'
                          ? 'text-emerald-400'
                          : log.type === 'warning'
                          ? 'text-amber-400'
                          : 'text-slate-300'
                      }
                    >
                      {log.message}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-6">
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-6 text-center">
                <Shield className="w-8 h-8 mx-auto mb-2 text-emerald-400" />
                <div className="text-3xl font-bold text-emerald-400">{summaryStats.blocking}</div>
                <div className="text-sm text-emerald-400/70">Blocking</div>
              </div>
              <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-6 text-center">
                <Eye className="w-8 h-8 mx-auto mb-2 text-amber-400" />
                <div className="text-3xl font-bold text-amber-400">{summaryStats.monitoring}</div>
                <div className="text-sm text-amber-400/70">Monitoring</div>
              </div>
              <div className="bg-slate-700/30 border border-slate-600 rounded-xl p-6 text-center">
                <AlertTriangle className="w-8 h-8 mx-auto mb-2 text-slate-400" />
                <div className="text-3xl font-bold text-slate-300">{summaryStats.disabled}</div>
                <div className="text-sm text-slate-500">Disabled/None</div>
              </div>
            </div>

            <div className="bg-slate-800/50 border border-slate-700 rounded-xl">
              <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
                <div className="flex items-center gap-2">
                  {(['all', 'blocking', 'monitoring', 'nowaf'] as Filter[]).map(f => (
                    <button
                      key={f}
                      onClick={() => setFilter(f)}
                      className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                        filter === f
                          ? 'bg-blue-500 text-white'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700'
                      }`}
                    >
                      {f === 'all' ? 'All' : f === 'nowaf' ? 'No WAF' : f.charAt(0).toUpperCase() + f.slice(1)}
                    </button>
                  ))}
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    placeholder="Search..."
                    className="px-3 py-1.5 bg-slate-700 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-500 w-48"
                  />
                  <button
                    onClick={exportExcel}
                    className="flex items-center gap-1 px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
                  >
                    <Table className="w-4 h-4" />
                    Excel
                  </button>
                  <button
                    onClick={exportJson}
                    className="flex items-center gap-1 px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
                  >
                    <FileJson className="w-4 h-4" />
                    JSON
                  </button>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-slate-700/30">
                    <tr>
                      <th className="px-4 py-3 text-left text-slate-400 font-medium">Namespace</th>
                      <th className="px-4 py-3 text-left text-slate-400 font-medium">Load Balancer</th>
                      <th className="px-4 py-3 text-left text-slate-400 font-medium">Route</th>
                      <th className="px-4 py-3 text-left text-slate-400 font-medium">WAF Policy</th>
                      <th className="px-4 py-3 text-left text-slate-400 font-medium">Mode</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredRows.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-4 py-12 text-center text-slate-500">
                          No results found
                        </td>
                      </tr>
                    ) : (
                      filteredRows.map((row, i) => (
                        <tr
                          key={i}
                          className={`border-t border-slate-700/50 ${row.inherited ? 'opacity-70' : ''}`}
                        >
                          <td className="px-4 py-3 text-slate-300">{row.namespace}</td>
                          <td className="px-4 py-3 text-slate-300">{row.lb_name}</td>
                          <td className="px-4 py-3 text-slate-400 font-mono text-xs">{row.route}</td>
                          <td className="px-4 py-3 text-slate-300">{row.waf_name}</td>
                          <td className="px-4 py-3">
                            <span
                              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${
                                row.waf_mode === 'blocking'
                                  ? 'bg-emerald-500/15 text-emerald-400'
                                  : row.waf_mode === 'monitoring'
                                  ? 'bg-amber-500/15 text-amber-400'
                                  : 'bg-slate-700 text-slate-400'
                              }`}
                            >
                              {row.waf_mode === 'blocking' && '🛡️'}
                              {row.waf_mode === 'monitoring' && '👁️'}
                              {row.waf_mode !== 'blocking' && row.waf_mode !== 'monitoring' && '⚠️'}
                              {row.waf_mode}
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              <div className="px-4 py-3 border-t border-slate-700 text-sm text-slate-500">
                Found {rows.length} configuration records across {stats.loadBalancers} load balancers
              </div>
            </div>

            <div className="flex justify-center">
              <button
                onClick={() => {
                  setStep(1);
                  setRows([]);
                  setSelectedNs([]);
                }}
                className="px-6 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
              >
                Start New Scan
              </button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
