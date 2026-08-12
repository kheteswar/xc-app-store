import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Copy,
  Loader2,
  Check,
  X,
  ChevronRight,
  ChevronDown,
  Server,
  ArrowRight,
  Eye,
  EyeOff,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Code,
  RefreshCw,
  Building2,
  FolderOpen,
  HelpCircle,
} from 'lucide-react';
import { apiClient } from '../services/api';
import { F5XCApiClient } from '../services/api';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import type { Namespace, AlertReceiver, AlertPolicy, CDNCacheRule } from '../types';

type CopyMode = 'cross-tenant' | 'cross-namespace';
type Step = 1 | 2 | 3 | 4;

// Every namespaced F5 XC config object the tool can copy. `path` is the API
// segment (/api/config/namespaces/<ns>/<path>). XC uses the "...policys" spelling.
type CopyType =
  | 'http_loadbalancer' | 'tcp_loadbalancer' | 'cdn_loadbalancer'
  | 'origin_pool' | 'healthcheck'
  | 'app_firewall' | 'service_policy' | 'service_policy_set' | 'rate_limiter' | 'rate_limiter_policy'
  | 'bot_defense_policy' | 'api_definition' | 'malicious_user_mitigation' | 'user_identification' | 'forward_proxy_policy'
  | 'ip_prefix_set' | 'bgp_asn_set'
  | 'dns_zone' | 'dns_load_balancer'
  | 'virtual_site'
  | 'alert_receiver' | 'alert_policy' | 'global_log_receiver'
  | 'cdn_cache_rule'
  | 'certificate' | 'trusted_ca_list';

const API_PATHS: Record<CopyType, string> = {
  http_loadbalancer: 'http_loadbalancers', tcp_loadbalancer: 'tcp_loadbalancers', cdn_loadbalancer: 'cdn_loadbalancers',
  origin_pool: 'origin_pools', healthcheck: 'healthchecks',
  app_firewall: 'app_firewalls', service_policy: 'service_policys', service_policy_set: 'service_policy_sets',
  rate_limiter: 'rate_limiters', rate_limiter_policy: 'rate_limiter_policys',
  bot_defense_policy: 'bot_defense_policys', api_definition: 'api_definitions', malicious_user_mitigation: 'malicious_user_mitigations',
  user_identification: 'user_identifications', forward_proxy_policy: 'forward_proxy_policys',
  ip_prefix_set: 'ip_prefix_sets', bgp_asn_set: 'bgp_asn_sets',
  dns_zone: 'dns_zones', dns_load_balancer: 'dns_load_balancers',
  virtual_site: 'virtual_sites',
  alert_receiver: 'alert_receivers', alert_policy: 'alert_policys', global_log_receiver: 'global_log_receivers',
  cdn_cache_rule: 'cdn_cache_rules',
  certificate: 'certificates', trusted_ca_list: 'trusted_ca_lists',
};

const TYPE_LABELS: Record<CopyType, string> = {
  http_loadbalancer: 'HTTP Load Balancer', tcp_loadbalancer: 'TCP Load Balancer', cdn_loadbalancer: 'CDN Load Balancer',
  origin_pool: 'Origin Pool', healthcheck: 'Health Check',
  app_firewall: 'WAF Policy', service_policy: 'Service Policy', service_policy_set: 'Service Policy Set',
  rate_limiter: 'Rate Limiter', rate_limiter_policy: 'Rate Limiter Policy',
  bot_defense_policy: 'Bot Defense Policy', api_definition: 'API Definition', malicious_user_mitigation: 'Malicious User Mitigation',
  user_identification: 'User Identification', forward_proxy_policy: 'Forward Proxy Policy',
  ip_prefix_set: 'IP Prefix Set', bgp_asn_set: 'BGP ASN Set',
  dns_zone: 'DNS Zone', dns_load_balancer: 'DNS Load Balancer',
  virtual_site: 'Virtual Site',
  alert_receiver: 'Alert Receiver', alert_policy: 'Alert Policy', global_log_receiver: 'Global Log Receiver',
  cdn_cache_rule: 'CDN Cache Rule',
  certificate: 'TLS Certificate', trusted_ca_list: 'Trusted CA List',
};

// Grouped for the selector UI.
const TYPE_CATEGORIES: { label: string; types: CopyType[] }[] = [
  { label: 'Load Balancers', types: ['http_loadbalancer', 'tcp_loadbalancer', 'cdn_loadbalancer'] },
  { label: 'Pools & Health', types: ['origin_pool', 'healthcheck'] },
  { label: 'App Security', types: ['app_firewall', 'service_policy', 'service_policy_set', 'rate_limiter', 'rate_limiter_policy', 'bot_defense_policy', 'api_definition', 'malicious_user_mitigation', 'user_identification', 'forward_proxy_policy'] },
  { label: 'Matchers & Sets', types: ['ip_prefix_set', 'bgp_asn_set'] },
  { label: 'DNS', types: ['dns_zone', 'dns_load_balancer'] },
  { label: 'Network', types: ['virtual_site'] },
  { label: 'Observability', types: ['alert_receiver', 'alert_policy', 'global_log_receiver'] },
  { label: 'Content & Certs', types: ['cdn_cache_rule', 'certificate', 'trusted_ca_list'] },
];

// Namespaces whose objects are global/built-in — referenced, never copied.
const SHARED_NS = new Set(['shared', 'system', 'ves-io-shared']);
// Types that carry child references we auto-resolve.
const PARENT_TYPES: CopyType[] = ['http_loadbalancer', 'tcp_loadbalancer', 'cdn_loadbalancer', 'origin_pool', 'service_policy_set'];
const hasChildren = (t: CopyType) => PARENT_TYPES.includes(t);

interface DepNode {
  type: CopyType; name: string; namespace: string;
  spec: any; obj: any; error?: string; existsInDest?: boolean;
}
interface LbTree { root: string; nodes: DepNode[]; } // nodes in create order (children first, LB last)

// Extract the child-object references from a load balancer / origin pool spec.
function childRefs(type: CopyType, spec: any): Array<{ type: CopyType; name: string; namespace?: string }> {
  const refs: Array<{ type: CopyType; name: string; namespace?: string }> = [];
  const add = (ref: any, t: CopyType) => { if (ref && ref.name) refs.push({ type: t, name: ref.name, namespace: ref.namespace }); };
  if (type === 'http_loadbalancer') {
    add(spec.app_firewall, 'app_firewall');
    add(spec.bot_defense?.policy, 'bot_defense_policy');
    add(spec.user_identification, 'user_identification');
    (spec.active_service_policies?.policies || []).forEach((p: any) => add(p, 'service_policy'));
    (spec.rate_limit?.policies?.policies || []).forEach((p: any) => add(p, 'rate_limiter_policy'));
    (spec.default_route_pools || []).forEach((p: any) => add(p.pool, 'origin_pool'));
    (spec.routes || []).forEach((r: any) => {
      (r.simple_route?.origin_pools || []).forEach((d: any) => add(d.pool, 'origin_pool'));
      (r.route_destination?.destinations || []).forEach((d: any) => add(d.pool, 'origin_pool'));
    });
    add(spec.origin_pool, 'origin_pool');
    add(spec.malicious_user_mitigation, 'malicious_user_mitigation');
    add(spec.api_definition, 'api_definition');
  } else if (type === 'tcp_loadbalancer') {
    (spec.origin_pools || []).forEach((d: any) => add(d.pool, 'origin_pool'));
    (spec.origin_pools_weights || []).forEach((d: any) => add(d.pool, 'origin_pool'));
    (spec.active_service_policies?.policies || []).forEach((p: any) => add(p, 'service_policy'));
  } else if (type === 'service_policy_set') {
    (spec.policies || []).forEach((p: any) => add(p, 'service_policy'));
  } else if (type === 'cdn_loadbalancer') {
    (spec.custom_cache_rule?.cdn_cache_rules || []).forEach((r: any) => add(r, 'cdn_cache_rule'));
    add(spec.app_firewall, 'app_firewall');
  } else if (type === 'origin_pool') {
    (spec.healthcheck || []).forEach((hc: any) => add(hc, 'healthcheck'));
  }
  return refs;
}

// Prepare a spec for creation in the destination: drop read-only fields and
// repoint same-namespace references to the destination namespace (names stay
// identical, so cross-tenant/cross-namespace copies resolve correctly).
function sanitizeSpec(o: any, from: string, to: string): void {
  if (Array.isArray(o)) { o.forEach(x => sanitizeSpec(x, from, to)); return; }
  if (o && typeof o === 'object') {
    const isRef = typeof o.name === 'string' && (typeof o.namespace === 'string' || typeof o.tenant === 'string');
    if ('uid' in o) delete o.uid;
    if ('tenant' in o) delete o.tenant;
    if (isRef && 'kind' in o) delete o.kind;   // read-only on object references
    if (typeof o.namespace === 'string' && o.namespace === from) o.namespace = to;
    for (const k of Object.keys(o)) sanitizeSpec(o[k], from, to);
  }
}

function buildPayload(node: DepNode, destNs: string, sourceNs: string): any {
  const obj = node.obj || {};
  const rawSpec = node.spec || obj.spec || obj.get_spec || {};
  const spec = JSON.parse(JSON.stringify(rawSpec));
  sanitizeSpec(spec, sourceNs, destNs);
  const md = obj.metadata || {};
  const metadata: Record<string, unknown> = { name: node.name, namespace: destNs };
  if (md.description) metadata.description = md.description;
  if (md.labels && Object.keys(md.labels).length) metadata.labels = md.labels;
  if (md.annotations && Object.keys(md.annotations).length) metadata.annotations = md.annotations;
  if (md.disable) metadata.disable = md.disable;
  return { metadata, spec };
}

interface SelectedObject {
  type: CopyType;
  name: string;
  namespace: string;
  data: AlertReceiver | AlertPolicy | CDNCacheRule;
}

interface CopyResult {
  name: string;
  success: boolean;
  error?: string;
  skipped?: boolean;
}

export function CopyConfig() {
  const { isConnected, tenant } = useApp();
  const navigate = useNavigate();
  const toast = useToast();

  // Step management
  const [step, setStep] = useState<Step>(1);
  const [copyMode, setCopyMode] = useState<CopyMode | null>(null);

  // Source tenant (current connected tenant)
  const [sourceNamespaces, setSourceNamespaces] = useState<Namespace[]>([]);
  const [selectedSourceNs, setSelectedSourceNs] = useState('');
  const [isLoadingSourceNs, setIsLoadingSourceNs] = useState(true);

  // Destination tenant (for cross-tenant mode)
  const DEST_CREDS_KEY = 'xc_copyconfig_dest_creds';
  const [destTenant, setDestTenant] = useState('');
  const [destApiToken, setDestApiToken] = useState('');
  const [showDestToken, setShowDestToken] = useState(false);
  const [rememberDest, setRememberDest] = useState(false);
  const [isValidatingDest, setIsValidatingDest] = useState(false);
  const [destValidated, setDestValidated] = useState(false);
  const [destNamespaces, setDestNamespaces] = useState<Namespace[]>([]);
  const [selectedDestNs, setSelectedDestNs] = useState('');

  // Config object selection
  const [selectedObjectType, setSelectedObjectType] = useState<CopyType>('alert_receiver');
  const [availableObjects, setAvailableObjects] = useState<Array<{ name: string; data: unknown }>>([]);
  const [selectedObjects, setSelectedObjects] = useState<string[]>([]);
  const [isLoadingObjects, setIsLoadingObjects] = useState(false);

  // Preview & Copy
  const [depTrees, setDepTrees] = useState<LbTree[]>([]);
  const [expandedPreview, setExpandedPreview] = useState<string | null>(null);
  const [isCopying, setIsCopying] = useState(false);
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);
  const [copyResults, setCopyResults] = useState<CopyResult[]>([]);

  // JSON Modal
  const [jsonModal, setJsonModal] = useState<{ title: string; data: unknown } | null>(null);

  useEffect(() => {
    if (!isConnected) {
      navigate('/');
      return;
    }
    loadSourceNamespaces();
    // Restore remembered destination credentials
    try {
      const saved = localStorage.getItem(DEST_CREDS_KEY);
      if (saved) {
        const { tenant: t, token } = JSON.parse(saved);
        if (t) setDestTenant(t);
        if (token) setDestApiToken(token);
        setRememberDest(true);
      }
    } catch {
      // ignore corrupt storage
    }
  }, [isConnected, navigate]);

  const loadSourceNamespaces = async () => {
    setIsLoadingSourceNs(true);
    try {
      const resp = await apiClient.getNamespaces();
      setSourceNamespaces(resp.items.sort((a, b) => a.name.localeCompare(b.name)));
    } catch {
      toast.error('Failed to load namespaces');
    } finally {
      setIsLoadingSourceNs(false);
    }
  };

  const handleRememberChange = (checked: boolean) => {
    setRememberDest(checked);
    if (checked && destTenant.trim() && destApiToken.trim()) {
      localStorage.setItem(DEST_CREDS_KEY, JSON.stringify({ tenant: destTenant.trim(), token: destApiToken.trim() }));
    } else if (!checked) {
      localStorage.removeItem(DEST_CREDS_KEY);
    }
  };

  const validateDestinationTenant = async () => {
    if (!destTenant.trim() || !destApiToken.trim()) {
      toast.warning('Please enter destination tenant and API token');
      return;
    }

    setIsValidatingDest(true);
    try {
      const resp = await F5XCApiClient.proxyRequestStatic<{ items: Namespace[] }>(
        destTenant.trim(),
        destApiToken.trim(),
        '/api/web/namespaces',
        'GET'
      );
      setDestNamespaces(resp.items.sort((a, b) => a.name.localeCompare(b.name)));
      setDestValidated(true);
      if (rememberDest) {
        localStorage.setItem(DEST_CREDS_KEY, JSON.stringify({ tenant: destTenant.trim(), token: destApiToken.trim() }));
      }
      toast.success(`Connected to ${destTenant}`);
    } catch (err) {
      toast.error('Failed to connect to destination tenant. Check credentials.');
      setDestValidated(false);
    } finally {
      setIsValidatingDest(false);
    }
  };

  const loadConfigObjects = async () => {
    if (!selectedSourceNs) return;

    setIsLoadingObjects(true);
    setAvailableObjects([]);
    setSelectedObjects([]);

    try {
      // Generic list — works for every namespaced config object type.
      const resp: any = await apiClient.get(`/api/config/namespaces/${selectedSourceNs}/${API_PATHS[selectedObjectType]}`);
      const items = (resp.items || []).map((item: any) => ({ name: item.name || item.metadata?.name || 'unknown', data: item }));
      setAvailableObjects(items);
    } catch (err) {
      toast.error(`Failed to load ${TYPE_LABELS[selectedObjectType]}s`);
    } finally {
      setIsLoadingObjects(false);
    }
  };

  useEffect(() => {
    if (selectedSourceNs && step === 2) {
      loadConfigObjects();
    }
  }, [selectedSourceNs, selectedObjectType, step]);

  const toggleObjectSelection = (name: string) => {
    setSelectedObjects(prev =>
      prev.includes(name) ? prev.filter(n => n !== name) : [...prev, name]
    );
  };

  const selectAllObjects = () => {
    setSelectedObjects(availableObjects.map(o => o.name));
  };

  const deselectAllObjects = () => {
    setSelectedObjects([]);
  };

  // ─── Fetchers (source = current tenant; dest = current or remote tenant) ──
  const sourceGet = (path: string): Promise<any> => apiClient.get(path);
  const destGet = (path: string): Promise<any> =>
    copyMode === 'cross-tenant'
      ? F5XCApiClient.proxyRequestStatic(destTenant.trim(), destApiToken.trim(), path, 'GET')
      : apiClient.get(path);
  const destPost = (path: string, body: unknown): Promise<any> =>
    copyMode === 'cross-tenant'
      ? F5XCApiClient.proxyRequestStatic(destTenant.trim(), destApiToken.trim(), path, 'POST', body)
      : apiClient.post(path, body);

  // Does an object already exist in the destination namespace?
  const existsInDest = async (type: CopyType, name: string, ns: string): Promise<boolean> => {
    try { await destGet(`/api/config/namespaces/${ns}/${API_PATHS[type]}/${encodeURIComponent(name)}`); return true; }
    catch { return false; }
  };

  // DFS from a load balancer, fetching each object's spec and recursing into its
  // children. Produces a post-order list (children first, LB last) — the create
  // order. Shared/system references and cross-namespace refs are left as links.
  const resolveTree = async (rootType: CopyType, rootName: string, rootNs: string, visited: Set<string>, ordered: DepNode[]): Promise<void> => {
    const key = `${rootType}:${rootName}`;
    if (visited.has(key)) return;
    visited.add(key);
    let obj: any = null, spec: any = null;
    try {
      obj = await sourceGet(`/api/config/namespaces/${rootNs}/${API_PATHS[rootType]}/${encodeURIComponent(rootName)}`);
      spec = obj.spec || obj.get_spec;
    } catch {
      ordered.push({ type: rootType, name: rootName, namespace: rootNs, spec: null, obj: null, error: 'Source fetch failed' });
      return;
    }
    for (const c of childRefs(rootType, spec || {})) {
      const cns = c.namespace || rootNs;
      if (SHARED_NS.has(cns)) continue;   // global/built-in — reference, don't copy
      if (cns !== rootNs) continue;       // lives in another namespace — leave as link
      await resolveTree(c.type, c.name, rootNs, visited, ordered);
    }
    ordered.push({ type: rootType, name: rootName, namespace: rootNs, spec, obj });
  };

  const preparePreview = async () => {
    setIsLoadingPreview(true);
    setDepTrees([]);
    const trees: LbTree[] = [];
    try {
      for (const name of selectedObjects) {
        const visited = new Set<string>();
        const ordered: DepNode[] = [];
        await resolveTree(selectedObjectType, name, selectedSourceNs, visited, ordered);
        for (const node of ordered) {
          node.existsInDest = node.error ? false : await existsInDest(node.type, node.name, selectedDestNs);
        }
        trees.push({ root: name, nodes: ordered });
      }
      setDepTrees(trees);
      setStep(3);
    } catch (err) {
      toast.error(`Failed to resolve dependencies: ${err instanceof Error ? err.message : err}`);
    } finally {
      setIsLoadingPreview(false);
    }
  };


  // Copy a load balancer with all its children, in dependency order.
  const executeCopyLb = async () => {
    setIsCopying(true);
    setCopyResults([]);
    const results: CopyResult[] = [];
    for (const tree of depTrees) {
      for (const node of tree.nodes) {
        const label = `${TYPE_LABELS[node.type]}: ${node.name}`;
        let exists = node.existsInDest === true;
        if (!exists && !node.error) exists = await existsInDest(node.type, node.name, selectedDestNs);
        if (exists) { results.push({ name: label, success: true, skipped: true }); continue; }
        if (node.error || !node.obj) { results.push({ name: label, success: false, error: node.error || 'No source data' }); continue; }
        try {
          const payload = buildPayload(node, selectedDestNs, selectedSourceNs);
          await destPost(`/api/config/namespaces/${selectedDestNs}/${API_PATHS[node.type]}`, payload);
          results.push({ name: label, success: true });
        } catch (err) {
          results.push({ name: label, success: false, error: err instanceof Error ? err.message : 'Unknown error' });
        }
      }
    }
    setCopyResults(results);
    setStep(4);
    setIsCopying(false);
    const created = results.filter(r => r.success && !r.skipped).length;
    const skipped = results.filter(r => r.skipped).length;
    const failed = results.filter(r => !r.success).length;
    if (failed === 0) toast.success(`Copied ${created} object(s)${skipped ? `, ${skipped} already existed` : ''}`);
    else toast.warning(`Created ${created}, skipped ${skipped}, failed ${failed}`);
  };

  const executeCopy = async () => {
    if (!selectedDestNs) { toast.warning('Please select a destination namespace'); return; }
    await executeCopyLb();
  };

  const resetWizard = () => {
    setStep(1);
    setCopyMode(null);
    setSelectedSourceNs('');
    setSelectedDestNs('');
    setDestTenant('');
    setDestApiToken('');
    setDestValidated(false);
    setDestNamespaces([]);
    setSelectedObjects([]);
    setDepTrees([]);
    setCopyResults([]);
  };

  // After a copy: keep the tenant/namespace setup, go back to type selection.
  const resetForNewType = () => {
    setSelectedObjects([]);
    setDepTrees([]);
    setCopyResults([]);
    setStep(2);
  };

  const getReceiverType = (receiver: AlertReceiver): string => {
    const spec = receiver.spec || receiver.get_spec;
    if (!spec) return 'Unknown';
    if (spec.slack) return 'Slack';
    if (spec.pagerduty) return 'PagerDuty';
    if (spec.opsgenie) return 'OpsGenie';
    if (spec.email) return 'Email';
    if (spec.sms) return 'SMS';
    if (spec.webhook) return 'Webhook';
    return 'None';
  };

  const canProceedToStep2 = () => {
    if (copyMode === 'cross-tenant') {
      return destValidated && selectedSourceNs;
    }
    return selectedSourceNs;
  };

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header */}
      <div className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => step === 1 ? navigate('/') : setStep((step - 1) as Step)}
              title={step === 1 ? 'Back to Home' : 'Previous step'}
              className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-emerald-500/15 rounded-xl flex items-center justify-center text-emerald-400">
                <Copy className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-slate-100">Copy Config</h1>
                <p className="text-xs text-slate-500">
                  Copy configurations across tenants or namespaces
                </p>
              </div>
            </div>
            <Link to="/explainer/copy-config" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
              <HelpCircle className="w-3.5 h-3.5" /> How does this work?
            </Link>
          </div>

          {/* Progress Steps */}
          <div className="flex items-center gap-2">
            {[1, 2, 3, 4].map(s => (
              <div
                key={s}
                className={`flex items-center gap-1 ${s <= step ? 'text-emerald-400' : 'text-slate-600'}`}
              >
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold ${
                    s < step
                      ? 'bg-emerald-500 text-white'
                      : s === step
                      ? 'bg-emerald-500/20 border-2 border-emerald-500 text-emerald-400'
                      : 'bg-slate-800 text-slate-500'
                  }`}
                >
                  {s < step ? <Check className="w-4 h-4" /> : s}
                </div>
                {s < 4 && (
                  <ChevronRight className={`w-4 h-4 ${s < step ? 'text-emerald-400' : 'text-slate-600'}`} />
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      <main className="max-w-5xl mx-auto px-6 py-8">
        {/* Step 1: Select Mode & Configure Tenants */}
        {step === 1 && (
          <div className="space-y-8">
            <div className="text-center mb-8">
              <h2 className="text-2xl font-bold text-slate-100 mb-2">Select Copy Mode</h2>
              <p className="text-slate-400">Choose how you want to copy configurations</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Cross-Tenant Option */}
              <button
                onClick={() => setCopyMode('cross-tenant')}
                className={`p-6 rounded-xl border-2 text-left transition-all ${
                  copyMode === 'cross-tenant'
                    ? 'border-emerald-500 bg-emerald-500/10'
                    : 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                }`}
              >
                <div className="flex items-center gap-3 mb-4">
                  <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                    copyMode === 'cross-tenant' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-700 text-slate-400'
                  }`}>
                    <Building2 className="w-6 h-6" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-slate-100">Copy Across Tenants</h3>
                    <span className="text-sm text-slate-500">Different F5 XC tenants</span>
                  </div>
                </div>
                <p className="text-sm text-slate-400">
                  Copy configurations from this tenant to a different F5 XC tenant. Requires API token for the destination tenant.
                </p>
              </button>

              {/* Cross-Namespace Option */}
              <button
                onClick={() => setCopyMode('cross-namespace')}
                className={`p-6 rounded-xl border-2 text-left transition-all ${
                  copyMode === 'cross-namespace'
                    ? 'border-emerald-500 bg-emerald-500/10'
                    : 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                }`}
              >
                <div className="flex items-center gap-3 mb-4">
                  <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                    copyMode === 'cross-namespace' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-700 text-slate-400'
                  }`}>
                    <FolderOpen className="w-6 h-6" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-slate-100">Copy Across Namespaces</h3>
                    <span className="text-sm text-slate-500">Same tenant, different namespace</span>
                  </div>
                </div>
                <p className="text-sm text-slate-400">
                  Copy configurations between namespaces within the current tenant ({tenant}).
                </p>
              </button>
            </div>

            {/* Cross-Tenant Configuration */}
            {copyMode === 'cross-tenant' && (
              <div className="mt-8 p-6 bg-slate-800/50 border border-slate-700 rounded-xl">
                <h3 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
                  <Building2 className="w-5 h-5 text-emerald-400" />
                  Destination Tenant Configuration
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Destination Tenant Name */}
                  <div>
                    <label className="block text-sm font-semibold text-slate-200 mb-2">
                      Destination Tenant Name
                    </label>
                    <div className="relative">
                      <input
                        type="text"
                        value={destTenant}
                        onChange={e => {
                          setDestTenant(e.target.value);
                          setDestValidated(false);
                          if (rememberDest) localStorage.removeItem(DEST_CREDS_KEY);
                        }}
                        placeholder="destination-tenant"
                        className="w-full px-4 py-3 pr-48 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 font-mono text-sm focus:outline-none focus:border-emerald-500 placeholder:text-slate-600"
                      />
                      <span className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 font-mono text-xs pointer-events-none">
                        .console.ves.volterra.io
                      </span>
                    </div>
                  </div>

                  {/* Destination API Token */}
                  <div>
                    <label className="block text-sm font-semibold text-slate-200 mb-2">
                      Destination API Token
                    </label>
                    <div className="relative">
                      <input
                        type={showDestToken ? 'text' : 'password'}
                        value={destApiToken}
                        onChange={e => {
                          setDestApiToken(e.target.value);
                          setDestValidated(false);
                          if (rememberDest) localStorage.removeItem(DEST_CREDS_KEY);
                        }}
                        placeholder="API token for destination tenant"
                        className="w-full px-4 py-3 pr-12 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 font-mono text-sm focus:outline-none focus:border-emerald-500 placeholder:text-slate-600"
                      />
                      <button
                        type="button"
                        onClick={() => setShowDestToken(!showDestToken)}
                        className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                      >
                        {showDestToken ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="mt-4 flex items-center gap-4 flex-wrap">
                  <button
                    onClick={validateDestinationTenant}
                    disabled={isValidatingDest || !destTenant.trim() || !destApiToken.trim()}
                    className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors"
                  >
                    {isValidatingDest ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Check className="w-4 h-4" />
                    )}
                    Validate Connection
                  </button>

                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={rememberDest}
                      onChange={e => handleRememberChange(e.target.checked)}
                      className="w-4 h-4 rounded border-slate-600 bg-slate-900 text-emerald-500 accent-emerald-500 cursor-pointer"
                    />
                    <span className="text-sm text-slate-400">Remember credentials</span>
                  </label>

                  {destValidated && (
                    <span className="flex items-center gap-2 text-emerald-400 text-sm">
                      <CheckCircle className="w-4 h-4" />
                      Connected to {destTenant}
                    </span>
                  )}
                </div>
              </div>
            )}

            {/* Source & Destination Namespace Selection */}
            {copyMode && (
              <div className="mt-8 p-6 bg-slate-800/50 border border-slate-700 rounded-xl">
                <h3 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
                  <FolderOpen className="w-5 h-5 text-blue-400" />
                  Namespace Selection
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Source Namespace */}
                  <div>
                    <label className="block text-sm font-semibold text-slate-200 mb-2">
                      Source Namespace <span className="text-slate-500">({tenant})</span>
                    </label>
                    <select
                      value={selectedSourceNs}
                      onChange={e => setSelectedSourceNs(e.target.value)}
                      disabled={isLoadingSourceNs}
                      className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 text-sm focus:outline-none focus:border-blue-500"
                    >
                      <option value="">Select source namespace</option>
                      {sourceNamespaces.map(ns => (
                        <option key={ns.name} value={ns.name}>{ns.name}</option>
                      ))}
                    </select>
                  </div>

                  {/* Destination Namespace */}
                  <div>
                    <label className="block text-sm font-semibold text-slate-200 mb-2">
                      Destination Namespace
                      {copyMode === 'cross-tenant' && destTenant && (
                        <span className="text-slate-500"> ({destTenant})</span>
                      )}
                      {copyMode === 'cross-namespace' && (
                        <span className="text-slate-500"> ({tenant})</span>
                      )}
                    </label>
                    <select
                      value={selectedDestNs}
                      onChange={e => setSelectedDestNs(e.target.value)}
                      disabled={
                        copyMode === 'cross-tenant'
                          ? !destValidated
                          : !selectedSourceNs
                      }
                      className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 text-sm focus:outline-none focus:border-blue-500 disabled:opacity-50"
                    >
                      <option value="">Select destination namespace</option>
                      {(copyMode === 'cross-tenant' ? destNamespaces : sourceNamespaces).map(ns => (
                        <option key={ns.name} value={ns.name}>{ns.name}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>
            )}

            {/* Next Button */}
            {copyMode && (
              <div className="flex justify-end">
                <button
                  onClick={() => setStep(2)}
                  disabled={!canProceedToStep2() || !selectedDestNs}
                  className="flex items-center gap-2 px-6 py-3 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors"
                >
                  Continue
                  <ChevronRight className="w-5 h-5" />
                </button>
              </div>
            )}
          </div>
        )}

        {/* Step 2: Select Objects to Copy */}
        {step === 2 && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold text-slate-100 mb-2">Select Objects to Copy</h2>
                <p className="text-slate-400">
                  From <span className="text-blue-400">{selectedSourceNs}</span> to{' '}
                  <span className="text-emerald-400">{selectedDestNs}</span>
                  {copyMode === 'cross-tenant' && (
                    <span className="text-slate-500"> ({destTenant})</span>
                  )}
                </p>
              </div>
              <button
                onClick={() => setStep(1)}
                className="px-4 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
              >
                Back
              </button>
            </div>

            {/* Object Type Selector */}
            <div className="p-4 bg-slate-800/50 border border-slate-700 rounded-xl">
              <p className="text-xs text-slate-500 mb-3">Select a config type to load objects from <span className="text-blue-400 font-medium">{selectedSourceNs}</span>:</p>
              <div className="space-y-3">
                {TYPE_CATEGORIES.map(cat => (
                  <div key={cat.label} className="flex items-start gap-3">
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 w-28 flex-shrink-0 pt-2">{cat.label}</span>
                    <div className="flex flex-wrap gap-2">
                      {cat.types.map(type => (
                        <button
                          key={type}
                          onClick={() => setSelectedObjectType(type)}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                            selectedObjectType === type
                              ? 'bg-blue-500 border-blue-500 text-white shadow shadow-blue-500/20'
                              : 'bg-slate-700/60 border-slate-600 text-slate-300 hover:border-blue-500/50 hover:text-white'
                          }`}
                        >
                          {selectedObjectType === type && isLoadingObjects
                            ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            : selectedObjectType === type
                            ? <Check className="w-3.5 h-3.5" />
                            : hasChildren(type) ? <Server className="w-3.5 h-3.5 opacity-60" /> : null}
                          {TYPE_LABELS[type]}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              {hasChildren(selectedObjectType) && (
                <p className="mt-3 text-xs text-emerald-400/90 flex items-center gap-1.5">
                  <Check className="w-3.5 h-3.5" /> Child objects (origin pools, WAF, service &amp; rate-limit policies, health checks…) are auto-detected and created first if missing.
                </p>
              )}
            </div>

            {/* Objects List */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl">
              <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
                <span className="text-sm font-semibold text-slate-300">
                  Available {TYPE_LABELS[selectedObjectType]}s
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={selectAllObjects}
                    className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
                  >
                    Select All
                  </button>
                  <button
                    onClick={deselectAllObjects}
                    className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
                  >
                    Deselect All
                  </button>
                </div>
              </div>

              <div className="p-4">
                {isLoadingObjects ? (
                  <div className="flex items-center justify-center py-12">
                    <Loader2 className="w-8 h-8 animate-spin text-blue-400" />
                  </div>
                ) : availableObjects.length === 0 ? (
                  <div className="text-center py-12 text-slate-500">
                    No {TYPE_LABELS[selectedObjectType].toLowerCase()}s found in {selectedSourceNs}
                  </div>
                ) : (
                  <div className="space-y-2">
                    {availableObjects.map(obj => (
                      <div
                        key={obj.name}
                        onClick={() => toggleObjectSelection(obj.name)}
                        className={`flex items-center justify-between p-4 rounded-lg border cursor-pointer transition-colors ${
                          selectedObjects.includes(obj.name)
                            ? 'bg-blue-500/10 border-blue-500/50'
                            : 'bg-slate-700/30 border-slate-700 hover:border-slate-600'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <div
                            className={`w-5 h-5 rounded border-2 flex items-center justify-center ${
                              selectedObjects.includes(obj.name)
                                ? 'bg-blue-500 border-blue-500'
                                : 'border-slate-500'
                            }`}
                          >
                            {selectedObjects.includes(obj.name) && (
                              <Check className="w-3 h-3 text-white" />
                            )}
                          </div>
                          <div>
                            <span className="text-slate-200 font-medium">{obj.name}</span>
                            {selectedObjectType === 'alert_receiver' && (
                              <span className="ml-2 text-xs text-slate-500">
                                ({getReceiverType(obj.data as AlertReceiver)})
                              </span>
                            )}
                          </div>
                        </div>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setJsonModal({ title: obj.name, data: obj.data });
                          }}
                          className="p-2 text-slate-500 hover:text-slate-300 hover:bg-slate-700 rounded transition-colors"
                        >
                          <Code className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="px-4 py-3 border-t border-slate-700 text-sm text-slate-500">
                {selectedObjects.length} of {availableObjects.length} selected
              </div>
            </div>

            {/* Next Button */}
            <div className="flex justify-between">
              <button
                onClick={() => setStep(1)}
                className="px-6 py-3 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
              >
                Back
              </button>
              <button
                onClick={preparePreview}
                disabled={selectedObjects.length === 0 || isLoadingPreview}
                className="flex items-center gap-2 px-6 py-3 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors"
              >
                {isLoadingPreview ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Loading Details...
                  </>
                ) : (
                  <>
                    Preview Changes
                    <ChevronRight className="w-5 h-5" />
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* Step 3: Preview & Confirm */}
        {step === 3 && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold text-slate-100 mb-2">Preview & Confirm</h2>
                <p className="text-slate-400">
                  Review the objects that will be copied
                </p>
              </div>
              <button
                onClick={() => setStep(2)}
                className="px-4 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
              >
                Back
              </button>
            </div>

            {/* Copy Summary */}
            <div className="p-4 bg-slate-800/50 border border-slate-700 rounded-xl">
              <div className="flex items-center gap-6">
                <div className="flex items-center gap-2">
                  <Server className="w-5 h-5 text-blue-400" />
                  <div>
                    <span className="text-xs text-slate-500 block">Source</span>
                    <span className="text-slate-200 font-medium">{tenant}/{selectedSourceNs}</span>
                  </div>
                </div>
                <ArrowRight className="w-5 h-5 text-slate-500" />
                <div className="flex items-center gap-2">
                  <Server className="w-5 h-5 text-emerald-400" />
                  <div>
                    <span className="text-xs text-slate-500 block">Destination</span>
                    <span className="text-slate-200 font-medium">
                      {copyMode === 'cross-tenant' ? destTenant : tenant}/{selectedDestNs}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Objects to create (dependency tree, children first) */}
            <div className="space-y-4">
              {depTrees.map(tree => {
                const deps = tree.nodes.length - 1;
                return (
                  <div key={tree.root} className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
                    <div className="px-4 py-3 border-b border-slate-700 flex items-center gap-2">
                      <Server className="w-4 h-4 text-blue-400" />
                      <span className="text-sm font-semibold text-slate-200">{tree.root}</span>
                      <span className="px-2 py-0.5 bg-blue-500/10 text-blue-300 rounded text-xs">{TYPE_LABELS[selectedObjectType]}</span>
                      <span className="ml-auto text-xs text-slate-500">{deps > 0 ? `${deps} dependenc${deps === 1 ? 'y' : 'ies'}` : 'no dependencies'}</span>
                    </div>
                    <div className="divide-y divide-slate-700/60">
                      {tree.nodes.map((node, i) => {
                        const isRoot = i === tree.nodes.length - 1;
                        const status = node.error ? 'error' : node.existsInDest ? 'exists' : 'create';
                        return (
                          <div key={`${node.type}:${node.name}`} className={`px-4 py-2.5 flex items-center gap-3 ${isRoot ? 'bg-blue-500/5' : ''}`}>
                            <span className="text-slate-600 w-4 text-center flex-shrink-0">{isRoot ? '' : '↳'}</span>
                            <span className="px-2 py-0.5 rounded text-[11px] bg-slate-700 text-slate-300 w-36 text-center flex-shrink-0">{TYPE_LABELS[node.type]}</span>
                            <span className="text-sm text-slate-200 truncate flex-1">{node.name}</span>
                            {status === 'exists' && <span className="text-xs px-2 py-0.5 rounded bg-slate-600/40 text-slate-400 flex items-center gap-1 flex-shrink-0"><Check className="w-3 h-3" /> Exists — skip</span>}
                            {status === 'create' && <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 flex items-center gap-1 flex-shrink-0"><Copy className="w-3 h-3" /> Will create</span>}
                            {status === 'error' && <span className="text-xs px-2 py-0.5 rounded bg-red-500/15 text-red-300 flex items-center gap-1 flex-shrink-0"><XCircle className="w-3 h-3" /> {node.error}</span>}
                            {!node.error && node.obj && (
                              <button onClick={() => setJsonModal({ title: `${node.name} (Create Payload)`, data: buildPayload(node, selectedDestNs, selectedSourceNs) })} className="p-1.5 text-slate-500 hover:text-slate-300 hover:bg-slate-700 rounded flex-shrink-0">
                                <Code className="w-4 h-4" />
                              </button>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Warning */}
            <div className="flex items-start gap-3 p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl">
              <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
              <div>
                <span className="text-amber-400 font-semibold block">Before you proceed</span>
                <span className="text-sm text-slate-400">
                  Objects are created in dependency order (children first). Objects that already exist in the destination are skipped, not overwritten — names are kept identical. Shared/system references and objects in other namespaces are left as links.
                  {selectedObjectType === 'certificate' && (
                    <span className="block mt-1 text-amber-300/80">
                      TLS Certificates hold tenant-encrypted (blindfold) secrets — a cross-tenant copy of the private key will not decrypt and may need re-import.
                    </span>
                  )}
                </span>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-between">
              <button
                onClick={() => setStep(2)}
                className="px-6 py-3 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
              >
                Back
              </button>
              <button
                onClick={executeCopy}
                disabled={isCopying}
                className="flex items-center gap-2 px-6 py-3 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors"
              >
                {isCopying ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <Copy className="w-5 h-5" />
                )}
                {`Create ${depTrees.reduce((s, t) => s + t.nodes.filter(n => !n.existsInDest && !n.error).length, 0)} object(s)`}
              </button>
            </div>
          </div>
        )}

        {/* Step 4: Results */}
        {step === 4 && (
          <div className="space-y-6">
            <div className="text-center mb-8">
              <h2 className="text-2xl font-bold text-slate-100 mb-2">Copy Complete</h2>
              <p className="text-slate-400">
                {copyResults.filter(r => r.success).length} of {copyResults.length} objects copied successfully
              </p>
            </div>

            {/* Results Summary */}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-6 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-center">
                <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                <div className="text-3xl font-bold text-emerald-400">
                  {copyResults.filter(r => r.success).length}
                </div>
                <div className="text-sm text-emerald-400/70">Succeeded</div>
              </div>
              <div className="p-6 bg-red-500/10 border border-red-500/30 rounded-xl text-center">
                <XCircle className="w-8 h-8 text-red-400 mx-auto mb-2" />
                <div className="text-3xl font-bold text-red-400">
                  {copyResults.filter(r => !r.success).length}
                </div>
                <div className="text-sm text-red-400/70">Failed</div>
              </div>
            </div>

            {/* Detailed Results */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl">
              <div className="px-4 py-3 border-b border-slate-700">
                <span className="text-sm font-semibold text-slate-300">Detailed Results</span>
              </div>
              <div className="divide-y divide-slate-700">
                {copyResults.map((result, idx) => (
                  <div
                    key={idx}
                    className={`p-4 flex items-center justify-between ${
                      result.success ? 'bg-emerald-500/5' : 'bg-red-500/5'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      {result.success ? (
                        <CheckCircle className="w-5 h-5 text-emerald-400" />
                      ) : (
                        <XCircle className="w-5 h-5 text-red-400" />
                      )}
                      <span className="text-slate-200">{result.name}</span>
                    </div>
                    {result.error && (
                      <span className="text-sm text-red-400">{result.error}</span>
                    )}
                    {result.skipped && (
                      <span className="text-xs text-slate-500">already existed — skipped</span>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-center gap-4">
              <button
                onClick={resetForNewType}
                className="flex items-center gap-2 px-6 py-3 bg-emerald-500 hover:bg-emerald-600 text-white font-semibold rounded-lg transition-colors"
                title={`Keep ${tenant}/${selectedSourceNs} → ${selectedDestNs} and copy a different config type`}
              >
                <Copy className="w-5 h-5" />
                Copy Another Type
              </button>
              <button
                onClick={resetWizard}
                className="flex items-center gap-2 px-6 py-3 bg-slate-700 hover:bg-slate-600 text-slate-200 font-semibold rounded-lg transition-colors"
              >
                <RefreshCw className="w-5 h-5" />
                Start Over
              </button>
              <Link
                to="/"
                className="flex items-center gap-2 px-6 py-3 bg-blue-500 hover:bg-blue-600 text-white font-semibold rounded-lg transition-colors"
              >
                Back to Home
              </Link>
            </div>
          </div>
        )}
      </main>

      {/* JSON Modal */}
      {jsonModal && (
        <div
          className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={() => setJsonModal(null)}
        >
          <div
            className="bg-slate-800 border border-slate-700 rounded-xl max-w-4xl w-full max-h-[85vh] overflow-hidden"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
              <h3 className="font-semibold text-slate-200">{jsonModal.title}</h3>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(JSON.stringify(jsonModal.data, null, 2));
                    toast.success('Copied to clipboard');
                  }}
                  className="flex items-center gap-1 px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
                >
                  <Copy className="w-4 h-4" /> Copy
                </button>
                <button
                  onClick={() => setJsonModal(null)}
                  className="p-1 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>
            <div className="p-6 overflow-auto max-h-[70vh]">
              <pre className="text-sm text-slate-300 font-mono whitespace-pre-wrap">
                {JSON.stringify(jsonModal.data, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
