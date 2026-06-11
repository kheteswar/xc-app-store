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
import type { Namespace, AlertReceiver, AlertPolicy, CDNCacheRule, ConfigObjectType } from '../types';

type CopyMode = 'cross-tenant' | 'cross-namespace';
type Step = 1 | 2 | 3 | 4;

interface SelectedObject {
  type: ConfigObjectType;
  name: string;
  namespace: string;
  data: AlertReceiver | AlertPolicy | CDNCacheRule;
}

interface CopyResult {
  name: string;
  success: boolean;
  error?: string;
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
  const [selectedObjectType, setSelectedObjectType] = useState<ConfigObjectType>('alert_receiver');
  const [availableObjects, setAvailableObjects] = useState<Array<{ name: string; data: unknown }>>([]);
  const [selectedObjects, setSelectedObjects] = useState<string[]>([]);
  const [isLoadingObjects, setIsLoadingObjects] = useState(false);

  // Preview & Copy
  const [objectsToPreview, setObjectsToPreview] = useState<SelectedObject[]>([]);
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
      let items: Array<{ name: string; data: unknown }> = [];

      if (selectedObjectType === 'alert_receiver') {
        const resp = await apiClient.getAlertReceivers(selectedSourceNs);
        items = (resp.items || []).map(item => ({
          name: item.metadata?.name || item.name || 'unknown',
          data: item,
        }));
      } else if (selectedObjectType === 'alert_policy') {
        const resp = await apiClient.getAlertPolicies(selectedSourceNs);
        items = (resp.items || []).map(item => ({
          name: item.metadata?.name || item.name || 'unknown',
          data: item,
        }));
      } else if (selectedObjectType === 'cdn_cache_rule') {
        const resp = await apiClient.getCDNCacheRules(selectedSourceNs);
        items = (resp.items || []).map(item => ({
          name: item.metadata?.name || item.name || 'unknown',
          data: item,
        }));
      }

      setAvailableObjects(items);
    } catch (err) {
      toast.error(`Failed to load ${selectedObjectType.replace('_', ' ')}s`);
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

  const preparePreview = async () => {
    setIsLoadingPreview(true);
    const previews: SelectedObject[] = [];

    // Fetch full details for each selected object
    // The list API often returns minimal data, we need to GET each object individually
    for (const name of selectedObjects) {
      try {
        let fullData: AlertReceiver | AlertPolicy | CDNCacheRule;

        if (selectedObjectType === 'alert_receiver') {
          fullData = await apiClient.getAlertReceiver(selectedSourceNs, name);
        } else if (selectedObjectType === 'alert_policy') {
          fullData = await apiClient.getAlertPolicy(selectedSourceNs, name);
        } else {
          fullData = await apiClient.getCDNCacheRule(selectedSourceNs, name);
        }
        
        console.log(`[CopyConfig] Fetched full details for ${name}:`, JSON.stringify(fullData, null, 2));
        
        previews.push({
          type: selectedObjectType,
          name,
          namespace: selectedSourceNs,
          data: fullData,
        });
      } catch (err) {
        console.error(`[CopyConfig] Failed to fetch details for ${name}:`, err);
        toast.error(`Failed to fetch details for ${name}`);
      }
    }

    setObjectsToPreview(previews);
    setIsLoadingPreview(false);
    setStep(3);
  };

  const prepareCreatePayload = (original: AlertReceiver | AlertPolicy | CDNCacheRule, destNamespace: string, _destTenantName?: string): unknown => {
    // Deep clone the original object
    const source: Record<string, unknown> = JSON.parse(JSON.stringify(original));

    console.log('[CopyConfig] Original source object:', JSON.stringify(source, null, 2));

    // F5 XC API expects a specific structure for POST requests:
    // { metadata: { name, namespace, ... }, spec: { ... } }
    
    // Extract the name - could be in metadata.name or at root level
    const objectName = (source.metadata as Record<string, unknown>)?.name || source.name;
    
    // CRITICAL: F5 XC list API returns spec in 'get_spec', not 'spec'
    // We need to prioritize get_spec over spec
    const spec = source.get_spec || source.spec || {};
    
    console.log('[CopyConfig] Extracted spec:', JSON.stringify(spec, null, 2));
    
    // Extract description and labels from metadata or root
    const sourceMetadata = (source.metadata || {}) as Record<string, unknown>;
    const description = sourceMetadata.description || source.description || '';
    const labels = sourceMetadata.labels || source.labels || {};
    const annotations = sourceMetadata.annotations || source.annotations || {};
    const disable = sourceMetadata.disable || source.disabled || false;

    // Build clean metadata for the create request
    const metadata: Record<string, unknown> = {
      name: objectName,
      namespace: destNamespace,
    };

    // Only add optional fields if they have values
    if (description) metadata.description = description;
    if (labels && Object.keys(labels as object).length > 0) metadata.labels = labels;
    if (annotations && Object.keys(annotations as object).length > 0) metadata.annotations = annotations;
    if (disable) metadata.disable = disable;

    // Deep clone the spec to avoid mutations
    const cleanSpec: Record<string, unknown> = JSON.parse(JSON.stringify(spec));
    
    // For alert receivers, clean up receiver-specific fields
    if (selectedObjectType === 'alert_receiver') {
      // Alert receivers don't need namespace updates in spec, just copy as-is
      // But remove any tenant references that might cause issues
      // The spec structure varies by receiver type (slack, pagerduty, email, etc.)
    }
    
    // For alert policies, update receiver references to point to destination namespace
    if (selectedObjectType === 'alert_policy') {
      // Update top-level receiver references
      if (cleanSpec.receivers && Array.isArray(cleanSpec.receivers)) {
        cleanSpec.receivers = (cleanSpec.receivers as Array<Record<string, unknown>>).map(r => {
          // Keep only name and namespace, remove tenant/kind which are read-only
          return {
            name: r.name,
            namespace: destNamespace,
          };
        });
      }

      // Update routes - preserve ALL route fields, just update receiver namespaces
      if (cleanSpec.routes && Array.isArray(cleanSpec.routes)) {
        cleanSpec.routes = (cleanSpec.routes as Array<Record<string, unknown>>).map(route => {
          const cleanRoute: Record<string, unknown> = { ...route };
          
          // Update receivers in the route if present
          if (cleanRoute.receivers && Array.isArray(cleanRoute.receivers)) {
            cleanRoute.receivers = (cleanRoute.receivers as Array<Record<string, unknown>>).map(r => ({
              name: r.name,
              namespace: destNamespace,
            }));
          }
          
          return cleanRoute;
        });
      }
      
      // Copy notification_parameters if present
      // Copy notification_grouping if present
      // These are already in cleanSpec from the deep clone
    }

    // Build the final payload in the format F5 XC API expects
    const payload: Record<string, unknown> = {
      metadata,
      spec: cleanSpec,
    };

    console.log('[CopyConfig] Final prepared payload:', JSON.stringify(payload, null, 2));

    return payload;
  };

  const executeCopy = async () => {
    const targetNamespace = copyMode === 'cross-tenant' ? selectedDestNs : selectedDestNs;
    const targetTenant = copyMode === 'cross-tenant' ? destTenant : tenant;
    const targetToken = copyMode === 'cross-tenant' ? destApiToken : null;

    if (!targetNamespace) {
      toast.warning('Please select a destination namespace');
      return;
    }

    setIsCopying(true);
    setCopyResults([]);
    const results: CopyResult[] = [];

    for (const obj of objectsToPreview) {
      try {
        const payload = prepareCreatePayload(obj.data, targetNamespace);
        const apiPath = selectedObjectType === 'alert_receiver' ? 'alert_receivers'
          : selectedObjectType === 'alert_policy' ? 'alert_policys'
          : 'cdn_cache_rules';

        if (copyMode === 'cross-tenant' && targetToken) {
          await F5XCApiClient.proxyRequestStatic(
            targetTenant!,
            targetToken,
            `/api/config/namespaces/${targetNamespace}/${apiPath}`,
            'POST',
            payload
          );
        } else {
          await apiClient.post(`/api/config/namespaces/${targetNamespace}/${apiPath}`, payload);
        }

        results.push({ name: obj.name, success: true });
      } catch (err) {
        results.push({
          name: obj.name,
          success: false,
          error: err instanceof Error ? err.message : 'Unknown error',
        });
      }
    }

    setCopyResults(results);
    setStep(4);
    setIsCopying(false);

    const successCount = results.filter(r => r.success).length;
    const failCount = results.filter(r => !r.success).length;

    if (failCount === 0) {
      toast.success(`Successfully copied ${successCount} object(s)`);
    } else if (successCount === 0) {
      toast.error(`Failed to copy all ${failCount} object(s)`);
    } else {
      toast.warning(`Copied ${successCount}, failed ${failCount}`);
    }
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
    setObjectsToPreview([]);
    setCopyResults([]);
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
              onClick={() => step === 1 ? navigate('/') : step === 2 ? setStep(1) : setStep(2)}
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
              <div className="flex gap-3">
                {(['alert_receiver', 'alert_policy', 'cdn_cache_rule'] as ConfigObjectType[]).map(type => (
                  <button
                    key={type}
                    onClick={() => setSelectedObjectType(type)}
                    className={`flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold border-2 transition-all ${
                      selectedObjectType === type
                        ? 'bg-blue-500 border-blue-500 text-white shadow-lg shadow-blue-500/20'
                        : 'bg-slate-700 border-slate-600 text-slate-300 hover:border-blue-500/50 hover:text-white'
                    }`}
                  >
                    {selectedObjectType === type && isLoadingObjects
                      ? <Loader2 className="w-4 h-4 animate-spin" />
                      : selectedObjectType === type
                      ? <Check className="w-4 h-4" />
                      : null}
                    {type === 'alert_receiver' ? 'Alert Receivers' : type === 'alert_policy' ? 'Alert Policies' : 'CDN Cache Rules'}
                  </button>
                ))}
              </div>
            </div>

            {/* Objects List */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl">
              <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
                <span className="text-sm font-semibold text-slate-300">
                  Available {selectedObjectType === 'alert_receiver' ? 'Alert Receivers' : selectedObjectType === 'alert_policy' ? 'Alert Policies' : 'CDN Cache Rules'}
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
                    No {selectedObjectType === 'alert_receiver' ? 'alert receivers' : selectedObjectType === 'alert_policy' ? 'alert policies' : 'CDN cache rules'} found in {selectedSourceNs}
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

            {/* Objects to Copy */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl">
              <div className="px-4 py-3 border-b border-slate-700">
                <span className="text-sm font-semibold text-slate-300">
                  Objects to Copy ({objectsToPreview.length})
                </span>
              </div>
              <div className="divide-y divide-slate-700">
                {objectsToPreview.map(obj => (
                  <div key={obj.name} className="p-4">
                    <div
                      className="flex items-center justify-between cursor-pointer"
                      onClick={() => setExpandedPreview(expandedPreview === obj.name ? null : obj.name)}
                    >
                      <div className="flex items-center gap-3">
                        {expandedPreview === obj.name ? (
                          <ChevronDown className="w-5 h-5 text-slate-400" />
                        ) : (
                          <ChevronRight className="w-5 h-5 text-slate-400" />
                        )}
                        <span className="text-slate-200 font-medium">{obj.name}</span>
                        <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">
                          {obj.type === 'alert_receiver' ? 'Alert Receiver' : 'Alert Policy'}
                        </span>
                      </div>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setJsonModal({
                            title: `${obj.name} (Create Payload)`,
                            data: prepareCreatePayload(obj.data, selectedDestNs),
                          });
                        }}
                        className="p-2 text-slate-500 hover:text-slate-300 hover:bg-slate-700 rounded transition-colors"
                      >
                        <Code className="w-4 h-4" />
                      </button>
                    </div>

                    {expandedPreview === obj.name && (
                      <div className="mt-4 p-4 bg-slate-900/50 rounded-lg">
                        <pre className="text-xs text-slate-400 overflow-auto max-h-64">
                          {JSON.stringify(prepareCreatePayload(obj.data, selectedDestNs), null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Warning */}
            <div className="flex items-start gap-3 p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl">
              <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
              <div>
                <span className="text-amber-400 font-semibold block">Before you proceed</span>
                <span className="text-sm text-slate-400">
                  This will create new objects in the destination namespace. If objects with the same name already exist, the operation may fail.
                  {selectedObjectType === 'alert_policy' && (
                    <span className="block mt-1">
                      Alert Policies reference Alert Receivers. Make sure the referenced receivers exist in the destination namespace.
                    </span>
                  )}
                  {selectedObjectType === 'cdn_cache_rule' && (
                    <span className="block mt-1">
                      CDN Cache Rules are standalone objects. After copying, attach them to your CDN Load Balancer in the destination namespace.
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
                Copy {objectsToPreview.length} Object{objectsToPreview.length !== 1 ? 's' : ''}
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
                  </div>
                ))}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-center gap-4">
              <button
                onClick={resetWizard}
                className="flex items-center gap-2 px-6 py-3 bg-slate-700 hover:bg-slate-600 text-slate-200 font-semibold rounded-lg transition-colors"
              >
                <RefreshCw className="w-5 h-5" />
                Start New Copy
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
