import { useState, useEffect, useCallback, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Grid3X3,
  Loader2,
  Globe,
  Server,
  Shield,
  Bot,
  Search,
  Lock,
  User,
  AlertTriangle,
  Network,
  Eye,
  Code,
  Code2,
  ExternalLink,
  Check,
  Copy,
  X,
  Clock,
  Home,
  Activity,
  FileText,
  Zap,
  RefreshCw,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Settings,
  Database,
  ArrowRight,
  Timer,
  Hash,
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  Layers,
  Route,
  Cloud,
  HardDrive,
  HelpCircle,
} from 'lucide-react';
import { apiClient } from '../services/api';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import type { Namespace, LoadBalancer, CDNLoadBalancer, CDNCacheRule, ParsedRoute, OriginPool, WAFPolicy, HealthCheck, ServicePolicy, ServicePolicyRule, AppType, AppSetting, AppTypeSetting, VirtualSite, UserIdentificationPolicy, Certificate } from '../types';

import { parseCertificateUrl } from '../utils/certParser';

function isDefined<T>(v: T | null | undefined): v is T {
  return v !== undefined && v !== null;
}

const FEATURE_TYPE_NAMES: Record<string, string> = {
  'USER_BEHAVIOR_ANALYSIS': 'Malicious User Detection',
  'TIMESERIES_ANOMALY_DETECTION': 'DDoS Detection',
  'BUSINESS_LOGIC_MARKUP': 'API Discovery',
  'PER_REQ_ANOMALY_DETECTION': 'Per API Request Analysis',
};

const getFeatureDisplayName = (type: string): string => {
  return FEATURE_TYPE_NAMES[type] || type;
};

interface ViewerState {
  rootLB: LoadBalancer | null;
  namespace: string;
  certificates: Map<string, Certificate>;
  routes: ParsedRoute[];
  originPools: Map<string, OriginPool>;
  wafPolicies: Map<string, WAFPolicy>;
  healthChecks: Map<string, HealthCheck>;
  servicePolicies: Map<string, unknown>;
  virtualSites: Map<string, VirtualSite>;
  objects: Map<string, unknown>;
  appType: AppType | null;
  appSetting: AppSetting | null;
  appTypeSetting: AppTypeSetting | null;
  userIdentificationPolicy: UserIdentificationPolicy | null;
  rootCDN: CDNLoadBalancer | null;
  cacheRules: Map<string, CDNCacheRule>;
}

export function ConfigVisualizer() {
  const { isConnected } = useApp();
  const navigate = useNavigate();
  const toast = useToast();

  const [selectedType, setSelectedType] = useState<'http' | 'cdn'>('http');

  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [resourceList, setResourceList] = useState<Array<{ name: string }>>([]);
  const [selectedNs, setSelectedNs] = useState('');
  const [selectedResource, setSelectedResource] = useState('');
  const [selectedResources, setSelectedResources] = useState<Set<string>>(new Set());
  const [isLoadingNs, setIsLoadingNs] = useState(true);
  const [isLoadingResources, setIsLoadingResources] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [scanLog, setScanLog] = useState('');
  const [allStates, setAllStates] = useState<ViewerState[]>([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [lbDropOpen, setLbDropOpen] = useState(false);
  const [lbFilter, setLbFilter] = useState('');
  const lbDropRef = useRef<HTMLDivElement>(null);
  // CHANGE: Added 'advanced', 'features', 'domains' to the default set
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set([
    'routes', 
    'origins', 
    'security', 
    'tls', 
    'caching', 
    'apptype', 
    'advanced', 
    'features',
    'domains'
  ]));

  const [state, setState] = useState<ViewerState>({
    rootLB: null,
    rootCDN: null,
    cacheRules: new Map(),
    namespace: '',
    routes: [],
    originPools: new Map(),
    wafPolicies: new Map(),
    healthChecks: new Map(),
    servicePolicies: new Map(),
    virtualSites: new Map(),
    objects: new Map(),
    appType: null,
    appSetting: null,
    appTypeSetting: null,
    userIdentificationPolicy: null,
    certificates: new Map(),
  });

  const [jsonModal, setJsonModal] = useState<{ title: string; data: unknown } | null>(null);

  useEffect(() => {
    if (!isConnected) {
      navigate('/');
      return;
    }
    loadNamespaces();
  }, [isConnected, navigate]);

  // Close LB multi-select on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (lbDropRef.current && !lbDropRef.current.contains(e.target as Node)) setLbDropOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const loadNamespaces = async () => {
    setIsLoadingNs(true);
    try {
      const resp = await apiClient.getNamespaces();
      setNamespaces(resp.items.sort((a, b) => a.name.localeCompare(b.name)));
    } catch {
      toast.error('Failed to load namespaces');
    } finally {
      setIsLoadingNs(false);
    }
  };

  const loadResources = async (ns: string, type: 'http' | 'cdn') => {
    setSelectedNs(ns);
    setSelectedResource(''); // Reset selection
    setSelectedResources(new Set());
    setResourceList([]);
    
    if (!ns) return;

    setIsLoadingResources(true); // You can keep using isLoadingLbs or rename it to isLoadingResources
    try {
      if (type === 'http') {
        const resp = await apiClient.getLoadBalancers(ns);
        setResourceList((resp.items || []).sort((a, b) => a.name.localeCompare(b.name)));
      } else {
        const resp = await apiClient.getCDNs(ns);
        setResourceList((resp.items || []).sort((a, b) => a.name.localeCompare(b.name)));
      }
    } catch {
      toast.error(`Failed to load ${type.toUpperCase()} resources`);
    } finally {
      setIsLoadingResources(false);
    }
};

  const log = useCallback((msg: string) => setScanLog(msg), []);

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev);
      if (next.has(section)) next.delete(section);
      else next.add(section);
      return next;
    });
  };

  const parseRoute = (route: NonNullable<NonNullable<LoadBalancer['spec']>['routes']>[number], index: number): ParsedRoute => {
    const parsed: ParsedRoute = {
      index,
      type: 'unknown',
      path: '/',
      pathMatch: 'prefix',
      methods: ['ANY'],
      origins: [],
      waf: null,
    };

    if (route.custom_route_object) {
      parsed.type = 'custom';
      parsed.path = route.custom_route_object.route_ref?.name || 'Custom Route';
      (parsed as unknown as Record<string, unknown>).routeRef = route.custom_route_object.route_ref;
      return parsed;
    }

    if (route.simple_route) {
      parsed.type = 'simple';
      const sr = route.simple_route;
      if (sr.path) {
        if (sr.path.prefix) {
          parsed.path = sr.path.prefix;
          parsed.pathMatch = 'prefix';
        } else if (sr.path.regex) {
          parsed.path = sr.path.regex;
          parsed.pathMatch = 'regex';
        } else if (sr.path.path) {
          parsed.path = sr.path.path;
          parsed.pathMatch = 'exact';
        }
      }
      if (typeof sr.http_method === 'string') {
        parsed.methods = [sr.http_method];
      } else if (sr.http_method?.methods) {
        parsed.methods = sr.http_method.methods;
      }
      if (sr.origin_pools) {
        parsed.origins = sr.origin_pools.map(op => ({
          name: op.pool?.name,
          namespace: op.pool?.namespace,
          weight: op.weight,
          priority: op.priority,
        }));
      }
      if (sr.advanced_options) {
        const ao = sr.advanced_options;
        if (ao.app_firewall) {
          parsed.waf = {
            name: ao.app_firewall.name,
            namespace: ao.app_firewall.namespace,
          };
        }
        if (ao.disable_waf) parsed.waf = { disabled: true };
        parsed.timeout = ao.timeout || ao.request_timeout;
        parsed.retries = ao.retry_policy || ao.default_retry_policy;
        parsed.corsPolicy = ao.cors_policy;
        parsed.advancedOptions = {
          hostRewrite: sr.host_rewrite || (sr.auto_host_rewrite !== undefined ? 'auto' : (sr.disable_host_rewrite !== undefined ? 'disabled' : null)),
          prefixRewrite: ao.prefix_rewrite || (ao.disable_prefix_rewrite !== undefined ? null : undefined),
          webSocket: ao.enable_web_socket_config !== undefined ? true : (ao.disable_web_socket_config !== undefined ? false : null),
          spdy: ao.enable_spdy !== undefined ? true : (ao.disable_spdy !== undefined ? false : null),
          buffering: ao.buffer_policy || ao.common_buffering,
          mirroring: ao.mirror_policy || (ao.disable_mirroring !== undefined ? false : null),
          locationAdd: ao.disable_location_add === false,
          requestHeaders: ao.request_headers_to_add?.length || 0,
          responseHeaders: ao.response_headers_to_add?.length || 0,
          requestCookies: (ao.request_cookies_to_add?.length || 0) + (ao.request_cookies_to_remove?.length || 0),
          responseCookies: (ao.response_cookies_to_add?.length || 0) + (ao.response_cookies_to_remove?.length || 0),
          priority: ao.priority,
          botDefense: ao.bot_defense_javascript_injection || ao.inherited_bot_defense_javascript_injection,
        };
      }
      parsed.headerMatchers = sr.headers;
      parsed.queryParams = sr.query_params as unknown as unknown[];
    } else if (route.redirect_route) {
      parsed.type = 'redirect';
      const rr = route.redirect_route;
      if (rr.path?.prefix) parsed.path = rr.path.prefix;
      parsed.redirectConfig = {
        host: rr.host_redirect,
        path: rr.path_redirect,
        code: rr.response_code || '301',
      };
    } else if (route.direct_response_route) {
      parsed.type = 'direct_response';
      const dr = route.direct_response_route;
      if (dr.path?.prefix) parsed.path = dr.path.prefix;
      parsed.directResponse = { code: dr.response_code, body: dr.response_body };
    }

    return parsed;
  };

  const startViewer = async () => {
    // Support both multi-select and single select
    const resources = selectedResources.size > 0
      ? Array.from(selectedResources)
      : selectedResource ? [selectedResource] : [];
    if (!selectedNs || resources.length === 0) return;
    setIsLoading(true);
    setAllStates([]);
    setCurrentIndex(0);

    setExpandedSections(new Set(['routes', 'origins', 'security', 'tls', 'caching', 'apptype', 'advanced', 'features', 'domains']));

    const fetchedStates: ViewerState[] = [];

    try {
      for (let i = 0; i < resources.length; i++) {
        const resourceName = resources[i];
        log(`Fetching ${i + 1}/${resources.length}: ${resourceName}`);

        const newState: ViewerState = {
          rootLB: null,
          rootCDN: null,
          namespace: selectedNs,
          routes: [],
          originPools: new Map(),
          wafPolicies: new Map(),
          healthChecks: new Map(),
          servicePolicies: new Map(),
          virtualSites: new Map(),
          objects: new Map(),
          cacheRules: new Map(),
          appType: null,
          appSetting: null,
          appTypeSetting: null,
          userIdentificationPolicy: null,
          certificates: new Map(),
        };

        try {
          if (selectedType === 'http') {
            const lb = await apiClient.getLoadBalancer(selectedNs, resourceName);
            if (!lb) continue;
            newState.rootLB = lb;
            if (lb.spec?.routes) {
              lb.spec.routes.forEach((r, ri) => newState.routes.push(parseRoute(r, ri)));
            }
            await fetchDependencies(lb, newState, selectedNs);
          } else {
            const cdn = await apiClient.getCDN(selectedNs, resourceName);
            if (!cdn) continue;
            newState.rootCDN = cdn;
            await fetchCDNDependencies(cdn, newState, selectedNs);
          }
          fetchedStates.push(newState);
        } catch (e) {
          console.warn(`Failed to load ${resourceName}:`, e);
        }
      }

      if (fetchedStates.length === 0) throw new Error('No resources could be loaded');

      setAllStates(fetchedStates);
      setCurrentIndex(0);
      setState(fetchedStates[0]);
      log(`Report generated for ${fetchedStates.length} resource(s).`);

    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to load');
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  const goToLB = (index: number) => {
    if (index < 0 || index >= allStates.length) return;
    setCurrentIndex(index);
    setState(allStates[index]);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // --- HELPER FUNCTIONS ---

  const fetchDependencies = async (lb: LoadBalancer, state: ViewerState, ns: string) => {
    // CRITICAL: Removed the 'const newState = ...' line. 
    // We update the 'state' object passed in by reference.
    try {
      const spec = lb.spec as any;
      
      // 1. WAF Policies
      if (spec?.app_firewall && !spec.disable_waf) {
        await fetchWAF(spec.app_firewall.name, spec.app_firewall.namespace || ns, state);
      }

      // 2. Route WAFs
      if (state.routes) {
        for (const r of state.routes) {
          if (r.waf?.name && !state.wafPolicies.has(r.waf.name)) {
            await fetchWAF(r.waf.name, r.waf.namespace || ns, state); 
          }
        }
      }

      // 3. Certificates Logic
      const certRefs = new Set<string>();
      const httpsConfig = spec.https || spec.https_auto_cert;

      if (httpsConfig) {
        const addCertRef = (cert: { name: string; namespace?: string }) => {
          if (cert?.name) {
            certRefs.add(`${cert.namespace || ns}/${cert.name}`);
          }
        };
        if (httpsConfig.tls_certificates) httpsConfig.tls_certificates.forEach(addCertRef);
        if (httpsConfig.tls_config?.tls_certificates) httpsConfig.tls_config.tls_certificates.forEach(addCertRef);
        if (httpsConfig.tls_cert_params?.certificates) httpsConfig.tls_cert_params.certificates.forEach(addCertRef);
      }

      // Wait for all certificates to be fetched and stored in the map
      if (certRefs.size > 0) {
        console.log(`[Visualizer] Fetching ${certRefs.size} certificate(s)...`);
        console.log(`[Visualizer] Fetching certRefs - `+certRefs);
        
          await Promise.all(Array.from(certRefs).map(async (refKey) => {
          const [certNs, certName] = refKey.split('/');
          

          const res = await apiClient.get<{ spec?: unknown; data?: Certificate }>(`/api/config/namespaces/${certNs}/certificates/${certName}`);

          // The API returns the certificate object directly, not wrapped in .data
          const certData = (res?.spec ? res : res?.data) as Certificate | undefined;
          
          if (certData?.spec?.certificate_url) {
            state.certificates.set(refKey, certData);
          }
          
        }));
      }

      // 4. Origin Pools
      const poolRefs = new Set<string>();
      if (spec?.default_route_pools) {
        spec.default_route_pools.forEach((p: any) => {
          if (p.pool?.name) poolRefs.add(`${p.pool.namespace || ns}/${p.pool.name}`);
        });
      }
      if (state.routes) {
        state.routes.forEach(r => {
          r.origins.forEach(o => {
            if (o.name) poolRefs.add(`${o.namespace || ns}/${o.name}`);
          });
        });
      }
      await fetchOriginPools(poolRefs, state, ns);

      // 5. Service Policies & App Types
      if (spec?.active_service_policies?.policies) {
        for (const pol of spec.active_service_policies.policies) {
           try {
             const sp = await apiClient.getServicePolicy(pol.namespace || ns, pol.name);
             state.servicePolicies.set(pol.name, sp);
           } catch(e) { console.warn(e); }
        }
      }
      await fetchAppTypesAndSecurity(lb, state, ns);

    } catch (err) {
      console.error("[Visualizer] Error in fetchDependencies:", err);
    }
  };

  const fetchCDNDependencies = async (cdn: CDNLoadBalancer, state: ViewerState, ns: string) => {
      const spec = cdn.spec as any;
      
      // 1. Origin Pool: 
      // Skip fetching external pools unless explicitly referenced. 
      // Most CDNs use inline definitions which we handle in Render.

      // 2. WAF
      if (spec?.app_firewall) {
          await fetchWAF(spec.app_firewall.name, spec.app_firewall.namespace || ns, state);
      }

      // 3. Cache Rules (Look in both cdn_settings and custom_cache_rule)
      const cacheRulesList = spec?.cdn_settings?.cache_rules || spec?.custom_cache_rule?.cdn_cache_rules || [];
      for (const ruleRef of cacheRulesList) {
          if (ruleRef.name) {
              log(`Fetching Cache Rule: ${ruleRef.name}`);
              try {
                  const rule = await apiClient.getCDNCacheRule(ruleRef.namespace || ns, ruleRef.name);
                  state.cacheRules.set(ruleRef.name, rule);
              } catch (e) {
                  log(`Failed to fetch cache rule ${ruleRef.name}`);
              }
          }
      }
      
      // 4. User Identification
      if (spec?.user_identification) {
          try {
             const uid = await apiClient.getUserIdentificationPolicy(
                 spec.user_identification.namespace || ns, 
                 spec.user_identification.name
             );
             state.userIdentificationPolicy = uid;
          } catch (e) { console.log('Failed to fetch User ID policy'); }
      }
  };

  const fetchWAF = async (name: string, ns: string, state: ViewerState) => {
    log(`Fetching WAF: ${name}`);
    try {
        const waf = await apiClient.getWAFPolicy(ns, name);
        state.wafPolicies.set(name, waf);
    } catch {
        try {
            const waf = await apiClient.getWAFPolicy('shared', name);
            state.wafPolicies.set(name, { ...waf, shared: true } as WAFPolicy);
        } catch { log(`Failed to fetch WAF ${name}`); }
    }
  };

  const fetchOriginPools = async (refs: Set<string>, state: ViewerState, _currentNs: string) => {
      for (const ref of refs) {
          const [ns, name] = ref.split('/');
          if (state.originPools.has(name)) continue;
          
          log(`Fetching Pool: ${name}`);
          try {
              const pool = await apiClient.getOriginPool(ns, name);
              state.originPools.set(name, pool);
              
              if (pool.spec?.healthcheck) {
                  for (const hc of pool.spec.healthcheck) {
                      if (hc.name && !state.healthChecks.has(hc.name)) {
                          try {
                              const check = await apiClient.getHealthCheck(hc.namespace || ns, hc.name);
                              state.healthChecks.set(hc.name, check as HealthCheck);
                          } catch { /* Try shared */ }
                      }
                  }
              }
          } catch {
              try {
                  const pool = await apiClient.getOriginPool('shared', name);
                  state.originPools.set(name, pool);
              } catch { log(`Failed to fetch pool ${name}`); }
          }
      }
      
      // Populate Virtual Sites from Pools
      for (const pool of state.originPools.values()) {
        const servers = pool.spec?.origin_servers || [];
        for (const server of servers) {
          const vs = server.private_ip?.site_locator?.virtual_site ||
                     server.private_name?.site_locator?.virtual_site ||
                     server.k8s_service?.site_locator?.virtual_site;
          if (vs?.name && vs?.namespace && !state.virtualSites.has(`${vs.namespace}/${vs.name}`)) {
             try {
                 const vSite = await apiClient.getVirtualSite(vs.namespace, vs.name);
                 state.virtualSites.set(`${vs.namespace}/${vs.name}`, vSite);
             } catch {}
          }
        }
      }
  };

  const fetchAppTypesAndSecurity = async (lb: LoadBalancer, state: ViewerState, ns: string) => {
      const appTypeName = lb.metadata?.labels?.['ves.io/app_type'];
      if (appTypeName) {
        try {
            state.appType = await apiClient.getAppType(appTypeName);
            const appSettingsResp = await apiClient.getAppSettings(ns);
            if (appSettingsResp.items?.length > 0) {
                for (const setting of appSettingsResp.items) {
                  const spec = setting.spec || setting.get_spec;
                  const matching = spec?.app_type_settings?.find((ats: AppTypeSetting) => ats.app_type_ref?.name === appTypeName);
                  if (matching) {
                    state.appSetting = setting;
                    state.appTypeSetting = matching;
                    break;
                  }
                }
            }
        } catch {}
      }
      if (lb.spec?.user_identification?.name) {
          try {
              state.userIdentificationPolicy = await apiClient.getUserIdentificationPolicy(
                  lb.spec.user_identification.namespace || ns, 
                  lb.spec.user_identification.name
              );
          } catch {}
      }
  };

  const getWafMode = (waf: WAFPolicy | null | undefined): string => {
    if (!waf?.spec) return 'unknown';
    if (waf.spec.blocking) return 'Blocking';
    if (waf.spec.monitoring) return 'Monitoring';
    if (waf.spec.ai_risk_based_blocking) return 'AI Risk-Based';
    if (waf.spec.mode) return waf.spec.mode;
    return 'Unknown';
  };

  const formatDate = (timestamp?: string) => {
    if (!timestamp) return 'Unknown';
    return new Date(timestamp).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const formatAlgorithm = (algo?: string) => {
    const map: Record<string, string> = {
      ROUND_ROBIN: 'Round Robin',
      LEAST_ACTIVE: 'Least Connections',
      RANDOM: 'Random',
      RING_HASH: 'Ring Hash',
      SOURCE_IP_STICKINESS: 'Source IP Sticky',
      LB_OVERRIDE: 'Override',
    };
    return map[algo || ''] || algo || 'Round Robin';
  };

  const copyJson = () => {
    if (jsonModal?.data) {
      navigator.clipboard
        .writeText(JSON.stringify(jsonModal.data, null, 2))
        .then(() => toast.success('Copied!'))
        .catch(() => toast.error('Copy failed'));
    }
  };

  const lb = state.rootLB;

  const getRouteTypeLabel = (type: string) => {
    const labels: Record<string, { text: string; color: string }> = {
      simple: { text: 'Simple', color: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' },
      redirect: { text: 'Redirect', color: 'bg-amber-500/15 text-amber-400 border-amber-500/30' },
      direct_response: { text: 'Direct Response', color: 'bg-violet-500/15 text-violet-400 border-violet-500/30' },
      unknown: { text: 'Custom', color: 'bg-slate-500/15 text-slate-400 border-slate-500/30' },
    };
    return labels[type] || labels.unknown;
  };

  const getPathMatchLabel = (match: string) => {
    const labels: Record<string, { text: string; symbol: string }> = {
      prefix: { text: 'Prefix Match', symbol: '~' },
      regex: { text: 'Regex Match', symbol: '.*' },
      exact: { text: 'Exact Match', symbol: '=' },
    };
    return labels[match] || labels.prefix;
  };

  // Helper for HTTP method colors (required for the Routes section)
  const renderHTTPLBContent = () => {
    const lb = state.rootLB!;
    const spec = lb.spec as any;
    const sysMeta = lb.system_metadata as any;

    // --- Legacy Variable Calculations ---
    let lbType = 'HTTP';
    let lbTypeClass = 'bg-slate-600';
    if (spec?.https_auto_cert) {
      lbType = 'HTTPS (Auto Cert)';
      lbTypeClass = 'bg-emerald-600';
    } else if (spec?.https) {
      lbType = 'HTTPS (Custom)';
      lbTypeClass = 'bg-blue-600';
    }

    let advertiseType = 'Unknown';
    if (spec?.advertise_on_public_default_vip) advertiseType = 'Public (Default VIP)';
    else if (spec?.advertise_on_public) advertiseType = 'Public (Custom)';
    else if (spec?.advertise_custom) advertiseType = 'Custom';
    else if (spec?.do_not_advertise) advertiseType = 'Not Advertised';
    
    

    // --- HELPER: Reusable WAF Detail Renderer ---
  const renderWafConfiguration = (waf: WAFPolicy | undefined) => {
    const wafSpec = waf?.spec;
    if (!wafSpec) return null;

    const formatRiskAction = (action?: string) => {
      if (!action) return 'Default';
      if (action === 'AI_BLOCK') return 'Block';
      if (action === 'AI_REPORT') return 'Report';
      return action.replace('AI_', '');
    };

    return (
      <div className="space-y-4 border-t border-slate-700/50 pt-4 mt-4">
        {wafSpec.ai_risk_based_blocking && (
          <div className="p-4 bg-slate-800/50 rounded-lg">
            <span className="text-xs text-slate-500 block mb-3 flex items-center gap-2">
              <Zap className="w-3.5 h-3.5" /> Security Policy: AI Risk-Based Blocking
            </span>
            <div className="grid grid-cols-3 gap-3">
              <DetailItem
                label="High Risk"
                value={formatRiskAction(wafSpec.ai_risk_based_blocking.high_risk_action)}
                enabled={wafSpec.ai_risk_based_blocking.high_risk_action === 'AI_BLOCK'}
                warning={wafSpec.ai_risk_based_blocking.high_risk_action === 'AI_REPORT'}
                small
              />
              <DetailItem
                label="Medium Risk"
                value={formatRiskAction(wafSpec.ai_risk_based_blocking.medium_risk_action)}
                enabled={wafSpec.ai_risk_based_blocking.medium_risk_action === 'AI_BLOCK'}
                warning={wafSpec.ai_risk_based_blocking.medium_risk_action === 'AI_REPORT'}
                small
              />
              <DetailItem
                label="Low Risk"
                value={formatRiskAction(wafSpec.ai_risk_based_blocking.low_risk_action)}
                enabled={wafSpec.ai_risk_based_blocking.low_risk_action === 'AI_BLOCK'}
                warning={wafSpec.ai_risk_based_blocking.low_risk_action === 'AI_REPORT'}
                small
              />
            </div>
          </div>
        )}

        {wafSpec.detection_settings && (
          <div className="p-4 bg-slate-800/50 rounded-lg space-y-4">
            <span className="text-xs text-slate-500 block">Detection Settings</span>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
              <DetailItem
                label="Threat Campaigns"
                value={wafSpec.detection_settings.disable_threat_campaigns !== undefined ? 'Disabled' : 'Enabled'}
                enabled={wafSpec.detection_settings.disable_threat_campaigns === undefined}
                small
              />
              <DetailItem
                label="Suppression"
                value={wafSpec.detection_settings.disable_suppression !== undefined ? 'Disabled' : 'Enabled'}
                enabled={wafSpec.detection_settings.disable_suppression === undefined}
                small
              />
              <DetailItem
                label="Signature Accuracy"
                value={
                  wafSpec.detection_settings.signature_selection_setting?.high_medium_low_accuracy_signatures !== undefined ? 'High/Med/Low' :
                  wafSpec.detection_settings.signature_selection_setting?.only_high_accuracy_signatures !== undefined ? 'High Only' : 'High/Med'
                }
                small
              />
              <DetailItem
                label="Signature Staging"
                value={
                  wafSpec.detection_settings.stage_new_signatures?.staging_period
                    ? `${wafSpec.detection_settings.stage_new_signatures.staging_period} days`
                    : 'Disabled'
                }
                enabled={!!wafSpec.detection_settings.stage_new_signatures?.staging_period}
                small
              />
              {wafSpec.detection_settings.signature_selection_setting?.attack_type_settings?.disabled_attack_types && wafSpec.detection_settings.signature_selection_setting.attack_type_settings.disabled_attack_types.length > 0 && (
                <DetailItem
                  label="Disabled Attack Types"
                  value={wafSpec.detection_settings.signature_selection_setting.attack_type_settings.disabled_attack_types.length.toString()}
                  warning
                  small
                />
              )}
              {wafSpec.detection_settings.violation_settings?.disabled_violation_types && wafSpec.detection_settings.violation_settings.disabled_violation_types.length > 0 && (
                <DetailItem
                  label="Disabled Violations"
                  value={wafSpec.detection_settings.violation_settings.disabled_violation_types.length.toString()}
                  warning
                  small
                />
              )}
            </div>

            {wafSpec.detection_settings.signature_selection_setting?.attack_type_settings?.disabled_attack_types && wafSpec.detection_settings.signature_selection_setting.attack_type_settings.disabled_attack_types.length > 0 && (
              <div className="pt-3 border-t border-slate-700/50">
                <span className="text-xs text-slate-500 block mb-2">Disabled Attack Types</span>
                <div className="flex flex-wrap gap-1.5">
                  {wafSpec.detection_settings.signature_selection_setting.attack_type_settings.disabled_attack_types.map((at: string, idx: number) => (
                    <span key={idx} className="px-2 py-1 bg-amber-500/10 text-amber-400 rounded text-xs">
                      {at.replace('ATTACK_TYPE_', '').replace(/_/g, ' ')}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {wafSpec.detection_settings.violation_settings?.disabled_violation_types && wafSpec.detection_settings.violation_settings.disabled_violation_types.length > 0 && (
              <div className="pt-3 border-t border-slate-700/50">
                <span className="text-xs text-slate-500 block mb-2">Disabled Violation Types</span>
                <div className="flex flex-wrap gap-1.5">
                  {wafSpec.detection_settings.violation_settings.disabled_violation_types.map((vt: string, idx: number) => (
                    <span key={idx} className="px-2 py-1 bg-amber-500/10 text-amber-400 rounded text-xs">
                      {vt.replace('VIOL_', '').replace(/_/g, ' ')}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {wafSpec.detection_settings.bot_protection_setting && (
              <div className="pt-3 border-t border-slate-700/50">
                <span className="text-xs text-slate-500 block mb-2">Bot Protection Settings</span>
                <div className="grid grid-cols-3 gap-3">
                  <DetailItem
                    label="Malicious Bots"
                    value={wafSpec.detection_settings.bot_protection_setting.malicious_bot_action || 'Default'}
                    enabled={wafSpec.detection_settings.bot_protection_setting.malicious_bot_action === 'BLOCK'}
                    warning={wafSpec.detection_settings.bot_protection_setting.malicious_bot_action === 'IGNORE'}
                    small
                  />
                  <DetailItem
                    label="Suspicious Bots"
                    value={wafSpec.detection_settings.bot_protection_setting.suspicious_bot_action || 'Default'}
                    enabled={wafSpec.detection_settings.bot_protection_setting.suspicious_bot_action === 'BLOCK'}
                    small
                  />
                  <DetailItem
                    label="Good Bots"
                    value={wafSpec.detection_settings.bot_protection_setting.good_bot_action || 'Default'}
                    small
                  />
                </div>
              </div>
            )}
          </div>
        )}

        {wafSpec.bot_protection_setting && !wafSpec.detection_settings?.bot_protection_setting && (
          <div className="p-4 bg-slate-800/50 rounded-lg">
            <span className="text-xs text-slate-500 block mb-3">Bot Protection Settings</span>
            <div className="grid grid-cols-3 gap-3">
              <DetailItem
                label="Malicious Bots"
                value={wafSpec.bot_protection_setting.malicious_bot_action || 'Default'}
                enabled={wafSpec.bot_protection_setting.malicious_bot_action === 'BLOCK'}
                warning={wafSpec.bot_protection_setting.malicious_bot_action === 'IGNORE'}
                small
              />
              <DetailItem
                label="Suspicious Bots"
                value={wafSpec.bot_protection_setting.suspicious_bot_action || 'Default'}
                enabled={wafSpec.bot_protection_setting.suspicious_bot_action === 'BLOCK'}
                small
              />
              <DetailItem
                label="Good Bots"
                value={wafSpec.bot_protection_setting.good_bot_action || 'Default'}
                small
              />
            </div>
          </div>
        )}

        <div className="p-4 bg-slate-800/50 rounded-lg space-y-4">
          <span className="text-xs text-slate-500 block">Response Settings</span>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <DetailItem
              label="Response Codes"
              value={wafSpec.allow_all_response_codes !== undefined ? 'Allow All' : (wafSpec.allowed_response_codes?.response_code?.length ? `${wafSpec.allowed_response_codes.response_code.length} codes` : 'Default')}
              small
            />
            <DetailItem
              label="Anonymization"
              value={wafSpec.default_anonymization !== undefined ? 'Default' : (wafSpec.custom_anonymization ? 'Custom' : 'None')}
              small
            />
            <DetailItem
              label="Blocking Page"
              value={wafSpec.use_default_blocking_page !== undefined ? 'Default' : ((wafSpec.blocking_page?.blocking_page || wafSpec.blocking_page?.blocking_page_body) ? 'Custom' : 'Default')}
              small
            />
            {wafSpec.blocking_page?.response_code && (
              <DetailItem
                label="Blocking Code"
                value={wafSpec.blocking_page.response_code}
                small
              />
            )}
          </div>
          {wafSpec.allowed_response_codes?.response_code && wafSpec.allowed_response_codes.response_code.length > 0 && (
            <div className="pt-3 border-t border-slate-700/50">
              <span className="text-xs text-slate-500 block mb-2">Allowed Response Codes</span>
              <div className="flex flex-wrap gap-1.5">
                {wafSpec.allowed_response_codes.response_code.map((code: number, idx: number) => (
                  <span key={idx} className={`px-2 py-1 rounded text-xs font-mono ${
                    code >= 200 && code < 300 ? 'bg-emerald-500/10 text-emerald-400' :
                    code >= 300 && code < 400 ? 'bg-blue-500/10 text-blue-400' :
                    code >= 400 && code < 500 ? 'bg-amber-500/10 text-amber-400' :
                    code >= 500 ? 'bg-red-500/10 text-red-400' : 'bg-slate-700 text-slate-400'
                  }`}>
                    {code}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {wafSpec.http_protocol_settings && (
          <div className="p-4 bg-slate-800/50 rounded-lg">
            <span className="text-xs text-slate-500 block mb-3">HTTP Protocol Settings</span>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {wafSpec.http_protocol_settings.max_url_length !== undefined && (
                <DetailItem label="Max URL Length" value={`${wafSpec.http_protocol_settings.max_url_length}`} small />
              )}
              {wafSpec.http_protocol_settings.max_query_string_length && (
                <DetailItem label="Max Query String" value={`${wafSpec.http_protocol_settings.max_query_string_length}`} small />
              )}
              {wafSpec.http_protocol_settings.max_request_body_size && (
                <DetailItem label="Max Body Size" value={`${wafSpec.http_protocol_settings.max_request_body_size}`} small />
              )}
              {wafSpec.http_protocol_settings.max_headers && (
                <DetailItem label="Max Headers" value={`${wafSpec.http_protocol_settings.max_headers}`} small />
              )}
              <DetailItem
                label="Unknown Content Types"
                value={wafSpec.http_protocol_settings.allow_unknown_content_types ? 'Allowed' : 'Blocked'}
                enabled={wafSpec.http_protocol_settings.allow_unknown_content_types}
                small
              />
            </div>
          </div>
        )}

        {wafSpec.data_leak_prevention_setting && (
          <div className="p-4 bg-slate-800/50 rounded-lg">
            <span className="text-xs text-slate-500 block mb-3">Data Leak Prevention</span>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <DetailItem
                label="Credit Card Numbers"
                value={wafSpec.data_leak_prevention_setting.credit_card_numbers || 'Not configured'}
                small
              />
              <DetailItem
                label="US SSN"
                value={wafSpec.data_leak_prevention_setting.us_social_security_numbers || 'Not configured'}
                small
              />
              {wafSpec.data_leak_prevention_setting.custom_patterns && wafSpec.data_leak_prevention_setting.custom_patterns.length > 0 && (
                <DetailItem
                  label="Custom Patterns"
                  value={`${wafSpec.data_leak_prevention_setting.custom_patterns.length} pattern(s)`}
                  small
                />
              )}
            </div>
          </div>
        )}

        {wafSpec.file_upload_restriction_setting && (
          <div className="p-4 bg-slate-800/50 rounded-lg">
            <span className="text-xs text-slate-500 block mb-3">File Upload Restrictions</span>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <DetailItem
                label="File Upload"
                value={wafSpec.file_upload_restriction_setting.disable_file_upload ? 'Disabled' : 'Enabled'}
                enabled={!wafSpec.file_upload_restriction_setting.disable_file_upload}
                small
              />
              {wafSpec.file_upload_restriction_setting.max_file_size && (
                <DetailItem label="Max File Size" value={`${wafSpec.file_upload_restriction_setting.max_file_size} bytes`} small />
              )}
              {wafSpec.file_upload_restriction_setting.allowed_file_types && wafSpec.file_upload_restriction_setting.allowed_file_types.length > 0 && (
                <DetailItem label="Allowed Types" value={wafSpec.file_upload_restriction_setting.allowed_file_types.length.toString()} small />
              )}
            </div>
          </div>
        )}

        {wafSpec.cookie_protection_setting && (
          <div className="p-4 bg-slate-800/50 rounded-lg">
            <span className="text-xs text-slate-500 block mb-3">Cookie Protection</span>
            <div className="grid grid-cols-3 gap-3">
              <DetailItem
                label="Secure Attribute"
                value={wafSpec.cookie_protection_setting.add_secure_attribute ? 'Added' : 'Not Added'}
                enabled={wafSpec.cookie_protection_setting.add_secure_attribute}
                small
              />
              <DetailItem
                label="SameSite"
                value={wafSpec.cookie_protection_setting.add_samesite_attribute || 'Not Set'}
                small
              />
              <DetailItem
                label="HttpOnly"
                value={wafSpec.cookie_protection_setting.add_httponly_attribute ? 'Added' : 'Not Added'}
                enabled={wafSpec.cookie_protection_setting.add_httponly_attribute}
                small
              />
            </div>
          </div>
        )}

        {wafSpec.graphql_settings?.enabled && (
          <div className="p-4 bg-slate-800/50 rounded-lg">
            <span className="text-xs text-slate-500 block mb-3">GraphQL Settings</span>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <DetailItem label="Status" value="Enabled" enabled small />
              {wafSpec.graphql_settings.max_depth && (
                <DetailItem label="Max Depth" value={`${wafSpec.graphql_settings.max_depth}`} small />
              )}
              {wafSpec.graphql_settings.max_batched_queries && (
                <DetailItem label="Max Batched" value={`${wafSpec.graphql_settings.max_batched_queries}`} small />
              )}
              {wafSpec.graphql_settings.max_total_length && (
                <DetailItem label="Max Length" value={`${wafSpec.graphql_settings.max_total_length}`} small />
              )}
            </div>
          </div>
        )}

        <button
          onClick={() => setJsonModal({ title: 'WAF Policy Configuration', data: waf })}
          className="flex items-center gap-2 px-4 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors text-sm"
        >
          <Code className="w-4 h-4" /> View WAF Policy JSON
        </button>
      </div>
    );
  };

    return (
      <div className="space-y-6">
       {/* 1. Header & Meta */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
          <div className="flex items-start justify-between mb-6">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 bg-blue-500/15 rounded-xl flex items-center justify-center text-blue-400">
                <Globe className="w-7 h-7" />
              </div>
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className={`px-2 py-0.5 text-xs font-semibold rounded ${lbTypeClass} text-white`}>
                    {lbType}
                  </span>
                  <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-700 text-slate-300">
                    {advertiseType}
                  </span>
                  {lb.metadata?.disable && (
                    <span className="px-2 py-0.5 text-xs font-semibold rounded bg-red-500/20 text-red-400">
                      Disabled
                    </span>
                  )}
                </div>
                <h1 className="text-2xl font-bold text-slate-100">{lb.metadata?.name}</h1>
                
                {/* METADATA ROW */}
                <div className="flex flex-wrap items-center gap-x-6 gap-y-2 mt-2 text-sm text-slate-500">
                  <span className="flex items-center gap-1.5" title="Namespace">
                    <Home className="w-4 h-4" /> {lb.metadata?.namespace}
                  </span>
                  <span className="flex items-center gap-1.5" title="Created At">
                    <Clock className="w-4 h-4" /> {formatDate(sysMeta?.creation_timestamp)}
                  </span>
                  {sysMeta?.modification_timestamp && (
                    <span className="flex items-center gap-1.5" title="Last Modified">
                      <RefreshCw className="w-3.5 h-3.5" /> {formatDate(sysMeta.modification_timestamp)}
                    </span>
                  )}
                  {sysMeta?.creator_id && (
                    <span className="flex items-center gap-1.5" title="Creator ID">
                      <User className="w-3.5 h-3.5" /> {sysMeta.creator_id}
                    </span>
                  )}
                </div>
              </div>
            </div>
            <button
              onClick={() => setJsonModal({ title: 'Complete Load Balancer Configuration', data: lb })}
              className="flex items-center gap-2 px-4 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors text-sm"
            >
              <Code className="w-4 h-4" /> View Full JSON
            </button>
          </div>

          {/* NETWORK DETAILS GRID (VIP & CNAME) */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t border-slate-700/50">
            {spec?.host_name && (
              <div className="bg-slate-900/50 p-3 rounded-lg border border-slate-700/50 flex items-center justify-between">
                <div>
                  <span className="text-xs text-slate-500 block mb-1">CNAME (Host Name)</span>
                  <code className="text-sm text-cyan-400 font-mono break-all">{spec.host_name}</code>
                </div>
                <button 
                  onClick={() => navigator.clipboard.writeText(spec.host_name)}
                  className="p-1.5 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
            
            {spec?.dns_info && spec.dns_info.length > 0 && (
              <div className="bg-slate-900/50 p-3 rounded-lg border border-slate-700/50 flex items-center justify-between">
                <div>
                  <span className="text-xs text-slate-500 block mb-1">VIP IP Address</span>
                  <code className="text-sm text-emerald-400 font-mono">
                    {spec.dns_info.map((info: any) => info.ip_address).join(', ')}
                  </code>
                </div>
                <button 
                  onClick={() => navigator.clipboard.writeText(spec.dns_info[0]?.ip_address || '')}
                  className="p-1.5 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>

          {lb.metadata?.labels && Object.keys(lb.metadata.labels).length > 0 && (
            <div className="mt-4 pt-4 border-t border-slate-700">
              <div className="flex items-center gap-2 mb-2">
                <Hash className="w-4 h-4 text-slate-400" />
                <span className="text-sm font-medium text-slate-400">Labels</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {Object.entries(lb.metadata.labels).map(([key, value]) => (
                  <span key={key} className="inline-flex items-center px-3 py-1.5 bg-blue-500/10 border border-blue-500/30 rounded-lg text-sm">
                    <span className="text-blue-400 font-medium">{key}</span>
                    <span className="text-slate-500 mx-1.5">=</span>
                    <span className="text-slate-300">{String(value)}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* 2. Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
          {[
            { label: 'Domains', value: spec?.domains?.length || 0, icon: Globe, color: 'text-blue-400' },
            { label: 'Routes', value: state.routes.length, icon: Route, color: 'text-cyan-400' },
            { label: 'Origin Pools', value: state.originPools.size, icon: Server, color: 'text-emerald-400' },
            { label: 'Health Checks', value: state.healthChecks.size, icon: Activity, color: 'text-rose-400' },
            { label: 'WAF Policies', value: state.wafPolicies.size, icon: Shield, color: 'text-amber-400' },
            { label: 'Service Policies', value: state.servicePolicies.size, icon: FileText, color: 'text-teal-400' },
            { label: 'WAF Exclusions', value: spec?.waf_exclusion?.waf_exclusion_inline_rules?.rules?.length || spec?.waf_exclusion_rules?.length || 0, icon: ShieldOff, color: (spec?.waf_exclusion?.waf_exclusion_inline_rules?.rules?.length || spec?.waf_exclusion_rules?.length) ? 'text-amber-400' : 'text-slate-500' },
            { label: 'Trusted Clients', value: spec?.trusted_clients?.length || 0, icon: User, color: spec?.trusted_clients?.length ? 'text-emerald-400' : 'text-slate-500' },
          ].map(stat => (
            <div key={stat.label} className="bg-slate-800/50 border border-slate-700 rounded-xl p-3">
              <div className={`w-7 h-7 mb-1.5 ${stat.color}`}>
                <stat.icon className="w-full h-full" />
              </div>
              <div className={`text-lg font-bold ${typeof stat.value === 'string' ? (stat.value === 'On' ? 'text-emerald-400' : 'text-slate-500') : 'text-slate-100'}`}>
                {stat.value}
              </div>
              <div className="text-xs text-slate-500">{stat.label}</div>
            </div>
          ))}
        </div>

        {/* 3. App Type (Detailed) */}
        {state.appType && (() => {
          const appTypeSpec = state.appType.spec || state.appType.get_spec;
          const appTypeName = state.appType.metadata?.name || state.appType.name || 'Unknown';
          const appTypeNs = state.appType.metadata?.namespace || state.appType.namespace || 'shared';
          const appTypeDisabled = state.appType.metadata?.disable || (state.appType as { disabled?: boolean }).disabled;
          return (
            <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
              <button
                onClick={() => toggleSection('apptype')}
                className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <Layers className="w-5 h-5 text-violet-400" />
                  <h2 className="text-lg font-semibold text-slate-100">App Type Settings</h2>
                  <span className="px-2 py-0.5 bg-violet-500/15 text-violet-400 rounded text-xs font-medium">
                    {appTypeName}
                  </span>
                  {state.appSetting && (
                    <span className="px-2 py-0.5 bg-cyan-500/15 text-cyan-400 rounded text-xs font-medium">
                      App Setting: {state.appSetting.metadata?.name || state.appSetting.name}
                    </span>
                  )}
                </div>
                {expandedSections.has('apptype') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
              </button>

              {expandedSections.has('apptype') && (
                <div className="p-6 space-y-6">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <DetailItem label="App Type Name" value={appTypeName} />
                    <DetailItem label="Namespace" value={appTypeNs} />
                    <DetailItem label="Status" value={appTypeDisabled ? 'Disabled' : 'Enabled'} enabled={!appTypeDisabled} />
                    {state.appSetting && (
                      <DetailItem label="App Setting" value={state.appSetting.metadata?.name || state.appSetting.name || 'N/A'} />
                    )}
                  </div>

                  {/* App Type Features */}
                  {appTypeSpec?.features && appTypeSpec.features.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                        <Activity className="w-4 h-4 text-cyan-400" />
                        AI/ML Feature Types
                      </h4>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {appTypeSpec.features.map((feature: any, idx: number) => (
                          <div key={idx} className="p-3 rounded-lg border bg-emerald-500/5 border-emerald-500/20">
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-sm text-slate-300">{getFeatureDisplayName(feature.type || '')}</span>
                              <span className="px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/15 text-emerald-400 flex-shrink-0">
                                Enabled
                              </span>
                            </div>
                            <span className="text-xs text-slate-500 mt-1 block">{feature.type}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* API Discovery (App Type) */}
                  {appTypeSpec?.business_logic_markup_setting && (
                    <div>
                      <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                        <Search className="w-4 h-4 text-cyan-400" />
                        API Discovery Settings
                      </h4>
                      <div className="bg-slate-700/30 rounded-lg p-4">
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                          <DetailItem
                            label="Learn from Traffic with Redirect Response"
                            value={appTypeSpec.business_logic_markup_setting.disable ? 'Disabled' : 'Enabled'}
                            enabled={!appTypeSpec.business_logic_markup_setting.disable}
                          />
                          {appTypeSpec.business_logic_markup_setting.discovered_api_settings?.purge_duration_for_inactive_discovered_apis !== undefined && (
                            <DetailItem
                              label="Purge Duration"
                              value={`${appTypeSpec.business_logic_markup_setting.discovered_api_settings.purge_duration_for_inactive_discovered_apis} days`}
                            />
                          )}
                        </div>
                      </div>
                    </div>
                  )}

                   {/* API Discovery (App Setting) */}
                   {state.appTypeSetting?.business_logic_markup_setting && (
                      <div>
                        <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                          <Search className="w-4 h-4 text-cyan-400" />
                          API Discovery Settings (from App Setting)
                        </h4>
                        <div className="bg-slate-700/30 rounded-lg p-4">
                          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                            <DetailItem
                              label="Learn from Traffic with Redirect Response"
                              value={state.appTypeSetting.business_logic_markup_setting.disable ? 'Disabled' : 'Enabled'}
                              enabled={!state.appTypeSetting.business_logic_markup_setting.disable}
                            />
                            {state.appTypeSetting.business_logic_markup_setting.discovered_api_settings?.purge_duration_for_inactive_discovered_apis !== undefined && (
                              <DetailItem
                                label="Purge Duration"
                                value={`${state.appTypeSetting.business_logic_markup_setting.discovered_api_settings.purge_duration_for_inactive_discovered_apis} days`}
                              />
                            )}
                          </div>
                        </div>
                      </div>
                    )}

                  {/* UBA Settings */}
                  {(state.appTypeSetting?.user_behavior_analysis_setting || (state.appSetting?.spec || state.appSetting?.get_spec)?.user_behavior_analysis_setting) && (() => {
                    const ubaSetting = state.appTypeSetting?.user_behavior_analysis_setting || (state.appSetting?.spec || state.appSetting?.get_spec)?.user_behavior_analysis_setting;
                    return ubaSetting && (
                      <div>
                        <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                          <User className="w-4 h-4 text-blue-400" />
                          Malicious User Detection Settings (from App Setting)
                        </h4>
                        <div className="bg-slate-700/30 rounded-lg p-4">
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            <DetailItem
                              label="Detection"
                              value={ubaSetting.enable_detection ? 'Enabled' : 'Disabled'}
                              enabled={ubaSetting.enable_detection}
                            />
                            <DetailItem
                              label="Learning"
                              value={ubaSetting.enable_learning ? 'Enabled' : 'Disabled'}
                              enabled={ubaSetting.enable_learning}
                            />
                            {isDefined(ubaSetting.cooldown_period) && (
                              <DetailItem label="Cooldown Period" value={`${ubaSetting.cooldown_period}s`} />
                            )}
                            <DetailItem label="Include Failed Login" value={ubaSetting.include_failed_login ? 'Yes' : 'No'} enabled={ubaSetting.include_failed_login} />
                            <DetailItem label="Include Forbidden" value={ubaSetting.include_forbidden_requests ? 'Yes' : 'No'} enabled={ubaSetting.include_forbidden_requests} />
                            <DetailItem label="Include IP Reputation" value={ubaSetting.include_ip_reputation ? 'Yes' : 'No'} enabled={ubaSetting.include_ip_reputation} />
                            <DetailItem label="Include WAF Data" value={ubaSetting.include_waf_data ? 'Yes' : 'No'} enabled={ubaSetting.include_waf_data} />
                          </div>
                        </div>
                      </div>
                    );
                  })()}

                  {/* Malicious Mitigation */}
                  {(state.appSetting?.spec || state.appSetting?.get_spec)?.malicious_user_mitigation && (
                    <div>
                      <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-red-400" />
                        Malicious User Mitigation (from App Setting)
                      </h4>
                      <div className="bg-slate-700/30 rounded-lg p-4">
                        <DetailItem
                          label="Policy"
                          value={(state.appSetting?.spec || state.appSetting?.get_spec)?.malicious_user_mitigation?.name || 'Configured'}
                        />
                      </div>
                    </div>
                  )}

                  {/* Bot Defense */}
                  {appTypeSpec?.bot_defense_setting && (
                    <div>
                      <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                        <Bot className="w-4 h-4 text-amber-400" />
                        Bot Defense Settings
                      </h4>
                      <div className="bg-slate-700/30 rounded-lg p-4">
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                          {appTypeSpec.bot_defense_setting.regional_endpoint && (
                            <DetailItem label="Regional Endpoint" value={appTypeSpec.bot_defense_setting.regional_endpoint} />
                          )}
                          {appTypeSpec.bot_defense_setting.policy && (
                            <DetailItem label="Policy" value={appTypeSpec.bot_defense_setting.policy.name} />
                          )}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* JSON Buttons */}
                  <div className="flex justify-end gap-2">
                    {state.appSetting && (
                      <button
                        onClick={() => setJsonModal({ title: `App Setting: ${state.appSetting!.metadata?.name || state.appSetting!.name}`, data: state.appSetting })}
                        className="flex items-center gap-2 px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
                      >
                        <Code className="w-4 h-4" /> View App Setting JSON
                      </button>
                    )}
                    <button
                      onClick={() => setJsonModal({ title: `App Type: ${appTypeName}`, data: state.appType })}
                      className="flex items-center gap-2 px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
                    >
                      <Code className="w-4 h-4" /> View App Type JSON
                    </button>
                  </div>
                </div>
              )}
            </section>
          );
        })()}

        {/* 4. Domains & Listeners */}
        {spec?.domains && spec.domains.length > 0 && (
          <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
            <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-700">
              <Globe className="w-5 h-5 text-blue-400" />
              <h2 className="text-lg font-semibold text-slate-100">Domains & Listeners</h2>
              <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">
                {spec.domains.length} domain{spec.domains.length !== 1 ? 's' : ''}
              </span>
            </div>
            <div className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {spec.domains.map((domain: string) => (
                  <div
                    key={domain}
                    className="flex items-center gap-3 p-4 bg-slate-700/30 rounded-lg border border-slate-700/50"
                  >
                    <Globe className="w-5 h-5 text-blue-400 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-slate-200 font-medium truncate">{domain}</div>
                      <div className="text-xs text-slate-500">
                        {spec.https_auto_cert || spec.https ? 'HTTPS' : 'HTTP'} : Port {spec.https_auto_cert || spec.https ? '443' : '80'}
                      </div>
                    </div>
                    <a
                      href={`https://${domain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-1 text-slate-500 hover:text-slate-300 transition-colors"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </a>
                  </div>
                ))}
              </div>

              <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3">
                <DetailItem label="HSTS Header" value={spec.add_hsts_header ? 'Enabled' : 'Disabled'} enabled={spec.add_hsts_header} />
                <DetailItem label="HTTP Redirect" value={spec.http_redirect ? 'Enabled' : 'Disabled'} enabled={spec.http_redirect} />
                <DetailItem label="WebSocket" value={spec.enable_websocket ? 'Enabled' : 'Disabled'} enabled={spec.enable_websocket} />
                <DetailItem label="Compression" value={spec.enable_automatic_compression ? 'Enabled' : 'Disabled'} enabled={spec.enable_automatic_compression} />
              </div>
            </div>
          </section>
        )}

       {/* 5. TLS Configuration */}
        <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
          <button
            onClick={() => toggleSection('tls')}
            className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20 transition-colors"
          >
            <div className="flex items-center gap-3">
              <Lock className="w-5 h-5 text-amber-400" />
              <h2 className="text-lg font-semibold text-slate-100">TLS & Certificate Configuration</h2>
            </div>
            {expandedSections.has('tls') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
          </button>

          {expandedSections.has('tls') && (
            <div className="p-6 space-y-6">
              {!spec?.https_auto_cert && !spec?.https ? (
                <div className="flex items-center gap-3 text-slate-500">
                  <ShieldOff className="w-5 h-5" />
                  <span>HTTP only - No TLS configured</span>
                </div>
              ) : (
                <>
                  <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                    <DetailItem
                      label="TLS Type"
                      value={spec?.https_auto_cert ? "Auto Certificate (Let's Encrypt)" : 'Custom Certificate'}
                    />
                    <DetailItem
                      label="Min TLS Version"
                      value={(spec?.https_auto_cert?.tls_config || spec?.https?.tls_config || spec?.https?.tls_cert_params?.tls_config)?.min_version || 'TLS 1.0'}
                    />
                    <DetailItem
                      label="Max TLS Version"
                      value={(spec?.https_auto_cert?.tls_config || spec?.https?.tls_config || spec?.https?.tls_cert_params?.tls_config)?.max_version || 'TLS 1.3'}
                    />
                    <DetailItem
                      label="mTLS"
                      value={(spec?.https_auto_cert || spec?.https?.tls_cert_params || spec?.https)?.mtls ? 'Enabled' : 'Disabled'}
                      enabled={!!((spec?.https_auto_cert || spec?.https?.tls_cert_params || spec?.https)?.mtls)}
                    />
                    <DetailItem
                      label="HTTP Redirect"
                      value={(spec?.https_auto_cert || spec?.https)?.http_redirect ? 'Enabled' : 'Disabled'}
                      enabled={(spec?.https_auto_cert || spec?.https)?.http_redirect}
                    />
                    <DetailItem
                      label="HSTS"
                      value={(spec?.https_auto_cert || spec?.https)?.add_hsts ? 'Enabled' : 'Disabled'}
                      enabled={(spec?.https_auto_cert || spec?.https)?.add_hsts}
                    />
                  </div>

                  {/* AUTO CERT DETAILS - STRICT CHECK: Only if https_auto_cert is present */}
                  {spec?.https_auto_cert && spec?.auto_cert_info && (
                    <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                      <div className="flex items-center gap-3 mb-4">
                        <ShieldCheck className="w-6 h-6 text-emerald-400" />
                        <h3 className="text-lg font-semibold text-slate-200">Auto Certificate Details</h3>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                          spec.auto_cert_info.auto_cert_state === 'CertificateValid' ? 'bg-emerald-500/15 text-emerald-400' : 'bg-amber-500/15 text-amber-400'
                        }`}>
                          {spec.auto_cert_info.auto_cert_state}
                        </span>
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
                        <DetailItem 
                          label="Expiration" 
                          value={spec.auto_cert_info.auto_cert_expiry ? formatDate(spec.auto_cert_info.auto_cert_expiry) : 'N/A'} 
                          enabled={spec.auto_cert_info.auto_cert_expiry && new Date(spec.auto_cert_info.auto_cert_expiry) > new Date()}
                        />
                        <div className="col-span-2">
                          <span className="text-xs text-slate-500 block mb-1">Subject</span>
                          <span className="text-sm text-slate-300 font-mono break-all">{spec.auto_cert_info.auto_cert_subject || 'Pending...'}</span>
                        </div>
                        <div className="col-span-2">
                           <span className="text-xs text-slate-500 block mb-1">Issuer</span>
                           <span className="text-sm text-slate-300 font-mono break-all">{spec.auto_cert_info.auto_cert_issuer || 'Pending...'}</span>
                        </div>
                      </div>

                      {/* ACME Challenge Records */}
                      {spec.auto_cert_info.dns_records && spec.auto_cert_info.dns_records.length > 0 && (
                        <div className="mt-4 pt-4 border-t border-slate-600/30">
                          <span className="text-xs text-slate-500 block mb-3 font-medium">ACME DNS Challenge Records</span>
                          <div className="space-y-2">
                            {spec.auto_cert_info.dns_records.map((rec: any, idx: number) => (
                              <div key={idx} className="bg-slate-900/50 p-3 rounded border border-slate-700/50 flex flex-col md:flex-row gap-4">
                                <div className="flex-1 min-w-0">
                                  <span className="text-xs text-slate-500 block">Name</span>
                                  <code className="text-xs text-cyan-400 break-all">{rec.name}</code>
                                </div>
                                <div className="flex-shrink-0">
                                  <span className="text-xs text-slate-500 block">Type</span>
                                  <code className="text-xs text-slate-300">{rec.type}</code>
                                </div>
                                <div className="flex-1 min-w-0">
                                  <span className="text-xs text-slate-500 block">Value</span>
                                  <code className="text-xs text-emerald-400 break-all">{rec.value}</code>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                 {/* CUSTOM CERTIFICATES DETAILS */}
                  {spec?.https && (() => {
                    const tlsConfig = spec.https;
                    const certRefs = tlsConfig.tls_certificates || 
                                     tlsConfig.tls_config?.tls_certificates ||
                                     tlsConfig.tls_cert_params?.certificates;

                    if (!certRefs?.length) return null;

                    return (
                      <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                        <div className="flex items-center gap-3 mb-4">
                          <Lock className="w-6 h-6 text-amber-400" />
                          <h3 className="text-lg font-semibold text-slate-200">TLS Certificates</h3>
                          <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">
                            {certRefs.length} certificate{certRefs.length !== 1 ? 's' : ''}
                          </span>
                        </div>

                        <div className="space-y-4">
                          {certRefs.map((ref: any, i: number) => {
                            // 1. Lookup the fetched certificate object from state
                            const lookupKey = `${ref.namespace || state.namespace}/${ref.name}`;
                            const fullCert = state.certificates?.get(lookupKey);

                            console.log('fullCert:'+fullCert);
                            
                            // DEBUG LOG: Verify we found the cert object
                            console.log(`[Visualizer] Looking for cert: ${lookupKey}`, { 
                                found: !!fullCert, 
                                urlLength: fullCert?.spec?.certificate_url?.length || 0 
                            });

                            // 2. Parse the raw certificate_url using our new utility
                            // Ensure fullCert and spec.certificate_url exist before calling
                            const parsedDetails = (fullCert && fullCert.spec?.certificate_url) 
                                ? parseCertificateUrl(fullCert.spec.certificate_url) 
                                : null;
                            
                            // 3. Fallback to API 'infos' if parsing failed or data missing
                            const apiInfo = fullCert?.spec?.infos?.[0];

                            return (
                              <div key={i} className="bg-slate-800/50 rounded-lg overflow-hidden border border-slate-700/30">
                                {/* Card Header */}
                                <div className="p-4 border-b border-slate-700/30 flex items-center justify-between bg-slate-800">
                                  <div className="flex items-center gap-2">
                                    <Lock className="w-4 h-4 text-amber-400" />
                                    <span className="text-slate-200 font-medium">
                                      {ref.name}
                                    </span>
                                    {fullCert?.metadata?.disable && (
                                      <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-[10px] uppercase font-bold">Disabled</span>
                                    )}
                                  </div>
                                  <div className="flex items-center gap-2">
                                    <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400 font-mono">
                                      {ref.namespace || state.namespace}
                                    </span>
                                    {fullCert && (
                                      <button
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          setJsonModal({ title: `Certificate: ${ref.name}`, data: fullCert });
                                        }}
                                        className="p-1.5 text-slate-500 hover:text-slate-300 hover:bg-slate-700 rounded transition-colors"
                                        title="View JSON"
                                      >
                                        <Code className="w-3.5 h-3.5" />
                                      </button>
                                    )}
                                  </div>
                                </div>

                                {/* Card Body */}
                                <div className="p-4">
                                  {parsedDetails ? (
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-4">
                                      {/* Primary Info: Subject & Issuer */}
                                      <div className="col-span-1 md:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4 pb-4 border-b border-slate-700/30">
                                        <div className="bg-slate-900/40 p-3 rounded border border-slate-700/50">
                                          <span className="text-xs text-slate-500 block mb-1">Common Name (CN)</span>
                                          <div className="text-sm text-emerald-400 font-medium break-all">
                                            {parsedDetails.subject.commonName}
                                          </div>
                                          {parsedDetails.subject.organization && (
                                            <div className="text-xs text-slate-400 mt-1">{parsedDetails.subject.organization}</div>
                                          )}
                                        </div>
                                        
                                        <div className="bg-slate-900/40 p-3 rounded border border-slate-700/50">
                                          <span className="text-xs text-slate-500 block mb-1">Issuer</span>
                                          <div className="text-sm text-slate-300 break-all line-clamp-2" title={parsedDetails.issuer.commonName}>
                                            {parsedDetails.issuer.commonName}
                                          </div>
                                          {parsedDetails.issuer.organization && (
                                            <div className="text-xs text-slate-400 mt-1">{parsedDetails.issuer.organization}</div>
                                          )}
                                        </div>
                                      </div>

                                      {/* Details Grid */}
                                      <DetailItem 
                                        label="Valid From" 
                                        value={parsedDetails.validFrom.toLocaleString()} 
                                        small
                                      />
                                      <DetailItem 
                                        label="Valid To" 
                                        value={parsedDetails.validTo.toLocaleString()}
                                        enabled={parsedDetails.validTo > new Date()}
                                        warning={parsedDetails.validTo <= new Date()}
                                        small
                                      />
                                      <DetailItem 
                                        label="Serial Number" 
                                        value={parsedDetails.serialNumber} 
                                        small 
                                      />
                                      <DetailItem 
                                        label="Signature" 
                                        value={parsedDetails.isSelfSigned ? 'Self-Signed' : 'Signed'} 
                                        warning={parsedDetails.isSelfSigned}
                                        small 
                                      />
                                      {parsedDetails.fingerprint && (
                                        <DetailItem 
                                          label="Fingerprint (SHA1)" 
                                          value={parsedDetails.fingerprint} 
                                          small 
                                        />
                                      )}
                                      
                                      {/* Subject Alternative Names (SANs) */}
                                      {parsedDetails.sans.length > 0 && (
                                        <div className="col-span-1 md:col-span-2 mt-2 pt-2 border-t border-slate-700/30">
                                          <span className="text-xs text-slate-500 block mb-2">Subject Alternative Names (SANs)</span>
                                          <div className="flex flex-wrap gap-1.5">
                                            {parsedDetails.sans.map((san, k) => (
                                              <span key={k} className="px-2 py-0.5 bg-slate-700/50 border border-slate-600/50 rounded text-xs text-slate-300 font-mono">
                                                {san}
                                              </span>
                                            ))}
                                          </div>
                                        </div>
                                      )}
                                    </div>
                                  ) : apiInfo ? (
                                    /* Fallback: API Info (if parsing failed but basic info exists) */
                                    <div className="grid grid-cols-2 gap-4">
                                      <DetailItem label="Common Name" value={apiInfo.common_name || 'N/A'} />
                                      <DetailItem label="Expiry" value={apiInfo.expiry || apiInfo.not_after || 'N/A'} />
                                      <div className="col-span-2 text-xs text-amber-500 italic mt-2">
                                        Note: Full certificate details could not be parsed. Showing cached API summary.
                                      </div>
                                    </div>
                                  ) : (
                                    /* Empty State */
                                    <div className="text-center py-6">
                                      {fullCert ? (
                                        <div className="text-sm text-red-400 flex items-center justify-center gap-2">
                                          <AlertTriangle className="w-4 h-4" />
                                          <span>Failed to parse certificate data</span>
                                        </div>
                                      ) : (
                                        <div className="flex items-center justify-center gap-2 text-slate-500">
                                          <Loader2 className="w-4 h-4 animate-spin" />
                                          <span className="text-sm">Fetching certificate details...</span>
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })()}

                  {(() => {
                    const tlsConfig = spec?.https?.tls_config || spec?.https_auto_cert?.tls_config || spec?.https?.tls_cert_params?.tls_config;
                    if (!tlsConfig?.cipher_suites?.length) return null;

                    return (
                      <div className="p-4 bg-slate-700/30 rounded-lg">
                        <span className="text-xs text-slate-500 block mb-3">Cipher Suites ({tlsConfig.cipher_suites.length})</span>
                        <div className="flex flex-wrap gap-2">
                          {tlsConfig.cipher_suites.map((cipher: string, i: number) => (
                            <span key={i} className="px-2 py-1 bg-slate-800 rounded text-xs text-slate-300 font-mono">
                              {cipher}
                            </span>
                          ))}
                        </div>
                      </div>
                    );
                  })()}

                  <button
                    onClick={() => setJsonModal({ title: 'TLS Configuration', data: spec?.https || spec?.https_auto_cert })}
                    className="flex items-center gap-2 px-4 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors text-sm"
                  >
                    <Code className="w-4 h-4" /> View Full TLS Config JSON
                  </button>
                </>
              )}
            </div>
          )}
        </section>

        {/* 6. Routes */}
        <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
          <button
            onClick={() => toggleSection('routes')}
            className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20 transition-colors"
          >
            <div className="flex items-center gap-3">
              <Route className="w-5 h-5 text-cyan-400" />
              <h2 className="text-lg font-semibold text-slate-100">Routes Configuration</h2>
              <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">
                {state.routes.length} route{state.routes.length !== 1 ? 's' : ''}
              </span>
            </div>
            {expandedSections.has('routes') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
          </button>

          {expandedSections.has('routes') && (
            <div className="p-6 space-y-4">
              {spec?.default_route_pools && spec.default_route_pools.length > 0 && (
                <div className="p-4 bg-slate-700/30 rounded-lg border border-slate-700/50 mb-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Database className="w-4 h-4 text-slate-400" />
                    <span className="text-sm font-medium text-slate-300">Default Route Pools</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {spec.default_route_pools.map((p: any, i: number) => (
                      <span key={i} className="px-3 py-1.5 bg-slate-800 rounded-lg text-sm text-slate-300 border border-slate-600">
                        {p.pool?.name}
                        {p.weight && <span className="text-slate-500 ml-1">(weight: {p.weight})</span>}
                        {p.priority && <span className="text-slate-500 ml-1">(priority: {p.priority})</span>}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {state.routes.length === 0 ? (
                <p className="text-slate-500 text-center py-8">No custom routes defined - using default route pools</p>
              ) : (
                state.routes.map((r, i) => {
                  const typeInfo = getRouteTypeLabel(r.type);
                  const pathInfo = getPathMatchLabel(r.pathMatch);
                  const rawRoute = lb.spec?.routes?.[i];

                  return (
                    <div key={i} className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex items-center gap-3">
                          <span className="flex items-center justify-center w-8 h-8 bg-slate-800 rounded-lg text-slate-400 font-mono text-sm">
                            {r.index + 1}
                          </span>
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <span className={`px-2.5 py-1 rounded-lg text-xs font-semibold border ${typeInfo.color}`}>
                                {typeInfo.text}
                              </span>
                              <span className="px-2 py-0.5 bg-slate-800 rounded text-xs text-slate-400" title={pathInfo.text}>
                                {pathInfo.symbol} {pathInfo.text}
                              </span>
                            </div>
                            <code className="text-lg text-slate-200 font-mono">{r.path}</code>
                          </div>
                        </div>
                        <button
                          onClick={() => setJsonModal({ title: `Route ${r.index + 1} Configuration`, data: rawRoute })}
                          className="p-2 text-slate-500 hover:text-slate-300 hover:bg-slate-700 rounded-lg transition-colors"
                        >
                          <Code className="w-4 h-4" />
                        </button>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
                        <div>
                          <span className="text-xs text-slate-500 block mb-1">HTTP Methods</span>
                          <div className="flex flex-wrap gap-1">
                            {r.methods.map((m: string) => (
                              <span key={m} className="px-2 py-0.5 bg-slate-800 rounded text-xs text-slate-300 font-mono">
                                {m}
                              </span>
                            ))}
                          </div>
                        </div>

                        {r.type === 'simple' && (
                          <>
                            <div>
                              <span className="text-xs text-slate-500 block mb-1">Origin Pools</span>
                              {r.origins.length > 0 ? (
                                <div className="flex flex-wrap gap-1">
                                  {r.origins.map((o, j) => (
                                    <span key={j} className="px-2 py-0.5 bg-emerald-500/15 text-emerald-400 rounded text-xs">
                                      {o.name}
                                      {o.weight && <span className="opacity-70"> ({o.weight})</span>}
                                    </span>
                                  ))}
                                </div>
                              ) : (
                                <span className="text-slate-500 text-sm">Using default pools</span>
                              )}
                            </div>
                            <div>
                              <span className="text-xs text-slate-500 block mb-1">Route WAF</span>
                              {r.waf?.disabled ? (
                                <span className="flex items-center gap-1 text-red-400 text-sm">
                                  <ShieldOff className="w-3 h-3" /> Disabled
                                </span>
                              ) : r.waf?.name ? (
                                <span className="flex items-center gap-1 text-blue-400 text-sm">
                                  <Shield className="w-3 h-3" /> {r.waf.name}
                                </span>
                              ) : (
                                <span className="text-slate-500 text-sm">Inherited from LB</span>
                              )}
                            </div>
                            <div>
                              <span className="text-xs text-slate-500 block mb-1">Timeout</span>
                              <span className="text-slate-300 text-sm">
                                {r.timeout ? (r.timeout >= 1000 ? `${r.timeout / 1000}s` : `${r.timeout}ms`) : 'Default'}
                              </span>
                            </div>
                          </>
                        )}

                        {r.type === 'redirect' && (
                          <>
                            <div>
                              <span className="text-xs text-slate-500 block mb-1">Redirect To</span>
                              <span className="text-amber-400 text-sm flex items-center gap-1">
                                <ArrowRight className="w-3 h-3" />
                                {r.redirectConfig?.host || r.redirectConfig?.path || '-'}
                              </span>
                            </div>
                            <div>
                              <span className="text-xs text-slate-500 block mb-1">Response Code</span>
                              <span className="text-slate-300 text-sm">{r.redirectConfig?.code || '301'}</span>
                            </div>
                          </>
                        )}

                        {r.type === 'direct_response' && (
                          <>
                            <div>
                              <span className="text-xs text-slate-500 block mb-1">Response Code</span>
                              <span className="text-violet-400 text-sm font-mono">HTTP {r.directResponse?.code}</span>
                            </div>
                            <div className="col-span-2">
                              <span className="text-xs text-slate-500 block mb-1">Response Body</span>
                              <span className="text-slate-300 text-sm truncate block">
                                {r.directResponse?.body ? (r.directResponse.body.length > 50 ? r.directResponse.body.substring(0, 50) + '...' : r.directResponse.body) : 'Empty'}
                              </span>
                            </div>
                          </>
                        )}
                      </div>

                      {Boolean(r.headerMatchers?.length || r.queryParams?.length || r.corsPolicy || r.retries) && (
                        <div className="pt-3 border-t border-slate-700/50 grid grid-cols-2 md:grid-cols-4 gap-3">
                          {r.headerMatchers && r.headerMatchers.length > 0 && (
                            <div>
                              <span className="text-xs text-slate-500 block mb-1">Header Matchers</span>
                              <span className="text-slate-300 text-sm">{r.headerMatchers.length} rule(s)</span>
                            </div>
                          )}
                          {r.queryParams && r.queryParams.length > 0 && (
                            <div>
                              <span className="text-xs text-slate-500 block mb-1">Query Params</span>
                              <span className="text-slate-300 text-sm">{r.queryParams.length} rule(s)</span>
                            </div>
                          )}
                          {!!r.corsPolicy && (
                            <div>
                              <span className="text-xs text-slate-500 block mb-1">CORS Policy</span>
                              <span className="text-emerald-400 text-sm">Configured</span>
                            </div>
                          )}
                          {!!r.retries && (
                            <div>
                              <span className="text-xs text-slate-500 block mb-1">Retry Policy</span>
                              <span className="text-emerald-400 text-sm">Configured</span>
                            </div>
                          )}
                        </div>
                      )}

                      {r.advancedOptions && (
                        <div className="pt-3 border-t border-slate-700/50">
                          <span className="text-xs text-slate-500 block mb-2">Advanced Options</span>
                          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                            {r.timeout !== undefined && (
                              <div>
                                <span className="text-xs text-slate-500 block">Timeout</span>
                                <span className="text-slate-300 text-sm">{r.timeout}ms</span>
                              </div>
                            )}
                            {r.advancedOptions.hostRewrite && (
                              <div>
                                <span className="text-xs text-slate-500 block">Host Rewrite</span>
                                <span className="text-slate-300 text-sm">{r.advancedOptions.hostRewrite === 'auto' ? 'Auto' : (r.advancedOptions.hostRewrite === 'disabled' ? 'Disabled' : r.advancedOptions.hostRewrite)}</span>
                              </div>
                            )}
                            {r.advancedOptions.priority && (
                              <div>
                                <span className="text-xs text-slate-500 block">Priority</span>
                                <span className="text-slate-300 text-sm">{r.advancedOptions.priority}</span>
                              </div>
                            )}
                            {r.advancedOptions.webSocket !== null && (
                              <div>
                                <span className="text-xs text-slate-500 block">WebSocket</span>
                                <span className={`text-sm ${r.advancedOptions.webSocket ? 'text-emerald-400' : 'text-slate-500'}`}>
                                  {r.advancedOptions.webSocket ? 'Enabled' : 'Disabled'}
                                </span>
                              </div>
                            )}
                            {r.advancedOptions.spdy !== null && (
                              <div>
                                <span className="text-xs text-slate-500 block">SPDY</span>
                                <span className={`text-sm ${r.advancedOptions.spdy ? 'text-emerald-400' : 'text-slate-500'}`}>
                                  {r.advancedOptions.spdy ? 'Enabled' : 'Disabled'}
                                </span>
                              </div>
                            )}
                            {r.advancedOptions.mirroring !== null && (
                              <div>
                                <span className="text-xs text-slate-500 block">Mirroring</span>
                                <span className={`text-sm ${r.advancedOptions.mirroring ? 'text-emerald-400' : 'text-slate-500'}`}>
                                  {r.advancedOptions.mirroring ? 'Enabled' : 'Disabled'}
                                </span>
                              </div>
                            )}
                            {(r.advancedOptions.requestHeaders || 0) > 0 && (
                              <div>
                                <span className="text-xs text-slate-500 block">Req Headers</span>
                                <span className="text-blue-400 text-sm">+{r.advancedOptions.requestHeaders}</span>
                              </div>
                            )}
                            {(r.advancedOptions.responseHeaders || 0) > 0 && (
                              <div>
                                <span className="text-xs text-slate-500 block">Resp Headers</span>
                                <span className="text-emerald-400 text-sm">+{r.advancedOptions.responseHeaders}</span>
                              </div>
                            )}
                            {(r.advancedOptions.requestCookies || 0) > 0 && (
                              <div>
                                <span className="text-xs text-slate-500 block">Req Cookies</span>
                                <span className="text-slate-300 text-sm">{r.advancedOptions.requestCookies}</span>
                              </div>
                            )}
                            {(r.advancedOptions.responseCookies || 0) > 0 && (
                              <div>
                                <span className="text-xs text-slate-500 block">Resp Cookies</span>
                                <span className="text-slate-300 text-sm">{r.advancedOptions.responseCookies}</span>
                              </div>
                            )}
                            {!!r.advancedOptions.botDefense && (
                              <div>
                                <span className="text-xs text-slate-500 block">Bot Defense JS</span>
                                <span className="text-emerald-400 text-sm">Inherited</span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          )}
        </section>

        {/* 7. Origins & Health Checks */}
        <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
          <button
            onClick={() => toggleSection('origins')}
            className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20 transition-colors"
          >
            <div className="flex items-center gap-3">
              <Server className="w-5 h-5 text-emerald-400" />
              <h2 className="text-lg font-semibold text-slate-100">Origin Pools & Health Checks</h2>
              <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">
                {state.originPools.size} pool{state.originPools.size !== 1 ? 's' : ''}
              </span>
            </div>
            {expandedSections.has('origins') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
          </button>

          {expandedSections.has('origins') && (
            <div className="p-6 space-y-4">
              {Array.from(state.originPools.entries()).map(([name, pool]) => {
                const poolSpec = pool.spec;

                let originType = 'Unknown';
                const originDetails: Array<{ value: string; labels?: Record<string, string> }> = [];
                if (poolSpec?.origin_servers?.length) {
                  const first = poolSpec.origin_servers[0];
                  if (first.public_ip) {
                    originType = 'Public IP';
                    poolSpec.origin_servers.forEach((o: any) => originDetails.push({ value: o.public_ip?.ip || '' }));
                  } else if (first.public_name) {
                    originType = 'Public DNS';
                    poolSpec.origin_servers.forEach((o: any) => originDetails.push({ value: o.public_name?.dns_name || '' }));
                  } else if (first.private_ip) {
                    originType = 'IP';
                    poolSpec.origin_servers.forEach((o: any) => originDetails.push({ value: o.private_ip?.ip || '' }));
                  } else if (first.private_name) {
                    originType = 'Private DNS';
                    poolSpec.origin_servers.forEach((o: any) => originDetails.push({ value: o.private_name?.dns_name || '' }));
                  } else if (first.k8s_service) {
                    originType = 'K8s Service';
                    poolSpec.origin_servers.forEach((o: any) => originDetails.push({ value: o.k8s_service?.service_name || '' }));
                  }
                }

                const healthCheckRefs = poolSpec?.healthcheck || [];

                return (
                  <div key={name} className="bg-slate-700/30 rounded-xl border border-slate-700/50 overflow-hidden">
                    <div className="p-5">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                          <Server className="w-6 h-6 text-emerald-400" />
                          <div>
                            <h3 className="font-semibold text-slate-200 text-lg">{name}</h3>
                            <span className="text-xs text-slate-500">{pool.metadata?.namespace}</span>
                          </div>
                        </div>
                        <button
                          onClick={() => setJsonModal({ title: `${name} Configuration`, data: pool })}
                          className="p-2 text-slate-500 hover:text-slate-300 hover:bg-slate-700 rounded-lg transition-colors"
                        >
                          <Code className="w-4 h-4" />
                        </button>
                      </div>

                      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 mb-4">
                        <DetailItem label="Origin Type" value={originType} />
                        <DetailItem label="Port" value={poolSpec?.port?.toString() || 'N/A'} />
                        <DetailItem label="TLS to Origin" value={poolSpec?.use_tls ? 'Enabled' : 'Disabled'} enabled={!!poolSpec?.use_tls} />
                        <DetailItem label="LB Algorithm" value={formatAlgorithm(poolSpec?.loadbalancer_algorithm)} />
                        <DetailItem label="Endpoint Selection" value={poolSpec?.endpoint_selection?.replace(/_/g, ' ') || 'Default'} />
                        <DetailItem label="Health Checks" value={healthCheckRefs.length.toString()} />
                      </div>

                      {poolSpec?.use_tls && typeof poolSpec.use_tls === 'object' && (
                        <div className="mb-4 p-4 bg-slate-800/30 rounded-lg border border-slate-700/30">
                          <span className="text-xs text-slate-500 block mb-3 flex items-center gap-2">
                            <Lock className="w-3.5 h-3.5" /> TLS Settings
                          </span>
                          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                            <DetailItem
                              label="SNI"
                              value={poolSpec.use_tls.use_host_header_as_sni !== undefined ? 'Use Host Header' : (poolSpec.use_tls.sni || 'Default')}
                              small
                            />
                            <DetailItem
                              label="TLS Security"
                              value={
                                poolSpec.use_tls.tls_config?.custom_security ? 'Custom' :
                                poolSpec.use_tls.tls_config?.low_security ? 'Low' :
                                poolSpec.use_tls.tls_config?.medium_security ? 'Medium' : 'Default'
                              }
                              small
                            />
                            <DetailItem
                              label="Server Verification"
                              value={
                                poolSpec.use_tls.skip_server_verification !== undefined ? 'Skip' :
                                poolSpec.use_tls.volterra_trusted_ca !== undefined ? 'Volterra Trusted CA' :
                                poolSpec.use_tls.use_server_verification ? 'Custom CA' : 'Default'
                              }
                              enabled={poolSpec.use_tls.skip_server_verification === undefined}
                              warning={poolSpec.use_tls.skip_server_verification !== undefined}
                              small
                            />
                            <DetailItem
                              label="mTLS"
                              value={poolSpec.use_tls.use_mtls ? 'Enabled' : 'Disabled'}
                              enabled={!!poolSpec.use_tls.use_mtls}
                              small
                            />
                            <DetailItem
                              label="Session Key Caching"
                              value={
                                poolSpec.use_tls.disable_session_key_caching !== undefined ? 'Disabled' :
                                poolSpec.use_tls.default_session_key_caching !== undefined ? 'Default' : 'Enabled'
                              }
                              small
                            />
                          </div>
                        </div>
                      )}

                      <div className="mb-4">
                        <span className="text-xs text-slate-500 block mb-2">Origin Servers ({poolSpec?.origin_servers?.length || 0})</span>
                        <div className="space-y-3">
                          {poolSpec?.origin_servers?.map((server: any, idx: number) => {
                            const siteLocator = server.private_ip?.site_locator || server.private_name?.site_locator || server.k8s_service?.site_locator;
                            const vs = siteLocator?.virtual_site;
                            const site = siteLocator?.site;
                            const virtualSiteData = vs ? state.virtualSites.get(`${vs.namespace}/${vs.name}`) : null;
                            const networkType = server.private_ip?.outside_network !== undefined ? 'Outside Network' :
                                              server.private_ip?.inside_network !== undefined ? 'Inside Network' :
                                              server.private_name?.outside_network !== undefined ? 'Outside Network' :
                                              server.private_name?.inside_network !== undefined ? 'Inside Network' : null;
                            const serverValue = server.public_ip?.ip || server.public_name?.dns_name ||
                                              server.private_ip?.ip || server.private_name?.dns_name ||
                                              server.k8s_service?.service_name || 'N/A';

                            return (
                              <div key={idx} className="p-4 bg-slate-800/50 rounded-lg">
                                <div className="flex items-center gap-3 mb-3">
                                  <Database className="w-4 h-4 text-emerald-400" />
                                  <code className="text-slate-200 font-medium">{serverValue}</code>
                                  {networkType && (
                                    <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">{networkType}</span>
                                  )}
                                </div>
                                {(vs || site) && (
                                  <div className="pl-7 space-y-2">
                                    {vs && (
                                      <div className="flex items-center gap-2 text-sm">
                                        <Layers className="w-3.5 h-3.5 text-cyan-400" />
                                        <span className="text-slate-400">Virtual Site:</span>
                                        <span className="text-slate-200">{vs.namespace}/{vs.name}</span>
                                      </div>
                                    )}
                                    {site && (
                                      <div className="flex items-center gap-2 text-sm">
                                        <Network className="w-3.5 h-3.5 text-cyan-400" />
                                        <span className="text-slate-400">Site:</span>
                                        <span className="text-slate-200">{site.namespace}/{site.name}</span>
                                      </div>
                                    )}
                                    {virtualSiteData?.spec && (
                                      <div className="mt-3 p-3 bg-slate-900/50 rounded-lg border border-slate-700/50">
                                        <div className="flex items-center gap-2 mb-2">
                                          <Layers className="w-3.5 h-3.5 text-cyan-400" />
                                          <span className="text-xs font-medium text-slate-300">Virtual Site Details</span>
                                        </div>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                                          <div>
                                            <span className="text-slate-500">Site Type:</span>
                                            <span className="text-slate-300 ml-2">
                                              {virtualSiteData.spec.site_type === 'CUSTOMER_EDGE' ? 'Customer Edge (CE)' :
                                               virtualSiteData.spec.site_type === 'REGIONAL_EDGE' ? 'Regional Edge (RE)' :
                                               virtualSiteData.spec.site_type || 'N/A'}
                                            </span>
                                          </div>
                                        </div>
                                        {virtualSiteData.spec.site_selector?.expressions && virtualSiteData.spec.site_selector.expressions.length > 0 && (
                                          <div className="mt-2">
                                            <span className="text-xs text-slate-500 block mb-1">Site Selector Expression</span>
                                            <div className="flex flex-wrap gap-1.5">
                                              {virtualSiteData.spec.site_selector.expressions.map((expr: string, exprIdx: number) => {
                                                const parts = expr.split(' ');
                                                if (parts.length >= 3) {
                                                  const key = parts[0];
                                                  const op = parts[1];
                                                  const values = parts.slice(2).join(', ');
                                                  return (
                                                    <div key={exprIdx} className="flex items-center gap-1 text-xs">
                                                      <span className="px-2 py-1 bg-slate-700/70 text-slate-300 rounded">{key}</span>
                                                      <span className="text-slate-500">{op}</span>
                                                      <span className="px-2 py-1 bg-cyan-500/10 text-cyan-400 rounded">{values}</span>
                                                    </div>
                                                  );
                                                }
                                                return (
                                                  <span key={exprIdx} className="px-2 py-1 bg-slate-700/70 text-slate-300 rounded text-xs">{expr}</span>
                                                );
                                              })}
                                            </div>
                                          </div>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>

                      {healthCheckRefs.length > 0 && (
                        <div className="pt-4 border-t border-slate-700/50">
                          <span className="text-xs text-slate-500 block mb-3 flex items-center gap-2">
                            <Activity className="w-4 h-4" /> Health Check Configuration
                          </span>
                          <div className="space-y-3">
                            {healthCheckRefs.map((hcRef: any, hcIndex: number) => {
                              const hc = state.healthChecks.get(hcRef.name);
                              const hcSpec = hc?.spec;
                              const isHttp = !!hcSpec?.http_health_check;

                              return (
                                <div key={hcIndex} className="p-4 bg-slate-800/50 rounded-lg">
                                  <div className="flex items-center justify-between mb-3">
                                    <div className="flex items-center gap-2">
                                      <Activity className="w-4 h-4 text-rose-400" />
                                      <span className="text-slate-200 font-medium">{hcRef.name}</span>
                                      <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">
                                        {isHttp ? 'HTTP' : 'TCP'}
                                      </span>
                                    </div>
                                    {hc && (
                                      <button
                                        onClick={() => setJsonModal({ title: `${hcRef.name} Health Check`, data: hc })}
                                        className="p-1.5 text-slate-500 hover:text-slate-300 hover:bg-slate-700 rounded transition-colors"
                                      >
                                        <Code className="w-3.5 h-3.5" />
                                      </button>
                                    )}
                                  </div>

                                  {hc ? (
                                    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                                      {isHttp && (
                                        <>
                                          <DetailItem label="Path" value={hcSpec?.http_health_check?.path || '/'} small />
                                          <DetailItem label="Host Header" value={hcSpec?.http_health_check?.host_header || 'Origin'} small />
                                          <DetailItem
                                            label="Expected Status"
                                            value={hcSpec?.http_health_check?.expected_status_codes?.join(', ') || '200'}
                                            small
                                          />
                                        </>
                                      )}
                                      <DetailItem label="Interval" value={hcSpec?.interval ? `${hcSpec.interval}s` : '5s'} small />
                                      <DetailItem label="Timeout" value={hcSpec?.timeout ? `${hcSpec.timeout}s` : '3s'} small />
                                      <DetailItem label="Unhealthy Threshold" value={hcSpec?.unhealthy_threshold?.toString() || '3'} small />
                                      <DetailItem label="Healthy Threshold" value={hcSpec?.healthy_threshold?.toString() || '2'} small />
                                      {hcSpec?.jitter_percent !== undefined && (
                                        <DetailItem label="Jitter" value={`${hcSpec.jitter_percent}%`} small />
                                      )}
                                    </div>
                                  ) : (
                                    <p className="text-slate-500 text-sm">Health check details not available</p>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {poolSpec?.advanced_options && (
                        <div className="pt-4 border-t border-slate-700/50">
                          <span className="text-xs text-slate-500 block mb-3 flex items-center gap-2">
                            <Settings className="w-4 h-4" /> Advanced Options
                          </span>
                          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                            {poolSpec.advanced_options.connection_timeout !== undefined && (
                              <DetailItem
                                label="Connection Timeout"
                                value={`${poolSpec.advanced_options.connection_timeout}ms`}
                                small
                              />
                            )}
                            {poolSpec.advanced_options.http_idle_timeout !== undefined && (
                              <DetailItem
                                label="HTTP Idle Timeout"
                                value={`${poolSpec.advanced_options.http_idle_timeout}ms`}
                                small
                              />
                            )}
                            <DetailItem
                              label="Circuit Breaker"
                              value={poolSpec.advanced_options.circuit_breaker ? 'Custom' : poolSpec.advanced_options.default_circuit_breaker ? 'Default' : 'Disabled'}
                              small
                            />
                            <DetailItem
                              label="Outlier Detection"
                              value={poolSpec.advanced_options.outlier_detection ? 'Custom' : poolSpec.advanced_options.disable_outlier_detection ? 'Disabled' : 'Default'}
                              small
                            />
                            <DetailItem
                              label="Panic Threshold"
                              value={poolSpec.advanced_options.panic_threshold !== undefined ? `${poolSpec.advanced_options.panic_threshold}%` : poolSpec.advanced_options.no_panic_threshold ? 'Disabled' : 'Default'}
                              small
                            />
                            <DetailItem
                              label="HTTP Config"
                              value={poolSpec.advanced_options.http2_config ? 'HTTP/2' : poolSpec.advanced_options.http1_config ? 'HTTP/1.1' : 'Auto'}
                              small
                            />
                            <DetailItem
                              label="LB Source IP Persist"
                              value={poolSpec.advanced_options.enable_lb_source_ip_persistance ? 'Enabled' : 'Disabled'}
                              enabled={!!poolSpec.advanced_options.enable_lb_source_ip_persistance}
                              small
                            />
                            <DetailItem
                              label="Proxy Protocol"
                              value={poolSpec.advanced_options.proxy_protocol_v1 ? 'v1' : poolSpec.advanced_options.proxy_protocol_v2 ? 'v2' : 'Disabled'}
                              small
                            />
                            <DetailItem
                              label="Subsets"
                              value={poolSpec.advanced_options.enable_subsets ? 'Enabled' : 'Disabled'}
                              small
                            />
                          </div>

                          {poolSpec.advanced_options.circuit_breaker && (
                            <div className="mt-3 p-3 bg-slate-800/50 rounded-lg">
                              <span className="text-xs text-slate-400 block mb-2">Circuit Breaker Settings</span>
                              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                {poolSpec.advanced_options.circuit_breaker.max_connections !== undefined && (
                                  <DetailItem label="Max Connections" value={poolSpec.advanced_options.circuit_breaker.max_connections.toString()} small />
                                )}
                                {poolSpec.advanced_options.circuit_breaker.max_pending_requests !== undefined && (
                                  <DetailItem label="Max Pending Requests" value={poolSpec.advanced_options.circuit_breaker.max_pending_requests.toString()} small />
                                )}
                                {poolSpec.advanced_options.circuit_breaker.max_requests !== undefined && (
                                  <DetailItem label="Max Requests" value={poolSpec.advanced_options.circuit_breaker.max_requests.toString()} small />
                                )}
                                {poolSpec.advanced_options.circuit_breaker.max_retries !== undefined && (
                                  <DetailItem label="Max Retries" value={poolSpec.advanced_options.circuit_breaker.max_retries.toString()} small />
                                )}
                              </div>
                            </div>
                          )}

                          {poolSpec.advanced_options.outlier_detection && (
                            <div className="mt-3 p-3 bg-slate-800/50 rounded-lg">
                              <span className="text-xs text-slate-400 block mb-2">Outlier Detection Settings</span>
                              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                {poolSpec.advanced_options.outlier_detection.consecutive_5xx !== undefined && (
                                  <DetailItem label="Consecutive 5xx" value={poolSpec.advanced_options.outlier_detection.consecutive_5xx.toString()} small />
                                )}
                                {poolSpec.advanced_options.outlier_detection.consecutive_gateway_failure !== undefined && (
                                  <DetailItem label="Gateway Failures" value={poolSpec.advanced_options.outlier_detection.consecutive_gateway_failure.toString()} small />
                                )}
                                {poolSpec.advanced_options.outlier_detection.interval !== undefined && (
                                  <DetailItem label="Interval" value={`${poolSpec.advanced_options.outlier_detection.interval}ms`} small />
                                )}
                                {poolSpec.advanced_options.outlier_detection.base_ejection_time !== undefined && (
                                  <DetailItem label="Base Ejection Time" value={`${poolSpec.advanced_options.outlier_detection.base_ejection_time}ms`} small />
                                )}
                                {poolSpec.advanced_options.outlier_detection.max_ejection_percent !== undefined && (
                                  <DetailItem label="Max Ejection %" value={`${poolSpec.advanced_options.outlier_detection.max_ejection_percent}%`} small />
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {poolSpec?.upstream_conn_pool_reuse_type && (
                        <div className="pt-4 border-t border-slate-700/50">
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-slate-500">Connection Pool Reuse:</span>
                            <span className={`text-xs font-medium ${poolSpec.upstream_conn_pool_reuse_type.enable_conn_pool_reuse ? 'text-emerald-400' : 'text-slate-400'}`}>
                              {poolSpec.upstream_conn_pool_reuse_type.enable_conn_pool_reuse ? 'Enabled' : 'Disabled'}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

       {/* 8. Security (WAF) */}
        <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
          <button
            onClick={() => toggleSection('security')}
            className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20 transition-colors"
          >
            <div className="flex items-center gap-3">
              <Shield className="w-5 h-5 text-amber-400" />
              <h2 className="text-lg font-semibold text-slate-100">Security Configuration</h2>
            </div>
            {expandedSections.has('security') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
          </button>

          {expandedSections.has('security') && (
            <div className="p-6 space-y-6">
              
              {/* Main WAF Policy */}
              <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                <div className="flex items-center gap-3 mb-4">
                  <Shield className="w-6 h-6 text-amber-400" />
                  <h3 className="text-lg font-semibold text-slate-200">Web Application Firewall (WAF)</h3>
                </div>

                {spec?.disable_waf ? (
                  <div className="flex items-center gap-2 text-red-400">
                    <ShieldOff className="w-5 h-5" />
                    <span>WAF is disabled for this Load Balancer</span>
                  </div>
                ) : spec?.app_firewall ? (
                  <div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                      <DetailItem label="Policy Name" value={spec.app_firewall.name} />
                      <DetailItem label="Namespace" value={spec.app_firewall.namespace || state.namespace} />
                      <DetailItem
                        label="Mode"
                        value={getWafMode(state.wafPolicies.get(spec.app_firewall.name))}
                        enabled={getWafMode(state.wafPolicies.get(spec.app_firewall.name)) === 'Blocking'}
                        warning={getWafMode(state.wafPolicies.get(spec.app_firewall.name)) === 'Monitoring'}
                      />
                      <DetailItem
                        label="Shared"
                        value={state.wafPolicies.get(spec.app_firewall.name)?.shared ? 'Yes' : 'No'}
                      />
                    </div>
                    {/* Render Main WAF Details */}
                    {renderWafConfiguration(state.wafPolicies.get(spec.app_firewall.name))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2 text-slate-500">
                    <ShieldOff className="w-5 h-5" />
                    <span>No WAF policy configured</span>
                  </div>
                )}
              </div>

              {/* Route WAF Policies */}
              {state.wafPolicies.size > 1 && (
                <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                  <div className="flex items-center gap-3 mb-4">
                    <Shield className="w-6 h-6 text-cyan-400" />
                    <h3 className="text-lg font-semibold text-slate-200">Route-Level WAF Policies</h3>
                    <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">
                      {state.wafPolicies.size - (spec?.app_firewall ? 1 : 0)} additional
                    </span>
                  </div>
                  <div className="space-y-4">
                    {Array.from(state.wafPolicies.entries())
                      .filter(([name]) => name !== spec?.app_firewall?.name)
                      .map(([name, waf]) => {
                        return (
                          <div key={name} className="p-5 bg-slate-800/40 rounded-lg border border-slate-700/30">
                            <div className="flex items-center justify-between mb-4">
                              <div className="flex items-center gap-3">
                                <Shield className="w-5 h-5 text-cyan-400" />
                                <span className="text-slate-200 font-semibold text-lg">{name}</span>
                                <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                                  getWafMode(waf) === 'Blocking' ? 'bg-emerald-500/15 text-emerald-400' :
                                  getWafMode(waf) === 'Monitoring' ? 'bg-amber-500/15 text-amber-400' :
                                  getWafMode(waf) === 'AI Risk-Based' ? 'bg-blue-500/15 text-blue-400' :
                                  'bg-slate-700 text-slate-400'
                                }`}>
                                  {getWafMode(waf)}
                                </span>
                              </div>
                              <button
                                onClick={() => setJsonModal({ title: `${name} WAF Policy`, data: waf })}
                                className="p-2 text-slate-500 hover:text-slate-300 hover:bg-slate-700 rounded-lg transition-colors"
                              >
                                <Code className="w-4 h-4" />
                              </button>
                            </div>

                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                              <DetailItem label="Policy Name" value={name} />
                              <DetailItem label="Namespace" value={waf.metadata?.namespace || 'N/A'} />
                              <DetailItem
                                label="Mode"
                                value={getWafMode(waf)}
                                enabled={getWafMode(waf) === 'Blocking'}
                                warning={getWafMode(waf) === 'Monitoring'}
                              />
                              <DetailItem label="Shared" value={waf.shared ? 'Yes' : 'No'} />
                            </div>

                            {/* Render Route WAF Details */}
                            {renderWafConfiguration(waf)}
                          </div>
                        );
                      })}
                  </div>
                </div>
              )}

              {/* Service Policies */}
              {spec?.active_service_policies?.policies && spec.active_service_policies.policies.length > 0 && (
                <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                  <div className="flex items-center gap-3 mb-4">
                    <FileText className="w-6 h-6 text-teal-400" />
                    <h3 className="text-lg font-semibold text-slate-200">Service Policies</h3>
                    <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">
                      {spec.active_service_policies.policies.length}
                    </span>
                  </div>

                  <div className="space-y-4">
                    {spec.active_service_policies.policies.map((pol: any, i: number) => {
                      const spData = state.servicePolicies.get(pol.name) as ServicePolicy | undefined;
                      const rules = spData?.spec?.rule_list?.rules || spData?.spec?.deny_list?.rules || spData?.spec?.allow_list?.rules || [];
                      return (
                        <div key={i} className="p-4 bg-slate-800/50 rounded-lg">
                          <div className="flex items-center justify-between mb-3">
                            <div className="flex items-center gap-2">
                              <FileText className="w-4 h-4 text-teal-400" />
                              <span className="text-slate-200 font-medium">{pol.name}</span>
                              <span className="text-xs text-slate-500">{pol.namespace || state.namespace}</span>
                              {spData?.spec?.deny_list && <span className="px-2 py-0.5 bg-red-500/15 text-red-400 rounded text-xs">Deny List</span>}
                              {spData?.spec?.allow_list && <span className="px-2 py-0.5 bg-emerald-500/15 text-emerald-400 rounded text-xs">Allow List</span>}
                            </div>
                            {spData && (
                              <button
                                onClick={() => setJsonModal({ title: `${pol.name} Service Policy`, data: spData })}
                                className="p-1.5 text-slate-500 hover:text-slate-300 hover:bg-slate-700 rounded transition-colors"
                              >
                                <Code className="w-3.5 h-3.5" />
                              </button>
                            )}
                          </div>
                          {spData?.spec && (
                            <>
                              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                                <DetailItem label="Algorithm" value={spData.spec.algo || 'FIRST_MATCH'} small />
                                <DetailItem label="Rules" value={rules.length.toString()} small />
                                <DetailItem label="Any Server" value={spData.spec.any_server ? 'Yes' : 'No'} small />
                                {spData.spec.server_name && (
                                  <DetailItem label="Server Name" value={spData.spec.server_name} small />
                                )}
                              </div>

                              {rules.length > 0 && (
                                <div className="mt-3 pt-3 border-t border-slate-700/50">
                                  <span className="text-xs text-slate-500 block mb-2">Policy Rules</span>
                                  <div className="space-y-2 max-h-48 overflow-y-auto">
                                    {rules.slice(0, 5).map((rule: any, ruleIdx: number) => {
                                      const r = rule as ServicePolicyRule;
                                      return (
                                        <div key={ruleIdx} className="p-2 bg-slate-900/50 rounded text-sm">
                                          <div className="flex items-center gap-2 mb-1">
                                            <span className="text-slate-400 font-mono text-xs">{ruleIdx + 1}</span>
                                            <span className="text-slate-200">{r.metadata?.name || `Rule ${ruleIdx + 1}`}</span>
                                            <span className={`px-1.5 py-0.5 rounded text-xs ${
                                              r.spec?.action === 'ALLOW' ? 'bg-emerald-500/15 text-emerald-400' :
                                              r.spec?.action === 'DENY' ? 'bg-red-500/15 text-red-400' :
                                              'bg-slate-700 text-slate-400'
                                            }`}>
                                              {r.spec?.action || 'ALLOW'}
                                            </span>
                                          </div>
                                          <div className="flex flex-wrap gap-2 text-xs">
                                            {r.spec?.any_client && <span className="text-slate-500">Any Client</span>}
                                            {r.spec?.any_ip && <span className="text-slate-500">Any IP</span>}
                                            {r.spec?.ip_prefix_list?.prefixes && r.spec.ip_prefix_list.prefixes.length > 0 && (
                                              <span className="text-blue-400">{r.spec.ip_prefix_list.prefixes.length} IP prefix(es)</span>
                                            )}
                                            {r.spec?.path?.prefix && <span className="text-cyan-400">Path: {r.spec.path.prefix}</span>}
                                            {r.spec?.path?.regex && <span className="text-cyan-400">Regex: {r.spec.path.regex}</span>}
                                            {r.spec?.http_method?.methods && r.spec.http_method.methods.length > 0 && (
                                              <span className="text-amber-400">{r.spec.http_method.methods.join(', ')}</span>
                                            )}
                                            {r.spec?.waf_action?.waf_skip_processing && <span className="text-red-400">Skip WAF</span>}
                                            {r.spec?.waf_action?.waf_in_monitoring_mode && <span className="text-amber-400">WAF Monitor</span>}
                                            {r.spec?.headers && r.spec.headers.length > 0 && <span className="text-slate-400">{r.spec.headers.length} header(s)</span>}
                                            {r.spec?.asn_list?.as_numbers && r.spec.asn_list.as_numbers.length > 0 && <span className="text-slate-400">{r.spec.asn_list.as_numbers.length} ASN(s)</span>}
                                          </div>
                                        </div>
                                      );
                                    })}
                                    {rules.length > 5 && (
                                      <div className="text-center text-slate-500 text-xs py-1">
                                        ... and {rules.length - 5} more rules
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}
                            </>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* User Identification */}
              <div className="space-y-4">
                {spec && (
                  <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-emerald-500/15 text-emerald-400">
                          <User className="w-5 h-5" />
                        </div>
                        <div>
                          <h3 className="text-lg font-semibold text-slate-200">User Identification</h3>
                          <span className="text-sm text-slate-400">
                            {spec.user_identification?.name || 'Client IP Address'}
                          </span>
                        </div>
                        <span className="px-2 py-1 bg-emerald-500/15 text-emerald-400 rounded text-xs font-medium">Enabled</span>
                      </div>
                      
                      {state.userIdentificationPolicy && (
                        <button
                          onClick={() => setJsonModal({ title: `User Identification: ${spec.user_identification?.name}`, data: state.userIdentificationPolicy })}
                          className="px-3 py-1.5 text-xs text-cyan-400 hover:text-cyan-300 hover:bg-slate-700 rounded flex items-center gap-1.5 transition-colors"
                        >
                          <Code2 className="w-3.5 h-3.5" />
                          View JSON
                        </button>
                      )}
                    </div>
                    
                    {state.userIdentificationPolicy && (() => {
                      const policySpec = state.userIdentificationPolicy.spec || state.userIdentificationPolicy.get_spec;
                      const rules = policySpec?.rules || [];
                      if (rules.length === 0) return null;
                      return (
                        <div className="border-t border-slate-700/50 pt-4">
                          <span className="text-xs text-slate-500 block mb-3">Identification Rules ({rules.length})</span>
                          <div className="overflow-x-auto">
                            <table className="w-full text-sm">
                              <thead>
                                <tr className="text-left text-xs text-slate-500">
                                  <th className="pb-2 pr-4 w-16">Order</th>
                                  <th className="pb-2">Identifier Type</th>
                                </tr>
                              </thead>
                              <tbody>
                                {rules.map((rule: any, idx: number) => {
                                  let idType = 'Unknown';
                                  let idDetail = '';
                                  const identifier = rule.client_identifier;
                                  if (rule.ip_and_ja4_tls_fingerprint !== undefined || identifier?.ip_and_ja4_tls_fingerprint !== undefined) {
                                    idType = 'IP Address + TLS JA4 Fingerprint';
                                  } else if (rule.ip_and_tls_fingerprint !== undefined || identifier?.ip_and_tls_fingerprint !== undefined) {
                                    idType = 'IP Address + TLS Fingerprint';
                                  } else if (rule.ja4_tls_fingerprint !== undefined || identifier?.ja4_tls_fingerprint !== undefined) {
                                    idType = 'TLS JA4 Fingerprint';
                                  } else if (rule.client_ip !== undefined || identifier?.client_ip !== undefined) {
                                    idType = 'Client IP';
                                  } else if (rule.tls_fingerprint !== undefined || identifier?.tls_fingerprint !== undefined) {
                                    idType = 'TLS Fingerprint';
                                  } else if (rule.http_header || identifier?.http_header) {
                                    idType = 'HTTP Header';
                                    idDetail = rule.http_header?.name || identifier?.http_header?.name || '';
                                  } else if (rule.http_cookie || identifier?.http_cookie) {
                                    idType = 'HTTP Cookie';
                                    idDetail = rule.http_cookie?.name || identifier?.http_cookie?.name || '';
                                  } else if (rule.none !== undefined || identifier?.none !== undefined) {
                                    idType = 'None';
                                  }
                                  return (
                                    <tr key={idx} className="border-t border-slate-700/30">
                                      <td className="py-2 pr-4 text-slate-400">{idx + 1}</td>
                                      <td className="py-2 text-cyan-400">{idType}{idDetail && <span className="text-slate-400 ml-2">({idDetail})</span>}</td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      );
                    })()}
                  </div>
                )}

                {/* CORS Policy */}
                {spec?.cors_policy && !spec.cors_policy.disabled && (
                  <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-blue-500/15 text-blue-400">
                          <Globe className="w-5 h-5" />
                        </div>
                        <div>
                          <h3 className="text-lg font-semibold text-slate-200">CORS Policy</h3>
                        </div>
                        <span className="px-2 py-1 bg-emerald-500/15 text-emerald-400 rounded text-xs font-medium">Enabled</span>
                      </div>
                      <button
                        onClick={() => setJsonModal({ title: 'CORS Policy', data: spec.cors_policy })}
                        className="px-3 py-1.5 text-xs text-cyan-400 hover:text-cyan-300 hover:bg-slate-700 rounded flex items-center gap-1.5 transition-colors"
                      >
                        <Code2 className="w-3.5 h-3.5" />
                        View JSON
                      </button>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                      <DetailItem label="Allow Methods" value={spec.cors_policy.allow_methods || '*'} />
                      <DetailItem label="Allow Headers" value={spec.cors_policy.allow_headers || '*'} />
                      <DetailItem label="Expose Headers" value={spec.cors_policy.expose_headers || '*'} />
                      <DetailItem label="Allow Credentials" value={spec.cors_policy.allow_credentials ? 'Yes' : 'No'} enabled={spec.cors_policy.allow_credentials} />
                    </div>
                    {(spec.cors_policy.allow_origin?.length || spec.cors_policy.allow_origin_regex?.length) && (
                      <div className="border-t border-slate-700/50 pt-4">
                        <span className="text-xs text-slate-500 block mb-2">Allowed Origins</span>
                        <div className="flex flex-wrap gap-2">
                          {spec.cors_policy.allow_origin?.map((origin: string, i: number) => (
                            <span key={i} className="px-3 py-1 bg-slate-800 rounded text-sm text-slate-300">{origin}</span>
                          ))}
                          {spec.cors_policy.allow_origin_regex?.map((regex: string, i: number) => (
                            <span key={`regex-${i}`} className="px-3 py-1 bg-slate-800 rounded text-sm text-amber-400 font-mono">{regex}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Rate Limiting */}
                {spec?.rate_limit && (
                  <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-amber-500/15 text-amber-400">
                          <Timer className="w-5 h-5" />
                        </div>
                        <div>
                          <h3 className="text-lg font-semibold text-slate-200">Rate Limiting</h3>
                        </div>
                        <span className="px-2 py-1 bg-emerald-500/15 text-emerald-400 rounded text-xs font-medium">Enabled</span>
                      </div>
                      <button
                        onClick={() => setJsonModal({ title: 'Rate Limit Configuration', data: spec.rate_limit })}
                        className="px-3 py-1.5 text-xs text-cyan-400 hover:text-cyan-300 hover:bg-slate-700 rounded flex items-center gap-1.5 transition-colors"
                      >
                        <Code2 className="w-3.5 h-3.5" />
                        View JSON
                      </button>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      {spec.rate_limit.rate_limiter && (
                        <>
                          <DetailItem label="Rate" value={`${spec.rate_limit.rate_limiter.total_number || 0} / ${spec.rate_limit.rate_limiter.unit || 'MINUTE'}`} />
                          <DetailItem label="Burst Multiplier" value={String(spec.rate_limit.rate_limiter.burst_multiplier || 1)} />
                          <DetailItem label="Period Multiplier" value={String(spec.rate_limit.rate_limiter.period_multiplier || 1)} />
                        </>
                      )}
                      <DetailItem label="IP Allow List" value={spec.rate_limit.no_ip_allowed_list !== undefined ? 'None' : (spec.rate_limit.ip_allowed_list?.prefixes?.length ? `${spec.rate_limit.ip_allowed_list.prefixes.length} IPs` : 'None')} />
                    </div>
                  </div>
                )}

                {/* Client Lists */}
                {((spec?.blocked_clients?.length || 0) + (spec?.trusted_clients?.length || 0)) > 0 && (
                  <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-slate-600/50 text-slate-300">
                          <User className="w-5 h-5" />
                        </div>
                        <div>
                          <h3 className="text-lg font-semibold text-slate-200">Client Lists</h3>
                        </div>
                        <span className="px-2 py-1 bg-slate-600 text-slate-300 rounded text-xs font-medium">
                          {(spec?.blocked_clients?.length || 0) + (spec?.trusted_clients?.length || 0)} entries
                        </span>
                      </div>
                      <button
                        onClick={() => setJsonModal({ title: 'Client Lists', data: { blocked_clients: spec?.blocked_clients, trusted_clients: spec?.trusted_clients } })}
                        className="px-3 py-1.5 text-xs text-cyan-400 hover:text-cyan-300 hover:bg-slate-700 rounded flex items-center gap-1.5 transition-colors"
                      >
                        <Code2 className="w-3.5 h-3.5" />
                        View JSON
                      </button>
                    </div>
                    {spec?.blocked_clients && spec.blocked_clients.length > 0 && (
                      <div className="mb-4">
                        <div className="flex items-center gap-2 mb-2">
                          <X className="w-4 h-4 text-red-400" />
                          <span className="text-sm text-red-400 font-medium">Blocked Clients ({spec.blocked_clients.length})</span>
                        </div>
                        <div className="space-y-2">
                          {spec.blocked_clients.map((client: any, i: number) => (
                            <div key={i} className="px-4 py-3 bg-red-500/5 border border-red-500/20 rounded-lg">
                              <div className="flex items-center gap-3">
                                <code className="text-slate-200">{client.ip_prefix || `ASN: ${client.as_number}`}</code>
                                {client.metadata?.name && <span className="text-slate-500">({client.metadata.name})</span>}
                                {client.metadata?.disable && <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">Disabled</span>}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                   {/* TRUSTED CLIENTS */}
                    {spec?.trusted_clients && spec.trusted_clients.length > 0 && (
                      <div>
                        <div className="flex items-center gap-2 mb-2">
                          <Check className="w-4 h-4 text-emerald-400" />
                          <span className="text-sm text-emerald-400 font-medium">Trusted Clients ({spec.trusted_clients.length})</span>
                        </div>
                        <div className="space-y-2">
                          {spec.trusted_clients.map((client: any, i: number) => (
                            <div key={i} className="px-4 py-3 bg-emerald-500/5 border border-emerald-500/20 rounded-lg">
                              <div className="flex items-center justify-between mb-2">
                                <div className="flex items-center gap-3">
                                  <code className="text-slate-200 font-bold">{client.ip_prefix || `ASN: ${client.as_number}`}</code>
                                  {client.metadata?.name && <span className="text-slate-500">({client.metadata.name})</span>}
                                </div>
                              </div>
                              
                              {/* SECURITY SKIPS DISPLAY */}
                              {(client.actions || client.skip_processing) && (
                                <div className="mt-2">
                                  <span className="text-xs text-slate-500 block mb-1">Security Controls Skipped:</span>
                                  <div className="flex flex-wrap gap-1.5">
                                    {(client.actions || client.skip_processing).map((skip: string, j: number) => (
                                      <span key={j} className="px-2 py-0.5 bg-slate-800 text-teal-400 border border-teal-500/20 rounded text-[10px] uppercase font-medium tracking-wide">
                                        {skip.replace('SKIP_PROCESSING_', '').replace(/_/g, ' ')}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Protected Cookies */}
                {spec?.protected_cookies && spec.protected_cookies.length > 0 && (
                  <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-teal-500/15 text-teal-400">
                          <FileText className="w-5 h-5" />
                        </div>
                        <div>
                          <h3 className="text-lg font-semibold text-slate-200">Protected Cookies</h3>
                        </div>
                        <span className="px-2 py-1 bg-slate-600 text-slate-300 rounded text-xs font-medium">{spec.protected_cookies.length} cookie{spec.protected_cookies.length !== 1 ? 's' : ''}</span>
                      </div>
                      <button
                        onClick={() => setJsonModal({ title: 'Protected Cookies', data: spec.protected_cookies })}
                        className="px-3 py-1.5 text-xs text-cyan-400 hover:text-cyan-300 hover:bg-slate-700 rounded flex items-center gap-1.5 transition-colors"
                      >
                        <Code2 className="w-3.5 h-3.5" />
                        View JSON
                      </button>
                    </div>
                    <div className="space-y-2">
                      {spec.protected_cookies.map((cookie: any, i: number) => (
                        <div key={i} className="flex items-center justify-between px-4 py-2 bg-slate-800/50 rounded">
                          <code className="text-slate-200">{cookie.name}</code>
                          <div className="flex items-center gap-2">
                            {(cookie.add_secure !== undefined || cookie.ignore_secure === undefined) && <span className="px-2 py-0.5 bg-teal-500/15 text-teal-400 rounded text-xs">Secure</span>}
                            {(cookie.add_httponly !== undefined || cookie.ignore_httponly === undefined) && <span className="px-2 py-0.5 bg-teal-500/15 text-teal-400 rounded text-xs">HttpOnly</span>}
                            {cookie.enable_tampering_protection !== undefined && <span className="px-2 py-0.5 bg-amber-500/15 text-amber-400 rounded text-xs">Tamper Protected</span>}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* AI/ML Security */}
                {(() => {
                  const appTypeSpec = state.appType?.spec || state.appType?.get_spec;
                  const appSettingSpec = state.appSetting?.spec || state.appSetting?.get_spec;
                  const hasAiMlSettings = appTypeSpec?.user_behavior_analysis_setting || appTypeSpec?.malicious_user_mitigation || appSettingSpec?.user_behavior_analysis_setting || appSettingSpec?.malicious_user_mitigation;

                  if (!hasAiMlSettings) return null;

                  const userBehavior = appTypeSpec?.user_behavior_analysis_setting || appSettingSpec?.user_behavior_analysis_setting;
                  const maliciousMitigation = appTypeSpec?.malicious_user_mitigation || appSettingSpec?.malicious_user_mitigation;

                  return (
                    <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-violet-500/15 text-violet-400">
                            <Eye className="w-5 h-5" />
                          </div>
                          <div>
                            <h3 className="text-lg font-semibold text-slate-200">AI/ML Security Features</h3>
                            <span className="text-xs text-slate-500">From App Type: {state.appType?.metadata?.name || state.appType?.name}</span>
                          </div>
                          <span className="px-2 py-1 bg-emerald-500/15 text-emerald-400 rounded text-xs font-medium">Enabled</span>
                        </div>
                        <button
                          onClick={() => setJsonModal({ title: 'AI/ML Security Settings', data: { user_behavior_analysis: userBehavior, malicious_user_mitigation: maliciousMitigation, app_type: state.appType, app_setting: state.appSetting } })}
                          className="px-3 py-1.5 text-xs text-cyan-400 hover:text-cyan-300 hover:bg-slate-700 rounded flex items-center gap-1.5 transition-colors"
                        >
                          <Code2 className="w-3.5 h-3.5" />
                          View JSON
                        </button>
                      </div>
                      <div className="space-y-4">
                        {userBehavior && (
                          <div className="p-4 bg-slate-800/50 rounded-lg">
                            <h4 className="text-sm font-medium text-slate-300 mb-3">User Behavior Analysis (Malicious User Detection)</h4>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                              <DetailItem label="Detection" value={userBehavior.enable_detection ? 'Enabled' : 'Disabled'} enabled={userBehavior.enable_detection} small />
                              <DetailItem label="Learning" value={userBehavior.enable_learning ? 'Enabled' : 'Disabled'} enabled={userBehavior.enable_learning} small />
                              {userBehavior.cooldown_period && <DetailItem label="Cooldown Period" value={`${userBehavior.cooldown_period}s`} small />}
                              <DetailItem label="Failed Login" value={userBehavior.include_failed_login ? 'Included' : 'Excluded'} enabled={userBehavior.include_failed_login} small />
                              <DetailItem label="Forbidden Requests" value={userBehavior.include_forbidden_requests ? 'Included' : 'Excluded'} enabled={userBehavior.include_forbidden_requests} small />
                              <DetailItem label="IP Reputation" value={userBehavior.include_ip_reputation ? 'Included' : 'Excluded'} enabled={userBehavior.include_ip_reputation} small />
                              <DetailItem label="WAF Data" value={userBehavior.include_waf_data ? 'Included' : 'Excluded'} enabled={userBehavior.include_waf_data} small />
                            </div>
                          </div>
                        )}
                        {maliciousMitigation && (
                          <div className="p-4 bg-slate-800/50 rounded-lg">
                            <h4 className="text-sm font-medium text-slate-300 mb-3">Malicious User Mitigation</h4>
                            <div className="flex items-center gap-2">
                              <span className="text-slate-400">Policy:</span>
                              <span className="text-slate-200">{maliciousMitigation.name}</span>
                              {maliciousMitigation.namespace && <span className="text-slate-500">({maliciousMitigation.namespace})</span>}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })()}

                {/* IP Reputation */}
                {(spec?.enable_ip_reputation || spec?.ip_reputation) && (
                  <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-amber-500/15 text-amber-400">
                          <Network className="w-5 h-5" />
                        </div>
                        <div>
                          <h3 className="text-lg font-semibold text-slate-200">IP Reputation</h3>
                        </div>
                        <span className="px-2 py-1 bg-emerald-500/15 text-emerald-400 rounded text-xs font-medium">Enabled</span>
                      </div>
                      <button
                        onClick={() => setJsonModal({ title: 'IP Reputation Configuration', data: { enable_ip_reputation: spec?.enable_ip_reputation, ip_reputation: spec?.ip_reputation } })}
                        className="px-3 py-1.5 text-xs text-cyan-400 hover:text-cyan-300 hover:bg-slate-700 rounded flex items-center gap-1.5 transition-colors"
                      >
                        <Code2 className="w-3.5 h-3.5" />
                        View JSON
                      </button>
                    </div>
                    {spec?.enable_ip_reputation && typeof spec.enable_ip_reputation === 'object' && (spec.enable_ip_reputation as { ip_threat_categories?: string[] }).ip_threat_categories && (spec.enable_ip_reputation as { ip_threat_categories?: string[] }).ip_threat_categories!.length > 0 && (
                      <div className="border-t border-slate-700/50 pt-4">
                        <span className="text-xs text-slate-500 block mb-2">Threat Categories</span>
                        <div className="flex flex-wrap gap-2">
                          {((spec.enable_ip_reputation as { ip_threat_categories?: string[] }).ip_threat_categories || []).map((cat, i) => (
                            <span key={i} className="px-3 py-1.5 bg-amber-500/10 text-amber-400 rounded text-sm">{cat}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Challenges */}
                {(spec?.captcha_challenge || spec?.js_challenge || spec?.policy_based_challenge) && (
                  <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-cyan-500/15 text-cyan-400">
                          <ShieldCheck className="w-5 h-5" />
                        </div>
                        <div>
                          <h3 className="text-lg font-semibold text-slate-200">Challenge Configuration</h3>
                          <span className="text-sm text-slate-400">
                            {spec?.captcha_challenge ? 'CAPTCHA Challenge' : spec?.js_challenge ? 'JavaScript Challenge' : 'Policy Based Challenge'}
                          </span>
                        </div>
                      </div>
                      <button
                        onClick={() => setJsonModal({ title: 'Challenge Configuration', data: { captcha_challenge: spec?.captcha_challenge, js_challenge: spec?.js_challenge, policy_based_challenge: spec?.policy_based_challenge } })}
                        className="px-3 py-1.5 text-xs text-cyan-400 hover:text-cyan-300 hover:bg-slate-700 rounded flex items-center gap-1.5 transition-colors"
                      >
                        <Code2 className="w-3.5 h-3.5" />
                        View JSON
                      </button>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      {spec?.js_challenge && (
                        <>
                          <DetailItem label="Cookie Expiry" value={`${spec.js_challenge.cookie_expiry || 3600}s`} />
                          <DetailItem label="Script Delay" value={`${spec.js_challenge.js_script_delay || 5000}ms`} />
                        </>
                      )}
                      {spec?.captcha_challenge && (
                        <DetailItem label="Cookie Expiry" value={`${spec.captcha_challenge.cookie_expiry || 3600}s`} />
                      )}
                      {spec?.policy_based_challenge && (
                        <>
                          {spec.policy_based_challenge.malicious_user_mitigation && (
                            <DetailItem label="Malicious User Mitigation" value={spec.policy_based_challenge.malicious_user_mitigation.name} />
                          )}
                          <DetailItem label="Default Captcha Params" value={spec.policy_based_challenge.default_captcha_challenge_parameters ? 'Yes' : 'No'} />
                          <DetailItem label="Default JS Params" value={spec.policy_based_challenge.default_js_challenge_parameters ? 'Yes' : 'No'} />
                        </>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* WAF Exclusion Rules */}
              {spec?.waf_exclusion?.waf_exclusion_inline_rules?.rules && spec.waf_exclusion.waf_exclusion_inline_rules.rules.length > 0 && (
                <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                  <div className="flex items-center gap-3 mb-4">
                    <ShieldOff className="w-6 h-6 text-amber-400" />
                    <h3 className="text-lg font-semibold text-slate-200">WAF Exclusion Rules</h3>
                    <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">
                      {spec.waf_exclusion.waf_exclusion_inline_rules.rules.length} rule{spec.waf_exclusion.waf_exclusion_inline_rules.rules.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                  <div className="space-y-3">
                    {(spec.waf_exclusion.waf_exclusion_inline_rules.rules as Array<{
                      metadata?: { name?: string; disable?: boolean };
                      any_domain?: unknown;
                      exact_domain?: string;
                      path_prefix?: string;
                      path_regex?: string;
                      methods?: string[];
                      app_firewall_detection_control?: {
                        exclude_signature_contexts?: Array<{ signature_id?: number; context?: string }>;
                        exclude_attack_type_contexts?: Array<{ exclude_attack_type?: string; context?: string }>;
                        exclude_violation_contexts?: Array<{ violation_type?: string; context?: string }>;
                      };
                    }>).map((rule, idx) => (
                      <div key={idx} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-2">
                            <span className="text-slate-200 font-medium">{rule.metadata?.name || `Rule ${idx + 1}`}</span>
                            {rule.metadata?.disable && (
                              <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">Disabled</span>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            {rule.methods && (
                              <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">
                                {rule.methods.join(', ')}
                              </span>
                            )}
                          </div>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                          <div>
                            <span className="text-xs text-slate-500 block">Domain</span>
                            <span className="text-slate-300">{rule.any_domain ? 'Any' : rule.exact_domain || 'N/A'}</span>
                          </div>
                          <div>
                            <span className="text-xs text-slate-500 block">Path</span>
                            <code className="text-slate-300">{rule.path_prefix || rule.path_regex || '/'}</code>
                          </div>
                          {rule.app_firewall_detection_control?.exclude_attack_type_contexts && rule.app_firewall_detection_control.exclude_attack_type_contexts.length > 0 && (
                            <div className="col-span-2">
                              <span className="text-xs text-slate-500 block mb-1">Excluded Attack Types</span>
                              <div className="flex flex-wrap gap-1">
                                {rule.app_firewall_detection_control.exclude_attack_type_contexts.map((ctx, ctxIdx) => (
                                  <span key={ctxIdx} className="px-2 py-0.5 bg-amber-500/10 text-amber-400 rounded text-xs">
                                    {ctx.exclude_attack_type?.replace('ATTACK_TYPE_', '').replace(/_/g, ' ')}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </section>

        {/* 9. Advanced Settings & Timeouts */}
        <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
          <button
            onClick={() => toggleSection('advanced')}
            className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20 transition-colors"
          >
            <div className="flex items-center gap-3">
              <Settings className="w-5 h-5 text-slate-400" />
              <h2 className="text-lg font-semibold text-slate-100">Advanced Settings & Timeouts</h2>
            </div>
            {expandedSections.has('advanced') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
          </button>

          {expandedSections.has('advanced') && (
            <div className="p-6 space-y-6">
              {(() => {
                const httpsConfig = spec?.https || spec?.https_auto_cert;
                const moreOpts = spec?.more_option;
                return (
                  <>
                    <div className="p-4 bg-slate-700/30 rounded-lg">
                      <span className="text-xs text-slate-500 block mb-3">Timeout Settings</span>
                      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                        <DetailItem
                          label="Connection Idle Timeout"
                          value={httpsConfig?.connection_idle_timeout ? `${httpsConfig.connection_idle_timeout}ms` : 'Default'}
                        />
                        <DetailItem
                          label="Idle Timeout"
                          value={moreOpts?.idle_timeout ? `${moreOpts.idle_timeout}ms` : (spec?.idle_timeout ? `${spec.idle_timeout}ms` : 'Default')}
                        />
                        <DetailItem
                          label="System Timeouts"
                          value={spec?.system_default_timeouts !== undefined ? 'Default' : 'Custom'}
                        />
                        {moreOpts?.buffer_policy?.max_request_time !== undefined && (
                          <DetailItem
                            label="Max Request Time"
                            value={moreOpts.buffer_policy.max_request_time === 0 ? 'Unlimited' : `${moreOpts.buffer_policy.max_request_time}ms`}
                          />
                        )}
                      </div>
                    </div>

                    <div className="p-4 bg-slate-700/30 rounded-lg">
                      <span className="text-xs text-slate-500 block mb-3">HTTP Protocol Settings</span>
                      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                        <DetailItem
                          label="Port"
                          value={httpsConfig?.port?.toString() || (spec?.https ? '443' : '80')}
                        />
                        <DetailItem
                          label="HTTP Protocol"
                          value={
                            httpsConfig?.http_protocol_options?.http_protocol_enable_v1_only ? 'HTTP/1.x Only' :
                            httpsConfig?.http_protocol_options?.http_protocol_enable_v2_only ? 'HTTP/2 Only' :
                            httpsConfig?.http_protocol_options?.http_protocol_enable_v1_v2 ? 'HTTP/1.x & HTTP/2' : 'Default'
                          }
                        />
                        <DetailItem
                          label="Header Transform"
                          value={
                            httpsConfig?.header_transformation_type?.legacy_header_transformation ? 'Legacy' :
                            httpsConfig?.header_transformation_type?.proper_case_header_transformation ? 'Proper Case' :
                            httpsConfig?.header_transformation_type?.preserve_case_header_transformation ? 'Preserve Case' : 'Default'
                          }
                        />
                        <DetailItem
                          label="Path Normalize"
                          value={httpsConfig?.enable_path_normalize ? 'Enabled' : 'Disabled'}
                          enabled={!!httpsConfig?.enable_path_normalize}
                        />
                        <DetailItem
                          label="Coalescing"
                          value={
                            httpsConfig?.coalescing_options?.disable_coalescing ? 'Disabled' :
                            httpsConfig?.coalescing_options?.default_coalescing ? 'Default' :
                            httpsConfig?.coalescing_options?.apply_coalescing ? `TTL: ${httpsConfig.coalescing_options.apply_coalescing.ttl}` : 'Default'
                          }
                        />
                        <DetailItem
                          label="Add Location"
                          value={spec?.add_location ? 'Enabled' : 'Disabled'}
                          enabled={spec?.add_location}
                        />
                      </div>
                    </div>

                    {moreOpts?.max_request_header_size !== undefined && (
                      <div className="p-4 bg-slate-700/30 rounded-lg">
                        <span className="text-xs text-slate-500 block mb-3">Request Size Limits</span>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                          <DetailItem
                            label="Max Request Header Size"
                            value={`${moreOpts.max_request_header_size} KB`}
                          />
                          {moreOpts.buffer_policy && (
                            <>
                              <DetailItem
                                label="Max Request Body"
                                value={moreOpts.buffer_policy.max_request_bytes ? `${(moreOpts.buffer_policy.max_request_bytes / 1024 / 1024).toFixed(1)} MB` : 'Default'}
                              />
                              <DetailItem
                                label="Request Buffering"
                                value={moreOpts.buffer_policy.disabled ? 'Disabled' : 'Enabled'}
                                enabled={!moreOpts.buffer_policy.disabled}
                              />
                            </>
                          )}
                        </div>
                      </div>
                    )}

                    <div className="p-4 bg-slate-700/30 rounded-lg">
                      <span className="text-xs text-slate-500 block mb-3">Load Balancing & Stickiness</span>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <DetailItem
                          label="Algorithm"
                          value={
                            spec?.round_robin !== undefined ? 'Round Robin' :
                            spec?.least_active !== undefined ? 'Least Active' :
                            spec?.ring_hash !== undefined ? 'Ring Hash' :
                            spec?.random !== undefined ? 'Random' :
                            spec?.source_ip_stickiness !== undefined ? 'Source IP' :
                            spec?.cookie_stickiness_hash !== undefined ? 'Cookie Hash' : 'Round Robin'
                          }
                        />
                        {spec?.cookie_stickiness?.name && (
                          <DetailItem label="Cookie Stickiness" value={spec.cookie_stickiness.name} />
                        )}
                        <DetailItem
                          label="Trust Client IP Headers"
                          value={spec?.disable_trust_client_ip_headers !== undefined ? 'Disabled' : (spec?.enable_trust_client_ip_headers ?
                            (typeof spec.enable_trust_client_ip_headers === 'object' && spec.enable_trust_client_ip_headers.client_ip_headers?.length
                              ? spec.enable_trust_client_ip_headers.client_ip_headers.join(', ')
                              : 'Enabled')
                            : 'Default')}
                          enabled={!!spec?.enable_trust_client_ip_headers}
                        />
                        <DetailItem
                          label="User ID"
                          value={spec?.user_identification?.name || (spec?.user_id_client_ip !== undefined ? 'Client IP' : 'Not configured')}
                        />
                      </div>
                    </div>

                    {moreOpts?.custom_errors && Object.keys(moreOpts.custom_errors).length > 0 && (
                      <div className="p-4 bg-slate-700/30 rounded-lg">
                        <span className="text-xs text-slate-500 block mb-3">Custom Error Responses ({Object.keys(moreOpts.custom_errors).length})</span>
                        <div className="space-y-2">
                          {Object.entries(moreOpts.custom_errors).map(([code, value]) => (
                            <div key={code} className="flex items-center gap-3 px-3 py-2 bg-slate-800/50 rounded">
                              <span className="px-2 py-0.5 bg-amber-500/15 text-amber-400 rounded text-sm font-mono">{code}</span>
                              <span className="text-slate-400 text-sm">
                                {(value as string).startsWith('string:///') ? 'Custom HTML Page' : (value as string)}
                              </span>
                            </div>
                          ))}
                        </div>
                        <DetailItem
                          label="Default Error Pages"
                          value={moreOpts.disable_default_error_pages ? 'Disabled' : 'Enabled'}
                          enabled={!moreOpts.disable_default_error_pages}
                        />
                      </div>
                    )}

                    {spec?.rate_limit && (
                      <div className="p-4 bg-slate-700/30 rounded-lg">
                        <span className="text-xs text-slate-500 block mb-3">Rate Limiting</span>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                          {spec.rate_limit.rate_limiter && (
                            <>
                              <DetailItem
                                label="Rate"
                                value={`${spec.rate_limit.rate_limiter.total_number || 0} per ${spec.rate_limit.rate_limiter.unit || 'MINUTE'}`}
                              />
                              <DetailItem
                                label="Burst Multiplier"
                                value={`${spec.rate_limit.rate_limiter.burst_multiplier || 1}x`}
                              />
                              <DetailItem
                                label="Period Multiplier"
                                value={`${spec.rate_limit.rate_limiter.period_multiplier || 1}x`}
                              />
                            </>
                          )}
                          <DetailItem label="IP Allow List" value={spec.rate_limit.no_ip_allowed_list !== undefined ? 'None' : (spec.rate_limit.ip_allowed_list?.prefixes?.length ? `${spec.rate_limit.ip_allowed_list.prefixes.length} IPs` : 'None')} />
                        </div>
                      </div>
                    )}

                    {spec?.l7_ddos_protection && (
                      <div className="p-4 bg-slate-700/30 rounded-lg">
                        <span className="text-xs text-slate-500 block mb-3">L7 DDoS Protection</span>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                          <DetailItem
                            label="Mitigation Action"
                            value={
                              spec.l7_ddos_protection.mitigation_block !== undefined ? 'Block' :
                              spec.l7_ddos_protection.mitigation_js_challenge !== undefined ? 'JS Challenge' :
                              spec.l7_ddos_protection.mitigation_captcha !== undefined ? 'CAPTCHA' : 'Default'
                            }
                          />
                          <DetailItem
                            label="RPS Threshold"
                            value={
                              spec.l7_ddos_protection.default_rps_threshold !== undefined ? 'Default' :
                              spec.l7_ddos_protection.custom_rps_threshold?.threshold ? `${spec.l7_ddos_protection.custom_rps_threshold.threshold} RPS` : 'Default'
                            }
                          />
                          <DetailItem
                            label="Client-Side Action"
                            value={
                              spec.l7_ddos_protection.clientside_action_none !== undefined ? 'None' :
                              spec.l7_ddos_protection.clientside_action_block !== undefined ? 'Block' :
                              spec.l7_ddos_protection.clientside_action_redirect !== undefined ? 'Redirect' : 'None'
                            }
                          />
                          <DetailItem
                            label="DDoS Policy"
                            value={spec.l7_ddos_protection.ddos_policy?.name || (spec.l7_ddos_protection.ddos_policy_none !== undefined ? 'None' : 'Default')}
                          />
                        </div>
                      </div>
                    )}

                    {(moreOpts?.request_headers_to_add?.length || spec?.request_headers_to_add?.length) && (
                      <div className="p-4 bg-slate-700/30 rounded-lg">
                        <span className="text-xs text-slate-500 block mb-3">Request Headers to Add ({(moreOpts?.request_headers_to_add || spec?.request_headers_to_add || []).length})</span>
                        <div className="space-y-2 max-h-64 overflow-y-auto">
                          {(moreOpts?.request_headers_to_add || spec?.request_headers_to_add || []).map((h: any, i: number) => (
                            <div key={i} className="flex items-center gap-2 px-3 py-2 bg-slate-800/50 rounded">
                              <code className="text-blue-400 font-medium">{h.name}</code>
                              <span className="text-slate-500">:</span>
                              <code className="text-slate-300 truncate text-sm">{h.value || '[dynamic]'}</code>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {(moreOpts?.response_headers_to_add?.length || spec?.response_headers_to_add?.length) && (
                      <div className="p-4 bg-slate-700/30 rounded-lg">
                        <span className="text-xs text-slate-500 block mb-3">Response Headers to Add ({(moreOpts?.response_headers_to_add || spec?.response_headers_to_add || []).length})</span>
                        <div className="space-y-2 max-h-64 overflow-y-auto">
                          {(moreOpts?.response_headers_to_add || spec?.response_headers_to_add || []).map((h: any, i: number) => (
                            <div key={i} className="flex items-center gap-2 px-3 py-2 bg-slate-800/50 rounded">
                              <code className="text-emerald-400 font-medium">{h.name}</code>
                              <span className="text-slate-500">:</span>
                              <code className="text-slate-300 truncate text-sm">{h.value || '[dynamic]'}</code>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {(moreOpts?.request_headers_to_remove?.length || spec?.request_headers_to_remove?.length) && (
                      <div className="p-4 bg-slate-700/30 rounded-lg">
                        <span className="text-xs text-slate-500 block mb-3">Request Headers to Remove</span>
                        <div className="flex flex-wrap gap-2">
                          {(moreOpts?.request_headers_to_remove || spec?.request_headers_to_remove || []).map((h: string, i: number) => (
                            <span key={i} className="px-2 py-1 bg-red-500/10 text-red-400 rounded text-sm">{h}</span>
                          ))}
                        </div>
                      </div>
                    )}

                    {(moreOpts?.response_headers_to_remove?.length || spec?.response_headers_to_remove?.length) && (
                      <div className="p-4 bg-slate-700/30 rounded-lg">
                        <span className="text-xs text-slate-500 block mb-3">Response Headers to Remove</span>
                        <div className="flex flex-wrap gap-2">
                          {(moreOpts?.response_headers_to_remove || spec?.response_headers_to_remove || []).map((h: string, i: number) => (
                            <span key={i} className="px-2 py-1 bg-red-500/10 text-red-400 rounded text-sm">{h}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                );
              })()}
            </div>
          )}
        </section>

        {/* 10. Features Status Grid */}
        {(() => {
          const appTypeSpec = state.appType?.spec || state.appType?.get_spec;
          const appTypeName = state.appType?.metadata?.name || state.appType?.name;
          const appTypeFeatures = appTypeSpec?.features || [];
          const hasFeature = (featureType: string) => appTypeFeatures.some((f: any) => f.type === featureType);
          const appSettingSpec = state.appSetting?.spec || state.appSetting?.get_spec;

          return (
            <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
              <button
                onClick={() => toggleSection('features')}
                className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <Activity className="w-5 h-5 text-cyan-400" />
                  <h2 className="text-lg font-semibold text-slate-100">Features Status</h2>
                  {state.appType && (
                    <span className="px-2 py-0.5 bg-violet-500/15 text-violet-400 rounded text-xs font-medium">
                      App Type: {appTypeName}
                    </span>
                  )}
                </div>
                {expandedSections.has('features') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
              </button>

              {expandedSections.has('features') && (
                <div className="p-6 space-y-4">
                  {state.appType && (
                    <p className="text-xs text-slate-500 mb-2">
                      Settings from App Type "{appTypeName}" take precedence over Load Balancer settings
                    </p>
                  )}

                  {appTypeFeatures.length > 0 && (
                    <div className="mb-4">
                      <h4 className="text-xs font-medium text-slate-400 mb-2">AI/ML Features (from App Type)</h4>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <FeatureStatusItem
                          label="Malicious User Detection"
                          enabled={hasFeature('USER_BEHAVIOR_ANALYSIS')}
                          disabled={false}
                          fromAppType={true}
                        />
                        <FeatureStatusItem
                          label="DDoS Detection"
                          enabled={hasFeature('TIMESERIES_ANOMALY_DETECTION')}
                          disabled={false}
                          fromAppType={true}
                        />
                        <FeatureStatusItem
                          label="API Discovery"
                          enabled={hasFeature('BUSINESS_LOGIC_MARKUP')}
                          disabled={false}
                          fromAppType={true}
                        />
                        <FeatureStatusItem
                          label="Per API Request Analysis"
                          enabled={hasFeature('PER_REQ_ANOMALY_DETECTION')}
                          disabled={false}
                          fromAppType={true}
                        />
                      </div>
                    </div>
                  )}

                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                    <FeatureStatusItem
                      label="Bot Defense"
                      enabled={appTypeSpec?.bot_defense_setting ? true : (!spec?.disable_bot_defense && !!spec?.bot_defense)}
                      disabled={!!spec?.disable_bot_defense && !appTypeSpec?.bot_defense_setting}
                      fromAppType={!!appTypeSpec?.bot_defense_setting}
                    />
                    <FeatureStatusItem
                      label="API Discovery (LB)"
                      enabled={!spec?.disable_api_discovery && !!spec?.enable_api_discovery}
                      disabled={!!spec?.disable_api_discovery}
                    />
                    <FeatureStatusItem label="API Testing" enabled={!spec?.disable_api_testing} disabled={!!spec?.disable_api_testing} />
                    <FeatureStatusItem label="API Definition" enabled={!spec?.disable_api_definition && !!(spec?.api_definition || spec?.api_specification?.api_definition)} disabled={!!spec?.disable_api_definition} />
                    <FeatureStatusItem label="IP Reputation" enabled={!spec?.disable_ip_reputation && !!spec?.enable_ip_reputation} disabled={!!spec?.disable_ip_reputation} />
                    <FeatureStatusItem
                      label="Malicious User Detection"
                      enabled={!spec?.disable_malicious_user_detection && !!spec?.enable_malicious_user_detection}
                      disabled={!!spec?.disable_malicious_user_detection}
                    />
                    <FeatureStatusItem
                      label="Malicious User Mitigation"
                      enabled={!!appSettingSpec?.malicious_user_mitigation || !!spec?.malicious_user_mitigation}
                      disabled={!appSettingSpec?.malicious_user_mitigation && !spec?.malicious_user_mitigation}
                      fromAppType={!!appSettingSpec?.malicious_user_mitigation}
                    />
                    <FeatureStatusItem
                      label="Client-Side Defense"
                      enabled={appTypeSpec?.client_side_defense?.policy ? true : (!spec?.disable_client_side_defense && !!spec?.client_side_defense)}
                      disabled={!!spec?.disable_client_side_defense && !appTypeSpec?.client_side_defense?.policy}
                      fromAppType={!!appTypeSpec?.client_side_defense?.policy}
                    />
                    <FeatureStatusItem label="Threat Mesh" enabled={!spec?.disable_threat_mesh} disabled={!!spec?.disable_threat_mesh} />
                    <FeatureStatusItem label="Malware Protection" enabled={!spec?.disable_malware_protection} disabled={!!spec?.disable_malware_protection} />
                    <FeatureStatusItem label="Challenge" enabled={!spec?.no_challenge && (!!spec?.enable_challenge || !!spec?.captcha_challenge || !!spec?.js_challenge || !!spec?.policy_based_challenge)} disabled={!!spec?.no_challenge} />
                    <FeatureStatusItem label="WAF" enabled={!spec?.disable_waf && !!spec?.app_firewall} disabled={!!spec?.disable_waf} />
                    <FeatureStatusItem label="Sensitive Data Policy" enabled={!!spec?.default_sensitive_data_policy || !!spec?.sensitive_data_disclosure_rules} disabled={false} />
                  </div>

                  {spec?.enable_ip_reputation && typeof spec.enable_ip_reputation === 'object' && spec.enable_ip_reputation.ip_threat_categories && spec.enable_ip_reputation.ip_threat_categories.length > 0 && (
                    <div className="pt-4 border-t border-slate-700/50">
                      <h4 className="text-xs font-medium text-slate-400 mb-2">IP Reputation - Threat Categories</h4>
                      <div className="flex flex-wrap gap-2">
                        {spec.enable_ip_reputation.ip_threat_categories.map((cat: string, idx: number) => (
                          <span key={idx} className="px-3 py-1.5 bg-rose-500/10 text-rose-400 rounded-lg text-sm">
                            {cat.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {spec?.l7_ddos_protection && (
                    <div className="pt-4 border-t border-slate-700/50">
                      <h4 className="text-xs font-medium text-slate-400 mb-2">L7 DDoS Protection</h4>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <DetailItem
                          label="Mitigation Action"
                          value={spec.l7_ddos_protection.mitigation_block ? 'Block' : spec.l7_ddos_protection.mitigation_js_challenge ? 'JS Challenge' : spec.l7_ddos_protection.mitigation_captcha ? 'Captcha' : 'Default'}
                          small
                        />
                        <DetailItem
                          label="RPS Threshold"
                          value={spec.l7_ddos_protection.custom_rps_threshold?.threshold ? `${spec.l7_ddos_protection.custom_rps_threshold.threshold}` : 'Default'}
                          small
                        />
                        <DetailItem
                          label="Client-Side Action"
                          value={spec.l7_ddos_protection.clientside_action_block ? 'Block' : spec.l7_ddos_protection.clientside_action_redirect ? 'Redirect' : 'None'}
                          small
                        />
                        <DetailItem
                          label="DDoS Policy"
                          value={spec.l7_ddos_protection.ddos_policy?.name || 'None'}
                          small
                        />
                      </div>
                    </div>
                  )}
                </div>
              )}
            </section>
          );
        })()}
      </div>
    );
  };

  const renderCDNContent = () => {
      const cdn = state.rootCDN!;
      const spec = cdn.spec as any; 
      const sysMeta = cdn.system_metadata as any;

      // Helper to safely get nested logging options
      const loggingOpts = spec.other_settings?.logging_options || spec.logging_options;
      const otherSettings = spec.other_settings || {};

      // Calculate counts for stats
      const spCount = spec.active_service_policies?.policies?.length ?? (spec.service_policies_from_namespace ? 'Namespace' : 0);
      const clientListCount = (spec.trusted_clients?.length || 0) + (spec.blocked_clients?.length || 0);
      const ddosRuleCount = spec.ddos_mitigation_rules?.length || 0;

      return (
        <div className="space-y-6">
            {/* 1. Header & Meta */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-14 h-14 bg-purple-500/15 rounded-xl flex items-center justify-center text-purple-400">
                    <Cloud className="w-7 h-7" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="px-2 py-0.5 text-xs font-semibold rounded bg-purple-600 text-white">CDN Distribution</span>
                      <span className={`px-2 py-0.5 text-xs font-semibold rounded ${!spec.disable ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                        {spec.disable ? 'Disabled' : 'Active'}
                      </span>
                      {spec.state && (
                        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                          {spec.state}
                        </span>
                      )}
                    </div>
                    <h1 className="text-2xl font-bold text-slate-100">{cdn.metadata?.name}</h1>
                    <div className="flex flex-wrap items-center gap-4 mt-2 text-sm text-slate-500">
                      <span className="flex items-center gap-1"><Home className="w-4 h-4" /> {cdn.metadata?.namespace}</span>
                      <span className="flex items-center gap-1"><Clock className="w-4 h-4" /> Created: {formatDate(sysMeta?.creation_timestamp)}</span>
                      {sysMeta?.modification_timestamp && (
                        <span className="flex items-center gap-1"><RefreshCw className="w-3.5 h-3.5" /> Modified: {formatDate(sysMeta.modification_timestamp)}</span>
                      )}
                      {sysMeta?.creator_id && (
                        <span className="flex items-center gap-1"><User className="w-3.5 h-3.5" /> Creator: {sysMeta.creator_id}</span>
                      )}
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => setJsonModal({ title: 'Complete CDN Configuration', data: cdn })}
                  className="flex items-center gap-2 px-4 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors text-sm"
                >
                  <Code className="w-4 h-4" /> JSON
                </button>
              </div>
            </div>

            {/* 2. Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
                 {[
                     { label: 'Domains', value: spec?.domains?.length || 0, icon: Globe, color: 'text-blue-400' },
                     { label: 'Cache Rules', value: (spec?.cdn_settings?.cache_rules?.length || 0) + (spec?.custom_cache_rule?.cdn_cache_rules?.length || 0), icon: HardDrive, color: 'text-amber-400' },
                     { label: 'Service Policies', value: spCount, icon: FileText, color: 'text-teal-400' },
                     { label: 'WAF', value: spec?.app_firewall ? 'Enabled' : 'Disabled', icon: Shield, color: spec?.app_firewall ? 'text-emerald-400' : 'text-slate-500' },
                     { label: 'User ID', value: spec?.user_identification ? 'Enabled' : 'Disabled', icon: User, color: spec?.user_identification ? 'text-cyan-400' : 'text-slate-500' },
                     { label: 'Bot Defense', value: !spec?.disable_bot_defense ? 'Enabled' : 'Disabled', icon: Bot, color: !spec?.disable_bot_defense ? 'text-purple-400' : 'text-slate-500' },
                     { label: 'Client Lists', value: clientListCount, icon: User, color: clientListCount > 0 ? 'text-indigo-400' : 'text-slate-500' },
                     { label: 'DDoS Rules', value: ddosRuleCount, icon: ShieldAlert, color: ddosRuleCount > 0 ? 'text-rose-400' : 'text-slate-500' },
                 ].map(stat => (
                    <div key={stat.label} className="bg-slate-800/50 border border-slate-700 rounded-xl p-3">
                        <div className={`w-7 h-7 mb-1.5 ${stat.color}`}><stat.icon className="w-full h-full" /></div>
                        <div className={`text-lg font-bold ${typeof stat.value === 'string' && (stat.value === 'Enabled' || stat.value === 'Namespace') ? 'text-emerald-400 text-base' : 'text-slate-100'}`}>{stat.value}</div>
                        <div className="text-xs text-slate-500">{stat.label}</div>
                    </div>
                 ))}
            </div>

            {/* 3. Service Domains */}
            {spec.service_domains && spec.service_domains.length > 0 && (
                <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                    <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-700">
                        <Network className="w-5 h-5 text-indigo-400" />
                        <h2 className="text-lg font-semibold text-slate-100">Service Domains</h2>
                    </div>
                    <div className="p-6 grid grid-cols-1 gap-3">
                        {spec.service_domains.map((sd: any, idx: number) => (
                            <div key={idx} className="p-4 bg-slate-700/30 rounded border border-slate-700/50 grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
                                <div>
                                    <span className="text-xs text-slate-500 block mb-1">User Domain</span>
                                    <code className="text-slate-200 text-lg">{sd.domain}</code>
                                </div>
                                <div className="md:text-right">
                                    <span className="text-xs text-slate-500 block mb-1">CNAME Target</span>
                                    <code className="text-cyan-400 select-all">{sd.service_domain}</code>
                                </div>
                            </div>
                        ))}
                    </div>
                </section>
            )}

            {/* 4. TLS & Certificate Details */}
            <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                 <button onClick={() => toggleSection('tls')} className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20">
                     <div className="flex items-center gap-3">
                         <Lock className="w-5 h-5 text-amber-400" />
                         <h2 className="text-lg font-semibold text-slate-100">TLS & Certificates</h2>
                     </div>
                     {expandedSections.has('tls') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
                 </button>
                 
                 {expandedSections.has('tls') && (
                     <div className="p-6 space-y-6">
                         <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                             <DetailItem 
                                label="HTTPS Auto Cert" 
                                value={spec.https_auto_cert ? 'Enabled' : 'Disabled'} 
                                enabled={!!spec.https_auto_cert} 
                             />
                             <DetailItem 
                                label="HSTS Header" 
                                value={spec.https_auto_cert?.add_hsts ? 'Enabled' : 'Disabled'} 
                                enabled={spec.https_auto_cert?.add_hsts}
                             />
                             <DetailItem 
                                label="HTTP Redirect" 
                                value={spec.https_auto_cert?.http_redirect ? 'Enabled' : 'Disabled'} 
                                enabled={spec.https_auto_cert?.http_redirect}
                             />
                             <DetailItem 
                                label="Cert State" 
                                value={spec.cert_state || spec.auto_cert_info?.auto_cert_state || 'Unknown'} 
                                warning={spec.cert_state !== 'AutoCertReady'}
                             />
                         </div>

                         {/* Certificate Info */}
                         {spec.auto_cert_info && (
                             <div className="p-4 bg-slate-700/30 rounded-lg border border-slate-700/50">
                                 <span className="text-xs text-slate-500 block mb-3">Auto Certificate Details</span>
                                 <div className="grid grid-cols-2 gap-4">
                                     <DetailItem 
                                        label="Expiry Date" 
                                        value={spec.auto_cert_info.auto_cert_expiry ? new Date(spec.auto_cert_info.auto_cert_expiry).toLocaleString() : 'N/A'} 
                                     />
                                     <DetailItem label="Subject" value={spec.auto_cert_info.auto_cert_subject || 'N/A'} small />
                                     <DetailItem label="Issuer" value={spec.auto_cert_info.auto_cert_issuer || 'N/A'} small />
                                 </div>
                                 
                                 {/* DNS Records for ACME */}
                                 {spec.auto_cert_info.dns_records && spec.auto_cert_info.dns_records.length > 0 && (
                                     <div className="mt-4 pt-3 border-t border-slate-700/50">
                                         <span className="text-xs text-amber-400 block mb-2 flex items-center gap-2">
                                            <AlertTriangle className="w-3 h-3" /> DNS Records for Challenge
                                         </span>
                                         <div className="space-y-2">
                                             {spec.auto_cert_info.dns_records.map((rec: any, idx: number) => (
                                                 <div key={idx} className="bg-slate-800/50 p-2 rounded text-xs font-mono flex flex-col md:flex-row gap-2">
                                                     <span className="text-slate-400 font-bold">{rec.type}</span>
                                                     <span className="text-slate-300">{rec.name}</span>
                                                     <span className="text-slate-500">→</span>
                                                     <span className="text-cyan-300 select-all">{rec.value}</span>
                                                 </div>
                                             ))}
                                         </div>
                                     </div>
                                 )}
                             </div>
                         )}
                     </div>
                 )}
            </section>

            {/* 5. Origin Configuration */}
            <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                 <button onClick={() => toggleSection('origins')} className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20">
                     <div className="flex items-center gap-3">
                         <Server className="w-5 h-5 text-emerald-400" />
                         <h2 className="text-lg font-semibold text-slate-100">Origin Configuration</h2>
                     </div>
                     {expandedSections.has('origins') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
                 </button>
                 
                 {expandedSections.has('origins') && spec.origin_pool && (
                     <div className="p-6">
                         <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                             {/* Basic Origin Info */}
                             <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4 border-b border-slate-700/50 pb-4">
                                <DetailItem label="Public Name" value={spec.origin_pool.public_name?.dns_name || 'N/A'} />
                                <DetailItem label="Refresh Interval" value={spec.origin_pool.public_name?.refresh_interval ? `${spec.origin_pool.public_name.refresh_interval}s` : 'N/A'} />
                                <DetailItem label="Protocol" value={spec.origin_pool.no_tls ? 'HTTP (No TLS)' : 'HTTPS (TLS)'} warning={!!spec.origin_pool.no_tls} />
                                <DetailItem label="Timeout" value={spec.origin_pool.origin_request_timeout || 'Default'} />
                                <DetailItem 
                                    label="Follow Redirect" 
                                    value={spec.origin_pool.follow_origin_redirect ? 'Enabled' : 'Disabled'} 
                                    enabled={spec.origin_pool.follow_origin_redirect}
                                />
                             </div>

                             {/* Advanced Origin Options */}
                             {spec.origin_pool.more_origin_options && (
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4 border-b border-slate-700/50 pb-4">
                                   <DetailItem 
                                     label="Byte Range Requests" 
                                     value={spec.origin_pool.more_origin_options.enable_byte_range_request ? 'Enabled' : 'Disabled'} 
                                     enabled={spec.origin_pool.more_origin_options.enable_byte_range_request}
                                   />
                                   <DetailItem 
                                     label="Websocket Proxy" 
                                     value={spec.origin_pool.more_origin_options.websocket_proxy ? 'Enabled' : 'Disabled'} 
                                     enabled={spec.origin_pool.more_origin_options.websocket_proxy}
                                   />
                                </div>
                             )}

                             <span className="text-xs text-slate-500 block mb-3">Origin Servers</span>
                             <div className="space-y-2">
                                {spec.origin_pool.origin_servers?.map((os: any, idx: number) => (
                                    <div key={idx} className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-lg">
                                        <Server className="w-4 h-4 text-emerald-400" />
                                        <code className="text-slate-200">{os.public_name?.dns_name || os.ip?.ip || 'Unknown'}</code>
                                        <span className="text-xs text-slate-500">Port: {os.port}</span>
                                    </div>
                                ))}
                             </div>
                         </div>
                     </div>
                 )}
            </section>

            {/* 6. Caching Policies */}
            <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                 <button onClick={() => toggleSection('caching')} className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20">
                     <div className="flex items-center gap-3">
                         <HardDrive className="w-5 h-5 text-amber-400" />
                         <h2 className="text-lg font-semibold text-slate-100">Caching Policies</h2>
                     </div>
                     {expandedSections.has('caching') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
                 </button>

                 {expandedSections.has('caching') && (
                     <div className="p-6 space-y-6">
                         {/* Default Policy */}
                         <div className="p-4 bg-slate-700/30 rounded-lg border border-slate-700/50">
                             <div className="flex items-center gap-2 mb-3">
                                 <Settings className="w-4 h-4 text-amber-400" />
                                 <span className="text-slate-200 font-medium">Default Caching Behavior</span>
                             </div>
                             <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                 <DetailItem label="TTL Override" value={spec.default_cache_action?.cache_ttl_override || 'N/A'} />
                                 <DetailItem label="Max Cache Size" value={spec.cdn_settings?.max_cache_size ? `${spec.cdn_settings.max_cache_size} MB` : 'Default'} />
                             </div>
                         </div>

                         {/* Custom Rules */}
                         {(spec.custom_cache_rule?.cdn_cache_rules || spec.cdn_settings?.cache_rules) && (
                             <div>
                                 <span className="text-xs text-slate-500 block mb-3">Custom Cache Rules</span>
                                 <div className="space-y-4">
                                    {[...(spec.custom_cache_rule?.cdn_cache_rules || []), ...(spec.cdn_settings?.cache_rules || [])].map((ref: any, idx: number) => {
                                        const ruleDetail = state.cacheRules.get(ref.name);
                                        const ruleSpec = (ruleDetail?.spec as { cache_rules?: any })?.cache_rules;
                                        
                                        // 1. Determine Action
                                        const isBypass = ruleSpec?.cache_bypass;
                                        const eligible = ruleSpec?.eligible_for_cache;
                                        
                                        // 2. Determine Cache Key Type & Config
                                        let cacheKeyLabel = 'Default';
                                        let cacheConfig = null;

                                        if (eligible?.scheme_proxy_host_uri) {
                                            cacheKeyLabel = 'Scheme + Host + URI (Ignores Query)';
                                            cacheConfig = eligible.scheme_proxy_host_uri;
                                        } else if (eligible?.scheme_proxy_host_request_uri) {
                                            cacheKeyLabel = 'Scheme + Host + Request URI (Includes Query)';
                                            cacheConfig = eligible.scheme_proxy_host_request_uri;
                                        }

                                        return (
                                            <div key={idx} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                                                <div className="flex items-center justify-between mb-3">
                                                    <div className="flex items-center gap-2">
                                                        <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">Rule {idx + 1}</span>
                                                        <span className="text-slate-200 font-medium">{ref.name}</span>
                                                    </div>
                                                    {ruleDetail && (
                                                        <button onClick={() => setJsonModal({title: `Cache Rule: ${ref.name}`, data: ruleDetail})} className="p-1 text-slate-500 hover:text-slate-300">
                                                            <Code className="w-4 h-4" />
                                                        </button>
                                                    )}
                                                </div>
                                                
                                                {ruleDetail ? (
                                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                                        <DetailItem 
                                                            label="Action" 
                                                            value={isBypass ? 'Bypass Cache' : 'Cache'} 
                                                            warning={!!isBypass}
                                                            enabled={!isBypass}
                                                        />
                                                        
                                                        {!isBypass && (
                                                            <div className="col-span-2 md:col-span-1">
                                                                <span className="text-xs text-slate-500 block mb-0.5">Cache Key</span>
                                                                <span className="text-sm text-cyan-400" title={cacheKeyLabel}>{cacheKeyLabel}</span>
                                                            </div>
                                                        )}

                                                        {!isBypass && cacheConfig && (
                                                            <>
                                                                <DetailItem 
                                                                    label="Cache TTL" 
                                                                    value={cacheConfig.cache_ttl || 'Default'} 
                                                                />
                                                                <DetailItem 
                                                                    label="Ignore Cookies" 
                                                                    value={cacheConfig.ignore_response_cookie ? 'Yes' : 'No'} 
                                                                    enabled={cacheConfig.ignore_response_cookie}
                                                                />
                                                                <DetailItem 
                                                                    label="Override Control" 
                                                                    value={cacheConfig.cache_override ? 'Active' : 'Passive'} 
                                                                    warning={cacheConfig.cache_override}
                                                                />
                                                            </>
                                                        )}
                                                        {ruleSpec?.browser_ttl && (
                                                            <DetailItem label="Browser TTL" value={`${ruleSpec.browser_ttl}s`} />
                                                        )}
                                                    </div>
                                                ) : <span className="text-sm text-slate-500 italic">Details not fetched</span>}
                                            </div>
                                        );
                                    })}
                                 </div>
                             </div>
                         )}
                     </div>
                 )}
            </section>

            {/* 7. Header Modifications */}
            {(spec.request_headers_to_add || spec.response_headers_to_add) && (
                <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                    <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-700">
                        <Settings className="w-5 h-5 text-blue-400" />
                        <h2 className="text-lg font-semibold text-slate-100">Header Modifications</h2>
                    </div>
                    <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                        {spec.request_headers_to_add && spec.request_headers_to_add.length > 0 && (
                            <div>
                                <span className="text-xs text-slate-500 block mb-2">Request Headers (Add)</span>
                                <div className="space-y-2">
                                    {spec.request_headers_to_add.map((h: any, i: number) => (
                                        <div key={i} className="flex items-center gap-2 px-3 py-2 bg-slate-700/30 rounded text-sm">
                                            <span className="text-blue-300 font-mono">{h.name}</span>
                                            <span className="text-slate-500">:</span>
                                            <span className="text-slate-300">{h.value}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                        {spec.response_headers_to_add && spec.response_headers_to_add.length > 0 && (
                            <div>
                                <span className="text-xs text-slate-500 block mb-2">Response Headers (Add)</span>
                                <div className="space-y-2">
                                    {spec.response_headers_to_add.map((h: any, i: number) => (
                                        <div key={i} className="flex items-center gap-2 px-3 py-2 bg-slate-700/30 rounded text-sm">
                                            <span className="text-emerald-300 font-mono">{h.name}</span>
                                            <span className="text-slate-500">:</span>
                                            <span className="text-slate-300">{h.value}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </section>
            )}

            {/* 8. Security Configuration */}
            <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                <button onClick={() => toggleSection('security')} className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20">
                    <div className="flex items-center gap-3">
                        <Shield className="w-5 h-5 text-red-400" />
                        <h2 className="text-lg font-semibold text-slate-100">Security Configuration</h2>
                    </div>
                    {expandedSections.has('security') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
                </button>
                
                {expandedSections.has('security') && (
                    <div className="p-6 space-y-6">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {/* WAF Card */}
                            <div className={`p-4 rounded-lg border ${spec.app_firewall ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-slate-700/30 border-slate-700/50'}`}>
                                <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center gap-2">
                                        <Shield className={`w-5 h-5 ${spec.app_firewall ? 'text-emerald-400' : 'text-slate-500'}`} />
                                        <span className="font-medium text-slate-200">Web App Firewall</span>
                                    </div>
                                    {spec.app_firewall && <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 rounded text-xs">Active</span>}
                                </div>
                                {spec.app_firewall ? (
                                    <div className="text-sm">
                                        <div className="text-slate-400">Policy: <span className="text-slate-200">{spec.app_firewall.name}</span></div>
                                        {state.wafPolicies.get(spec.app_firewall.name) && (
                                            <div className="text-slate-400 mt-1">
                                                Mode: <span className="text-slate-200">{getWafMode(state.wafPolicies.get(spec.app_firewall.name))}</span>
                                            </div>
                                        )}
                                        <button onClick={() => setJsonModal({title:'WAF Policy', data: state.wafPolicies.get(spec.app_firewall.name)})} className="text-xs text-blue-400 hover:underline mt-2 flex items-center gap-1">View Config <Code className="w-3 h-3"/></button>
                                    </div>
                                ) : <span className="text-sm text-slate-500">Not configured</span>}
                            </div>

                            {/* User ID Card */}
                            <div className={`p-4 rounded-lg border ${spec.user_identification ? 'bg-cyan-500/5 border-cyan-500/20' : 'bg-slate-700/30 border-slate-700/50'}`}>
                                <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center gap-2">
                                        <User className={`w-5 h-5 ${spec.user_identification ? 'text-cyan-400' : 'text-slate-500'}`} />
                                        <span className="font-medium text-slate-200">User Identification</span>
                                    </div>
                                    {spec.user_identification && <span className="px-2 py-0.5 bg-cyan-500/20 text-cyan-400 rounded text-xs">Active</span>}
                                </div>
                                {spec.user_identification ? (
                                    <div className="text-sm">
                                        <div className="text-slate-400">Policy: <span className="text-slate-200">{spec.user_identification.name}</span></div>
                                        <button onClick={() => setJsonModal({title:'User ID Policy', data: state.userIdentificationPolicy})} className="text-xs text-blue-400 hover:underline mt-2 flex items-center gap-1">View Config <Code className="w-3 h-3"/></button>
                                    </div>
                                ) : <span className="text-sm text-slate-500">Not configured</span>}
                            </div>
                        </div>

                        {/* Other Security Flags */}
                        <div className="pt-4 border-t border-slate-700/50 grid grid-cols-2 md:grid-cols-3 gap-3">
                             <DetailItem label="Bot Defense" value={!spec.disable_bot_defense ? 'Enabled' : 'Disabled'} small />
                             <DetailItem label="Rate Limiting" value={!spec.disable_rate_limit ? 'Enabled' : 'Disabled'} small />
                             <DetailItem label="Malicious User Detection" value={!spec.disable_malicious_user_detection ? 'Enabled' : 'Disabled'} small />
                        </div>
                    </div>
                )}
            </section>

            {/* 9. Access Control & DDoS */}
            {(clientListCount > 0 || ddosRuleCount > 0) && (
                <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                    <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-700">
                        <ShieldAlert className="w-5 h-5 text-rose-400" />
                        <h2 className="text-lg font-semibold text-slate-100">Access Control & DDoS</h2>
                    </div>
                    <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Client Lists */}
                        {clientListCount > 0 && (
                            <div>
                                <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                                    <User className="w-4 h-4 text-indigo-400" /> Client Lists
                                </h4>
                                <div className="space-y-2">
                                    {spec.blocked_clients?.map((c: any, i: number) => (
                                        <div key={`blk-${i}`} className="px-3 py-2 bg-red-500/10 border border-red-500/20 rounded flex justify-between items-center text-sm">
                                            <span className="text-red-300">{c.ip_prefix || `ASN ${c.as_number}`}</span>
                                            <span className="text-xs bg-red-500/20 text-red-300 px-2 py-0.5 rounded">Blocked</span>
                                        </div>
                                    ))}
                                    {spec.trusted_clients?.map((c: any, i: number) => (
                                        <div key={`trst-${i}`} className="px-3 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded flex justify-between items-center text-sm">
                                            <span className="text-emerald-300">{c.ip_prefix || `ASN ${c.as_number}`}</span>
                                            <span className="text-xs bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded">Trusted</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                        
                        {/* DDoS Rules */}
                        {ddosRuleCount > 0 && (
                            <div>
                                <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                                    <ShieldAlert className="w-4 h-4 text-rose-400" /> DDoS Rules
                                </h4>
                                <div className="space-y-2">
                                    {spec.ddos_mitigation_rules.map((rule: any, i: number) => (
                                        <div key={i} className="p-3 bg-slate-700/30 rounded border border-slate-700/50 text-sm">
                                            <div className="flex justify-between mb-1">
                                                <span className="text-slate-300 font-medium">{rule.metadata?.name}</span>
                                                <span className="text-xs text-slate-500">Rule {i+1}</span>
                                            </div>
                                            <div className="text-xs text-slate-400">
                                                Action: <span className="text-amber-400">{Object.keys(rule.mitigation_action || {}).join(', ') || 'None'}</span>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </section>
            )}

            {/* 10. Observability & Logging (Fixed Check) */}
            {(loggingOpts || spec.more_option?.custom_errors || otherSettings.add_location) && (
                <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                    <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-700">
                        <Activity className="w-5 h-5 text-blue-400" />
                        <h2 className="text-lg font-semibold text-slate-100">Observability & Logging</h2>
                    </div>
                    <div className="p-6 space-y-4">
                        {/* Header List */}
                        {loggingOpts?.client_log_options?.header_list && (
                            <div>
                                <span className="text-xs text-slate-500 block mb-2">Log Headers (Captured in Logs)</span>
                                <div className="flex flex-wrap gap-2">
                                    {loggingOpts.client_log_options.header_list.map((h: string, i: number) => (
                                        <span key={i} className="px-3 py-1 bg-blue-500/10 text-blue-300 border border-blue-500/20 rounded text-sm font-mono">
                                            {h}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Add Location */}
                        {otherSettings.add_location !== undefined && (
                            <div className="pt-2">
                                <DetailItem 
                                    label="Add Location Data" 
                                    value={otherSettings.add_location ? 'Enabled' : 'Disabled'}
                                    enabled={otherSettings.add_location}
                                />
                            </div>
                        )}
                        
                        {/* Error Pages */}
                        {spec.more_option?.custom_errors && (
                            <div className="pt-4 border-t border-slate-700/50">
                                <span className="text-xs text-slate-500 block mb-2">Custom Error Pages</span>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                    {Object.keys(spec.more_option.custom_errors).map((code) => (
                                        <div key={code} className="px-3 py-2 bg-slate-700/30 rounded text-sm flex justify-between">
                                            <span className="text-amber-400 font-mono">{code}</span>
                                            <span className="text-slate-400">Custom</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </section>
            )}
        </div>
      );
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
              <div className="w-10 h-10 bg-blue-500/15 rounded-xl flex items-center justify-center text-blue-400">
                <Grid3X3 className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-slate-100">Config Viewer</h1>
                <p className="text-xs text-slate-500">
                  Comprehensive Load Balancer Configuration View
                </p>
              </div>
            </div>
            <Link to="/explainer/config-viewer" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
              <HelpCircle className="w-3.5 h-3.5" /> How does this work?
            </Link>
          </div>

          <div className="flex items-center gap-3">
            
            {/* 2. NEW: Type Selector */}
            <select
              value={selectedType}
              onChange={e => {
                const newType = e.target.value as 'http' | 'cdn';
                setSelectedType(newType);
                loadResources(selectedNs, newType);
              }}
              className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-blue-500 min-w-[120px]"
            >
              <option value="http">HTTP LB</option>
              <option value="cdn">CDN</option>
            </select>

            {/* 1. Namespace Selector */}
            <select
              value={selectedNs}
              onChange={e => loadResources(e.target.value, selectedType)} // Updated handler
              disabled={isLoadingNs}
              className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-blue-500 min-w-[180px]"
            >
              <option value="">Select Namespace</option>
              {namespaces.map(ns => (
                <option key={ns.name} value={ns.name}>
                  {ns.name}
                </option>
              ))}
            </select>

            {/* 3. Multi-select Resource Picker */}
            <div ref={lbDropRef} className="relative">
              <button
                onClick={() => !isLoadingResources && selectedNs && setLbDropOpen(!lbDropOpen)}
                disabled={!selectedNs || isLoadingResources}
                className="flex items-center justify-between gap-2 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 hover:border-slate-500 disabled:opacity-50 disabled:cursor-not-allowed min-w-[240px]"
              >
                <span className={selectedResources.size > 0 ? 'text-slate-200' : 'text-slate-500'}>
                  {isLoadingResources ? 'Loading...' : selectedResources.size > 0 ? `${selectedResources.size} LB(s) selected` : `Select ${selectedType === 'http' ? 'Load Balancers' : 'Distributions'}`}
                </span>
                <ChevronDown className="w-4 h-4 text-slate-400" />
              </button>
              {lbDropOpen && (
                <div className="absolute z-50 mt-1 w-80 bg-slate-800 border border-slate-600 rounded-lg shadow-xl max-h-72 overflow-hidden">
                  <div className="p-2 border-b border-slate-700 space-y-2">
                    <div className="relative">
                      <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
                      <input
                        value={lbFilter}
                        onChange={(e) => setLbFilter(e.target.value)}
                        className="w-full pl-7 pr-3 py-1.5 bg-slate-700 rounded text-sm text-slate-200 placeholder-slate-500 outline-none"
                        placeholder="Filter..."
                        autoFocus
                      />
                    </div>
                    <div className="flex gap-2">
                      <button onClick={() => setSelectedResources(new Set(resourceList.map(r => r.name)))} className="text-xs text-blue-400 hover:text-blue-300">Select All</button>
                      <span className="text-slate-600">|</span>
                      <button onClick={() => setSelectedResources(new Set())} className="text-xs text-slate-400 hover:text-slate-300">Clear</button>
                    </div>
                  </div>
                  <div className="max-h-52 overflow-y-auto">
                    {resourceList.filter(r => r.name.toLowerCase().includes(lbFilter.toLowerCase())).map(r => {
                      const checked = selectedResources.has(r.name);
                      return (
                        <button
                          key={r.name}
                          onClick={() => {
                            setSelectedResources(prev => {
                              const next = new Set(prev);
                              if (next.has(r.name)) next.delete(r.name); else next.add(r.name);
                              return next;
                            });
                          }}
                          className={`w-full flex items-center gap-2 px-3 py-2 text-sm hover:bg-slate-700 ${checked ? 'bg-slate-700/50' : ''} text-slate-300`}
                        >
                          <span className={`w-4 h-4 rounded border flex items-center justify-center text-xs shrink-0 ${checked ? 'bg-blue-600 border-blue-500 text-white' : 'border-slate-500'}`}>
                            {checked && '✓'}
                          </span>
                          <span className="truncate">{r.name}</span>
                        </button>
                      );
                    })}
                    {resourceList.filter(r => r.name.toLowerCase().includes(lbFilter.toLowerCase())).length === 0 && <div className="px-3 py-4 text-sm text-slate-500 text-center">No results</div>}
                  </div>
                </div>
              )}
            </div>

            <button
              onClick={startViewer}
              disabled={!selectedNs || (selectedResources.size === 0 && !selectedResource) || isLoading}
              className={`flex items-center gap-2 px-5 py-2 font-semibold rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed text-white ${selectedType === 'http' ? 'bg-blue-500 hover:bg-blue-600' : 'bg-purple-500 hover:bg-purple-600'}`}
            >
              {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Eye className="w-4 h-4" />}
              View{selectedResources.size > 1 ? ` (${selectedResources.size})` : ''}
            </button>
          </div>
          
        </div>
      </div>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {isLoading && (
          <div className="flex flex-col items-center justify-center py-24">
            <Loader2 className="w-10 h-10 animate-spin text-blue-400 mb-4" />
            <p className="text-slate-400">{scanLog || 'Loading...'}</p>
          </div>
        )}

        {!isLoading && !lb && !state.rootCDN && (
          <div className="flex flex-col items-center justify-center py-24 text-center">
            <Grid3X3 className="w-16 h-16 text-slate-600 mb-4" />
            <h2 className="text-xl font-semibold text-slate-300 mb-2">
              Select a Load Balancer to visualize
            </h2>
            <p className="text-slate-500 max-w-md">
              Choose a namespace and load balancer from the dropdowns above to view its
              complete configuration details.
            </p>
          </div>
        )}

        {/* Navigation bar (top) - shown when multiple LBs loaded */}
        {!isLoading && allStates.length > 1 && (state.rootLB || state.rootCDN) && (
          <div className="flex items-center justify-between bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-3 mb-6 sticky top-2 z-40 backdrop-blur-sm">
            <button
              onClick={() => goToLB(currentIndex - 1)}
              disabled={currentIndex === 0}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="w-4 h-4" /> Previous
            </button>
            <div className="flex items-center gap-3">
              <span className="text-sm text-slate-400">{currentIndex + 1} / {allStates.length}</span>
              <select
                value={currentIndex}
                onChange={e => goToLB(Number(e.target.value))}
                className="px-3 py-1.5 bg-slate-700 border border-slate-600 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-blue-500"
              >
                {allStates.map((s, i) => {
                  const name = (s.rootLB as any)?.metadata?.name || (s.rootLB as any)?.name || (s.rootCDN as any)?.metadata?.name || `#${i + 1}`;
                  return <option key={i} value={i}>{name}</option>;
                })}
              </select>
            </div>
            <button
              onClick={() => goToLB(currentIndex + 1)}
              disabled={currentIndex === allStates.length - 1}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              Next <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        )}

        {!isLoading && state.rootLB && renderHTTPLBContent()}

        {!isLoading && state.rootCDN && renderCDNContent()}

        {/* Navigation bar (bottom) - shown when multiple LBs loaded */}
        {!isLoading && allStates.length > 1 && (state.rootLB || state.rootCDN) && (
          <div className="flex items-center justify-between bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-3 mt-6">
            <button
              onClick={() => goToLB(currentIndex - 1)}
              disabled={currentIndex === 0}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="w-4 h-4" /> Previous
            </button>
            <span className="text-sm text-slate-400">
              {currentIndex + 1} / {allStates.length} — {(() => {
                const s = allStates[currentIndex];
                return (s?.rootLB as any)?.metadata?.name || (s?.rootLB as any)?.name || (s?.rootCDN as any)?.metadata?.name || '';
              })()}
            </span>
            <button
              onClick={() => goToLB(currentIndex + 1)}
              disabled={currentIndex === allStates.length - 1}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              Next <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        )}

      </main>

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
                  onClick={copyJson}
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

function DetailItem({
  label,
  value,
  enabled,
  warning,
  small
}: {
  label: string;
  value: string;
  enabled?: boolean;
  warning?: boolean;
  small?: boolean;
}) {
  let valueColor = 'text-slate-300';
  if (enabled === true) valueColor = 'text-emerald-400';
  else if (enabled === false) valueColor = 'text-slate-500';
  else if (warning) valueColor = 'text-amber-400';

  return (
    <div>
      <span className={`text-slate-500 block ${small ? 'text-xs mb-0.5' : 'text-xs mb-1'}`}>{label}</span>
      <span className={`${valueColor} ${small ? 'text-sm' : ''}`}>{value}</span>
    </div>
  );
}

function FeatureStatusItem({ label, enabled, disabled, fromAppType }: { label: string; enabled: boolean; disabled: boolean; fromAppType?: boolean }) {
  const status = disabled ? 'disabled' : (enabled ? 'enabled' : 'not-configured');
  return (
    <div className={`p-3 rounded-lg border ${
      status === 'enabled' ? 'bg-emerald-500/5 border-emerald-500/20' :
      status === 'disabled' ? 'bg-red-500/5 border-red-500/20' :
      'bg-slate-700/30 border-slate-700'
    }`}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 min-w-0">
          <span className="text-sm text-slate-300 truncate">{label}</span>
          {fromAppType && (
            <span className="flex-shrink-0 w-1.5 h-1.5 bg-violet-400 rounded-full" title="From App Type" />
          )}
        </div>
        <span className={`flex-shrink-0 px-2 py-0.5 rounded text-xs font-medium ${
          status === 'enabled' ? 'bg-emerald-500/15 text-emerald-400' :
          status === 'disabled' ? 'bg-red-500/15 text-red-400' :
          'bg-slate-700 text-slate-500'
        }`}>
          {status === 'enabled' ? 'Enabled' : status === 'disabled' ? 'Disabled' : 'Off'}
        </span>
      </div>
    </div>
  );
}
