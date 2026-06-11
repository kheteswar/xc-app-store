// ═══════════════════════════════════════════════════════════════════════════
// Property Viewer - View selected properties across all config objects
// Supports multi-property selection, card+table views, CSV/Excel/JSON export
// Enhanced with additional properties, distribution filtering, and Raw JSON view
// ═══════════════════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback, useRef } from 'react';
import type { MouseEvent as ReactMouseEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, Layers, Loader2, Check, Search, FileJson, Table, Play, X,
  ChevronDown, ChevronUp, ChevronRight, Globe, Server, Shield, Hash,
  AlertTriangle, Copy, LayoutGrid, LayoutList, FileText, HelpCircle,
} from 'lucide-react';
import { apiClient } from '../services/api';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import type { Namespace } from '../types';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

type ObjectType = 'http_loadbalancer' | 'cdn_loadbalancer' | 'origin_pool' | 'app_firewall' | 'tcp_loadbalancer';

interface ObjectTypeInfo {
  id: ObjectType;
  label: string;
  apiListPath: (ns: string) => string;
  apiGetPath: (ns: string, name: string) => string;
  icon: typeof Globe;
  properties: PropertyDef[];
}

interface PropertyDef {
  id: string;
  label: string;
  category: string;
  extractor: (obj: any) => string | string[];
}

interface ResultRow {
  namespace: string;
  objectName: string;
  values: Record<string, string>;
  error?: boolean;
  rawData?: any; // Stores the full raw JSON object
}

interface LogEntry {
  time: string;
  message: string;
  type: 'info' | 'success' | 'warning' | 'error' | 'fetch';
}

type Step = 1 | 2 | 3;
type ViewMode = 'table' | 'cards';

// ═══════════════════════════════════════════════════════════════════════════
// PROPERTY DEFINITIONS & HELPERS
// ═══════════════════════════════════════════════════════════════════════════

const getAdvertiseType = (spec: any): string => {
  if (spec?.advertise_on_public_default_vip) return 'Public (Default VIP)';
  if (spec?.advertise_on_public) return 'Public (Custom)';
  if (spec?.advertise_custom) return 'Custom';
  if (spec?.do_not_advertise) return 'Not Advertised';
  return 'Unknown';
};
const getLBType = (spec: any): string => {
  if (spec?.https_auto_cert) return 'HTTPS (Auto Cert)';
  if (spec?.https) return 'HTTPS (Custom)';
  return 'HTTP';
};
const getTLSMinVersion = (spec: any): string => {
  const tls = spec?.https?.tls_config || spec?.https_auto_cert?.tls_config || spec?.https?.tls_cert_params?.tls_config || spec?.https?.tls_cert_options?.tls_cert_params?.tls_config;
  return tls ? (tls.min_version || 'Default') : 'N/A';
};
const getWafMode = (spec: any): string => {
  if (spec?.blocking) return 'Blocking';
  if (spec?.monitoring) return 'Monitoring';
  if (spec?.ai_risk_based_blocking) return 'AI Risk-Based Blocking';
  return spec?.mode || 'Unknown';
};
const getLabels = (obj: any): string => {
  const entries = Object.entries(obj?.metadata?.labels || {});
  return entries.length === 0 ? 'None' : entries.map(([k, v]) => `${k}=${v}`).join(', ');
};
const getBoolFlag = (val: any, t = 'Enabled', f = 'Disabled'): string =>
  (val === true || (val !== undefined && val !== null && typeof val === 'object')) ? t : f;

const HTTP_LB_PROPERTIES: PropertyDef[] = [
  // General
  { id: 'domains', label: 'Domains', category: 'General', extractor: (o) => o?.spec?.domains?.join(', ') || 'None' },
  { id: 'host_name', label: 'CNAME / Hostname', category: 'General', extractor: (o) => o?.spec?.host_name || 'N/A' },
  { id: 'dns_ips', label: 'DNS / VIP IPs', category: 'General', extractor: (o) => o?.spec?.dns_info?.map((d: any) => d.ip_address).join(', ') || 'N/A' },
  { id: 'advertise_ip_info', label: 'Advertise IP / VIP Name', category: 'General', extractor: (o) => {
      const pub = o?.spec?.advertise_on_public;
      if (pub?.public_ip?.name) return `IP Object: ${pub.public_ip.name}`;
      if (o?.spec?.advertise_on_public_default_vip) return 'Default VIP';
      return 'N/A';
  }},
  { id: 'labels', label: 'Labels', category: 'General', extractor: getLabels },
  { id: 'annotations', label: 'Annotations', category: 'General', extractor: (o) => Object.entries(o?.metadata?.annotations || {}).map(([k, v]) => `${k}=${v}`).join(', ') || 'None' },
  { id: 'description', label: 'Description', category: 'General', extractor: (o) => o?.metadata?.description || o?.metadata?.annotations?.description || 'N/A' },
  { id: 'lb_type', label: 'LB Type', category: 'General', extractor: (o) => getLBType(o?.spec) },
  { id: 'advertise_type', label: 'Advertise Policy', category: 'General', extractor: (o) => getAdvertiseType(o?.spec) },
  { id: 'creation_date', label: 'Creation Date', category: 'General', extractor: (o) => o?.system_metadata?.creation_timestamp ? new Date(o.system_metadata.creation_timestamp).toLocaleDateString() : 'N/A' },
  { id: 'disabled', label: 'Disabled', category: 'General', extractor: (o) => o?.metadata?.disable ? 'Yes' : 'No' },
  { id: 'add_location', label: 'Add Location', category: 'General', extractor: (o) => getBoolFlag(o?.spec?.add_location) },

  // Status
  { id: 'vh_state', label: 'Virtual Host State', category: 'Status', extractor: (o) => o?.spec?.state || 'N/A' },
  { id: 'cert_state', label: 'Certificate State', category: 'Status', extractor: (o) => o?.spec?.cert_state || 'N/A' },
  { id: 'auto_cert_state', label: 'Auto Cert State', category: 'Status', extractor: (o) => o?.spec?.auto_cert_info?.auto_cert_state || 'N/A' },

  // TLS/SSL
  { id: 'tls_min_version', label: 'TLS Min Version', category: 'TLS/SSL', extractor: (o) => getTLSMinVersion(o?.spec) },
  { id: 'hsts', label: 'HSTS Header', category: 'TLS/SSL', extractor: (o) => getBoolFlag(o?.spec?.add_hsts_header) },
  { id: 'http_redirect', label: 'HTTP→HTTPS Redirect', category: 'TLS/SSL', extractor: (o) => getBoolFlag(o?.spec?.http_redirect || o?.spec?.https_auto_cert?.http_redirect || o?.spec?.https?.http_redirect) },
  { id: 'mtls', label: 'mTLS', category: 'TLS/SSL', extractor: (o) => { const h = o?.spec?.https || o?.spec?.https_auto_cert; return h?.tls_cert_params?.use_mtls ? 'Enabled' : 'Disabled'; } },

  // Security
  { id: 'waf_policy', label: 'WAF Policy', category: 'Security', extractor: (o) => o?.spec?.disable_waf ? 'Disabled' : (o?.spec?.app_firewall?.name || 'None') },
  { id: 'bot_defense', label: 'Bot Defense', category: 'Security', extractor: (o) => (o?.spec?.disable_bot_defense !== undefined) ? 'Disabled' : (o?.spec?.bot_defense?.policy?.name || 'Enabled') },
  { id: 'ip_reputation', label: 'IP Reputation', category: 'Security', extractor: (o) => o?.spec?.enable_ip_reputation ? 'Enabled' : 'Disabled' },
  { id: 'api_discovery', label: 'API Discovery', category: 'Security', extractor: (o) => (o?.spec?.disable_api_discovery !== undefined) ? 'Disabled' : (o?.spec?.enable_api_discovery ? 'Enabled' : 'Default') },
  { id: 'api_testing', label: 'API Testing', category: 'Security', extractor: (o) => (o?.spec?.disable_api_testing !== undefined) ? 'Disabled' : 'Enabled' },
  { id: 'api_definition', label: 'API Definition', category: 'Security', extractor: (o) => (o?.spec?.disable_api_definition !== undefined) ? 'Disabled' : 'Enabled' },
  { id: 'malicious_user_detection', label: 'Malicious User Detection', category: 'Security', extractor: (o) => (o?.spec?.disable_malicious_user_detection !== undefined) ? 'Disabled' : (o?.spec?.enable_malicious_user_detection ? 'Enabled' : 'Default') },
  { id: 'ddos_detection', label: 'DDoS Detection', category: 'Security', extractor: (o) => o?.spec?.enable_ddos_detection ? 'Enabled' : 'Disabled' },
  { id: 'l7_ddos_protection', label: 'L7 DDoS Protection', category: 'Security', extractor: (o) => o?.spec?.l7_ddos_protection ? 'Enabled' : 'Disabled' },
  { id: 'rate_limit', label: 'Rate Limiting', category: 'Security', extractor: (o) => (o?.spec?.disable_rate_limit !== undefined) ? 'Disabled' : 'Enabled' },
  { id: 'malware_protection', label: 'Malware Protection', category: 'Security', extractor: (o) => (o?.spec?.disable_malware_protection !== undefined) ? 'Disabled' : 'Enabled' },
  { id: 'threat_mesh', label: 'Threat Mesh', category: 'Security', extractor: (o) => (o?.spec?.enable_threat_mesh !== undefined) ? 'Enabled' : 'Disabled' },
  { id: 'service_policies', label: 'Service Policies', category: 'Security', extractor: (o) => { const p = o?.spec?.active_service_policies?.policies; return p?.length ? p.map((x: any) => x.name).join(', ') : 'None'; } },
  { id: 'user_identification', label: 'User Identification', category: 'Security', extractor: (o) => o?.spec?.user_identification?.name || 'None' },
  { id: 'client_side_defense', label: 'Client-Side Defense', category: 'Security', extractor: (o) => (o?.spec?.disable_client_side_defense !== undefined) ? 'Disabled' : (o?.spec?.client_side_defense?.policy?.name || 'Enabled') },
  { id: 'challenge_type', label: 'Challenge Type', category: 'Security', extractor: (o) => { if (o?.spec?.no_challenge !== undefined) return 'None'; if (o?.spec?.policy_based_challenge) return 'Policy-Based'; if (o?.spec?.js_challenge) return 'JS Challenge'; if (o?.spec?.captcha_challenge) return 'Captcha'; if (o?.spec?.enable_challenge) return 'Default Challenge'; return 'None'; } },
  { id: 'cors_policy', label: 'CORS Policy', category: 'Security', extractor: (o) => { const c = o?.spec?.cors_policy; return (!c || c?.disabled) ? 'Disabled' : `Origins: ${c.allow_origin?.join(', ') || 'Any'}`; } },
  { id: 'csrf_policy', label: 'CSRF Policy', category: 'Security', extractor: (o) => (!o?.spec?.csrf_policy || o?.spec?.csrf_policy?.disabled) ? 'Disabled' : 'Enabled' },
  { id: 'trusted_clients_count', label: 'Trusted Clients', category: 'Security', extractor: (o) => String(o?.spec?.trusted_clients?.length || 0) },
  { id: 'blocked_clients_count', label: 'Blocked Clients', category: 'Security', extractor: (o) => String(o?.spec?.blocked_clients?.length || 0) },

  // Performance
  { id: 'idle_timeout', label: 'HTTP Idle Timeout', category: 'Performance', extractor: (o) => { const t = o?.spec?.idle_timeout || o?.spec?.more_option?.idle_timeout; return t ? `${t}ms` : 'Default'; } },
  { id: 'max_request_header_size', label: 'Max Req Header Size', category: 'Performance', extractor: (o) => { const s = o?.spec?.max_request_header_size || o?.spec?.more_option?.max_request_header_size; return s ? `${s} bytes` : 'Default'; } },
  { id: 'compression', label: 'Auto Compression', category: 'Performance', extractor: (o) => getBoolFlag(o?.spec?.enable_automatic_compression) },
  { id: 'websocket', label: 'WebSocket', category: 'Performance', extractor: (o) => getBoolFlag(o?.spec?.enable_websocket) },
  { id: 'lb_algorithm', label: 'LB Algorithm', category: 'Performance', extractor: (o) => { const s = o?.spec; if (s?.round_robin !== undefined) return 'Round Robin'; if (s?.least_active !== undefined) return 'Least Active'; if (s?.ring_hash !== undefined) return 'Ring Hash'; if (s?.random !== undefined) return 'Random'; if (s?.source_ip_stickiness !== undefined) return 'Source IP Stickiness'; return 'Round Robin (Default)'; } },
  { id: 'buffer_policy', label: 'Buffer Policy', category: 'Performance', extractor: (o) => { const b = o?.spec?.more_option?.buffer_policy; return (!b || b?.disabled !== false) ? 'Disabled/Default' : `Max Req: ${b?.max_request_bytes}B`; } },
  { id: 'custom_errors', label: 'Custom Error Pages', category: 'Performance', extractor: (o) => { const errs = o?.spec?.more_option?.custom_errors; return errs && Object.keys(errs).length > 0 ? Object.keys(errs).join(', ') : 'None'; } },

  // Routes & Origins
  { id: 'routes_count', label: 'Routes Count', category: 'Routes & Origins', extractor: (o) => String(o?.spec?.routes?.length || 0) },
  { id: 'default_pools', label: 'Default Origin Pools', category: 'Routes & Origins', extractor: (o) => { const p = o?.spec?.default_route_pools; return p?.length ? p.map((x: any) => x.pool?.name).filter(Boolean).join(', ') : 'None'; } },

  // Headers
  { id: 'trust_client_ip', label: 'Trust Client IP Headers', category: 'Headers', extractor: (o) => o?.spec?.enable_trust_client_ip_headers?.client_ip_headers?.join(', ') || 'Disabled' },
  { id: 'request_headers_add_count', label: 'Req Headers to Add', category: 'Headers', extractor: (o) => String((o?.spec?.request_headers_to_add?.length || 0) + (o?.spec?.more_option?.request_headers_to_add?.length || 0)) },
  { id: 'response_headers_add_count', label: 'Resp Headers to Add', category: 'Headers', extractor: (o) => String((o?.spec?.response_headers_to_add?.length || 0) + (o?.spec?.more_option?.response_headers_to_add?.length || 0)) },
  { id: 'waf_exclusions_count', label: 'WAF Exclusion Rules', category: 'Headers', extractor: (o) => { const inline = o?.spec?.waf_exclusion?.waf_exclusion_inline_rules?.rules?.length || 0; const refs = o?.spec?.waf_exclusion_rules?.length || 0; return String(inline + refs); } },
  { id: 'data_guard_rules_count', label: 'Data Guard Rules', category: 'Headers', extractor: (o) => String(o?.spec?.data_guard_rules?.length || 0) },
  { id: 'protected_cookies_count', label: 'Protected Cookies', category: 'Headers', extractor: (o) => String(o?.spec?.protected_cookies?.length || 0) },
];

const CDN_LB_PROPERTIES: PropertyDef[] = [
  // General
  { id: 'domains', label: 'Domains', category: 'General', extractor: (o) => o?.spec?.domains?.join(', ') || 'None' },
  { id: 'service_domain', label: 'Service Domain / CNAME', category: 'General', extractor: (o) => o?.spec?.service_domains?.map((d: any) => d.service_domain).join(', ') || 'N/A' },
  { id: 'dns_ips', label: 'DNS / VIP IPs', category: 'General', extractor: (o) => o?.spec?.dns_info?.map((d: any) => d.ip_address).join(', ') || 'N/A' },
  { id: 'labels', label: 'Labels', category: 'General', extractor: getLabels },
  { id: 'description', label: 'Description', category: 'General', extractor: (o) => o?.metadata?.description || o?.metadata?.annotations?.description || 'N/A' },
  { id: 'lb_type', label: 'CDN Type', category: 'General', extractor: (o) => getLBType(o?.spec) },
  { id: 'creation_date', label: 'Creation Date', category: 'General', extractor: (o) => o?.system_metadata?.creation_timestamp ? new Date(o.system_metadata.creation_timestamp).toLocaleDateString() : 'N/A' },
  { id: 'disabled', label: 'Disabled', category: 'General', extractor: (o) => o?.metadata?.disable ? 'Yes' : 'No' },
  
  // Status
  { id: 'vh_state', label: 'Virtual Host State', category: 'Status', extractor: (o) => o?.spec?.state || 'N/A' },
  { id: 'cert_state', label: 'Certificate State', category: 'Status', extractor: (o) => o?.spec?.cert_state || 'N/A' },
  { id: 'auto_cert_state', label: 'Auto Cert State', category: 'Status', extractor: (o) => o?.spec?.auto_cert_info?.auto_cert_state || 'N/A' },

  // Caching
  { id: 'default_cache_ttl', label: 'Default Cache TTL', category: 'Caching', extractor: (o) => o?.spec?.default_cache_action?.cache_ttl_override || 'Default' },
  { id: 'cache_rules_count', label: 'Cache Rules Count', category: 'Caching', extractor: (o) => String(o?.spec?.cache_rules?.length || 0) },
  { id: 'custom_cache_rules', label: 'Custom Cache Rules Count', category: 'Caching', extractor: (o) => String(o?.spec?.custom_cache_rule?.cdn_cache_rules?.length || 0) },

  // Origin
  { id: 'origin_pool', label: 'Origin Pool', category: 'Origin', extractor: (o) => o?.spec?.origin_pool?.pool?.name || 'Inline / Custom' },
  { id: 'origin_dns', label: 'Origin Public DNS', category: 'Origin', extractor: (o) => o?.spec?.origin_pool?.public_name?.dns_name || 'N/A' },
  { id: 'origin_request_timeout', label: 'Origin Request Timeout', category: 'Origin', extractor: (o) => o?.spec?.origin_pool?.origin_request_timeout || 'Default' },
  
  // TLS/SSL
  { id: 'http_redirect', label: 'HTTP→HTTPS Redirect', category: 'TLS/SSL', extractor: (o) => getBoolFlag(o?.spec?.https?.http_redirect || o?.spec?.http_redirect) },
  { id: 'hsts', label: 'HSTS Header', category: 'TLS/SSL', extractor: (o) => getBoolFlag(o?.spec?.https?.add_hsts || o?.spec?.add_hsts) },
  { id: 'tls_min_version', label: 'TLS Min Version', category: 'TLS/SSL', extractor: (o) => getTLSMinVersion(o?.spec) },

  // Security
  { id: 'waf_policy', label: 'WAF Policy', category: 'Security', extractor: (o) => (o?.spec?.disable_waf !== undefined) ? 'Disabled' : (o?.spec?.app_firewall?.name || 'Enabled') },
  { id: 'bot_defense', label: 'Bot Defense', category: 'Security', extractor: (o) => (o?.spec?.disable_bot_defense !== undefined) ? 'Disabled' : 'Enabled' },
  { id: 'ip_reputation', label: 'IP Reputation', category: 'Security', extractor: (o) => (o?.spec?.disable_ip_reputation !== undefined) ? 'Disabled' : 'Enabled' },
  { id: 'api_discovery', label: 'API Discovery', category: 'Security', extractor: (o) => (o?.spec?.disable_api_discovery !== undefined) ? 'Disabled' : 'Enabled' },
  { id: 'api_definition', label: 'API Definition', category: 'Security', extractor: (o) => (o?.spec?.disable_api_definition !== undefined) ? 'Disabled' : 'Enabled' },
  { id: 'malicious_user_detection', label: 'Malicious User Detection', category: 'Security', extractor: (o) => (o?.spec?.disable_malicious_user_detection !== undefined) ? 'Disabled' : 'Enabled' },
  { id: 'l7_ddos_protection', label: 'L7 DDoS Protection', category: 'Security', extractor: (o) => (o?.spec?.l7_ddos_action_default !== undefined) ? 'Default' : 'Custom' },
  { id: 'rate_limit', label: 'Rate Limiting', category: 'Security', extractor: (o) => (o?.spec?.disable_rate_limit !== undefined) ? 'Disabled' : 'Enabled' },
  { id: 'threat_mesh', label: 'Threat Mesh', category: 'Security', extractor: (o) => (o?.spec?.enable_threat_mesh !== undefined) ? 'Enabled' : 'Disabled' },
  { id: 'service_policies', label: 'Service Policies', category: 'Security', extractor: (o) => (o?.spec?.no_service_policies !== undefined) ? 'None' : 'Enabled' },
  { id: 'client_side_defense', label: 'Client-Side Defense', category: 'Security', extractor: (o) => (o?.spec?.disable_client_side_defense !== undefined) ? 'Disabled' : 'Enabled' },

  // Headers
  { id: 'request_headers_add_count', label: 'Req Headers to Add', category: 'Headers', extractor: (o) => String(o?.spec?.other_settings?.header_options?.request_headers_to_add?.length || 0) },
  { id: 'request_headers_remove_count', label: 'Req Headers to Remove', category: 'Headers', extractor: (o) => String(o?.spec?.other_settings?.header_options?.request_headers_to_remove?.length || 0) },
  { id: 'response_headers_add_count', label: 'Resp Headers to Add', category: 'Headers', extractor: (o) => String(o?.spec?.other_settings?.header_options?.response_headers_to_add?.length || 0) },
  { id: 'response_headers_remove_count', label: 'Resp Headers to Remove', category: 'Headers', extractor: (o) => String(o?.spec?.other_settings?.header_options?.response_headers_to_remove?.length || 0) },
];

const ORIGIN_POOL_PROPERTIES: PropertyDef[] = [
  { id: 'labels', label: 'Labels', category: 'General', extractor: getLabels },
  { id: 'port', label: 'Port', category: 'General', extractor: (o) => String(o?.spec?.port || 'N/A') },
  { id: 'origin_server_count', label: 'Origin Servers Count', category: 'General', extractor: (o) => String(o?.spec?.origin_servers?.length || 0) },
  { id: 'origin_servers', label: 'Origin Servers', category: 'General', extractor: (o) => { const s = o?.spec?.origin_servers || []; return s.map((x: any) => { if (x.public_ip) return `IP: ${x.public_ip.ip}`; if (x.public_name) return `DNS: ${x.public_name.dns_name}`; if (x.private_ip) return `Priv: ${x.private_ip.ip}`; if (x.private_name) return `PrivDNS: ${x.private_name.dns_name}`; if (x.k8s_service) return `K8s: ${x.k8s_service.service_name}`; return 'Unknown'; }).join(', ') || 'None'; } },
  { id: 'tls_to_origin', label: 'TLS to Origin', category: 'TLS/SSL', extractor: (o) => (o?.spec?.no_tls !== undefined) ? 'No TLS' : (o?.spec?.use_tls ? 'Enabled' : 'No TLS') },
  { id: 'sni', label: 'SNI', category: 'TLS/SSL', extractor: (o) => { const t = o?.spec?.use_tls; if (!t || typeof t !== 'object') return 'N/A'; return t.sni || (t.use_host_header_as_sni !== undefined ? 'Host Header' : 'N/A'); } },
  { id: 'lb_algorithm', label: 'LB Algorithm', category: 'Performance', extractor: (o) => o?.spec?.loadbalancer_algorithm || 'Default' },
  { id: 'healthcheck', label: 'Health Checks', category: 'Performance', extractor: (o) => { const h = o?.spec?.healthcheck; return h?.length ? h.map((x: any) => x.name).join(', ') : 'None'; } },
  { id: 'endpoint_selection', label: 'Endpoint Selection', category: 'Performance', extractor: (o) => o?.spec?.endpoint_selection || 'Default' },
  { id: 'connection_timeout', label: 'Connection Timeout', category: 'Performance', extractor: (o) => { const t = o?.spec?.advanced_options?.connection_timeout; return t ? `${t}ms` : 'Default'; } },
  { id: 'http_idle_timeout', label: 'HTTP Idle Timeout', category: 'Performance', extractor: (o) => { const t = o?.spec?.advanced_options?.http_idle_timeout; return t ? `${t}ms` : 'Default'; } },
  { id: 'circuit_breaker', label: 'Circuit Breaker', category: 'Performance', extractor: (o) => { if (o?.spec?.advanced_options?.default_circuit_breaker !== undefined) return 'Default'; if (o?.spec?.advanced_options?.circuit_breaker) return 'Custom'; return 'None'; } },
  { id: 'outlier_detection', label: 'Outlier Detection', category: 'Performance', extractor: (o) => { if (o?.spec?.advanced_options?.disable_outlier_detection !== undefined) return 'Disabled'; if (o?.spec?.advanced_options?.outlier_detection) return 'Enabled'; return 'Default'; } },
];

const WAF_POLICY_PROPERTIES: PropertyDef[] = [
  // General
  { id: 'labels', label: 'Labels', category: 'General', extractor: getLabels },
  { id: 'disabled', label: 'Disabled', category: 'General', extractor: (o) => o?.metadata?.disable ? 'Yes' : 'No' },
  
  // Detection Settings
  { id: 'waf_mode', label: 'WAF Mode', category: 'Security', extractor: (o) => getWafMode(o?.spec) },
  { id: 'signature_accuracy', label: 'Signature Accuracy', category: 'Security', extractor: (o) => { const s = o?.spec?.detection_settings?.signature_selection_setting; if (s?.high_medium_low_accuracy_signatures !== undefined) return 'High+Medium+Low'; if (s?.high_medium_accuracy_signatures !== undefined) return 'High+Medium'; if (s?.only_high_accuracy_signatures !== undefined) return 'High Only'; return 'Default'; } },
  { id: 'detection_disabled_types', label: 'Disabled Attack Types', category: 'Security', extractor: (o) => { const t = o?.spec?.detection_settings?.signature_selection_setting?.attack_type_settings?.disabled_attack_types; return t?.length ? `${t.length} Types Disabled` : 'None'; } },
  { id: 'disabled_violations', label: 'Disabled Violations', category: 'Security', extractor: (o) => { const v = o?.spec?.detection_settings?.violation_settings?.disabled_violation_types; return v?.length ? `${v.length} Violations Disabled` : 'None'; } },
  { id: 'staging', label: 'Signature Staging', category: 'Security', extractor: (o) => { if (o?.spec?.detection_settings?.disable_staging !== undefined) return 'Disabled'; const s = o?.spec?.detection_settings?.stage_new_signatures?.staging_period; return s !== undefined ? `${s} Days` : 'Default'; } },
  { id: 'threat_campaigns', label: 'Threat Campaigns', category: 'Security', extractor: (o) => o?.spec?.detection_settings?.enable_threat_campaigns !== undefined ? 'Enabled' : 'Disabled' },
  { id: 'suppression', label: 'Suppression', category: 'Security', extractor: (o) => o?.spec?.detection_settings?.enable_suppression !== undefined ? 'Enabled' : 'Disabled' },
  { id: 'bot_protection', label: 'Bot Protection', category: 'Security', extractor: (o) => { const b = o?.spec?.bot_protection_setting || o?.spec?.detection_settings?.bot_protection_setting; if (!b) return 'Default'; return `Malicious:${b.malicious_bot_action || 'N/A'}, Suspicious:${b.suspicious_bot_action || 'N/A'}, Good:${b.good_bot_action || 'N/A'}`; } },
  
  // Actions & Responses
  { id: 'allowed_response_codes', label: 'Allowed Response Codes', category: 'Actions', extractor: (o) => { if (o?.spec?.allow_all_response_codes !== undefined) return 'All'; const c = o?.spec?.allowed_response_codes?.response_code; return c?.length ? `${c.length} Codes` : 'Default'; } },
  { id: 'blocking_page', label: 'Blocking Page', category: 'Actions', extractor: (o) => (o?.spec?.use_default_blocking_page !== undefined) ? 'Default' : (o?.spec?.blocking_page ? 'Custom' : 'Default') },
];

const TCP_LB_PROPERTIES: PropertyDef[] = [
  { id: 'labels', label: 'Labels', category: 'General', extractor: getLabels },
  { id: 'listen_port', label: 'Listen Port', category: 'General', extractor: (o) => String(o?.spec?.listen_port || o?.spec?.advertise_on_public?.port || 'N/A') },
  { id: 'disabled', label: 'Disabled', category: 'General', extractor: (o) => o?.metadata?.disable ? 'Yes' : 'No' },
  { id: 'creation_date', label: 'Creation Date', category: 'General', extractor: (o) => o?.system_metadata?.creation_timestamp ? new Date(o.system_metadata.creation_timestamp).toLocaleDateString() : 'N/A' },
  { id: 'origin_pools', label: 'Origin Pools', category: 'Origins', extractor: (o) => { const p = o?.spec?.origin_pools || o?.spec?.origin_pools_weights; return p?.length ? p.map((x: any) => x.pool?.name || x.name).filter(Boolean).join(', ') : 'None'; } },
  { id: 'advertise_type', label: 'Advertise Policy', category: 'General', extractor: (o) => getAdvertiseType(o?.spec) },
  { id: 'idle_timeout', label: 'Idle Timeout', category: 'Performance', extractor: (o) => o?.spec?.idle_timeout ? `${o.spec.idle_timeout}ms` : 'Default' },
];

// ═══════════════════════════════════════════════════════════════════════════
// OBJECT TYPE REGISTRY
// ═══════════════════════════════════════════════════════════════════════════

const OBJECT_TYPES: ObjectTypeInfo[] = [
  { id: 'http_loadbalancer', label: 'HTTP Load Balancer', apiListPath: (ns) => `/api/config/namespaces/${ns}/http_loadbalancers`, apiGetPath: (ns, n) => `/api/config/namespaces/${ns}/http_loadbalancers/${n}`, icon: Globe, properties: HTTP_LB_PROPERTIES },
  { id: 'cdn_loadbalancer', label: 'CDN Load Balancer', apiListPath: (ns) => `/api/config/namespaces/${ns}/cdn_loadbalancers`, apiGetPath: (ns, n) => `/api/config/namespaces/${ns}/cdn_loadbalancers/${n}`, icon: Globe, properties: CDN_LB_PROPERTIES },
  { id: 'origin_pool', label: 'Origin Pool', apiListPath: (ns) => `/api/config/namespaces/${ns}/origin_pools`, apiGetPath: (ns, n) => `/api/config/namespaces/${ns}/origin_pools/${n}`, icon: Server, properties: ORIGIN_POOL_PROPERTIES },
  { id: 'app_firewall', label: 'App Firewall (WAF)', apiListPath: (ns) => `/api/config/namespaces/${ns}/app_firewalls`, apiGetPath: (ns, n) => `/api/config/namespaces/${ns}/app_firewalls/${n}`, icon: Shield, properties: WAF_POLICY_PROPERTIES },
  { id: 'tcp_loadbalancer', label: 'TCP Load Balancer', apiListPath: (ns) => `/api/config/namespaces/${ns}/tcp_loadbalancers`, apiGetPath: (ns, n) => `/api/config/namespaces/${ns}/tcp_loadbalancers/${n}`, icon: Server, properties: TCP_LB_PROPERTIES },
];

// ═══════════════════════════════════════════════════════════════════════════
// VALUE BADGE — semantic color-coded pill
// ═══════════════════════════════════════════════════════════════════════════

function ValueBadge({ value, compact, onClick }: { value: string; compact?: boolean; onClick?: () => void }) {
  const lower = value.toLowerCase();
  let cls = 'bg-slate-700/60 text-slate-300';
  if (lower === 'enabled' || lower === 'blocking' || lower === 'yes' || lower === 'custom' || lower === 'all') cls = 'bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/20';
  else if (lower === 'disabled' || lower === 'none' || lower === 'no') cls = 'bg-slate-700/40 text-slate-500';
  else if (lower === 'n/a' || lower === '0' || lower === 'disabled/default') cls = 'bg-slate-700/30 text-slate-600';
  else if (lower === 'monitoring') cls = 'bg-amber-500/15 text-amber-400 ring-1 ring-amber-500/20';
  else if (lower.startsWith('\u26a0')) cls = 'bg-red-500/15 text-red-400 ring-1 ring-red-500/20';
  else if (lower.includes('default')) cls = 'bg-slate-600/40 text-slate-400';
  else if (/^\d/.test(value)) cls = 'bg-blue-500/10 text-blue-300 ring-1 ring-blue-500/15';
  else if (value.includes('.') || value.includes('://')) cls = 'bg-cyan-500/10 text-cyan-300 ring-1 ring-cyan-500/20 font-mono'; 
  
  const display = value.length > 60 ? value.substring(0, 57) + '...' : value;
  
  return (
    <span 
      onClick={onClick}
      className={`inline-block px-2 py-0.5 rounded-md text-xs font-medium ${cls} ${compact ? '' : 'max-w-[320px]'} truncate ${onClick ? 'cursor-pointer hover:brightness-110 active:scale-95 transition-all' : ''}`} 
      title={value}
    >
      {display}
    </span>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════════════════════════

export function PropertyViewer() {
  const { isConnected } = useApp();
  const navigate = useNavigate();
  const toast = useToast();
  const [step, setStep] = useState<Step>(1);

  // Step 1
  const [selectedObjectType, setSelectedObjectType] = useState<ObjectType>('http_loadbalancer');
  const [selectedProperties, setSelectedProperties] = useState<string[]>([]);
  const [propertySearch, setPropertySearch] = useState('');

  // Step 2
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [selectedNs, setSelectedNs] = useState<string[]>([]);
  const [isLoadingNs, setIsLoadingNs] = useState(true);
  const [nsSearch, setNsSearch] = useState('');

  // Step 3
  const [rows, setRows] = useState<ResultRow[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressText, setProgressText] = useState('');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<string>('namespace');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [viewMode, setViewMode] = useState<ViewMode>('table');
  const [showDistribution, setShowDistribution] = useState(false);
  
  // Selection & Raw JSON View
  const [selectedRowIds, setSelectedRowIds] = useState<Set<string>>(new Set());
  const [selectedRawData, setSelectedRawData] = useState<any | null>(null);
  
  const cancelledRef = useRef(false);

  const currentType = OBJECT_TYPES.find(t => t.id === selectedObjectType)!;
  const selectedPropertyDefs = currentType.properties.filter(p => selectedProperties.includes(p.id));

  useEffect(() => { if (!isConnected) { navigate('/'); return; } loadNamespaces(); }, [isConnected, navigate]);

  const loadNamespaces = async () => {
    setIsLoadingNs(true);
    try { const r = await apiClient.getNamespaces(); setNamespaces(r.items.sort((a, b) => a.name.localeCompare(b.name))); }
    catch { toast.error('Failed to load namespaces'); }
    finally { setIsLoadingNs(false); }
  };

  const logEntry = useCallback((msg: string, type: LogEntry['type'] = 'info') => {
    setLogs(prev => [...prev, { time: new Date().toLocaleTimeString(), message: msg, type }]);
  }, []);

  const toggleProp = (id: string) => setSelectedProperties(prev => prev.includes(id) ? prev.filter(p => p !== id) : [...prev, id]);
  const toggleNs = (ns: string) => setSelectedNs(prev => prev.includes(ns) ? prev.filter(n => n !== ns) : [...prev, ns]);

  const filteredNamespaces = namespaces.filter(ns => ns.name.toLowerCase().includes(nsSearch.toLowerCase()));

  const selectAllNs = () => { const f = filteredNamespaces.map(n => n.name); setSelectedNs(prev => Array.from(new Set([...prev, ...f]))); };
  const deselectAllNs = () => { if (nsSearch) { const f = new Set(filteredNamespaces.map(n => n.name)); setSelectedNs(prev => prev.filter(n => !f.has(n))); } else setSelectedNs([]); };

  const groupedProperties = currentType.properties.reduce<Record<string, PropertyDef[]>>((a, p) => { if (!a[p.category]) a[p.category] = []; a[p.category].push(p); return a; }, {});
  const filteredGroupedProperties = propertySearch
    ? currentType.properties.filter(p => p.label.toLowerCase().includes(propertySearch.toLowerCase()) || p.category.toLowerCase().includes(propertySearch.toLowerCase())).reduce<Record<string, PropertyDef[]>>((a, p) => { if (!a[p.category]) a[p.category] = []; a[p.category].push(p); return a; }, {})
    : groupedProperties;

  const selectAllProps = () => { const ids = Object.values(filteredGroupedProperties).flat().map(p => p.id); setSelectedProperties(prev => Array.from(new Set([...prev, ...ids]))); };
  const deselectAllProps = () => { if (propertySearch) { const f = new Set(Object.values(filteredGroupedProperties).flat().map(p => p.id)); setSelectedProperties(prev => prev.filter(id => !f.has(id))); } else setSelectedProperties([]); };

  // ─── Scan ──────────────────────────────────────────────────────────
  const startScan = async () => {
    if (selectedProperties.length === 0 || selectedNs.length === 0) return;
    const propDefs = currentType.properties.filter(p => selectedProperties.includes(p.id));
    setStep(3); setIsScanning(true); setRows([]); setLogs([]); setProgress(0); cancelledRef.current = false;
    setSelectedRowIds(new Set());

    const allRows: ResultRow[] = [];
    const fetchedKeys = new Set<string>(); // Tracks uniqueness so we don't fetch shared objects multiple times
    
    let processedNs = 0;
    logEntry(`Scanning ${propDefs.length} properties across ${selectedNs.length} namespace(s) for ${currentType.label}`, 'info');

    for (const ns of selectedNs) {
      if (cancelledRef.current) break;
      processedNs++;
      setProgress(Math.round((processedNs / selectedNs.length) * 100));
      setProgressText(`Scanning: ${ns}`);
      try {
        logEntry(`Listing ${currentType.label}s in ${ns}...`, 'fetch');
        const listResp: any = await apiClient.get(currentType.apiListPath(ns));
        const items: any[] = listResp?.items || [];
        if (!items.length) { logEntry(`No objects in ${ns}`, 'warning'); continue; }
        logEntry(`Found ${items.length} in ${ns}`, 'success');
        
        for (const item of items) {
          if (cancelledRef.current) break;
          const name = item.name || item.metadata?.name;
          
          // CRITICAL FIX: Extract the actual namespace where the object resides.
          // Because 'shared' objects appear in the list response of specific namespaces.
          const actualNs = item.namespace || item.tenant_string || item.metadata?.namespace || ns; 
          
          if (!name) continue;

          // Prevent duplicate fetches if multiple namespaces list the same shared object
          const uniqueKey = `${actualNs}::${name}`;
          if (fetchedKeys.has(uniqueKey)) continue;
          fetchedKeys.add(uniqueKey);

          try {
            logEntry(`Fetching ${name} (from ${actualNs})...`, 'fetch');
            const obj: any = await apiClient.get(currentType.apiGetPath(actualNs, name));
            const values: Record<string, string> = {};
            for (const pd of propDefs) values[pd.id] = String(pd.extractor(obj));
            allRows.push({ namespace: actualNs, objectName: name, values, rawData: obj });
          } catch (e) {
            logEntry(`Failed: ${name} in ${actualNs}`, 'error');
            const values: Record<string, string> = {};
            for (const pd of propDefs) values[pd.id] = '\u26a0 Error';
            allRows.push({ namespace: actualNs, objectName: name, values, error: true });
          }
        }
      } catch { logEntry(`Failed to list in ${ns}`, 'error'); }
    }
    setRows(allRows); setIsScanning(false);
    logEntry(`Done. ${allRows.length} object(s) found.`, 'success');
    if (!cancelledRef.current) toast.success(`Found ${allRows.length} results`);
  };

  const cancelScan = () => { cancelledRef.current = true; setIsScanning(false); logEntry('Cancelled', 'warning'); };

  // ─── Filter & sort ─────────────────────────────────────────────────
  const filteredRows = rows.filter(r => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return r.namespace.toLowerCase().includes(q) || r.objectName.toLowerCase().includes(q) || Object.values(r.values).some(v => v.toLowerCase().includes(q));
  });
  const sortedRows = [...filteredRows].sort((a, b) => {
    let c = 0;
    if (sortBy === 'namespace') c = a.namespace.localeCompare(b.namespace) || a.objectName.localeCompare(b.objectName);
    else if (sortBy === 'name') c = a.objectName.localeCompare(b.objectName);
    else c = (a.values[sortBy] || '').localeCompare(b.values[sortBy] || '');
    return sortDir === 'asc' ? c : -c;
  });

  const getDistribution = (pid: string) => {
    const c: Record<string, number> = {};
    rows.forEach(r => { const v = r.values[pid] || 'N/A'; c[v] = (c[v] || 0) + 1; });
    return Object.entries(c).sort((a, b) => b[1] - a[1]);
  };

  // ─── Selection Logic ────────────────────────────────────────────────
  const getRowId = (r: ResultRow) => `${r.namespace}::${r.objectName}`;
  
  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      const newIds = new Set(selectedRowIds);
      sortedRows.forEach(r => newIds.add(getRowId(r)));
      setSelectedRowIds(newIds);
    } else {
      const newIds = new Set(selectedRowIds);
      sortedRows.forEach(r => newIds.delete(getRowId(r)));
      setSelectedRowIds(newIds);
    }
  };

  const toggleRowSelection = (id: string) => {
    const newIds = new Set(selectedRowIds);
    if (newIds.has(id)) newIds.delete(id);
    else newIds.add(id);
    setSelectedRowIds(newIds);
  };

  const allCurrentSelected = sortedRows.length > 0 && sortedRows.every(r => selectedRowIds.has(getRowId(r)));
  const someCurrentSelected = sortedRows.some(r => selectedRowIds.has(getRowId(r)));

  const getRowsToExport = () => {
    // If user selected rows, only export those. Otherwise export the current filtered view.
    return selectedRowIds.size > 0 
      ? sortedRows.filter(r => selectedRowIds.has(getRowId(r))) 
      : sortedRows;
  };

  // ─── Exports ───────────────────────────────────────────────────────
  const esc = (v: string) => (v.includes(',') || v.includes('"') || v.includes('\n')) ? `"${v.replace(/"/g, '""')}"` : v;

  const exportCsv = () => {
    const targetRows = getRowsToExport();
    if (!targetRows.length) { toast.warning('No data to export'); return; }
    const cols = ['Namespace', currentType.label, ...selectedPropertyDefs.map(p => p.label)];
    const lines = [cols.map(esc).join(','), ...targetRows.map(r => [r.namespace, r.objectName, ...selectedPropertyDefs.map(p => r.values[p.id] || '')].map(esc).join(','))];
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const u = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = u; a.download = `property-report-${selectedRowIds.size > 0 ? 'selected' : 'all'}.csv`; a.click(); URL.revokeObjectURL(u);
    toast.success('CSV exported');
  };

  const exportExcel = () => {
    const targetRows = getRowsToExport();
    if (!targetRows.length) { toast.warning('No data to export'); return; }
    const hdr = ['Namespace', currentType.label, ...selectedPropertyDefs.map(p => p.label)].map(h => `<Cell><Data ss:Type="String">${h}</Data></Cell>`).join('');
    let trs = `<Row>${hdr}</Row>`;
    targetRows.forEach(r => { const cells = [r.namespace, r.objectName, ...selectedPropertyDefs.map(p => r.values[p.id] || '')].map(v => `<Cell><Data ss:Type="String">${v.replace(/&/g, '&amp;').replace(/</g, '&lt;')}</Data></Cell>`).join(''); trs += `<Row>${cells}</Row>`; });
    const xml = `<?xml version="1.0"?><?mso-application progid="Excel.Sheet"?><Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"><Worksheet ss:Name="Report"><Table>${trs}</Table></Worksheet></Workbook>`;
    const blob = new Blob([xml], { type: 'application/vnd.ms-excel' }); const u = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = u; a.download = `property-report-${selectedRowIds.size > 0 ? 'selected' : 'all'}.xls`; a.click(); URL.revokeObjectURL(u);
    toast.success('Excel exported');
  };

  const exportJson = () => {
    const targetRows = getRowsToExport();
    if (!targetRows.length) { toast.warning('No data to export'); return; }
    const rpt = { generated_at: new Date().toISOString(), tool: 'Property Viewer', object_type: currentType.label, properties: selectedPropertyDefs.map(p => p.label), summary: { total: targetRows.length, namespaces: Array.from(new Set(targetRows.map(r=>r.namespace))).length }, results: targetRows.map(r => ({ namespace: r.namespace, name: r.objectName, ...r.values })) };
    const blob = new Blob([JSON.stringify(rpt, null, 2)], { type: 'application/json' }); const u = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = u; a.download = `property-report-${selectedRowIds.size > 0 ? 'selected' : 'all'}.json`; a.click(); URL.revokeObjectURL(u);
    toast.success('JSON exported');
  };

  const copyTable = () => {
    const targetRows = getRowsToExport();
    if (!targetRows.length) return;
    const cols = ['Namespace', currentType.label, ...selectedPropertyDefs.map(p => p.label)];
    const lines = [cols.join('\t'), ...targetRows.map(r => [r.namespace, r.objectName, ...selectedPropertyDefs.map(p => r.values[p.id] || '')].join('\t'))];
    navigator.clipboard.writeText(lines.join('\n')).then(() => toast.success('Copied')).catch(() => toast.error('Failed'));
  };

  const toggleSort = (col: string) => { if (sortBy === col) setSortDir(p => p === 'asc' ? 'desc' : 'asc'); else { setSortBy(col); setSortDir('asc'); } };

  // ═══════════════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════════════
  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header */}
      <div className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-[1440px] mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link to="/" className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"><ArrowLeft className="w-5 h-5" /></Link>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-cyan-500/15 rounded-xl flex items-center justify-center text-cyan-400"><Layers className="w-5 h-5" /></div>
              <div>
                <h1 className="text-lg font-bold text-slate-100">Property Viewer</h1>
                <p className="text-xs text-slate-500">Compare properties across all config objects</p>
              </div>
            </div>
            <Link to="/explainer/property-viewer" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
              <HelpCircle className="w-3.5 h-3.5" /> How does this work?
            </Link>
          </div>
          <div className="flex items-center gap-2">
            {[1, 2, 3].map(s => (
              <div key={s} className="flex items-center">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold transition-colors ${step > s ? 'bg-emerald-500 text-white' : step === s ? 'bg-blue-500 text-white' : 'bg-slate-700 text-slate-400'}`}>
                  {step > s ? <Check className="w-4 h-4" /> : s}
                </div>
                {s < 3 && <div className={`w-8 h-0.5 ${step > s ? 'bg-emerald-500' : 'bg-slate-700'}`} />}
              </div>
            ))}
          </div>
        </div>
      </div>

      <main className="max-w-[1440px] mx-auto px-6 py-8">

        {/* ═══ STEP 1 ═══ */}
        {step === 1 && (
          <div className="space-y-6">
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <h2 className="text-lg font-semibold text-slate-100 mb-1">Select Object Type</h2>
              <p className="text-sm text-slate-400 mb-6">Choose the type of configuration object to inspect</p>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
                {OBJECT_TYPES.map(ot => {
                  const Icon = ot.icon;
                  return (
                    <button key={ot.id} onClick={() => { setSelectedObjectType(ot.id); setSelectedProperties([]); setPropertySearch(''); }}
                      className={`flex flex-col items-center gap-2 p-4 rounded-xl border transition-all ${selectedObjectType === ot.id ? 'bg-blue-500/15 border-blue-500/40 text-blue-300' : 'bg-slate-700/30 border-transparent hover:bg-slate-700/50 text-slate-400'}`}>
                      <Icon className="w-6 h-6" />
                      <span className="text-sm font-medium text-center leading-tight">{ot.label}</span>
                      <span className="text-[10px] text-slate-500">{ot.properties.length} properties</span>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
                <div>
                  <h2 className="text-lg font-semibold text-slate-100 mb-1">Select Properties</h2>
                  <p className="text-sm text-slate-400">Choose one or more properties to compare <span className="text-cyan-400 font-medium">({selectedProperties.length} selected)</span></p>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={selectAllProps} className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors">Select All</button>
                  <button onClick={deselectAllProps} className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors">Deselect All</button>
                  <div className="relative ml-2">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input type="text" value={propertySearch} onChange={e => setPropertySearch(e.target.value)} placeholder="Filter..." className="pl-9 pr-4 py-1.5 bg-slate-700/50 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-48" />
                  </div>
                </div>
              </div>
              <div className="space-y-4 max-h-[420px] overflow-y-auto pr-2">
                {Object.entries(filteredGroupedProperties).map(([cat, props]) => (
                  <div key={cat}>
                    <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2 sticky top-0 bg-slate-800/90 backdrop-blur-sm py-1 z-10">{cat}</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                      {props.map(p => (
                        <button key={p.id} onClick={() => toggleProp(p.id)}
                          className={`flex items-center gap-3 p-3 rounded-lg text-left transition-all ${selectedProperties.includes(p.id) ? 'bg-blue-500/15 border border-blue-500/30 text-blue-300' : 'bg-slate-700/20 border border-transparent hover:bg-slate-700/40 text-slate-300'}`}>
                          <div className={`w-5 h-5 rounded border flex items-center justify-center flex-shrink-0 transition-colors ${selectedProperties.includes(p.id) ? 'bg-blue-500 border-blue-500' : 'border-slate-500'}`}>
                            {selectedProperties.includes(p.id) && <Check className="w-3 h-3 text-white" />}
                          </div>
                          <span className="text-sm truncate">{p.label}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              {selectedProperties.length > 0 && (
                <div className="mt-4 pt-4 border-t border-slate-700/50 flex flex-wrap gap-1.5">
                  {selectedPropertyDefs.map(p => (
                    <span key={p.id} className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-blue-500/10 text-blue-400 rounded-lg text-xs font-medium border border-blue-500/20">
                      {p.label}
                      <button onClick={() => toggleProp(p.id)} className="hover:text-blue-200"><X className="w-3 h-3" /></button>
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-400">{selectedProperties.length > 0 ? `${selectedProperties.length} propert${selectedProperties.length === 1 ? 'y' : 'ies'} on ${currentType.label}` : 'Select at least one property'}</span>
              <button onClick={() => setStep(2)} disabled={selectedProperties.length === 0} className="flex items-center gap-2 px-6 py-3 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors">
                Next: Select Namespaces <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* ═══ STEP 2 ═══ */}
        {step === 2 && (
          <div className="space-y-6">
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 flex items-center gap-3 flex-wrap">
              <currentType.icon className="w-4 h-4 text-blue-400 flex-shrink-0" />
              <span className="font-medium text-slate-200 text-sm">{currentType.label}</span>
              <ChevronRight className="w-3 h-3 text-slate-600" />
              <div className="flex flex-wrap gap-1.5">
                {selectedPropertyDefs.map(p => (<span key={p.id} className="px-2 py-0.5 bg-cyan-500/10 text-cyan-400 rounded text-xs font-medium">{p.label}</span>))}
              </div>
              <button onClick={() => setStep(1)} className="ml-auto text-sm text-slate-400 hover:text-slate-200 transition-colors flex-shrink-0">Change</button>
            </div>

            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-center justify-between mb-6 flex-wrap gap-3">
                <div>
                  <h2 className="text-lg font-semibold text-slate-100 mb-1">Select Namespaces</h2>
                  <p className="text-sm text-slate-400">Choose which namespaces to scan <span className="text-cyan-400 font-medium">({selectedNs.length} selected)</span></p>
                </div>
                <div className="flex items-center gap-2">
                  <div className="relative mr-2">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input type="text" value={nsSearch} onChange={e => setNsSearch(e.target.value)} placeholder="Filter..." className="pl-9 pr-4 py-1.5 bg-slate-700/50 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-52" />
                  </div>
                  <button onClick={selectAllNs} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors">Select All</button>
                  <button onClick={deselectAllNs} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors">Deselect All</button>
                </div>
              </div>
              {isLoadingNs ? (
                <div className="flex items-center justify-center py-12"><Loader2 className="w-6 h-6 animate-spin text-blue-400" /></div>
              ) : (
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 max-h-80 overflow-y-auto">
                  {filteredNamespaces.map(ns => (
                    <label key={ns.name} className={`flex items-center gap-2 p-3 rounded-lg cursor-pointer transition-colors ${selectedNs.includes(ns.name) ? 'bg-blue-500/15 border border-blue-500/30' : 'bg-slate-700/30 border border-transparent hover:bg-slate-700/50'}`}>
                      <input type="checkbox" checked={selectedNs.includes(ns.name)} onChange={() => toggleNs(ns.name)} className="sr-only" />
                      <div className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${selectedNs.includes(ns.name) ? 'bg-blue-500 border-blue-500' : 'border-slate-500'}`}>
                        {selectedNs.includes(ns.name) && <Check className="w-3 h-3 text-white" />}
                      </div>
                      <span className="text-sm text-slate-300 truncate">{ns.name}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
            <div className="flex items-center justify-between">
              <button onClick={() => setStep(1)} className="flex items-center gap-2 px-4 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"><ArrowLeft className="w-4 h-4" /> Back</button>
              <span className="text-sm text-slate-400">{selectedNs.length > 0 ? `Ready to scan ${selectedNs.length} namespace${selectedNs.length > 1 ? 's' : ''}` : 'Select namespaces to continue'}</span>
              <button onClick={startScan} disabled={selectedNs.length === 0} className="flex items-center gap-2 px-6 py-3 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors"><Play className="w-4 h-4" /> Generate Report</button>
            </div>
          </div>
        )}

        {/* ═══ STEP 3 — RESULTS ═══ */}
        {step === 3 && (
          <div className="space-y-6">

            {/* Progress */}
            {isScanning && (
              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3"><Loader2 className="w-5 h-5 animate-spin text-blue-400" /><span className="text-sm font-medium text-slate-200">{progressText}</span></div>
                  <button onClick={cancelScan} className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-lg transition-colors"><X className="w-4 h-4" /> Cancel</button>
                </div>
                <div className="w-full bg-slate-700 rounded-full h-2"><div className="bg-blue-500 h-2 rounded-full transition-all duration-300" style={{ width: `${progress}%` }} /></div>
                <div className="bg-slate-900/50 rounded-lg p-3 max-h-40 overflow-y-auto font-mono text-xs space-y-0.5">
                  {logs.map((l, i) => (<div key={i} className={l.type === 'error' ? 'text-red-400' : l.type === 'warning' ? 'text-amber-400' : l.type === 'success' ? 'text-emerald-400' : 'text-slate-500'}><span className="text-slate-600">[{l.time}]</span> {l.message}</div>))}
                </div>
              </div>
            )}

            {/* Results */}
            {!isScanning && rows.length > 0 && (
              <>
                {/* Toolbar */}
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                  <div className="flex items-center justify-between flex-wrap gap-3">
                    <div className="flex items-center gap-2 text-sm flex-wrap">
                      <currentType.icon className="w-4 h-4 text-blue-400" />
                      <span className="font-medium text-slate-200">{currentType.label}</span>
                      <span className="text-slate-600">•</span>
                      <span className="text-slate-400">{rows.length} object{rows.length !== 1 ? 's' : ''}</span>
                      <span className="text-slate-600">•</span>
                      <span className="text-slate-400">{selectedNs.length} ns</span>
                      <span className="text-slate-600">•</span>
                      <span className="text-cyan-400">{selectedPropertyDefs.length} propert{selectedPropertyDefs.length === 1 ? 'y' : 'ies'}</span>
                    </div>
                    
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {selectedRowIds.size > 0 && (
                         <div className="flex items-center mr-2">
                           <span className="text-xs font-semibold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-1 rounded-md">
                             {selectedRowIds.size} Selected
                           </span>
                           <button onClick={() => setSelectedRowIds(new Set())} className="ml-1 p-1 text-slate-400 hover:text-red-400 transition-colors" title="Clear selection">
                             <X className="w-3.5 h-3.5" />
                           </button>
                         </div>
                      )}

                      <div className="flex items-center bg-slate-700/50 rounded-lg p-0.5 mr-2">
                        <button onClick={() => setViewMode('table')} className={`p-1.5 rounded-md transition-colors ${viewMode === 'table' ? 'bg-slate-600 text-slate-200' : 'text-slate-500 hover:text-slate-300'}`} title="Table view"><LayoutList className="w-3.5 h-3.5" /></button>
                        <button onClick={() => setViewMode('cards')} className={`p-1.5 rounded-md transition-colors ${viewMode === 'cards' ? 'bg-slate-600 text-slate-200' : 'text-slate-500 hover:text-slate-300'}`} title="Card view"><LayoutGrid className="w-3.5 h-3.5" /></button>
                      </div>
                      
                      <button onClick={copyTable} className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors">
                        <Copy className="w-3.5 h-3.5" /> Copy {selectedRowIds.size > 0 && `(${selectedRowIds.size})`}
                      </button>
                      <button onClick={exportCsv} className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors">
                        <FileText className="w-3.5 h-3.5" /> CSV {selectedRowIds.size > 0 && `(${selectedRowIds.size})`}
                      </button>
                      <button onClick={exportExcel} className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors">
                        <Table className="w-3.5 h-3.5" /> Excel {selectedRowIds.size > 0 && `(${selectedRowIds.size})`}
                      </button>
                      <button onClick={exportJson} className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors">
                        <FileJson className="w-3.5 h-3.5" /> JSON {selectedRowIds.size > 0 && `(${selectedRowIds.size})`}
                      </button>
                      
                      <button onClick={() => { setStep(1); setRows([]); setLogs([]); setSelectedRowIds(new Set()); }} className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 rounded-lg transition-colors ml-1">New Scan</button>
                    </div>
                  </div>
                </div>

                {/* Distribution (collapsible) */}
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
                  <button onClick={() => setShowDistribution(p => !p)} className="w-full flex items-center justify-between p-4 hover:bg-slate-700/20 transition-colors">
                    <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2"><Hash className="w-4 h-4 text-cyan-400" /> Value Distribution</h3>
                    {showDistribution ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
                  </button>
                  {showDistribution && (
                    <div className="px-4 pb-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                      {selectedPropertyDefs.map(prop => {
                        const dist = getDistribution(prop.id);
                        return (
                          <div key={prop.id} className="bg-slate-900/40 rounded-lg p-4">
                            <h4 className="text-xs font-semibold text-cyan-400 mb-3">{prop.label}</h4>
                            <div className="space-y-1.5">
                              {dist.slice(0, 8).map(([val, count]) => {
                                const pct = Math.round((count / rows.length) * 100);
                                return (
                                  <div key={val} className="flex items-center gap-2">
                                    <ValueBadge value={val} compact onClick={() => setSearchQuery(val)} />
                                    <div className="flex-1 bg-slate-700/30 rounded-full h-1.5"><div className="h-1.5 rounded-full bg-cyan-500/50" style={{ width: `${Math.max(pct, 2)}%` }} /></div>
                                    <span className="text-[10px] text-slate-500 w-14 text-right flex-shrink-0">{count} ({pct}%)</span>
                                  </div>
                                );
                              })}
                              {dist.length > 8 && <p className="text-[10px] text-slate-600 mt-1">+{dist.length - 8} more</p>}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Search */}
                <div className="flex items-center gap-3">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input type="text" value={searchQuery} onChange={e => setSearchQuery(e.target.value)} placeholder="Search namespace, name, or any value..." className="w-full pl-9 pr-4 py-2.5 bg-slate-800/50 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500" />
                  </div>
                  <span className="text-sm text-slate-500 flex-shrink-0">{sortedRows.length} of {rows.length}</span>
                </div>

                {/* TABLE VIEW */}
                {viewMode === 'table' && (
                  <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
                    <div className="overflow-x-auto">
                      <table className="w-full border-collapse">
                        <thead>
                          <tr className="bg-slate-800/80">
                            <th className="text-left px-5 py-3.5 text-[11px] font-semibold text-slate-400 uppercase tracking-wider select-none sticky left-0 bg-slate-800 z-10 border-b border-slate-600">
                              <div className="flex items-center gap-3">
                                <input 
                                  type="checkbox" 
                                  className="w-4 h-4 rounded border-slate-600 bg-slate-700/50 text-blue-500 focus:ring-blue-500 focus:ring-offset-slate-800 cursor-pointer"
                                  checked={allCurrentSelected}
                                  ref={input => { if (input) input.indeterminate = someCurrentSelected && !allCurrentSelected; }}
                                  onChange={handleSelectAll}
                                  title="Select/Deselect All in view"
                                />
                                <div className="flex items-center gap-1 cursor-pointer hover:text-slate-200" onClick={() => toggleSort('namespace')}>
                                  Namespace {sortBy === 'namespace' && (sortDir === 'asc' ? <ChevronUp className="w-3 h-3 text-blue-400" /> : <ChevronDown className="w-3 h-3 text-blue-400" />)}
                                </div>
                              </div>
                            </th>
                            <th className="text-left px-5 py-3.5 text-[11px] font-semibold text-slate-400 uppercase tracking-wider cursor-pointer hover:text-slate-200 select-none border-b border-slate-600" onClick={() => toggleSort('name')}>
                              <div className="flex items-center gap-1">Name {sortBy === 'name' && (sortDir === 'asc' ? <ChevronUp className="w-3 h-3 text-blue-400" /> : <ChevronDown className="w-3 h-3 text-blue-400" />)}</div>
                            </th>
                            {selectedPropertyDefs.map(p => (
                              <th key={p.id} className="text-left px-5 py-3.5 text-[11px] font-semibold text-cyan-500/80 uppercase tracking-wider cursor-pointer hover:text-cyan-300 select-none whitespace-nowrap border-b border-slate-600" onClick={() => toggleSort(p.id)}>
                                <div className="flex items-center gap-1">{p.label} {sortBy === p.id && (sortDir === 'asc' ? <ChevronUp className="w-3 h-3 text-blue-400" /> : <ChevronDown className="w-3 h-3 text-blue-400" />)}</div>
                              </th>
                            ))}
                            <th className="px-5 py-3.5 border-b border-slate-600 sticky right-0 bg-slate-800 z-10 w-16"></th>
                          </tr>
                        </thead>
                        <tbody>
                          {sortedRows.map((row, i) => {
                            const isNewNs = i === 0 || sortedRows[i - 1].namespace !== row.namespace;
                            const rId = getRowId(row);
                            const isSelected = selectedRowIds.has(rId);
                            return (
                              <tr key={`${rId}-${i}`}
                                className={`transition-colors hover:bg-blue-500/5 ${isSelected ? 'bg-blue-500/10' : row.error ? 'bg-red-500/5' : i % 2 === 0 ? 'bg-slate-800/10' : 'bg-slate-800/30'} ${isNewNs && i > 0 ? 'border-t-[3px] border-slate-600/60' : ''}`}>
                                <td className={`px-5 py-3.5 sticky left-0 z-10 border-b border-slate-700/40 ${isSelected ? 'bg-blue-900/40' : i % 2 === 0 ? 'bg-slate-900/60' : 'bg-slate-900/80'}`}>
                                  <div className="flex items-center gap-3">
                                    <input 
                                      type="checkbox" 
                                      className="w-4 h-4 rounded border-slate-600 bg-slate-700/50 text-blue-500 focus:ring-blue-500 focus:ring-offset-slate-900 cursor-pointer"
                                      checked={isSelected}
                                      onChange={() => toggleRowSelection(rId)}
                                    />
                                    {isNewNs ? <span className="text-xs font-semibold text-blue-400 font-mono">{row.namespace}</span> : <span className="text-xs text-slate-600 font-mono pl-2">↳</span>}
                                  </div>
                                </td>
                                <td className="px-5 py-3.5 border-b border-slate-700/40">
                                  <span className="text-sm text-slate-100 font-medium">{row.objectName}</span>
                                </td>
                                {selectedPropertyDefs.map(p => (
                                  <td key={p.id} className="px-5 py-3.5 border-b border-slate-700/40">
                                    <ValueBadge value={row.values[p.id] || 'N/A'} />
                                  </td>
                                ))}
                                <td className={`px-5 py-3.5 border-b border-slate-700/40 sticky right-0 z-10 text-right ${isSelected ? 'bg-blue-900/40' : i % 2 === 0 ? 'bg-slate-900/60' : 'bg-slate-900/80'}`}>
                                  <button onClick={(e) => { e.stopPropagation(); setSelectedRawData(row.rawData); }} className="p-1.5 text-slate-400 hover:text-blue-400 hover:bg-blue-500/10 rounded-lg transition-colors" title="View Raw JSON">
                                    <FileJson className="w-4 h-4" />
                                  </button>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                    {sortedRows.length === 0 && (
                      <div className="flex flex-col items-center justify-center py-16 text-slate-500"><Search className="w-8 h-8 mb-3 opacity-50" /><p className="text-sm">No matching results</p></div>
                    )}
                  </div>
                )}

                {/* CARD VIEW */}
                {viewMode === 'cards' && (
                  <div className="space-y-3">
                    {/* Select All Card View Toggle */}
                    <div className="flex items-center gap-3 px-2 py-1">
                       <input 
                         type="checkbox" 
                         className="w-4 h-4 rounded border-slate-600 bg-slate-700/50 text-blue-500 focus:ring-blue-500 cursor-pointer"
                         checked={allCurrentSelected}
                         ref={input => { if (input) input.indeterminate = someCurrentSelected && !allCurrentSelected; }}
                         onChange={handleSelectAll}
                         id="selectAllCards"
                       />
                       <label htmlFor="selectAllCards" className="text-sm font-medium text-slate-300 cursor-pointer select-none">Select All Results</label>
                    </div>

                    {sortedRows.map((row, i) => {
                      const rId = getRowId(row);
                      const isSelected = selectedRowIds.has(rId);
                      return (
                      <div key={`${rId}-${i}`} 
                           onClick={() => toggleRowSelection(rId)}
                           className={`rounded-xl border p-5 transition-all cursor-pointer ${isSelected ? 'border-blue-500/60 bg-blue-500/10 shadow-lg shadow-blue-500/5' : row.error ? 'border-red-500/30 bg-red-500/5' : 'border-slate-700/60 bg-gradient-to-r from-slate-800/40 to-slate-800/20 hover:border-slate-600 hover:shadow-lg hover:shadow-black/10'}`}>
                        <div className="flex items-center gap-3 mb-4 pb-3 border-b border-slate-700/40">
                          <input 
                             type="checkbox" 
                             className="w-4 h-4 rounded border-slate-600 bg-slate-700/50 text-blue-500 focus:ring-blue-500 cursor-pointer pointer-events-none" // pointer-events-none lets the card handle the click
                             checked={isSelected}
                             readOnly
                          />
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 ring-1 ring-blue-500/20">{row.namespace}</span>
                          <span className="text-base font-semibold text-slate-100">{row.objectName}</span>
                          <div className="ml-auto">
                            <button onClick={(e) => { e.stopPropagation(); setSelectedRawData(row.rawData); }} className="p-1.5 text-slate-400 hover:text-blue-400 hover:bg-blue-500/10 rounded-lg transition-colors" title="View Raw JSON">
                              <FileJson className="w-4 h-4" />
                            </button>
                          </div>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-x-6 gap-y-4">
                          {selectedPropertyDefs.map(p => (
                            <div key={p.id}>
                              <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1.5 font-medium">{p.label}</div>
                              <ValueBadge value={row.values[p.id] || 'N/A'} onClick={(e?: ReactMouseEvent) => e?.stopPropagation()} />
                            </div>
                          ))}
                        </div>
                      </div>
                    )})}
                    {sortedRows.length === 0 && (
                      <div className="flex flex-col items-center justify-center py-16 text-slate-500 bg-slate-800/30 rounded-xl border border-slate-700"><Search className="w-8 h-8 mb-3 opacity-50" /><p className="text-sm">No matching results</p></div>
                    )}
                  </div>
                )}
              </>
            )}

            {/* Empty */}
            {!isScanning && rows.length === 0 && logs.length > 0 && (
              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-12 flex flex-col items-center">
                <AlertTriangle className="w-12 h-12 text-amber-400 mb-4" />
                <h3 className="text-lg font-semibold text-slate-200 mb-2">No Objects Found</h3>
                <p className="text-sm text-slate-400 mb-6">No {currentType.label}s were found in the selected namespaces.</p>
                <button onClick={() => { setStep(1); setRows([]); setLogs([]); setSelectedRowIds(new Set()); }} className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg text-sm font-medium transition-colors">Start New Scan</button>
              </div>
            )}
          </div>
        )}
      </main>

      {/* RAW JSON MODAL */}
      {selectedRawData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-200">
          <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-slate-900/80">
              <h3 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                <FileJson className="w-5 h-5 text-blue-400" />
                Raw JSON Configuration
              </h3>
              <button onClick={() => setSelectedRawData(null)} className="p-1 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 overflow-auto flex-1 bg-slate-950/50 relative">
              <pre className="text-xs text-slate-300 font-mono whitespace-pre-wrap break-words">
                {JSON.stringify(selectedRawData, null, 2)}
              </pre>
            </div>
            <div className="p-4 border-t border-slate-800 bg-slate-900/80 flex justify-end">
              <button onClick={() => {
                navigator.clipboard.writeText(JSON.stringify(selectedRawData, null, 2));
                toast.success('JSON copied to clipboard');
              }} className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-200 rounded-lg text-sm font-medium transition-colors">
                <Copy className="w-4 h-4" /> Copy to Clipboard
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}