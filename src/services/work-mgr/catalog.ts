/**
 * F5 XC product catalog + per-product config templates + full customer-details
 * template. This is the shared domain backbone for Work Manager v1/v2/v3.
 *
 * Product list compiled from the mywork/ data: account 00-overview.md `products`
 * arrays (WAAP, BotDefense, BotDefense-Advanced, API, DDoS, DNS, CDN, MCN,
 * Platform-RBAC, Observability, Mobile-SDK, Client-Side Defense), the Career
 * skills-matrix (Shape Bot Defense, vSSE, BIG-IP/ASM, AI/ML), and the
 * xc-app-store tool coverage.
 */

export type FieldType =
  | 'text' | 'textarea' | 'select' | 'multiselect'
  | 'boolean' | 'number' | 'date' | 'url';

export interface ConfigField {
  key: string;
  label: string;
  type: FieldType;
  options?: string[];
  placeholder?: string;
  help?: string;
  group?: string;
}

export type ProductCategory =
  | 'WAAP' | 'Bot' | 'API' | 'DDoS' | 'Network' | 'DNS'
  | 'CDN' | 'Platform' | 'Client' | 'Edge' | 'Adjacent' | 'AI';

export interface ProductDef {
  key: string;        // stable key stored in account config
  name: string;       // full display name
  short: string;      // chip label
  category: ProductCategory;
  color: string;      // hex accent for chips/rails
  blurb: string;      // one-liner
  aliases: string[];  // strings that may appear in overview `products:` arrays
  fields: ConfigField[];
}

const MODE = ['Blocking', 'Monitoring', 'Transparent', 'Not deployed'];
const ENV = ['Production', 'UAT', 'Staging', 'Pre-prod', 'POC'];

// ---------------------------------------------------------------------------
// The catalog
// ---------------------------------------------------------------------------
export const PRODUCTS: ProductDef[] = [
  {
    key: 'xc-waap', name: 'XC WAAP (Web App & API Protection)', short: 'WAAP',
    category: 'WAAP', color: '#3b82f6',
    blurb: 'Bundled WAF + Bot + API + DDoS delivered on Regional Edge / CE.',
    aliases: ['WAAP', 'XC WAAP', 'WAF'],
    fields: [
      { key: 'tenant', label: 'Tenant name', type: 'text', placeholder: 'customer-tenant', group: 'Tenant' },
      { key: 'console_url', label: 'Console URL', type: 'url', placeholder: 'https://<tenant>.console.ves.volterra.io', group: 'Tenant' },
      { key: 'namespaces', label: 'Namespaces', type: 'text', placeholder: 'prod, uat, shared', group: 'Tenant' },
      { key: 'deployment', label: 'Deployment', type: 'multiselect', options: ['Regional Edge (RE)', 'Customer Edge (CE)', 'Cloud (AWS)', 'Cloud (Azure)', 'Cloud (GCP)'], group: 'Topology' },
      { key: 'lb_count', label: '# HTTP Load Balancers', type: 'number', group: 'Topology' },
      { key: 'domains', label: 'Protected domains / VIPs', type: 'textarea', placeholder: 'www.customer.com\napi.customer.com', group: 'Topology' },
      { key: 'waf_mode', label: 'WAF enforcement mode', type: 'select', options: MODE, group: 'Policy' },
      { key: 'bot_tier', label: 'Bot tier', type: 'select', options: ['None', 'Bot Defense Standard', 'Bot Defense Advanced'], group: 'Policy' },
      { key: 'api_protection', label: 'API protection enabled', type: 'boolean', group: 'Policy' },
      { key: 'ddos_profile', label: 'DDoS profile', type: 'select', options: ['Off', 'Auto', 'Custom'], group: 'Policy' },
      { key: 'service_policies', label: 'Service policies', type: 'textarea', placeholder: 'IP allow/deny, geo, rate-limit rules', group: 'Policy' },
    ],
  },
  {
    key: 'xc-waf', name: 'XC WAF (App Firewall)', short: 'WAF',
    category: 'WAAP', color: '#2563eb',
    blurb: 'Signature + rule-based web application firewall policy.',
    aliases: ['WAF', 'App Firewall', 'AppFirewall'],
    fields: [
      { key: 'policy_name', label: 'WAF policy name', type: 'text', group: 'Policy' },
      { key: 'mode', label: 'Enforcement mode', type: 'select', options: MODE, group: 'Policy' },
      { key: 'signature_staging', label: 'Signature staging enabled', type: 'boolean', group: 'Signatures' },
      { key: 'signature_set', label: 'Signature set / version', type: 'text', placeholder: 'e.g. latest, staged', group: 'Signatures' },
      { key: 'violation_rating', label: 'Blocking threshold (violation rating)', type: 'select', options: ['≥5 (default)', '≥4', '≥3', 'Custom'], group: 'Detection' },
      { key: 'detections', label: 'Detection settings', type: 'multiselect', options: ['Attack signatures', 'Threat campaigns', 'Evasion detection', 'Malicious IP', 'Bot detection', 'Data guard', 'Compliance'], group: 'Detection' },
      { key: 'fp_exclusions', label: 'FP exclusions / suppressions', type: 'number', help: '# active signature exclusions', group: 'Tuning' },
      { key: 'custom_rules', label: 'Custom rules', type: 'textarea', group: 'Tuning' },
      { key: 'allowed_response_codes', label: 'Allowed response codes', type: 'text', placeholder: '400-599', group: 'Tuning' },
    ],
  },
  {
    key: 'xc-bot-standard', name: 'XC Bot Defense Standard', short: 'Bot Std',
    category: 'Bot', color: '#0ea5e9',
    blurb: 'Signal-based bot mitigation bundled with WAAP.',
    aliases: ['BotDefense', 'Bot Defense', 'Bot Defense Standard', 'Bot Standard'],
    fields: [
      { key: 'protected_paths', label: 'Protected endpoints / paths', type: 'textarea', placeholder: '/login\n/checkout', group: 'Scope' },
      { key: 'policy', label: 'Bot policy name', type: 'text', group: 'Scope' },
      { key: 'action', label: 'Mitigation action', type: 'select', options: ['Block', 'Redirect', 'Flag/Log only', 'JS challenge', 'Custom'], group: 'Mitigation' },
      { key: 'categories', label: 'Categories mitigated', type: 'multiselect', options: ['Automation frameworks', 'Search bots (allow)', 'Scrapers', 'Vulnerability scanners', 'Account takeover', 'Unknown'], group: 'Mitigation' },
      { key: 'inline', label: 'Inline JS/header insertion', type: 'boolean', group: 'Integration' },
      { key: 'regions', label: 'Regions / apps in scope', type: 'text', group: 'Scope' },
    ],
  },
  {
    key: 'xc-bot-advanced', name: 'XC Bot Defense Advanced (Shape)', short: 'Bot Adv',
    category: 'Bot', color: '#06b6d4',
    blurb: 'Shape-powered ML bot defense with managed SOC + mobile SDK.',
    aliases: ['BotDefense-Advanced', 'Bot Defense Advanced', 'Shape', 'Shape Bot Defense', 'Bot Advanced'],
    fields: [
      { key: 'protected_endpoints', label: 'Protected endpoints', type: 'textarea', placeholder: 'login, signup, checkout, gift-card, OTP', group: 'Scope' },
      { key: 'integration', label: 'Integration method', type: 'multiselect', options: ['Web connector (JS)', 'iOS SDK', 'Android SDK', 'Reverse proxy', 'API'], group: 'Integration' },
      { key: 'sdk_version', label: 'Mobile SDK version(s)', type: 'text', placeholder: 'iOS x.y / Android x.y', group: 'Integration' },
      { key: 'mode', label: 'Mode', type: 'select', options: ['Mitigation', 'Observation/Telemetry only'], group: 'Mitigation' },
      { key: 'actions', label: 'Mitigation actions per endpoint', type: 'textarea', placeholder: 'login: block; checkout: flag', group: 'Mitigation' },
      { key: 'managed_soc', label: 'Managed SOC / service tier', type: 'select', options: ['SOC-managed', 'Self-managed', 'Co-managed'], group: 'Service' },
      { key: 'flow_labels', label: 'Flow labels configured', type: 'text', group: 'Scope' },
    ],
  },
  {
    key: 'xc-api', name: 'XC API Security', short: 'API Sec',
    category: 'API', color: '#8b5cf6',
    blurb: 'API discovery, schema enforcement, sensitive-data & rate control.',
    aliases: ['API', 'API Security', 'API Discovery', 'API Protection', 'APISec'],
    fields: [
      { key: 'discovery', label: 'API discovery enabled', type: 'boolean', group: 'Discovery' },
      { key: 'endpoints', label: '# discovered endpoints', type: 'number', group: 'Discovery' },
      { key: 'api_groups', label: 'API groups', type: 'text', group: 'Discovery' },
      { key: 'spec', label: 'OpenAPI/Swagger uploaded', type: 'boolean', group: 'Schema' },
      { key: 'validation', label: 'Schema validation mode', type: 'select', options: MODE, group: 'Schema' },
      { key: 'sensitive_data', label: 'Sensitive-data detection (PII)', type: 'boolean', group: 'Protection' },
      { key: 'auth', label: 'Auth type', type: 'multiselect', options: ['API key', 'JWT/OAuth', 'mTLS', 'Basic', 'Custom'], group: 'Protection' },
      { key: 'rate_limits', label: 'API rate limits', type: 'textarea', group: 'Protection' },
    ],
  },
  {
    key: 'xc-ddos', name: 'XC DDoS Mitigation', short: 'DDoS',
    category: 'DDoS', color: '#ef4444',
    blurb: 'L3-L4 volumetric + L7 application DDoS protection & auto-mitigation.',
    aliases: ['DDoS', 'DDoS-L7', 'DDOS'],
    fields: [
      { key: 'tier', label: 'Protection layer', type: 'multiselect', options: ['L3-L4 (volumetric)', 'L7 (application)', 'Slow-loris', 'Auto-mitigation'], group: 'Scope' },
      { key: 'auto_mitigation', label: 'Auto-mitigation enabled', type: 'boolean', group: 'Policy' },
      { key: 'thresholds', label: 'Threshold config', type: 'textarea', placeholder: 'RPS / connection thresholds per LB', group: 'Policy' },
      { key: 'mitigation_rules', label: 'Mitigation rules', type: 'textarea', group: 'Policy' },
      { key: 'alerting', label: 'Alert policy', type: 'text', group: 'Ops' },
      { key: 'blackhole', label: 'Blackhole / scrubbing', type: 'boolean', group: 'Ops' },
    ],
  },
  {
    key: 'xc-dns', name: 'XC DNS / DNS Load Balancer', short: 'DNS',
    category: 'DNS', color: '#14b8a6',
    blurb: 'Primary/secondary DNS, DNSSEC, geo/latency DNS load balancing.',
    aliases: ['DNS', 'DNSSEC', 'DNS LB'],
    fields: [
      { key: 'role', label: 'F5 XC role', type: 'select', options: ['Primary', 'Secondary', 'Hidden primary', 'DNS LB only'], group: 'Setup' },
      { key: 'zones', label: 'Zones managed', type: 'textarea', group: 'Setup' },
      { key: 'dnssec', label: 'DNSSEC enabled', type: 'boolean', group: 'Setup' },
      { key: 'lb_rules', label: 'Load-balancing rules', type: 'multiselect', options: ['Round robin', 'Geo', 'Latency', 'Ratio/weighted', 'Failover'], group: 'LB' },
      { key: 'health_checks', label: 'Health checks', type: 'text', group: 'LB' },
      { key: 'ttl', label: 'Default TTL', type: 'text', placeholder: 'e.g. 300s', group: 'LB' },
    ],
  },
  {
    key: 'xc-cdn', name: 'XC CDN', short: 'CDN',
    category: 'CDN', color: '#f59e0b',
    blurb: 'Content delivery + caching in front of app/LB origins.',
    aliases: ['CDN'],
    fields: [
      { key: 'distribution', label: 'CDN distribution name', type: 'text', group: 'Setup' },
      { key: 'origins', label: 'Origin pools', type: 'textarea', group: 'Setup' },
      { key: 'cache_rules', label: 'Cache rules', type: 'textarea', group: 'Caching' },
      { key: 'ttl', label: 'Cache TTL', type: 'text', group: 'Caching' },
      { key: 'purge', label: 'Purge method', type: 'select', options: ['API', 'Console', 'Auto on deploy'], group: 'Caching' },
      { key: 'tls', label: 'TLS / custom cert', type: 'text', group: 'Security' },
    ],
  },
  {
    key: 'xc-mcn', name: 'XC MCN (Multi-Cloud Networking)', short: 'MCN',
    category: 'Network', color: '#a855f7',
    blurb: 'Cloud & Edge sites, network + app connect, segmentation.',
    aliases: ['MCN', 'Multi-Cloud Networking', 'MCN Intro'],
    fields: [
      { key: 'sites', label: 'Sites (CE nodes)', type: 'textarea', placeholder: 'aws-sg-ce01, azure-hk-ce01', group: 'Sites' },
      { key: 'clouds', label: 'Clouds', type: 'multiselect', options: ['AWS', 'Azure', 'GCP', 'On-prem/VMware', 'Bare metal'], group: 'Sites' },
      { key: 'connect', label: 'Connectivity', type: 'multiselect', options: ['Network Connect', 'App Connect', 'Site-to-site', 'Direct connect / ExpressRoute'], group: 'Connectivity' },
      { key: 'segments', label: 'Segments / VRFs', type: 'textarea', group: 'Segmentation' },
      { key: 'segmentation_policy', label: 'Segmentation policies', type: 'textarea', group: 'Segmentation' },
      { key: 'routing', label: 'Routing (BGP/static)', type: 'text', group: 'Connectivity' },
    ],
  },
  {
    key: 'xc-csd', name: 'XC Client-Side Defense', short: 'CSD',
    category: 'Client', color: '#ec4899',
    blurb: 'Magecart / formjacking / supply-chain script monitoring.',
    aliases: ['Client-Side Defense', 'CSD'],
    fields: [
      { key: 'protected_pages', label: 'Protected pages', type: 'textarea', placeholder: 'checkout, payment', group: 'Scope' },
      { key: 'script_inventory', label: '# scripts inventoried', type: 'number', group: 'Detection' },
      { key: 'mode', label: 'Policy mode', type: 'select', options: MODE, group: 'Detection' },
      { key: 'mitigation', label: 'Mitigation (block/alert)', type: 'select', options: ['Block domains', 'Alert only', 'Enforce allow-list'], group: 'Mitigation' },
    ],
  },
  {
    key: 'xc-platform', name: 'XC Platform (Tenant / RBAC / Observability)', short: 'Platform',
    category: 'Platform', color: '#64748b',
    blurb: 'Tenant admin, RBAC, namespaces, alerts, global log receiver.',
    aliases: ['Platform', 'Platform-RBAC', 'Observability', 'RBAC'],
    fields: [
      { key: 'users', label: '# users / groups', type: 'text', group: 'RBAC' },
      { key: 'roles', label: 'Roles / RBAC model', type: 'textarea', placeholder: 'custom roles, namespace scoping', group: 'RBAC' },
      { key: 'sso', label: 'SSO / IdP', type: 'text', placeholder: 'Azure AD / Okta / SAML', group: 'RBAC' },
      { key: 'namespaces', label: 'Namespaces', type: 'text', group: 'Tenant' },
      { key: 'glr', label: 'Global Log Receiver (GLR) target', type: 'text', placeholder: 'Azure Event Hub / Splunk / S3', group: 'Observability' },
      { key: 'alerts', label: 'Alert receivers / policies', type: 'textarea', group: 'Observability' },
      { key: 'audit', label: 'Audit logging enabled', type: 'boolean', group: 'Observability' },
    ],
  },
  {
    key: 'shape-mobile-sdk', name: 'Shape / Mobile SDK', short: 'Mobile SDK',
    category: 'Bot', color: '#22c55e',
    blurb: 'Shape Enterprise Defense telemetry via native mobile SDK.',
    aliases: ['Mobile-SDK', 'Mobile SDK', 'Shape Enterprise'],
    fields: [
      { key: 'platforms', label: 'Platforms', type: 'multiselect', options: ['iOS', 'Android', 'React Native', 'Flutter'], group: 'Integration' },
      { key: 'sdk_version', label: 'SDK version', type: 'text', group: 'Integration' },
      { key: 'apps', label: 'Integrated apps', type: 'textarea', group: 'Integration' },
      { key: 'telemetry', label: 'Telemetry mode', type: 'select', options: ['Full', 'Sampled', 'Observation'], group: 'Telemetry' },
    ],
  },
  {
    key: 'vsse', name: 'vSSE (Secure Service Edge)', short: 'vSSE',
    category: 'Edge', color: '#0891b2',
    blurb: 'Volterra/XC secure service edge — SWG / access.',
    aliases: ['vSSE', 'SSE'],
    fields: [
      { key: 'services', label: 'Services', type: 'multiselect', options: ['SWG', 'ZTNA/Access', 'CASB', 'DLP'], group: 'Scope' },
      { key: 'users', label: '# users', type: 'number', group: 'Scope' },
      { key: 'policies', label: 'Access policies', type: 'textarea', group: 'Policy' },
    ],
  },
  {
    key: 'bigip', name: 'F5 BIG-IP / Advanced WAF (ASM)', short: 'BIG-IP',
    category: 'Adjacent', color: '#e11d48',
    blurb: 'On-prem / hybrid BIG-IP LTM, ASM/Adv WAF adjacent to XC.',
    aliases: ['BIG-IP', 'BigIP', 'ASM', 'Advanced WAF', 'AWAF'],
    fields: [
      { key: 'modules', label: 'Modules', type: 'multiselect', options: ['LTM', 'ASM/Adv WAF', 'APM', 'GTM/DNS', 'AFM'], group: 'Modules' },
      { key: 'version', label: 'TMOS version', type: 'text', group: 'Modules' },
      { key: 'migration', label: 'Migration to XC?', type: 'select', options: ['Not planned', 'Planned', 'In progress', 'Hybrid steady-state'], group: 'Lifecycle' },
      { key: 'irules', label: 'Key iRules', type: 'textarea', group: 'Config' },
    ],
  },
  {
    key: 'ai-gateway', name: 'F5 AI Gateway / AI Program', short: 'AI',
    category: 'AI', color: '#7c3aed',
    blurb: 'Emerging AI/LLM traffic protection & F5 AI initiatives.',
    aliases: ['AI', 'AI/ML', 'AI Gateway'],
    fields: [
      { key: 'usecase', label: 'Use case', type: 'textarea', placeholder: 'LLM prompt protection, AI app WAAP', group: 'Scope' },
      { key: 'status', label: 'Status', type: 'select', options: ['Exploration', 'POC', 'Pilot', 'Production'], group: 'Scope' },
    ],
  },
];

export const PRODUCTS_BY_KEY: Record<string, ProductDef> =
  Object.fromEntries(PRODUCTS.map(p => [p.key, p]));

/** Map a free-text product token from an overview `products:` array to a catalog key. */
export function resolveProductKey(token: string): string | null {
  const t = token.trim().toLowerCase();
  for (const p of PRODUCTS) {
    if (p.key === t) return p.key;
    if (p.aliases.some(a => a.toLowerCase() === t)) return p.key;
  }
  // loose contains match as a fallback
  for (const p of PRODUCTS) {
    if (p.aliases.some(a => t.includes(a.toLowerCase()) || a.toLowerCase().includes(t))) return p.key;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Full customer-details template (beyond the lean 00-overview frontmatter)
// ---------------------------------------------------------------------------
export interface DetailField extends ConfigField { }
export interface DetailSection { title: string; icon?: string; fields: DetailField[]; }

export const CUSTOMER_TEMPLATE: DetailSection[] = [
  {
    title: 'Identity', icon: 'building',
    fields: [
      { key: 'legal_name', label: 'Legal name', type: 'text' },
      { key: 'short_name', label: 'Short name', type: 'text' },
      { key: 'region', label: 'Region', type: 'select', options: ['APCJ', 'India', 'ASEAN', 'Greater China', 'ANZ', 'MEA', 'EMEA', 'Americas'] },
      { key: 'geos', label: 'Countries / geos', type: 'text', placeholder: 'SG, HK, MY, TH' },
      { key: 'industry', label: 'Industry', type: 'select', options: ['Banking / FSI', 'Insurance', 'Retail / F&B', 'Telco', 'Energy / Utilities', 'Public sector', 'Manufacturing', 'Technology', 'Other'] },
      { key: 'segment', label: 'Segment', type: 'select', options: ['Enterprise', 'Major', 'Commercial', 'Public'] },
    ],
  },
  {
    title: 'Commercial', icon: 'briefcase',
    fields: [
      { key: 'account_manager', label: 'F5 Account Manager', type: 'text' },
      { key: 'se', label: 'F5 SE / SA', type: 'text' },
      { key: 'partner', label: 'Partner / SI', type: 'text' },
      { key: 'service_tier', label: 'Service tier', type: 'select', options: ['Managed Service', 'Premium Plus', 'Premium', 'Standard', 'POC'] },
      { key: 'arr_band', label: 'ARR band', type: 'select', options: ['<$100K', '$100K-$500K', '$500K-$1M', '$1M-$5M', '>$5M'] },
      { key: 'renewal', label: 'Renewal date', type: 'date' },
    ],
  },
  {
    title: 'Engagement', icon: 'activity',
    fields: [
      { key: 'status', label: 'Status', type: 'select', options: ['active', 'monitoring', 'dormant', 'archived'] },
      { key: 'health', label: 'Health', type: 'select', options: ['Green', 'Amber', 'Red'] },
      { key: 'engagement_type', label: 'Engagement type', type: 'multiselect', options: ['Managed Service', 'Project delivery', 'POC', 'Escalation support', 'Advisory'] },
      { key: 'start_date', label: 'Start date', type: 'date' },
      { key: 'last_touched', label: 'Last touched', type: 'date' },
      { key: 'freshness_window_days', label: 'Freshness window (days)', type: 'number' },
    ],
  },
  {
    title: 'Environments', icon: 'server',
    fields: [
      { key: 'prod_tenant', label: 'Prod tenant / console URL', type: 'url' },
      { key: 'uat_tenant', label: 'UAT / staging tenant', type: 'url' },
      { key: 'namespaces', label: 'Namespaces', type: 'text' },
      { key: 'primary_apps', label: 'Primary apps / domains', type: 'textarea' },
    ],
  },
  {
    title: 'Key links', icon: 'link',
    fields: [
      { key: 'salesforce', label: 'Salesforce', type: 'url' },
      { key: 'jira', label: 'Jira / case tracker', type: 'url' },
      { key: 'project_plan', label: 'Project plan', type: 'text' },
      { key: 'runbooks', label: 'Runbooks', type: 'textarea' },
    ],
  },
];

/** Health color helper shared across variants. */
export const HEALTH_COLOR: Record<string, string> = {
  Green: '#22c55e', Amber: '#f59e0b', Red: '#ef4444',
};
export const STATUS_DOT: Record<string, string> = {
  active: '#22c55e', monitoring: '#f59e0b', dormant: '#64748b', archived: '#475569',
};
