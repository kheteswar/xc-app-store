// ═══════════════════════════════════════════════════════════════════════════
// F5 XC Configuration Extractors
//
// Single source of truth for reading security-relevant fields out of real
// F5 XC configuration JSON. Field paths and oneof discriminators mirror the
// verified logic in services/api-shield/config-scanner.ts and the XC type
// definitions in types/index.ts.
//
// IMPORTANT: There is NO `common_security_controls` wrapper on the LB spec —
// every control sits directly on `spec`, and most are oneof discriminators
// (e.g. `app_firewall` vs `disable_waf`, `enable_ip_reputation` vs
// `disable_ip_reputation`). Rules MUST read these paths, not guessed ones.
// ═══════════════════════════════════════════════════════════════════════════

// ───────────────────────────────────────────────────────────────────────────
// Primitive helpers
// ───────────────────────────────────────────────────────────────────────────

type Rec = Record<string, unknown>;

export function asRec(v: unknown): Rec {
  return v && typeof v === 'object' ? (v as Rec) : {};
}

/** The object's spec, tolerating get_spec / bare-spec shapes. */
export function getSpec(obj: unknown): Rec {
  const o = asRec(obj);
  return asRec(o.spec || o.get_spec || o);
}

export function getMetadata(obj: unknown): Rec {
  return asRec(asRec(obj).metadata);
}

export function objectName(obj: unknown): string {
  const md = getMetadata(obj);
  return (md.name as string) || (asRec(obj).name as string) || 'unknown';
}

/** True for a non-null, non-array object with at least one key. */
export function isNonEmptyObject(val: unknown): boolean {
  return val != null && typeof val === 'object' && !Array.isArray(val) && Object.keys(val as Rec).length > 0;
}

/** True for a non-empty string ref or a { name | namespace } ref object. */
export function isNonEmptyRef(val: unknown): boolean {
  if (typeof val === 'string') return val.length > 0;
  if (val != null && typeof val === 'object') {
    const obj = val as Rec;
    return !!(obj.name || obj.namespace);
  }
  return false;
}

export function refName(val: unknown): string | null {
  if (typeof val === 'string') return val;
  if (val != null && typeof val === 'object') {
    const n = (val as Rec).name;
    if (typeof n === 'string') return n;
  }
  return null;
}

/** A oneof "is configured" check: key present and not null. */
function keyPresent(spec: Rec, key: string): boolean {
  return key in spec && spec[key] !== undefined && spec[key] !== null;
}

// ───────────────────────────────────────────────────────────────────────────
// TLS level
// ───────────────────────────────────────────────────────────────────────────

export type TlsLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'DEFAULT' | 'UNKNOWN';

export function classifyTlsLevel(https: Rec | undefined): { level: TlsLevel; minVersion: string; permitsLegacyTls: boolean } {
  if (!https) return { level: 'UNKNOWN', minVersion: '', permitsLegacyTls: false };

  // The tls_config block can live directly on the HTTPS object or be nested
  // under tls_parameters / tls_cert_params depending on the LB type.
  const tc = asRec(
    https.tls_config ||
    asRec(https.tls_parameters).tls_config ||
    asRec(https.tls_cert_params).tls_config
  );
  const minVersion = String(tc.min_version || https.tls_security_level || '').toUpperCase();

  // F5 XC security presets (oneof), per the F5 Distributed Cloud TLS Reference:
  //   default_security  → TLS 1.2–1.3, AEAD/PFS ciphers only (the strong profile)
  //   medium_security   → min TLS 1.0 (adds CBC PFS ciphers)
  //   low_security      → min TLS 1.0 + non-PFS static-RSA ciphers
  // medium/low therefore PERMIT TLS 1.0/1.1 and must not be graded as "TLS 1.2+".
  if ('low_security' in tc) return { level: 'LOW', minVersion: minVersion || 'TLSv1.0', permitsLegacyTls: true };
  if ('medium_security' in tc) return { level: 'MEDIUM', minVersion: minVersion || 'TLSv1.0', permitsLegacyTls: true };
  if ('default_security' in tc) return { level: 'HIGH', minVersion: minVersion || 'TLSv1.2+', permitsLegacyTls: false };

  // Explicit min_version (string enum or numeric form). A custom profile that
  // explicitly pins min TLS 1.2/1.3 is fine even though it is not a named preset.
  if (minVersion.includes('1_3') || minVersion.includes('1.3')) return { level: 'HIGH', minVersion, permitsLegacyTls: false };
  if (minVersion.includes('1_2') || minVersion.includes('1.2')) return { level: 'MEDIUM', minVersion, permitsLegacyTls: false };
  if (minVersion.includes('1_0') || minVersion.includes('1_1') || minVersion.includes('1.0') || minVersion.includes('1.1')) {
    return { level: 'LOW', minVersion, permitsLegacyTls: true };
  }
  if (minVersion.includes('HIGH')) return { level: 'HIGH', minVersion, permitsLegacyTls: false };
  if (minVersion.includes('MEDIUM')) return { level: 'MEDIUM', minVersion, permitsLegacyTls: false };
  if (minVersion.includes('LOW')) return { level: 'LOW', minVersion, permitsLegacyTls: true };

  // custom_security with no explicit version, or nothing set → XC default (strong).
  return { level: 'DEFAULT', minVersion, permitsLegacyTls: false };
}

// ───────────────────────────────────────────────────────────────────────────
// HTTP Load Balancer posture
// ───────────────────────────────────────────────────────────────────────────

export interface LBPosture {
  // TLS / transport
  isHttps: boolean;
  httpRedirect: boolean;
  hsts: boolean;
  tlsLevel: TlsLevel;
  tlsMinVersion: string;
  tlsPermitsLegacy: boolean; // medium_security / low_security / min TLS 1.0-1.1
  // WAF
  wafEnabled: boolean;
  wafExplicitlyDisabled: boolean;
  wafPolicyName: string | null;
  // Access control
  servicePolicies: string[];
  servicePoliciesFromNamespace: boolean;
  hasServicePolicy: boolean;
  ipReputationEnabled: boolean;
  // DDoS
  ddosEnabled: boolean;
  slowDdosEnabled: boolean;
  // Bot / abuse
  botDefenseEnabled: boolean;
  botPolicyName: string | null;
  maliciousUserEnabled: boolean;
  rateLimitEnabled: boolean;
  clientSideDefenseEnabled: boolean;
  threatMeshEnabled: boolean;
  // API
  apiDiscoveryEnabled: boolean;
  apiDefinitionAttached: boolean;
  // Identity
  userIdEnabled: boolean;
  userIdMode: 'policy' | 'client_ip' | 'none';
  // Exclusions
  wafExclusionCount: number;
  broadWafExclusions: number;
  // Hardening / derivative controls
  malwareProtectionEnabled: boolean;
  csrfState: 'enabled' | 'disabled' | 'none';
  corsConfigured: boolean;
  corsWildcardWithCreds: boolean;
  securityHeaderNames: string[];
  hasCommonSecurityHeaders: boolean;
  serverHeaderSuppressed: boolean;
  addLocationEnabled: boolean;
  maxRequestBytes: number | null;
  dataGuardCount: number;
  protectedCookieCount: number;
  cookiesHardened: boolean;
  routeWafDisabledCount: number;
  pathNormalize: TriState;
  trustedClientSkipsWafBroadly: boolean;
  slowDdosRequestTimeoutDisabled: boolean;
  // Misc
  domains: string[];
  routeCount: number;
}

export function getLBPosture(obj: unknown): LBPosture {
  const spec = getSpec(obj);
  const https = (spec.https_auto_cert || spec.https) as Rec | undefined;
  const httpsRec = asRec(https);

  // TLS
  const isHttps = 'https' in spec || 'https_auto_cert' in spec;
  const httpRedirect = spec.http_redirect === true || httpsRec.http_redirect === true;
  const hsts = spec.add_hsts_header === true || httpsRec.add_hsts === true;
  const tls = classifyTlsLevel(https);

  // WAF
  const appFirewall = spec.app_firewall;
  const wafExplicitlyDisabled = keyPresent(spec, 'disable_waf') && spec.disable_waf !== false;
  const wafEnabled = !wafExplicitlyDisabled && isNonEmptyRef(appFirewall);

  // Service policies
  const servicePolicies: string[] = [];
  const active = asRec(spec.active_service_policies).policies;
  if (Array.isArray(active)) {
    for (const p of active) {
      const n = refName(p);
      if (n) servicePolicies.push(n);
    }
  }
  const servicePoliciesFromNamespace = keyPresent(spec, 'service_policies_from_namespace');

  // DDoS — L7 auto-mitigation (l7_ddos_protection), manual mitigation rules, OR
  // DDoS detection enabled via the app-profile path (enable_ddos_detection /
  // single_lb_app.enable_ddos_detection / ddos_detection).
  const l7 = spec.l7_ddos_protection;
  const ddosRules = spec.ddos_mitigation_rules;
  const ddosDetectionEnabled =
    keyPresent(spec, 'enable_ddos_detection') ||
    asRec(spec.single_lb_app).enable_ddos_detection === true ||
    isNonEmptyObject(spec.ddos_detection);
  const ddosEnabled =
    (l7 != null && typeof l7 === 'object') ||
    (Array.isArray(ddosRules) && ddosRules.length > 0) ||
    ddosDetectionEnabled;
  // Slow-DDoS: system_default_timeouts (request_headers_timeout = 10000 ms) apply
  // when absent, so absence is NOT a gap. Only an explicit "no request timeout"
  // (disable_request_timeout) removes the total-request Slowloris guard.
  const slow = asRec(spec.slow_ddos_mitigation);
  // Any explicitly-tuned timeout counts as configured slow-DDoS mitigation —
  // not just the request-headers / total-request timeouts.
  const slowDdosEnabled = isNonEmptyObject(slow) &&
    (slow.request_headers_timeout !== undefined ||
      slow.request_timeout !== undefined ||
      slow.request_body_timeout !== undefined);
  const slowDdosRequestTimeoutDisabled = keyPresent(slow, 'disable_request_timeout');

  // Bot
  const botDefenseEnabled = !keyPresent(spec, 'disable_bot_defense') && isNonEmptyObject(spec.bot_defense);
  const botPolicyName = refName(asRec(spec.bot_defense).policy);

  // Malicious user
  const maliciousUserEnabled =
    !keyPresent(spec, 'disable_malicious_user_detection') &&
    (keyPresent(spec, 'enable_malicious_user_detection') || isNonEmptyRef(spec.malicious_user_mitigation));

  // Rate limit
  const rateLimitEnabled =
    !keyPresent(spec, 'disable_rate_limit') &&
    (isNonEmptyRef(spec.rate_limiter) || isNonEmptyObject(spec.rate_limit) || isNonEmptyObject(spec.api_rate_limit));

  // IP reputation
  const ipReputationEnabled = keyPresent(spec, 'enable_ip_reputation') && !keyPresent(spec, 'disable_ip_reputation');

  // Client-side defense
  const clientSideDefenseEnabled =
    !keyPresent(spec, 'disable_client_side_defense') && isNonEmptyObject(spec.client_side_defense);

  // Threat Mesh — the F5 console default is DISABLED (oneof enable/disable).
  // Enabled only when enable_threat_mesh is explicitly present.
  const threatMeshEnabled = keyPresent(spec, 'enable_threat_mesh') && !keyPresent(spec, 'disable_threat_mesh');

  // API discovery
  const apiDiscoveryEnabled = keyPresent(spec, 'enable_api_discovery') && !keyPresent(spec, 'disable_api_discovery');
  // API definition is attached via the legacy direct `api_definition` ref or the
  // newer `api_specification` oneof, which wraps the api_definition ref.
  const apiSpecification = asRec(spec.api_specification);
  const apiDefinitionAttached =
    isNonEmptyRef(spec.api_definition) ||
    isNonEmptyRef(apiSpecification.api_definition) ||
    isNonEmptyObject(spec.api_specification);

  // User identification
  let userIdMode: LBPosture['userIdMode'] = 'none';
  if (isNonEmptyRef(spec.user_identification)) userIdMode = 'policy';
  else if (keyPresent(spec, 'user_id_client_ip')) userIdMode = 'client_ip';

  // WAF exclusions live either in the legacy flat spec.waf_exclusion_rules[]
  // (deprecated) or the current spec.waf_exclusion.waf_exclusion_inline_rules.rules[]
  // wrapper. Read both shapes.
  const inlineWrapperRules = asRec(asRec(spec.waf_exclusion).waf_exclusion_inline_rules).rules;
  const exclusions = [
    ...(Array.isArray(spec.waf_exclusion_rules) ? (spec.waf_exclusion_rules as Rec[]) : []),
    ...(Array.isArray(inlineWrapperRules) ? (inlineWrapperRules as Rec[]) : []),
  ];
  let broad = 0;
  for (const e of exclusions) {
    const anyDomain = e.any_domain !== undefined;
    const regex = String(e.path_regex || '');
    const broadRegex = regex === '.*' || regex === '.+' || regex === '/.*' || regex === '/.+';
    const anyPath = e.any_path !== undefined;
    if ((anyDomain && (anyPath || broadRegex)) || broadRegex) broad++;
  }

  // Malware Protection is a licensed add-on, OFF by default — enabled only when
  // the positive setting is present (not merely "not disabled").
  const malwareProtectionEnabled = isNonEmptyObject(spec.malware_protection_settings);
  // CSRF: csrf_policy.disabled is a oneof member ({} = "allow all source
  // origins"), not a boolean — detect by key presence. Absent = not configured.
  const csrf = asRec(spec.csrf_policy);
  const csrfState: 'enabled' | 'disabled' | 'none' = !keyPresent(spec, 'csrf_policy')
    ? 'none'
    : keyPresent(csrf, 'disabled')
    ? 'disabled'
    : 'enabled';

  // CORS
  const cors = asRec(spec.cors_policy);
  const corsConfigured = keyPresent(spec, 'cors_policy') && cors.disabled !== true;
  const allowOrigins = [
    ...(Array.isArray(cors.allow_origin) ? (cors.allow_origin as string[]) : []),
    ...(Array.isArray(cors.allow_origin_regex) ? (cors.allow_origin_regex as string[]) : []),
  ].map((o) => String(o));
  const corsWildcardWithCreds =
    corsConfigured && cors.allow_credentials === true && allowOrigins.some((o) => o === '*' || o === '.*' || o === '.*$');

  // Response headers (security headers, server suppression, x-volterra-location)
  const more = asRec(spec.more_option);
  const respAdd = [
    ...(Array.isArray(spec.response_headers_to_add) ? (spec.response_headers_to_add as Rec[]) : []),
    ...(Array.isArray(more.response_headers_to_add) ? (more.response_headers_to_add as Rec[]) : []),
  ];
  const respRemove = [
    ...(Array.isArray(spec.response_headers_to_remove) ? (spec.response_headers_to_remove as string[]) : []),
    ...(Array.isArray(more.response_headers_to_remove) ? (more.response_headers_to_remove as string[]) : []),
  ].map((h) => String(h).toLowerCase());
  const securityHeaderNames = respAdd
    .map((h) => String(h.name || '').toLowerCase())
    .filter(Boolean);
  const SEC_HEADERS = ['x-frame-options', 'x-content-type-options', 'content-security-policy', 'referrer-policy', 'permissions-policy', 'strict-transport-security'];
  const hasCommonSecurityHeaders = SEC_HEADERS.some((h) => securityHeaderNames.includes(h));
  // Suppression = the Server header is REMOVED, or overwritten with a static value
  // via append=false. Merely appending a Server header does not hide the origin's.
  const serverHeaderSuppressed =
    respRemove.includes('server') ||
    respAdd.some((h) => String(h.name || '').toLowerCase() === 'server' && h.append === false);
  const addLocationEnabled = spec.add_location === true;

  // Request size limit (buffer policy)
  const bufferPolicy = asRec(more.buffer_policy);
  const maxRequestBytes = typeof bufferPolicy.max_request_bytes === 'number' ? (bufferPolicy.max_request_bytes as number) : null;

  // Data guard
  const dataGuardCount = Array.isArray(spec.data_guard_rules) ? (spec.data_guard_rules as unknown[]).length : 0;

  // Protected cookies
  const cookies = Array.isArray(spec.protected_cookies) ? (spec.protected_cookies as Rec[]) : [];
  // A cookie is hardened only when the LB explicitly adds the Secure and
  // HttpOnly attributes. `ignore_secure`/`ignore_httponly` (or neither side of
  // the oneof) means the LB does not enforce the flag, so it is not hardened.
  const cookiesHardened =
    cookies.length > 0 &&
    cookies.every((c) => keyPresent(c, 'add_secure') && keyPresent(c, 'add_httponly'));

  // Routes that disable WAF (per-route override). The WAF-disabling
  // advanced_options can sit on any route-type wrapper (simple_route,
  // redirect_route, direct_response_route, custom_route_object), so inspect
  // each wrapper rather than only simple_route.
  const routesArr = Array.isArray(spec.routes) ? (spec.routes as Rec[]) : [];
  const ROUTE_WRAPPERS = ['simple_route', 'redirect_route', 'direct_response_route', 'custom_route_object'];
  let routeWafDisabledCount = 0;
  for (const r of routesArr) {
    const disablesWaf = ROUTE_WRAPPERS.some((w) => keyPresent(asRec(asRec(r[w]).advanced_options), 'disable_waf'));
    if (disablesWaf) routeWafDisabledCount++;
  }

  // Path normalization can sit on the HTTPS/TLS block, the spec root (deprecated
  // there in current schema), or more_option. Report a tri-state so the rule can
  // SKIP — rather than warn — when it genuinely cannot be determined.
  const pnEnabled =
    keyPresent(httpsRec, 'enable_path_normalize') || keyPresent(spec, 'enable_path_normalize') || keyPresent(more, 'enable_path_normalize');
  const pnDisabled =
    keyPresent(httpsRec, 'disable_path_normalize') || keyPresent(spec, 'disable_path_normalize') || keyPresent(more, 'disable_path_normalize');
  const pathNormalize: TriState = pnEnabled ? 'enabled' : pnDisabled ? 'disabled' : 'unknown';

  // Trusted clients that skip WAF for an overly-broad IP scope (0.0.0.0/0 or ::/0).
  // An empty ip_prefix (rule keyed by ASN/header instead) is NOT treated as broad.
  const trustedClients = Array.isArray(spec.trusted_clients) ? (spec.trusted_clients as Rec[]) : [];
  const trustedClientSkipsWafBroadly = trustedClients.some((c) => {
    const prefix = String(c.ip_prefix || '');
    const actions = [
      ...(Array.isArray(c.actions) ? (c.actions as string[]) : []),
      ...(Array.isArray(c.skip_processing) ? (c.skip_processing as string[]) : []),
    ].map((a) => String(a).toUpperCase());
    const skipsWaf = actions.some((a) => a.includes('WAF'));
    const broadScope = prefix === '0.0.0.0/0' || prefix === '::/0';
    return skipsWaf && broadScope;
  });

  const domains = Array.isArray(spec.domains) ? (spec.domains as string[]) : [];
  const routes = spec.routes;
  const routeCount = Array.isArray(routes) ? routes.length : 0;

  return {
    isHttps,
    httpRedirect,
    hsts,
    tlsLevel: tls.level,
    tlsMinVersion: tls.minVersion,
    tlsPermitsLegacy: tls.permitsLegacyTls,
    wafEnabled,
    wafExplicitlyDisabled,
    wafPolicyName: refName(appFirewall),
    servicePolicies,
    servicePoliciesFromNamespace,
    hasServicePolicy: servicePolicies.length > 0 || servicePoliciesFromNamespace,
    ipReputationEnabled,
    ddosEnabled,
    slowDdosEnabled,
    botDefenseEnabled,
    botPolicyName,
    maliciousUserEnabled,
    rateLimitEnabled,
    clientSideDefenseEnabled,
    threatMeshEnabled,
    apiDiscoveryEnabled,
    apiDefinitionAttached,
    userIdEnabled: userIdMode !== 'none',
    userIdMode,
    wafExclusionCount: exclusions.length,
    broadWafExclusions: broad,
    malwareProtectionEnabled,
    csrfState,
    corsConfigured,
    corsWildcardWithCreds,
    securityHeaderNames,
    hasCommonSecurityHeaders,
    serverHeaderSuppressed,
    addLocationEnabled,
    maxRequestBytes,
    dataGuardCount,
    protectedCookieCount: cookies.length,
    cookiesHardened,
    routeWafDisabledCount,
    pathNormalize,
    trustedClientSkipsWafBroadly,
    slowDdosRequestTimeoutDisabled,
    domains,
    routeCount,
  };
}

// ───────────────────────────────────────────────────────────────────────────
// Origin Pool posture
// ───────────────────────────────────────────────────────────────────────────

export interface OriginPosture {
  originCount: number;
  tlsEnabled: boolean;
  noTls: boolean;
  skipVerify: boolean;
  usesTrustedCA: boolean;
  tlsLevel: TlsLevel;
  tlsPermitsLegacy: boolean;
  healthCheckCount: number;
  healthCheckRefs: Array<{ name: string; namespace?: string }>;
  algorithm: string;
  outlierDetection: TriState;
  circuitBreaker: boolean;
}

export function getOriginPosture(obj: unknown): OriginPosture {
  const spec = getSpec(obj);
  const origins = Array.isArray(spec.origin_servers) ? (spec.origin_servers as unknown[]) : [];

  const useTlsRaw = spec.use_tls;
  const noTls = keyPresent(spec, 'no_tls') || useTlsRaw === false;
  const useTls = asRec(typeof useTlsRaw === 'object' ? useTlsRaw : {});
  const tlsEnabled = !noTls && (useTlsRaw === true || isNonEmptyObject(useTlsRaw) || ('use_tls' in spec && useTlsRaw !== undefined && useTlsRaw !== false));

  const skipVerify = keyPresent(useTls, 'skip_server_verification');
  const usesTrustedCA = keyPresent(useTls, 'volterra_trusted_ca') || isNonEmptyObject(useTls.use_server_verification);
  const tls = classifyTlsLevel(useTls);

  const hcs = Array.isArray(spec.healthcheck) ? (spec.healthcheck as unknown[]) : [];
  const healthCheckRefs = hcs
    .map((h) => refName(h))
    .filter((n): n is string => !!n)
    .map((n) => ({ name: n }));

  const adv = asRec(spec.advanced_options);
  const outlierDetection: TriState = keyPresent(adv, 'disable_outlier_detection')
    ? 'disabled'
    : isNonEmptyObject(adv.outlier_detection)
    ? 'enabled'
    : 'unknown';
  const circuitBreaker = isNonEmptyObject(adv.circuit_breaker) || keyPresent(adv, 'default_circuit_breaker');

  return {
    originCount: origins.length,
    tlsEnabled,
    noTls,
    skipVerify,
    usesTrustedCA,
    tlsLevel: tls.level,
    tlsPermitsLegacy: tls.permitsLegacyTls,
    healthCheckCount: hcs.length,
    healthCheckRefs,
    algorithm: String(spec.loadbalancer_algorithm || ''),
    outlierDetection,
    circuitBreaker,
  };
}

// ───────────────────────────────────────────────────────────────────────────
// Health Check posture
// ───────────────────────────────────────────────────────────────────────────

export interface HealthCheckPosture {
  isHttp: boolean;
  hasExpectedCodes: boolean;
  expectedCodes: string[];
  interval: number | null;
  unhealthyThreshold: number | null;
  hasPath: boolean;
}

export function getHealthCheckPosture(obj: unknown): HealthCheckPosture {
  const spec = getSpec(obj);
  const http = asRec(spec.http_health_check);
  const isHttp = keyPresent(spec, 'http_health_check');
  const expectedCodes = Array.isArray(http.expected_status_codes) ? (http.expected_status_codes as unknown[]).map(String) : [];
  return {
    isHttp,
    hasExpectedCodes: expectedCodes.length > 0,
    expectedCodes,
    interval: typeof spec.interval === 'number' ? (spec.interval as number) : null,
    unhealthyThreshold: typeof spec.unhealthy_threshold === 'number' ? (spec.unhealthy_threshold as number) : null,
    hasPath: typeof http.path === 'string' && (http.path as string).length > 0,
  };
}

// ───────────────────────────────────────────────────────────────────────────
// Certificate posture
// ───────────────────────────────────────────────────────────────────────────

export interface CertPosture {
  expiryDays: number | null;
  expiryDate: string | null;
  blindfolded: boolean | null; // null = could not determine
  isCleartext: boolean;
  keyAlgorithm: string;
  weakKey: boolean | null; // true = RSA<2048; null = unknown
}

function daysUntil(dateStr: unknown): number | null {
  if (!dateStr || typeof dateStr !== 'string') return null;
  const t = Date.parse(dateStr);
  if (Number.isNaN(t)) return null;
  return Math.round((t - Date.now()) / 86_400_000);
}

export function getCertPosture(obj: unknown): CertPosture {
  const spec = getSpec(obj);

  // Expiry can appear in spec.infos[].expiry/not_after or status[].
  let expiry: string | null = null;
  const infos = Array.isArray(spec.infos) ? (spec.infos as Rec[]) : [];
  for (const info of infos) {
    expiry = expiry || (info.expiry as string) || (info.not_after as string) || null;
  }
  const status = asRec(obj).status;
  const statusArr = Array.isArray(status) ? (status as Rec[]) : status ? [asRec(status)] : [];
  for (const s of statusArr) {
    expiry = expiry || (s.not_after as string) || (s.expiry as string) || (s.expiration_timestamp as string) || null;
  }
  expiry = expiry || (spec.expiration_timestamp as string) || null;

  // Private key storage
  const pk = asRec(spec.private_key);
  const blindfolded =
    'blindfold_secret_info' in pk ||
    'blindfold_secret_info_internal' in pk ||
    'vault_secret_info' in pk ||
    'wingman_secret_info' in pk;
  const isCleartext = 'clear_secret_info' in pk || JSON.stringify(pk).includes('-----BEGIN');

  // Key algorithm / strength (best-effort from infos[].public_key_algorithm).
  let keyAlgorithm = '';
  for (const info of infos) {
    keyAlgorithm = keyAlgorithm || String(info.public_key_algorithm || '');
  }
  const algUpper = keyAlgorithm.toUpperCase();
  let weakKey: boolean | null = null;
  if (algUpper) {
    const rsaBits = algUpper.match(/RSA\D*(\d{3,4})/);
    if (rsaBits) weakKey = parseInt(rsaBits[1], 10) < 2048;
    else if (algUpper.includes('RSA') && (algUpper.includes('1024') || algUpper.includes('512'))) weakKey = true;
    else weakKey = false; // ECDSA / RSA-2048+ / EC
  }

  return {
    expiryDays: daysUntil(expiry),
    expiryDate: expiry,
    blindfolded: blindfolded ? true : isCleartext ? false : null,
    isCleartext,
    keyAlgorithm,
    weakKey,
  };
}

// ───────────────────────────────────────────────────────────────────────────
// Service Policy posture
// ───────────────────────────────────────────────────────────────────────────

export interface ServicePolicyPosture {
  ruleCount: number;
  hasAllowAll: boolean;
  hasDenyAll: boolean;
  hasGeoRule: boolean;
  hasBroadAllowPrefix: boolean;
}

// Only true allow-all source prefixes belong here. NOTE: 0.0.0.0/1 is the LOWER
// HALF of the IPv4 space (0–127.x), NOT allow-all — including it produced a false
// HIGH "trusts 0.0.0.0/0" failure on legitimately-scoped ALLOW rules.
const BROAD_PREFIXES = new Set(['0.0.0.0/0', '::/0', '0/0']);

export function getServicePolicyPosture(obj: unknown): ServicePolicyPosture {
  const spec = getSpec(obj);
  const ruleList = asRec(spec.rule_list);
  const rules = (Array.isArray(spec.rules) ? spec.rules : Array.isArray(ruleList.rules) ? ruleList.rules : []) as Rec[];

  const ruleIsAllow = (r: Rec) => String(asRec(r.spec || r).action || r.action || '').toUpperCase() === 'ALLOW';

  const hasAllowAll =
    keyPresent(spec, 'allow_all_requests') ||
    rules.some((r) => {
      const rspec = asRec(r.spec || r);
      // XC encodes the `any_client`/`any_ip` source choice as an empty-object
      // oneof member ({}), not a boolean — detect by key presence.
      const anyClient = keyPresent(rspec, 'any_client') || keyPresent(rspec, 'any_ip');
      return ruleIsAllow(r) && anyClient;
    });

  // An ALLOW rule whose inline IP prefix list contains 0.0.0.0/0 (allow-all source).
  const hasBroadAllowPrefix = rules.some((r) => {
    if (!ruleIsAllow(r)) return false;
    const prefixes = asRec(asRec(r.spec || r).ip_prefix_list).prefixes;
    return Array.isArray(prefixes) && (prefixes as unknown[]).some((p) => BROAD_PREFIXES.has(String(p)));
  });

  const denyList = asRec(spec.deny_list).rules;
  const hasDenyAll =
    keyPresent(spec, 'deny_all_requests') ||
    (Array.isArray(denyList) && (denyList as Rec[]).some((r) => keyPresent(asRec(r.spec || r), 'any_client')));

  const hasGeoRule = rules.some((r) => {
    const s = JSON.stringify(asRec(r.spec || r));
    return s.includes('country') || s.includes('geo') || s.includes('asn');
  });

  return { ruleCount: rules.length, hasAllowAll, hasDenyAll, hasGeoRule, hasBroadAllowPrefix };
}

// ───────────────────────────────────────────────────────────────────────────
// App Firewall (WAF) posture
// ───────────────────────────────────────────────────────────────────────────

export type WafMode = 'BLOCKING' | 'MONITORING' | 'AI_RISK_BASED' | 'UNKNOWN';
export type TriState = 'enabled' | 'disabled' | 'unknown';

export interface WafPosture {
  mode: WafMode;
  isBlocking: boolean;
  // Whether the policy detail (detection_settings) was actually available.
  hasDetectionSettings: boolean;
  threatCampaigns: TriState;
  highMediumSignatures: TriState;
  exclusionCount: number;
  botProtection: TriState;
  disabledAttackTypes: number;
  disabledViolations: number;
  cookieProtection: TriState;
}

export function getWafPosture(obj: unknown): WafPosture {
  const spec = getSpec(obj);

  let mode: WafMode = 'UNKNOWN';
  if (keyPresent(spec, 'blocking')) mode = 'BLOCKING';
  else if (keyPresent(spec, 'monitoring')) mode = 'MONITORING';
  else if (keyPresent(spec, 'ai_risk_based_blocking')) mode = 'AI_RISK_BASED';
  else if (typeof spec.mode === 'string') {
    const m = String(spec.mode).toUpperCase();
    mode = m.includes('BLOCK') ? 'BLOCKING' : m.includes('MONITOR') ? 'MONITORING' : 'UNKNOWN';
  }

  // detection_settings carries the bulk of a WAF policy's behaviour. If it is
  // absent we only have the thin list view — report sub-settings as "unknown"
  // rather than falsely claiming they are off.
  //
  // A policy using the `default_detection_settings` oneof member (instead of a
  // custom `detection_settings` object) is the F5 baseline: ALL attack types,
  // high+medium accuracy signatures, threat campaigns, all violations and
  // malicious-bot blocking are ON. Treat those sub-controls as enabled.
  const usesDefaultDetection = keyPresent(spec, 'default_detection_settings');
  const detection = asRec(spec.detection_settings);
  const hasDetectionSettings = isNonEmptyObject(detection) || usesDefaultDetection;

  // Threat campaigns: enabled by default. F5 XC represents the on-state as an
  // empty object `enable_threat_campaigns: {}` inside detection_settings.
  const tcEnabled =
    keyPresent(detection, 'enable_threat_campaigns') ||
    keyPresent(spec, 'enable_threat_campaigns') ||
    isNonEmptyObject(spec.threat_campaigns);
  const tcDisabled =
    keyPresent(detection, 'disable_threat_campaigns') || keyPresent(spec, 'disable_threat_campaigns');
  const threatCampaigns: TriState = usesDefaultDetection || tcEnabled
    ? 'enabled'
    : !hasDetectionSettings
    ? 'unknown'
    : tcDisabled
    ? 'disabled'
    : 'enabled'; // default-on when detail present but not explicitly disabled

  // High & medium accuracy signature set (default-on, under signature_selection_setting).
  const sigSel = asRec(detection.signature_selection_setting);
  const hmEnabled =
    keyPresent(sigSel, 'high_medium_accuracy_signatures') ||
    keyPresent(sigSel, 'high_medium_low_accuracy_signatures') ||
    keyPresent(sigSel, 'default_attack_type_settings');
  const highMediumSignatures: TriState = usesDefaultDetection ? 'enabled' : !hasDetectionSettings ? 'unknown' : hmEnabled ? 'enabled' : 'disabled';

  // Signature-based bot protection (malicious bot action should be BLOCK).
  const botSetting = asRec(detection.bot_protection_setting || spec.bot_protection_setting);
  const maliciousBotAction = String(botSetting.malicious_bot_action || '').toUpperCase();
  const hasBotSetting = isNonEmptyObject(botSetting);
  const botProtection: TriState = usesDefaultDetection
    ? 'enabled' // baseline default: malicious bots blocked
    : !hasDetectionSettings && !hasBotSetting
    ? 'unknown'
    : maliciousBotAction === 'BLOCK'
    ? 'enabled'
    : hasBotSetting
    ? 'disabled'
    : 'unknown';

  // Disabled attack types / violations (fewer is better; 0 = full coverage).
  const attackTypeSettings = asRec(sigSel.attack_type_settings);
  const disabledAttackTypes = Array.isArray(attackTypeSettings.disabled_attack_types)
    ? (attackTypeSettings.disabled_attack_types as unknown[]).length
    : 0;
  const violationSettings = asRec(detection.violation_settings);
  const disabledViolations = Array.isArray(violationSettings.disabled_violation_types)
    ? (violationSettings.disabled_violation_types as unknown[]).length
    : 0;

  // Cookie protection setting on the WAF policy (secure/httponly/samesite).
  const cookieSetting = asRec(spec.cookie_protection_setting);
  const cookieProtection: TriState = isNonEmptyObject(cookieSetting)
    ? cookieSetting.add_secure_attribute === true || cookieSetting.add_httponly_attribute === true || keyPresent(cookieSetting, 'add_samesite_attribute')
      ? 'enabled'
      : 'disabled'
    : 'unknown';

  // WAF rule-activity exclusions (suppressed signatures/violations). `blocking_page`
  // is a custom response page, NOT an exclusions list, so it must not be a fallback.
  const exclusions = spec.rule_activity_exclusions;
  const exclusionCount = Array.isArray(exclusions) ? exclusions.length : 0;

  return {
    mode,
    isBlocking: mode === 'BLOCKING' || mode === 'AI_RISK_BASED',
    hasDetectionSettings,
    threatCampaigns,
    highMediumSignatures,
    exclusionCount,
    botProtection,
    disabledAttackTypes,
    disabledViolations,
    cookieProtection,
  };
}

// ───────────────────────────────────────────────────────────────────────────
// HTTP Load Balancer — v2 advanced posture (mTLS, exposure, API depth, headers)
// ───────────────────────────────────────────────────────────────────────────

export interface LBAdvancedPosture {
  // Downstream (client) mTLS
  mtlsEnabled: boolean;
  mtlsCrlAttached: boolean;
  mtlsClientCertOptional: boolean;
  // Exposure
  advertiseScope: 'public_default' | 'public_custom' | 'custom_internal' | 'none' | 'unknown';
  domainWildcard: 'bare' | 'subdomain' | 'none';
  // Real-client-IP extraction (XFF trust) behind CDN/proxy
  trustClientIpHeaders: boolean;
  // Challenge ladder
  challengeConfigured: boolean;
  // API security depth
  openApiValidation: 'block' | 'report' | 'disabled' | 'none';
  openApiFallThroughAllow: boolean;
  jwtValidation: 'block' | 'report' | 'none';
  apiProtectionRuleCount: number;
  sensitiveDataPolicy: 'custom' | 'default' | 'none';
  graphqlRuleCount: number;
  graphqlIntrospectionDisabled: boolean;
  graphqlHasLimits: boolean;
  apiEndpointRateLimitCount: number;
  // Malicious-user mitigation action
  maliciousUserMitigation: 'policy' | 'default' | 'none';
  maliciousUserDetectionEnabled: boolean;
  // Server header oneof
  serverHeaderMode: 'pass_through' | 'overwrite' | 'append' | 'default' | 'removed' | 'unknown';
  // Presence hints for SKIP logic on conditional rules
  botDefenseEnabled: boolean;
  clientSideDefenseEnabled: boolean;
  servesApi: boolean;
}

export function getLBAdvancedPosture(obj: unknown): LBAdvancedPosture {
  const spec = getSpec(obj);
  const https = asRec(spec.https_auto_cert || spec.https);
  const certParams = asRec(https.tls_cert_params);
  const useMtls = asRec(https.use_mtls || certParams.use_mtls);
  const mtlsEnabled = keyPresent(https, 'use_mtls') || keyPresent(certParams, 'use_mtls');
  const mtlsCrlAttached = isNonEmptyRef(useMtls.crl) || isNonEmptyObject(useMtls.crl);
  // Only OPTIONAL when the flag is truthy. An explicit `client_certificate_optional: false`
  // means the client cert is REQUIRED, so key-presence alone must not flag it as optional.
  const mtlsClientCertOptional = useMtls.client_certificate_optional === true;

  const advertiseScope: LBAdvancedPosture['advertiseScope'] =
    keyPresent(spec, 'advertise_on_public_default_vip') ? 'public_default'
    : keyPresent(spec, 'advertise_on_public') ? 'public_custom'
    : keyPresent(spec, 'advertise_custom') ? 'custom_internal'
    : keyPresent(spec, 'do_not_advertise') ? 'none'
    : 'unknown';

  const domains = Array.isArray(spec.domains) ? (spec.domains as unknown[]).map(String) : [];
  const domainWildcard: LBAdvancedPosture['domainWildcard'] =
    domains.some((d) => d.trim() === '*') ? 'bare'
    : domains.some((d) => d.includes('*')) ? 'subdomain'
    : 'none';

  const trustClientIpHeaders =
    isNonEmptyObject(spec.enable_trust_client_ip_headers) ||
    isNonEmptyObject(spec.trusted_client_ip_headers) ||
    (keyPresent(spec, 'enable_trust_client_ip_headers') && !keyPresent(spec, 'disable_trust_client_ip_headers'));

  const challengeConfigured =
    keyPresent(spec, 'js_challenge') || keyPresent(spec, 'captcha_challenge') ||
    keyPresent(spec, 'policy_based_challenge') || keyPresent(spec, 'enable_challenge') ||
    (typeof spec.challenge_type === 'string' && spec.challenge_type.toLowerCase() !== 'no_challenge' && spec.challenge_type !== '');

  // OpenAPI validation depth
  const apiSpec = asRec(spec.api_specification);
  const valTarget = asRec(apiSpec.validation_all_spec_endpoints || apiSpec.validation_custom_list);
  const valModeObj = asRec(valTarget.validation_mode);
  const valActive = asRec(valModeObj.validation_mode_active);
  let openApiValidation: LBAdvancedPosture['openApiValidation'] = 'none';
  if (!isNonEmptyObject(spec.api_specification)) openApiValidation = 'none';
  else if (keyPresent(apiSpec, 'validation_disabled')) openApiValidation = 'disabled';
  else if (keyPresent(valActive, 'enforcement_block')) openApiValidation = 'block';
  else if (keyPresent(valActive, 'enforcement_report') || keyPresent(valModeObj, 'validation_mode_skip')) openApiValidation = 'report';
  else if (isNonEmptyObject(valTarget)) openApiValidation = 'report';
  const ft = asRec(valTarget.fall_through_mode);
  const openApiFallThroughAllow = keyPresent(ft, 'fall_through_mode_allow');

  const jwt = asRec(spec.jwt_validation);
  const jwtAction = asRec(jwt.action);
  let jwtValidation: LBAdvancedPosture['jwtValidation'] = 'none';
  if (isNonEmptyObject(spec.jwt_validation)) {
    jwtValidation = keyPresent(jwtAction, 'block') || String(jwt.action || '').toLowerCase().includes('block') ? 'block' : 'report';
  }

  const apiProt = asRec(spec.api_protection_rules);
  const apiProtectionRuleCount =
    (Array.isArray(apiProt.api_endpoint_rules) ? apiProt.api_endpoint_rules.length : 0) +
    (Array.isArray(apiProt.api_groups_rules) ? apiProt.api_groups_rules.length : 0) +
    (Array.isArray(apiProt.api_groups) ? apiProt.api_groups.length : 0);

  const sensitiveDataPolicy: LBAdvancedPosture['sensitiveDataPolicy'] =
    isNonEmptyRef(spec.sensitive_data_policy) ? 'custom'
    : keyPresent(spec, 'default_sensitive_data_policy') || isNonEmptyObject(spec.sensitive_data_disclosure_rules) ? 'default'
    : 'none';

  const graphqlRules = Array.isArray(spec.graphql_rules) ? (spec.graphql_rules as Rec[]) : [];
  const graphqlRuleCount = graphqlRules.length;
  const graphqlIntrospectionDisabled =
    graphqlRules.length > 0 &&
    graphqlRules.every((g) => {
      const s = asRec(g.graphql_settings);
      return keyPresent(s, 'disable_introspection') || s.disable_introspection === true;
    });
  const graphqlHasLimits = graphqlRules.some((g) => {
    const s = asRec(g.graphql_settings);
    return s.max_depth !== undefined || s.max_batched_queries !== undefined;
  });

  const apiRl = asRec(spec.api_rate_limit);
  const apiEndpointRateLimitCount =
    (Array.isArray(apiRl.api_endpoint_rules) ? apiRl.api_endpoint_rules.length : 0) +
    (Array.isArray(apiRl.server_url_rules) ? apiRl.server_url_rules.length : 0);

  const maliciousUserDetectionEnabled =
    !keyPresent(spec, 'disable_malicious_user_detection') &&
    (keyPresent(spec, 'enable_malicious_user_detection') || isNonEmptyRef(spec.malicious_user_mitigation));
  const maliciousUserMitigation: LBAdvancedPosture['maliciousUserMitigation'] =
    isNonEmptyRef(spec.malicious_user_mitigation) ? 'policy'
    : keyPresent(spec, 'policy_based_challenge') ? 'policy'
    : maliciousUserDetectionEnabled ? 'default'
    : 'none';

  const more = asRec(spec.more_option);
  const respRemove = [
    ...(Array.isArray(spec.response_headers_to_remove) ? (spec.response_headers_to_remove as unknown[]) : []),
    ...(Array.isArray(more.response_headers_to_remove) ? (more.response_headers_to_remove as unknown[]) : []),
  ].map((h) => String(h).toLowerCase());
  let serverHeaderMode: LBAdvancedPosture['serverHeaderMode'] = 'unknown';
  if (respRemove.includes('server')) serverHeaderMode = 'removed';
  else if (keyPresent(more, 'pass_through')) serverHeaderMode = 'pass_through';
  else if (keyPresent(more, 'server_name')) serverHeaderMode = 'overwrite';
  else if (keyPresent(more, 'append_server_name')) serverHeaderMode = 'append';
  else if (keyPresent(more, 'default_header')) serverHeaderMode = 'default';

  const botDefenseEnabled = !keyPresent(spec, 'disable_bot_defense') && isNonEmptyObject(spec.bot_defense);
  const clientSideDefenseEnabled = !keyPresent(spec, 'disable_client_side_defense') && isNonEmptyObject(spec.client_side_defense);
  const servesApi =
    isNonEmptyObject(spec.api_specification) || isNonEmptyRef(spec.api_definition) ||
    keyPresent(spec, 'enable_api_discovery') || apiProtectionRuleCount > 0 || graphqlRuleCount > 0 ||
    isNonEmptyObject(spec.jwt_validation) || apiEndpointRateLimitCount > 0;

  return {
    mtlsEnabled, mtlsCrlAttached, mtlsClientCertOptional, advertiseScope, domainWildcard,
    trustClientIpHeaders, challengeConfigured, openApiValidation, openApiFallThroughAllow,
    jwtValidation, apiProtectionRuleCount, sensitiveDataPolicy, graphqlRuleCount,
    graphqlIntrospectionDisabled, graphqlHasLimits, apiEndpointRateLimitCount,
    maliciousUserMitigation, maliciousUserDetectionEnabled, serverHeaderMode,
    botDefenseEnabled, clientSideDefenseEnabled, servesApi,
  };
}

// ───────────────────────────────────────────────────────────────────────────
// Origin Pool — v2 advanced posture (SNI, origin mTLS, exposure/cloaking)
// ───────────────────────────────────────────────────────────────────────────

export interface OriginAdvancedPosture {
  tlsEnabled: boolean;
  sniMode: 'explicit' | 'host_header' | 'disabled' | 'none';
  serverVerifying: boolean;
  originMtls: boolean;
  exposure: 'public' | 'private' | 'mixed' | 'none';
}

export function getOriginAdvancedPosture(obj: unknown): OriginAdvancedPosture {
  const spec = getSpec(obj);
  const useTlsRaw = spec.use_tls;
  const noTls = keyPresent(spec, 'no_tls') || useTlsRaw === false;
  const useTls = asRec(typeof useTlsRaw === 'object' ? useTlsRaw : {});
  const tlsEnabled = !noTls && (useTlsRaw === true || isNonEmptyObject(useTlsRaw));
  const serverVerifying = keyPresent(useTls, 'volterra_trusted_ca') || isNonEmptyObject(useTls.use_server_verification);
  const sniMode: OriginAdvancedPosture['sniMode'] =
    keyPresent(useTls, 'use_host_header_as_sni') ? 'host_header'
    : typeof useTls.sni === 'string' && (useTls.sni as string).length > 0 ? 'explicit'
    : keyPresent(useTls, 'disable_sni') ? 'disabled'
    : 'none';
  const originMtls = keyPresent(useTls, 'use_mtls') && !keyPresent(useTls, 'no_mtls');
  const servers = Array.isArray(spec.origin_servers) ? (spec.origin_servers as Rec[]) : [];
  let pub = 0, priv = 0;
  for (const s of servers) {
    if (keyPresent(s, 'public_ip') || keyPresent(s, 'public_name')) pub++;
    else if (keyPresent(s, 'private_ip') || keyPresent(s, 'private_name') || keyPresent(s, 'k8s_service') || keyPresent(s, 'consul_service')) priv++;
  }
  const exposure: OriginAdvancedPosture['exposure'] =
    servers.length === 0 ? 'none' : pub > 0 && priv > 0 ? 'mixed' : pub > 0 ? 'public' : 'private';
  return { tlsEnabled, sniMode, serverVerifying, originMtls, exposure };
}

// DNSSEC mode on a DNS zone's primary config (for TENANT-DNS-01).
export function getDnsZoneDnssec(obj: unknown): 'enabled' | 'disabled' | 'unknown' {
  const spec = getSpec(obj);
  const mode = asRec(asRec(spec.primary).dnssec_mode);
  if (keyPresent(mode, 'enable')) return 'enabled';
  if (keyPresent(mode, 'disable')) return 'disabled';
  return 'unknown';
}

// Log types carried by a global_log_receiver (for TENANT-LOG-02). XC encodes the
// stream as a oneof on the receiver spec; tolerate several shapes.
export function getLogReceiverTypes(obj: unknown): { access: boolean; security: boolean; audit: boolean; dns: boolean } {
  const spec = getSpec(obj);
  const blob = JSON.stringify(spec).toLowerCase();
  const has = (...keys: string[]) => keys.some((k) => keyPresent(spec, k)) || keys.some((k) => blob.includes(k));
  return {
    access: has('http_access_logs', 'access_logs', 'request_logs'),
    security: has('security_events', 'waf_security_events', 'app_security'),
    audit: has('audit_logs'),
    dns: has('dns_request_logs', 'dns_logs'),
  };
}
