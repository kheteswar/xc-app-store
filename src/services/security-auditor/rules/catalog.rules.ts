// ═══════════════════════════════════════════════════════════════════════════
// Security Check Catalog
//
// The single, authoritative set of security checks for the Security Auditor.
// Every check reads real F5 XC config fields via xc-extractors (verified
// against api-shield/config-scanner.ts and types/index.ts). This replaces the
// earlier scattered rule files that read incorrect / guessed field paths.
//
// Each check carries the customer-facing framing from the F5 XC Proactive
// Assessment checklist: risk (High/Med/Low), entitlement (Base/Add-on/Config),
// an expected value, and remediation.
// ═══════════════════════════════════════════════════════════════════════════

import type { SecurityRule, CheckResult, AuditContext } from '../types';
import {
  getLBPosture,
  getOriginPosture,
  getCertPosture,
  getServicePolicyPosture,
  getWafPosture,
  getHealthCheckPosture,
  getLBAdvancedPosture,
  getOriginAdvancedPosture,
  getDnsZoneDnssec,
  getLogReceiverTypes,
} from '../xc-extractors';

const DOCS = 'https://docs.cloud.f5.com/docs';

const pass = (message: string, currentValue?: unknown, expectedValue?: unknown): CheckResult => ({
  status: 'PASS', message, currentValue, expectedValue,
});
const fail = (message: string, currentValue?: unknown, expectedValue?: unknown): CheckResult => ({
  status: 'FAIL', message, currentValue, expectedValue,
});
const warn = (message: string, currentValue?: unknown, expectedValue?: unknown): CheckResult => ({
  status: 'WARN', message, currentValue, expectedValue,
});
const skip = (message: string): CheckResult => ({ status: 'SKIP', message });
// INFO = "confirm intent" — surfaced for review, excluded from the score.
const info = (message: string, currentValue?: unknown, expectedValue?: unknown): CheckResult => ({
  status: 'INFO', message, currentValue, expectedValue,
});

// ═══════════════════════════════════════════════════════════════════════════
// HTTP LOAD BALANCER — TLS / TRANSPORT
// ═══════════════════════════════════════════════════════════════════════════

const LB_HTTPS: SecurityRule = {
  id: 'TLS-01',
  name: 'Load Balancer Serves HTTPS',
  description: 'Public HTTP load balancers should serve traffic over HTTPS. An HTTP-only listener exposes all traffic in plaintext.',
  category: 'TLS_SSL', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'HTTPS (auto or custom cert)',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Edit the load balancer and set the listener type to "HTTPS with Automatic Certificate" (or a custom certificate), then enable HTTP redirect to HTTPS.',
  referenceUrl: `${DOCS}/how-to/app-networking/http-load-balancer`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.isHttps
      ? pass('Load balancer serves traffic over HTTPS', 'HTTPS', 'HTTPS')
      : fail('Load balancer is HTTP-only — traffic is unencrypted', 'HTTP', 'HTTPS');
  },
};

const LB_REDIRECT: SecurityRule = {
  id: 'TLS-02',
  name: 'HTTP to HTTPS Redirect',
  description: 'HTTP requests should be redirected to HTTPS so no plaintext traffic reaches the application.',
  category: 'TLS_SSL', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'Enabled',
  appliesTo: ['http_loadbalancer'],
  remediation: 'In the load balancer HTTPS settings, enable "HTTP Redirect to HTTPS".',
  referenceUrl: `${DOCS}/how-to/app-networking/http-load-balancer`,
  check: (obj) => {
    const p = getLBPosture(obj);
    if (!p.isHttps) return skip('HTTP-only load balancer — redirect not applicable (see TLS-01)');
    return p.httpRedirect
      ? pass('HTTP to HTTPS redirect is enabled', 'Enabled', 'Enabled')
      : fail('HTTP to HTTPS redirect is not enabled', 'Disabled', 'Enabled');
  },
};

const LB_HSTS: SecurityRule = {
  id: 'TLS-03',
  name: 'HSTS Header Enabled',
  description: 'HSTS instructs browsers to only use HTTPS for the domain, preventing protocol-downgrade attacks.',
  category: 'TLS_SSL', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Enabled',
  appliesTo: ['http_loadbalancer'],
  remediation: 'In the load balancer HTTPS settings, enable "Add HSTS Header".',
  referenceUrl: `${DOCS}/how-to/app-networking/http-load-balancer`,
  check: (obj) => {
    const p = getLBPosture(obj);
    if (!p.isHttps) return skip('HTTP-only load balancer — HSTS not applicable');
    return p.hsts
      ? pass('HSTS header is enabled', 'Enabled', 'Enabled')
      : fail('HSTS header is not enabled', 'Disabled', 'Enabled');
  },
};

const LB_TLS_LEVEL: SecurityRule = {
  id: 'TLS-04',
  name: 'TLS Security Level (Medium+)',
  description: 'TLS should use the Default/High profile (TLS 1.2+). Per F5\'s TLS Reference, the Medium and Low presets both permit TLS 1.0/1.1 (Low also adds non-PFS ciphers).',
  category: 'TLS_SSL', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'Default / High (TLS 1.2+)',
  appliesTo: ['http_loadbalancer'],
  remediation: 'In the load balancer HTTPS / TLS settings, set the TLS Security Level to Default/High (TLS 1.2+). Avoid the Medium and Low presets, which permit TLS 1.0/1.1.',
  referenceUrl: `${DOCS}/how-to/app-networking/http-load-balancer`,
  check: (obj) => {
    const p = getLBPosture(obj);
    if (!p.isHttps) return skip('HTTP-only load balancer — TLS level not applicable');
    if (p.tlsLevel === 'LOW') {
      const cur = p.tlsMinVersion ? `Low (${p.tlsMinVersion})` : 'Low';
      return fail('TLS security level is Low — permits TLS 1.0/1.1 and weak (non-PFS) ciphers', cur, 'Default/High (TLS 1.2+)');
    }
    if (p.tlsPermitsLegacy) {
      // medium_security preset (or an explicit min TLS 1.0/1.1) — TLS 1.0/1.1 allowed.
      return warn('TLS "Medium" level permits TLS 1.0/1.1', `Medium (${p.tlsMinVersion || 'TLS 1.0+'})`, 'Default/High (TLS 1.2+)');
    }
    const label = p.tlsLevel === 'DEFAULT' ? 'Default (TLS 1.2+)' : p.tlsMinVersion ? `${p.tlsLevel} (${p.tlsMinVersion})` : p.tlsLevel;
    return pass(`TLS security level is ${label}`, label, 'Default/High (TLS 1.2+)');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// HTTP LOAD BALANCER — WAF
// ═══════════════════════════════════════════════════════════════════════════

const LB_WAF: SecurityRule = {
  id: 'WAF-01',
  name: 'WAF (App Firewall) Attached',
  description: 'An Application Firewall (WAF) policy should be attached to the load balancer. WAF is disabled by default and must be explicitly enabled.',
  category: 'WAF', severity: 'CRITICAL', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'WAF policy attached',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Attach an Application Firewall policy to the load balancer (Security Configuration → Web Application Firewall → Enable).',
  referenceUrl: `${DOCS}/how-to/app-security/cfg-waf`,
  check: (obj) => {
    const p = getLBPosture(obj);
    if (p.wafEnabled) return pass(`WAF policy "${p.wafPolicyName}" is attached`, p.wafPolicyName, 'Attached');
    if (p.wafExplicitlyDisabled) return fail('WAF is explicitly disabled on this load balancer', 'disable_waf', 'Attached');
    return fail('No WAF policy attached to this load balancer', 'None', 'Attached');
  },
};

const LB_WAF_EXCLUSIONS: SecurityRule = {
  id: 'WAF-02',
  name: 'No Broad WAF Exclusions',
  description: 'WAF exclusion rules matching any domain and any path (or path regex ".*") silence the WAF across the whole application.',
  category: 'WAF', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'Narrow, endpoint-specific exclusions only',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Replace any "any domain / any path" exclusion (or ".*" path regex) with narrow exclusions scoped to the exact signature and path.',
  referenceUrl: `${DOCS}/how-to/app-security/configure-waf-exclusion-rules`,
  check: (obj) => {
    const p = getLBPosture(obj);
    if (p.wafExclusionCount === 0) return pass('No WAF exclusion rules configured', '0 exclusions', 'Narrow only');
    if (p.broadWafExclusions > 0) return fail(`${p.broadWafExclusions} of ${p.wafExclusionCount} exclusion rule(s) match all traffic`, `${p.broadWafExclusions} broad`, 'Narrow only');
    return pass(`${p.wafExclusionCount} exclusion rule(s), all endpoint-specific`, `${p.wafExclusionCount} narrow`, 'Narrow only');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// HTTP LOAD BALANCER — ACCESS CONTROL / THREAT INTEL
// ═══════════════════════════════════════════════════════════════════════════

const LB_SERVICE_POLICY: SecurityRule = {
  id: 'AC-01',
  name: 'Service Policy Applied',
  description: 'A service policy controls allow/deny at L7. With no policy, traffic is implicitly allowed.',
  category: 'ACCESS_CONTROL', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Active or namespace service policy',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Apply an active service policy (or inherit the namespace service policy set) on the load balancer.',
  referenceUrl: `${DOCS}/how-to/advanced-security/service-policies`,
  check: (obj) => {
    const p = getLBPosture(obj);
    if (p.servicePolicies.length > 0) return pass(`Service policies: ${p.servicePolicies.join(', ')}`, p.servicePolicies.join(', '), '≥1 policy');
    if (p.servicePoliciesFromNamespace) return pass('Inherits namespace service policies', 'from namespace', '≥1 policy');
    return warn('No service policy applied — traffic is implicitly allowed', 'None', '≥1 policy');
  },
};

const LB_IP_REPUTATION: SecurityRule = {
  id: 'AC-02',
  name: 'IP Reputation Enabled',
  description: 'IP Reputation blocks known-malicious source IPs using F5 threat intelligence. Part of the base bundle; off by default, so enabling it is a recommended hardening step rather than a hard requirement.',
  category: 'ACCESS_CONTROL', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Enabled',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Enable IP Reputation on the load balancer (Security Configuration → enable IP Reputation).',
  referenceUrl: `${DOCS}/how-to/advanced-security`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.ipReputationEnabled
      ? pass('IP Reputation is enabled', 'Enabled', 'Enabled')
      : warn('IP Reputation is not enabled — recommended to block known-malicious source IPs', 'Disabled', 'Enabled');
  },
};

const LB_THREAT_MESH: SecurityRule = {
  id: 'AC-03',
  name: 'Threat Mesh Enabled',
  description: 'Threat Mesh shares cross-tenant threat intelligence. The F5 console default is Disabled, so it must be explicitly enabled.',
  category: 'ACCESS_CONTROL', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Enabled',
  verify: 'assisted',
  verifyNote: 'Threat Mesh is off by default; leaving it off is a valid choice — confirm whether cross-tenant threat sharing is wanted.',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Enable Threat Mesh in the load balancer Security Configuration to share cross-tenant threat intelligence.',
  referenceUrl: `${DOCS}/how-to/advanced-security`,
  check: (obj) => {
    const p = getLBPosture(obj);
    // F5 default is Disabled, so "not enabled" is the common, benign case → surface as review (INFO),
    // not a score-dragging FAIL. Only an explicit-disable would warrant a stronger signal.
    return p.threatMeshEnabled
      ? pass('Threat Mesh is enabled', 'Enabled', 'Enabled')
      : info('Threat Mesh is not enabled (F5 default) — enable it to share cross-tenant threat intelligence', 'Disabled', 'Enabled');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// HTTP LOAD BALANCER — DDoS
// ═══════════════════════════════════════════════════════════════════════════

const LB_DDOS: SecurityRule = {
  id: 'DDOS-01',
  name: 'L7 DDoS Protection',
  description: 'L7 DDoS auto-mitigation protects against application-layer floods. Distinct from network-layer DDoS.',
  category: 'DDOS', severity: 'MEDIUM', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'Configured',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Configure L7 DDoS protection (auto-mitigation) or DDoS mitigation rules on the load balancer.',
  referenceUrl: `${DOCS}/how-to/app-security/ddos-mitigation`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.ddosEnabled
      ? pass('L7 DDoS protection is configured', 'Configured', 'Configured')
      : warn('No L7 DDoS protection configured', 'Not configured', 'Configured');
  },
};

const LB_SLOW_DDOS: SecurityRule = {
  id: 'DDOS-02',
  name: 'Slow-Request (Slowloris) Mitigation',
  description: 'Request-header / request timeouts mitigate slow-loris attacks. XC applies system-default timeouts (request-headers timeout ≈ 10s) when not customised, so this only fails when the total request timeout is explicitly disabled.',
  category: 'DDOS', severity: 'LOW', risk: 'Low', entitlement: 'Base',
  expectedDisplay: 'Configured or system default (not disabled)',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Keep the request-headers / request timeout (or system defaults); do not select "No Request Timeout" unless required.',
  referenceUrl: `${DOCS}/how-to/app-security/ddos-mitigation`,
  check: (obj) => {
    const p = getLBPosture(obj);
    if (p.slowDdosRequestTimeoutDisabled) return warn('Total request timeout is explicitly disabled — Slowloris exposure', 'Disabled', 'Enabled / system default');
    return p.slowDdosEnabled
      ? pass('Slow-request mitigation timeouts are explicitly tuned', 'Configured', 'Configured')
      : info('Not configured — system default slow-DDoS timeouts apply (request-headers timeout ≈ 10s). Tune for long-poll/upload apps.', 'System default', 'Defaults acceptable; tune for long-poll/upload');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// HTTP LOAD BALANCER — BOT / ABUSE
// ═══════════════════════════════════════════════════════════════════════════

const LB_BOT: SecurityRule = {
  id: 'BOT-01',
  name: 'Bot Defense Attached',
  description: 'Bot Defense detects and mitigates automated attacks (credential stuffing, scraping, carding). Requires a licensed add-on.',
  category: 'BOT_DEFENSE', severity: 'HIGH', risk: 'High', entitlement: 'Entitlement',
  expectedDisplay: 'Bot Defense policy attached',
  verify: 'assisted',
  verifyNote: 'A Bot Defense policy being attached does not confirm it is enforcing (vs monitoring) or covers the right endpoints — verify the policy.',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Attach a Bot Defense policy to the load balancer (requires Bot Defense Standard/Advanced license).',
  referenceUrl: `${DOCS}/how-to/app-security/bot-defense`,
  check: (obj) => {
    const p = getLBPosture(obj);
    // Licensed add-on: absence is a review item (may not be licensed / needed), not a score-dragging WARN.
    return p.botDefenseEnabled
      ? pass(`Bot Defense attached${p.botPolicyName ? ` (${p.botPolicyName})` : ''}`, p.botPolicyName || 'Enabled', 'Attached')
      : info('Bot Defense is not attached (requires a Bot Defense license)', 'Not attached', 'Attached');
  },
};

const LB_MAL_USER: SecurityRule = {
  id: 'BOT-02',
  name: 'Malicious User Detection',
  description: 'Behavioral analysis that scores users and mitigates high-risk ones (challenge/block). Included in the base bundle.',
  category: 'BOT_DEFENSE', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Enabled',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Enable Malicious User Detection on the load balancer (and configure a mitigation policy / user identifier).',
  referenceUrl: `${DOCS}/how-to/app-security/malicious-users`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.maliciousUserEnabled
      ? pass('Malicious User Detection is enabled', 'Enabled', 'Enabled')
      : warn('Malicious User Detection is not enabled', 'Disabled', 'Enabled');
  },
};

const LB_RATE_LIMIT: SecurityRule = {
  id: 'RL-01',
  name: 'Rate Limiting Configured',
  description: 'Rate limiting protects against brute-force and volumetric abuse. Metered add-on.',
  category: 'RATE_LIMITING', severity: 'MEDIUM', risk: 'Med', entitlement: 'Entitlement',
  expectedDisplay: 'Configured',
  verify: 'assisted',
  verifyNote: 'A rate limiter being present does not mean the threshold is protective — a limit far above real peak traffic offers little protection. Confirm the threshold against observed peak.',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Configure a rate limiter (with an appropriate user identifier) on the load balancer.',
  referenceUrl: `${DOCS}/how-to/app-security/rate-limiting`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.rateLimitEnabled
      ? pass('Rate limiting is configured', 'Configured', 'Configured')
      : info('Rate limiting is not configured (metered add-on)', 'Not configured', 'Configured');
  },
};

const LB_CSD: SecurityRule = {
  id: 'CSD-01',
  name: 'Client-Side Defense',
  description: 'Client-Side Defense protects against Magecart / formjacking / skimming attacks. Requires a licensed add-on.',
  category: 'CLIENT_SECURITY', severity: 'MEDIUM', risk: 'High', entitlement: 'Entitlement',
  expectedDisplay: 'Enabled on payment/e-commerce LBs',
  verify: 'assisted',
  verifyNote: 'Client-Side Defense is only relevant on LBs serving payment / sensitive forms — confirm applicability for this application before treating absence as a gap.',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Enable Client-Side Defense on load balancers serving payment / sensitive forms (requires license).',
  referenceUrl: `${DOCS}/how-to/app-security/client-side-defense`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.clientSideDefenseEnabled
      ? pass('Client-Side Defense is enabled', 'Enabled', 'Enabled')
      : info('Client-Side Defense is not enabled (licensed add-on; relevant for payment/e-commerce LBs)', 'Disabled', 'Enabled (where applicable)');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// HTTP LOAD BALANCER — API SECURITY / IDENTITY
// ═══════════════════════════════════════════════════════════════════════════

const LB_API_DISCOVERY: SecurityRule = {
  id: 'API-01',
  name: 'API Discovery Enabled',
  description: 'API Discovery passively learns API endpoints from traffic, surfacing shadow and zombie APIs. Included in the base bundle.',
  category: 'API_SECURITY', severity: 'MEDIUM', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'Enabled',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Enable API Discovery on the load balancer and review the discovered inventory periodically.',
  referenceUrl: `${DOCS}/how-to/app-security/api-discovery`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.apiDiscoveryEnabled
      ? pass('API Discovery is enabled', 'Enabled', 'Enabled')
      : warn('API Discovery is not enabled', 'Disabled', 'Enabled');
  },
};

const LB_API_DEF: SecurityRule = {
  id: 'API-02',
  name: 'API Definition / Schema Attached',
  description: 'An attached API Definition (OpenAPI spec) enables positive-security schema validation of requests.',
  category: 'API_SECURITY', severity: 'LOW', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'API definition attached',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Upload an OpenAPI spec and attach it as an API Definition for schema-based validation.',
  referenceUrl: `${DOCS}/how-to/app-security/api-protection`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.apiDefinitionAttached
      ? pass('API definition is attached', 'Attached', 'Attached')
      : warn('No API definition attached — schema validation not enforced', 'None', 'Attached');
  },
};

const LB_USER_ID: SecurityRule = {
  id: 'UID-01',
  name: 'User Identification Policy',
  description: 'Rate limiting and malicious-user detection rely on a user identifier. Client-IP-only causes false positives behind shared NAT; prefer cookie/header-based identification for authenticated apps.',
  category: 'USER_IDENTIFICATION', severity: 'LOW', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Policy-based for authenticated apps',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Attach a user identification policy (cookie/header based) instead of relying on client-IP only for authenticated applications.',
  referenceUrl: `${DOCS}/how-to/advanced-security/user-identification`,
  check: (obj) => {
    const p = getLBPosture(obj);
    if (p.userIdMode === 'policy') return pass('Policy-based user identification configured', 'Policy', 'Policy-based');
    if (p.userIdMode === 'client_ip') return warn('User identification is client-IP only', 'Client IP', 'Policy-based');
    return warn('No user identification configured', 'None', 'Policy-based');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// ORIGIN POOL
// ═══════════════════════════════════════════════════════════════════════════

const OP_TLS: SecurityRule = {
  id: 'OP-01',
  name: 'TLS to Origin Enabled',
  description: 'Traffic from XC to the origin should use TLS for origins handling sensitive data. Origin pools default to plaintext.',
  category: 'TLS_SSL', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'TLS enabled',
  appliesTo: ['origin_pool'],
  remediation: 'Enable TLS to the origin in the origin pool (Origin Servers → TLS).',
  referenceUrl: `${DOCS}/how-to/app-networking/origin-pools`,
  check: (obj) => {
    const p = getOriginPosture(obj);
    return p.tlsEnabled
      ? pass('TLS to origin is enabled', 'Enabled', 'Enabled')
      : warn('Origin pool connects to origins over plaintext (no TLS)', 'No TLS', 'Enabled');
  },
};

const OP_VERIFY: SecurityRule = {
  id: 'OP-02',
  name: 'Origin Certificate Validation',
  description: 'When TLS to origin is enabled, server certificate verification must not be skipped — skip-verify exposes the origin leg to MITM.',
  category: 'ORIGIN', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'Verify enabled (no skip-verify)',
  appliesTo: ['origin_pool'],
  remediation: 'Disable "Skip Server Verification" and use Volterra Trusted CA or upload the origin CA for verification.',
  referenceUrl: `${DOCS}/how-to/app-networking/origin-pools`,
  check: (obj) => {
    const p = getOriginPosture(obj);
    if (!p.tlsEnabled) return skip('No TLS to origin — verification not applicable (see OP-01)');
    if (p.skipVerify) return fail('Origin TLS skips server certificate verification (MITM risk)', 'skip-verify', 'Verify enabled');
    return pass('Origin server certificate verification is enabled', p.usesTrustedCA ? 'Trusted CA' : 'Verifying', 'Verify enabled');
  },
};

const OP_HA: SecurityRule = {
  id: 'OP-03',
  name: 'Origin Pool High Availability',
  description: 'A production origin pool should have at least two origin servers across failure domains. A single origin has no failover.',
  category: 'ORIGIN', severity: 'MEDIUM', risk: 'High', entitlement: 'Config',
  expectedDisplay: '≥ 2 origin servers',
  appliesTo: ['origin_pool'],
  remediation: 'Add a second origin server (different AZ / failure domain) to provide failover.',
  referenceUrl: `${DOCS}/how-to/app-networking/origin-pools`,
  check: (obj) => {
    const p = getOriginPosture(obj);
    if (p.originCount >= 2) return pass(`Origin pool has ${p.originCount} origin servers`, p.originCount, '≥ 2');
    return warn(`Origin pool has only ${p.originCount} origin server(s) — no failover`, p.originCount, '≥ 2');
  },
};

const OP_HC: SecurityRule = {
  id: 'OP-04',
  name: 'Health Check Configured',
  description: 'An active health check is required so unhealthy origins are removed from rotation.',
  category: 'ORIGIN', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'Health check attached',
  appliesTo: ['origin_pool'],
  remediation: 'Attach an active HTTP/HTTPS health check (with an expected response code) to the origin pool.',
  referenceUrl: `${DOCS}/how-to/app-networking/origin-pools`,
  check: (obj) => {
    const p = getOriginPosture(obj);
    return p.healthCheckCount > 0
      ? pass(`${p.healthCheckCount} health check(s) configured`, p.healthCheckCount, '≥1')
      : fail('No health check configured — unhealthy origins stay in rotation', '0', '≥1');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// CERTIFICATE
// ═══════════════════════════════════════════════════════════════════════════

const CERT_EXPIRY: SecurityRule = {
  id: 'CERT-01',
  name: 'Certificate Expiry',
  description: 'Custom TLS certificates should have more than 28 days remaining. Thresholds align with F5\'s built-in cert alerts (Expiring < 28d, ExpiringSoon < 15d).',
  category: 'TLS_SSL', severity: 'HIGH', risk: 'High', entitlement: 'Config',
  expectedDisplay: '> 28 days remaining',
  appliesTo: ['certificate'],
  remediation: 'Renew the certificate before expiry (upload new cert + full chain), or migrate to XC auto-managed certificates.',
  referenceUrl: `${DOCS}/how-to/app-security/manage-certificates`,
  check: (obj) => {
    const p = getCertPosture(obj);
    if (p.expiryDays === null) return skip('Certificate expiry not available (likely auto-managed)');
    if (p.expiryDays <= 15) return fail(`Certificate expires in ${p.expiryDays} day(s) — renew immediately`, `${p.expiryDays} days`, '> 28 days');
    if (p.expiryDays <= 28) return warn(`Certificate expires in ${p.expiryDays} day(s) — schedule renewal`, `${p.expiryDays} days`, '> 28 days');
    return pass(`Certificate valid for ${p.expiryDays} more day(s)`, `${p.expiryDays} days`, '> 28 days');
  },
};

const CERT_BLINDFOLD: SecurityRule = {
  id: 'CERT-02',
  name: 'Certificate Key Blindfolded',
  description: 'The certificate private key must be stored as a Blindfold-encrypted (or Vault) secret, never as inline plaintext.',
  category: 'TLS_SSL', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'Blindfold / Vault (no plaintext)',
  appliesTo: ['certificate'],
  remediation: 'Re-import the certificate using a Blindfold-encrypted private key or a Vault reference; never store the key as plaintext.',
  referenceUrl: `${DOCS}/how-to/app-security/manage-certificates`,
  check: (obj) => {
    const p = getCertPosture(obj);
    if (p.blindfolded === true) return pass('Private key is Blindfold/Vault protected', 'Blindfold/Vault', 'Blindfold/Vault');
    if (p.blindfolded === false) return fail('Private key appears to be stored in plaintext', 'Cleartext', 'Blindfold/Vault');
    return skip('Private key storage method could not be determined');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// APP FIREWALL (WAF object)
// ═══════════════════════════════════════════════════════════════════════════

const WAF_MODE: SecurityRule = {
  id: 'WAFP-01',
  name: 'WAF Enforcement Mode (Blocking)',
  description: 'A WAF policy must be in Blocking (or AI risk-based blocking) mode in production. Monitoring mode only logs and does not block attacks.',
  category: 'WAF', severity: 'CRITICAL', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'Blocking',
  appliesTo: ['app_firewall'],
  remediation: 'Set the App Firewall enforcement mode to Blocking for production policies.',
  referenceUrl: `${DOCS}/how-to/app-security/cfg-waf`,
  check: (obj) => {
    const p = getWafPosture(obj);
    if (p.isBlocking) return pass(`WAF is in ${p.mode === 'AI_RISK_BASED' ? 'AI risk-based blocking' : 'Blocking'} mode`, p.mode, 'Blocking');
    if (p.mode === 'MONITORING') return fail('WAF is in Monitoring mode — attacks are logged but not blocked', 'Monitoring', 'Blocking');
    // Indeterminate ≠ misconfigured: don't pollute the score/warnings with a guess — flag for review.
    return info('WAF enforcement mode could not be determined from config — verify it is set to Blocking', p.mode, 'Blocking');
  },
};

const WAF_THREAT_CAMPAIGNS: SecurityRule = {
  id: 'WAFP-02',
  name: 'Threat Campaigns Enabled',
  description: 'F5-curated threat campaign signatures (e.g. Log4Shell) should be enabled on the WAF policy. They are on by default.',
  category: 'WAF', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Enabled',
  appliesTo: ['app_firewall'],
  remediation: 'Enable Threat Campaigns in the App Firewall policy detection settings.',
  referenceUrl: `${DOCS}/how-to/app-security/cfg-waf`,
  check: (obj) => {
    const p = getWafPosture(obj);
    if (p.threatCampaigns === 'enabled') return pass('Threat Campaigns are enabled', 'Enabled', 'Enabled');
    if (p.threatCampaigns === 'disabled') return fail('Threat Campaigns are disabled', 'Disabled', 'Enabled');
    return skip('WAF policy detail unavailable — could not read detection settings');
  },
};

const WAF_HM_SIGNATURES: SecurityRule = {
  id: 'WAFP-03',
  name: 'High/Medium Accuracy Signatures',
  description: 'The WAF should enforce the high & medium accuracy signature set (the default), covering OWASP attack types with low false positives.',
  category: 'WAF', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'Enabled',
  verify: 'assisted',
  verifyNote: 'The active signature set is not always unambiguous from config — confirm the high+medium accuracy set is actually enforced (and not narrowed) in the policy.',
  appliesTo: ['app_firewall'],
  remediation: 'Enable the high & medium accuracy signature set in the App Firewall policy signature selection settings.',
  referenceUrl: `${DOCS}/how-to/app-security/cfg-waf`,
  check: (obj) => {
    const p = getWafPosture(obj);
    if (p.highMediumSignatures === 'enabled') return pass('High/medium accuracy signatures enforced', 'Enabled', 'Enabled');
    // A narrower set (e.g. only_high_accuracy) is a deliberate low-FP stance — WARN, not FAIL.
    if (p.highMediumSignatures === 'disabled') return warn('A narrower signature set than high+medium is selected — confirm with the policy owner', 'Narrower set', 'High+medium');
    return skip('WAF policy detail unavailable — could not read signature settings');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// SERVICE POLICY
// ═══════════════════════════════════════════════════════════════════════════

const SP_ALLOW_ALL: SecurityRule = {
  id: 'SP-01',
  name: 'Service Policy No Allow-All',
  description: 'A terminal allow-all rule (any client / any request) negates every rule below it and effectively disables L7 access control.',
  category: 'ACCESS_CONTROL', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'No top-level allow-all rule',
  appliesTo: ['service_policy'],
  remediation: 'Review rule order; remove or constrain any top-level ALLOW rule matching all clients so deny/restriction rules are evaluated.',
  referenceUrl: `${DOCS}/how-to/advanced-security/service-policies`,
  check: (obj) => {
    const p = getServicePolicyPosture(obj);
    if (p.hasAllowAll) return fail('Service policy contains an allow-all rule', 'allow-all present', 'No allow-all');
    return pass(`No allow-all rule (${p.ruleCount} rule(s))`, `${p.ruleCount} rules`, 'No allow-all');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// TENANT-WIDE (logging / alerting) — run once via the engine's TENANT handling
// ═══════════════════════════════════════════════════════════════════════════

const TENANT_SIEM: SecurityRule = {
  id: 'TENANT-LOG-01',
  name: 'SIEM / Global Log Receiver Configured',
  description: 'A global log receiver streams security and access logs to an external SIEM. Without one, events are lost at the retention boundary.',
  category: 'LOGGING', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'At least one global log receiver',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Configure a Global Log Receiver (shared namespace) to stream logs to your SIEM (Splunk, S3, Datadog, etc.).',
  referenceUrl: `${DOCS}/how-to/app-security/global-log-receiver`,
  check: (_obj, context: AuditContext) => {
    const n = context.configs.globalLogReceivers.size;
    return n > 0
      ? pass(`${n} global log receiver(s) configured`, n, '≥1')
      : fail('No global log receiver configured — security logs are not streamed to a SIEM', '0', '≥1');
  },
};

const TENANT_ALERTS: SecurityRule = {
  id: 'TENANT-ALERT-01',
  name: 'Alert Policies Configured',
  description: 'At least one alert policy should exist to notify on LB errors, origin-down, and certificate-expiry events.',
  category: 'ALERTING', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'At least one alert policy + receiver',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Create alert policies (and alert receivers) covering error rate, origin health, and certificate expiry.',
  referenceUrl: `${DOCS}/how-to/monitoring/alerting`,
  check: (_obj, context: AuditContext) => {
    const policies = context.configs.alertPolicies.size;
    const receivers = context.configs.alertReceivers.size;
    if (policies > 0 && receivers > 0) return pass(`${policies} alert policy(ies), ${receivers} receiver(s)`, `${policies}/${receivers}`, '≥1 each');
    if (policies > 0) return warn('Alert policies exist but no alert receivers configured', `${policies}/0`, '≥1 each');
    return warn('No alert policies configured', '0', '≥1 each');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// HTTP LOAD BALANCER — HARDENING / DERIVATIVE CONTROLS (expanded)
// ═══════════════════════════════════════════════════════════════════════════

const LB_MALWARE: SecurityRule = {
  id: 'WAF-03',
  name: 'Malware Protection Enabled',
  description: 'Malware protection scans uploaded files for malware. It is a licensed add-on and is OFF by default — recommended on load balancers that accept file uploads.',
  category: 'WAF', severity: 'MEDIUM', risk: 'Med', entitlement: 'Entitlement',
  expectedDisplay: 'Enabled (where uploads are accepted)',
  verify: 'assisted',
  verifyNote: 'Only relevant on LBs that accept file uploads — confirm whether this application takes uploads before treating absence as a gap.',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Enable Malware Protection (licensed add-on) on load balancers that accept file uploads.',
  referenceUrl: `${DOCS}/how-to/app-security`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.malwareProtectionEnabled
      ? pass('Malware protection is enabled', 'Enabled', 'Enabled')
      : info('Malware protection is not enabled (licensed add-on, off by default)', 'Not enabled', 'Enabled (where uploads accepted)');
  },
};

const LB_CSRF: SecurityRule = {
  id: 'CSRF-01',
  name: 'CSRF Protection',
  description: 'Cross-Site Request Forgery protection rejects cross-origin state-changing requests. Configure allowed source origins.',
  category: 'CLIENT_SECURITY', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Enabled',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Enable CSRF protection on the load balancer and set the allowed source-origin domains.',
  referenceUrl: `${DOCS}/how-to/app-security`,
  check: (obj) => {
    const p = getLBPosture(obj);
    if (p.csrfState === 'enabled') return pass('CSRF protection is enabled', 'Enabled', 'Enabled');
    if (p.csrfState === 'disabled') return fail('CSRF protection is explicitly disabled', 'Disabled', 'Enabled');
    return warn('CSRF protection is not configured', 'Not configured', 'Enabled');
  },
};

const LB_CORS: SecurityRule = {
  id: 'CORS-01',
  name: 'CORS Not Over-Permissive',
  description: 'A CORS policy that allows any origin ("*") together with credentials exposes the app to cross-origin data theft.',
  category: 'ACCESS_CONTROL', severity: 'MEDIUM', risk: 'Med', entitlement: 'Config',
  expectedDisplay: 'No wildcard origin with credentials',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Restrict CORS Allow-Origin to specific trusted origins; never combine "*" with Allow-Credentials.',
  referenceUrl: `${DOCS}/how-to/app-security`,
  check: (obj) => {
    const p = getLBPosture(obj);
    if (!p.corsConfigured) return skip('No CORS policy configured');
    return p.corsWildcardWithCreds
      ? fail('CORS allows any origin ("*") with credentials', 'Wildcard + credentials', 'Specific origins')
      : pass('CORS policy is scoped (no wildcard-with-credentials)', 'Scoped', 'Specific origins');
  },
};

const LB_SEC_HEADERS: SecurityRule = {
  id: 'HDR-01',
  name: 'Security Response Headers',
  description: 'Security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) should be added on responses. XC does not inject these automatically.',
  category: 'CLIENT_SECURITY', severity: 'MEDIUM', risk: 'Med', entitlement: 'Config',
  expectedDisplay: 'CSP / X-Frame-Options / X-Content-Type-Options added',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Add response headers on the LB: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options: nosniff, Referrer-Policy.',
  referenceUrl: `${DOCS}/how-to/app-networking/configure-http-header-processing`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.hasCommonSecurityHeaders
      ? pass(`Security headers added: ${p.securityHeaderNames.filter((h) => h !== 'server').join(', ') || 'yes'}`, 'Configured', 'Configured')
      : warn('No common security response headers configured', 'None', 'CSP / X-Frame-Options / etc.');
  },
};

const LB_SERVER_HEADER: SecurityRule = {
  id: 'HDR-02',
  name: 'Server Header Suppression',
  description: 'The default response leaks a Server header (e.g. volt-adc). Remove or overwrite it to avoid disclosing the proxy.',
  category: 'CLIENT_SECURITY', severity: 'LOW', risk: 'Low', entitlement: 'Config',
  expectedDisplay: 'Server header removed / overwritten',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Add "server" to Remove Response Headers (or overwrite it) on the load balancer.',
  referenceUrl: `${DOCS}/how-to/app-networking/configure-http-header-processing`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    switch (a.serverHeaderMode) {
      case 'pass_through': return fail('Server header set to pass-through — leaks origin software/version', 'pass_through', 'Removed / overwritten');
      case 'overwrite':
      case 'removed': return pass('Server header is removed/overwritten', a.serverHeaderMode, 'Removed / overwritten');
      case 'append': return warn('Server header appended only when absent (still discloses origin when present)', 'append', 'Removed / overwritten');
      case 'default': return warn('Default server header (volt-adc) discloses the platform — acceptable for many orgs, overwrite for strict FSI', 'default_header (volt-adc)', 'Removed / overwritten');
      default: return warn('Server header handling not configured', 'Unknown', 'Removed / overwritten');
    }
  },
};

const LB_LOCATION_HEADER: SecurityRule = {
  id: 'HDR-03',
  name: 'x-volterra-location Header Disabled',
  description: 'The x-volterra-location header (Add Location) discloses which XC PoP served the request. Keep it off in production.',
  category: 'CLIENT_SECURITY', severity: 'LOW', risk: 'Low', entitlement: 'Config',
  expectedDisplay: 'Disabled',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Leave "Add Location" disabled in production unless actively used for debugging.',
  referenceUrl: `${DOCS}/how-to/app-networking/configure-http-header-processing`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.addLocationEnabled
      ? warn('x-volterra-location header is enabled (PoP disclosure)', 'Enabled', 'Disabled')
      : pass('x-volterra-location header is disabled', 'Disabled', 'Disabled');
  },
};

const LB_REQUEST_SIZE: SecurityRule = {
  id: 'DDOS-03',
  name: 'Request Size Limit',
  description: 'An explicit maximum request body size limits buffer-abuse and large-payload DoS.',
  category: 'DDOS', severity: 'LOW', risk: 'Low', entitlement: 'Config',
  expectedDisplay: 'Max request size configured',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Set a maximum request size (buffer policy) appropriate to the application.',
  referenceUrl: `${DOCS}/how-to/app-networking/http-load-balancer`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.maxRequestBytes && p.maxRequestBytes > 0
      ? pass(`Max request size: ${(p.maxRequestBytes / 1024 / 1024).toFixed(1)} MB`, `${p.maxRequestBytes} bytes`, 'Configured')
      : warn('No explicit request size limit configured', 'Default/unbounded', 'Configured');
  },
};

const LB_ROUTE_WAF: SecurityRule = {
  id: 'WAF-04',
  name: 'No Route Disabling WAF',
  description: 'A per-route override can disable the WAF on specific paths. Sensitive routes must not bypass the WAF.',
  category: 'WAF', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'No route disables WAF',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Remove per-route "disable WAF" overrides, or confirm they are intentional and on non-sensitive paths.',
  referenceUrl: `${DOCS}/how-to/app-security/cfg-waf`,
  check: (obj) => {
    const p = getLBPosture(obj);
    if (!p.wafEnabled) return skip('WAF not enabled at LB level (see WAF-01)');
    return p.routeWafDisabledCount > 0
      ? fail(`${p.routeWafDisabledCount} route(s) disable the WAF`, `${p.routeWafDisabledCount} route(s)`, 'None')
      : pass('No route disables the WAF', 'None', 'None');
  },
};

const LB_PATH_NORMALIZE: SecurityRule = {
  id: 'WAF-05',
  name: 'Path Normalization',
  description: 'Path normalization defeats path-based encoding/evasion tricks before security evaluation.',
  category: 'WAF', severity: 'LOW', risk: 'Low', entitlement: 'Config',
  expectedDisplay: 'Enabled',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Enable path normalization in the load balancer HTTP/HTTPS settings.',
  referenceUrl: `${DOCS}/how-to/app-networking/http-load-balancer`,
  check: (obj) => {
    const p = getLBPosture(obj);
    if (!p.isHttps) return skip('HTTP-only load balancer');
    if (p.pathNormalize === 'enabled') return pass('Path normalization is enabled', 'Enabled', 'Enabled');
    if (p.pathNormalize === 'disabled') return warn('Path normalization is disabled', 'Disabled', 'Enabled');
    // The top-level enable_path_normalize oneof is deprecated and may be absent;
    // do not penalise when it cannot be determined from the config.
    return skip('Path normalization setting not present in config (XC default applies)');
  },
};

const LB_PROTECTED_COOKIES: SecurityRule = {
  id: 'COOKIE-01',
  name: 'Cookie Protection (Secure/HttpOnly)',
  description: 'Application cookies should carry Secure and HttpOnly attributes (via Protected Cookies) to resist theft and XSS exfiltration.',
  category: 'CLIENT_SECURITY', severity: 'MEDIUM', risk: 'Med', entitlement: 'Config',
  expectedDisplay: 'Protected cookies with Secure + HttpOnly',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Add Protected Cookies with Secure, HttpOnly, and SameSite for session cookies.',
  referenceUrl: `${DOCS}/how-to/app-security`,
  check: (obj) => {
    const p = getLBPosture(obj);
    if (p.protectedCookieCount === 0) return warn('No protected cookies configured', 'None', 'Secure + HttpOnly');
    return p.cookiesHardened
      ? pass(`${p.protectedCookieCount} protected cookie(s) with Secure + HttpOnly`, 'Hardened', 'Secure + HttpOnly')
      : warn('Some protected cookies are missing Secure/HttpOnly', 'Partial', 'Secure + HttpOnly');
  },
};

const LB_TRUSTED_CLIENT_WAF: SecurityRule = {
  id: 'AC-04',
  name: 'No Broad WAF Bypass for Trusted Clients',
  description: 'A trusted-client rule that skips the WAF for an overly-broad scope (0.0.0.0/0) effectively disables protection.',
  category: 'ACCESS_CONTROL', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'No 0.0.0.0/0 WAF-skip rule',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Scope trusted-client WAF-skip rules to specific, justified IP prefixes — never 0.0.0.0/0.',
  referenceUrl: `${DOCS}/how-to/app-security`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.trustedClientSkipsWafBroadly
      ? fail('A trusted-client rule skips the WAF for all sources (0.0.0.0/0)', 'Broad WAF bypass', 'Scoped only')
      : pass('No overly-broad WAF-bypass trusted-client rule', 'None', 'Scoped only');
  },
};

const LB_DATA_GUARD: SecurityRule = {
  id: 'DG-01',
  name: 'Data Guard (Response Masking)',
  description: 'Data Guard masks sensitive data (credit cards, SSNs) in responses. Recommended for apps exposing PII/PAN.',
  category: 'API_SECURITY', severity: 'LOW', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Data Guard rules configured',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Configure Data Guard rules on pages/paths that may expose sensitive data.',
  referenceUrl: `${DOCS}/how-to/app-security`,
  check: (obj) => {
    const p = getLBPosture(obj);
    return p.dataGuardCount > 0
      ? pass(`${p.dataGuardCount} Data Guard rule(s) configured`, `${p.dataGuardCount} rule(s)`, 'Configured')
      : warn('No Data Guard rules configured', 'None', 'Configured (where PII is served)');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// ORIGIN POOL — expanded
// ═══════════════════════════════════════════════════════════════════════════

const OP_TLS_LEVEL: SecurityRule = {
  id: 'OP-05',
  name: 'Origin TLS Version (Medium+)',
  description: 'TLS to the origin should use TLS 1.2+ (Medium or higher), not a Low profile permitting TLS 1.0/1.1.',
  category: 'TLS_SSL', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Medium (TLS 1.2+) or High',
  appliesTo: ['origin_pool'],
  remediation: 'Set the origin TLS security level to Medium or High in the origin pool TLS settings.',
  referenceUrl: `${DOCS}/how-to/app-networking/origin-pools`,
  check: (obj) => {
    const p = getOriginPosture(obj);
    if (!p.tlsEnabled) return skip('No TLS to origin (see OP-01)');
    if (p.tlsLevel === 'LOW') return fail('Origin TLS level is Low — permits TLS 1.0/1.1 and weak ciphers', 'Low', 'Default/High (TLS 1.2+)');
    if (p.tlsPermitsLegacy) return warn('Origin TLS "Medium" level permits TLS 1.0/1.1', 'Medium', 'Default/High (TLS 1.2+)');
    return pass(`Origin TLS level is ${p.tlsLevel === 'DEFAULT' ? 'Default (TLS 1.2+)' : p.tlsLevel}`, p.tlsLevel, 'Default/High (TLS 1.2+)');
  },
};

const OP_OUTLIER: SecurityRule = {
  id: 'OP-06',
  name: 'Outlier Detection',
  description: 'Outlier detection proactively ejects statistically-abnormal origins before they hard-fail, improving resilience.',
  category: 'ORIGIN', severity: 'LOW', risk: 'Low', entitlement: 'Config',
  expectedDisplay: 'Enabled',
  appliesTo: ['origin_pool'],
  remediation: 'Enable outlier detection in the origin pool advanced options.',
  referenceUrl: `${DOCS}/how-to/app-networking/origin-pools`,
  check: (obj) => {
    const p = getOriginPosture(obj);
    if (p.outlierDetection === 'enabled') return pass('Outlier detection is enabled', 'Enabled', 'Enabled');
    if (p.outlierDetection === 'disabled') return warn('Outlier detection is disabled', 'Disabled', 'Enabled');
    return warn('Outlier detection not configured', 'Not configured', 'Enabled');
  },
};

const OP_CIRCUIT_BREAKER: SecurityRule = {
  id: 'OP-07',
  name: 'Circuit Breaker',
  description: 'A circuit breaker prevents cascading failure by capping connections/requests to a failing origin.',
  category: 'ORIGIN', severity: 'LOW', risk: 'Low', entitlement: 'Config',
  expectedDisplay: 'Configured',
  appliesTo: ['origin_pool'],
  remediation: 'Configure a circuit breaker (or enable the default) in the origin pool advanced options.',
  referenceUrl: `${DOCS}/how-to/app-networking/origin-pools`,
  check: (obj) => {
    const p = getOriginPosture(obj);
    return p.circuitBreaker
      ? pass('Circuit breaker is configured', 'Configured', 'Configured')
      : warn('No circuit breaker configured', 'Not configured', 'Configured');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// HEALTH CHECK — quality
// ═══════════════════════════════════════════════════════════════════════════

const HC_HTTP: SecurityRule = {
  id: 'HC-01',
  name: 'HTTP(S) Health Check with Expected Codes',
  description: 'An application-layer (HTTP/HTTPS) health check that validates expected status codes detects real app failures, unlike a TCP-only port check.',
  category: 'ORIGIN', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'HTTP health check with expected status codes',
  appliesTo: ['healthcheck'],
  remediation: 'Use an HTTP/HTTPS health check with an expected status code (e.g. 200) and a health path, not TCP-only.',
  referenceUrl: `${DOCS}/how-to/app-networking/origin-pools`,
  check: (obj) => {
    const p = getHealthCheckPosture(obj);
    if (!p.isHttp) return warn('Health check is TCP-only — does not validate the application layer', 'TCP', 'HTTP with 2xx check');
    return p.hasExpectedCodes
      ? pass(`HTTP health check (expects ${p.expectedCodes.join(', ')})`, p.expectedCodes.join(', '), 'HTTP with 2xx check')
      : warn('HTTP health check has no explicit expected status codes', 'HTTP, no codes', 'HTTP with 2xx check');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// APP FIREWALL — expanded
// ═══════════════════════════════════════════════════════════════════════════

const WAF_BOT_SIG: SecurityRule = {
  id: 'WAFP-04',
  name: 'WAF Bot Signature Protection',
  description: 'The WAF policy should block malicious bot signatures (scanners, DoS tools), complementing dedicated Bot Defense.',
  category: 'WAF', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Malicious bots blocked',
  appliesTo: ['app_firewall'],
  remediation: 'Set the WAF bot protection malicious-bot action to Block in the App Firewall policy.',
  referenceUrl: `${DOCS}/how-to/app-security/cfg-waf`,
  check: (obj) => {
    const p = getWafPosture(obj);
    if (p.botProtection === 'enabled') return pass('Malicious bot signatures are blocked', 'Block', 'Block');
    if (p.botProtection === 'disabled') return warn('WAF bot protection is not set to block malicious bots', 'Not blocking', 'Block');
    return skip('WAF policy detail unavailable — could not read bot settings');
  },
};

const WAF_ATTACK_TYPES: SecurityRule = {
  id: 'WAFP-05',
  name: 'No Attack Types Disabled',
  description: 'All OWASP attack-type signature categories should remain enabled. Disabling categories (e.g. SQLi, XSS) widens exposure.',
  category: 'WAF', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'No attack types disabled',
  appliesTo: ['app_firewall'],
  remediation: 'Re-enable any disabled attack-type categories in the App Firewall signature settings.',
  referenceUrl: `${DOCS}/how-to/app-security/cfg-waf`,
  check: (obj) => {
    const p = getWafPosture(obj);
    if (!p.hasDetectionSettings) return skip('WAF policy detail unavailable');
    return p.disabledAttackTypes > 0
      ? fail(`${p.disabledAttackTypes} attack-type categor(ies) disabled`, `${p.disabledAttackTypes} disabled`, 'None disabled')
      : pass('All attack-type categories enabled', 'None disabled', 'None disabled');
  },
};

const WAF_VIOLATIONS: SecurityRule = {
  id: 'WAFP-06',
  name: 'No Violation Types Disabled',
  description: 'HTTP protocol-compliance and evasion violations should remain enabled to catch malformed/evasive requests.',
  category: 'WAF', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'No violations disabled',
  appliesTo: ['app_firewall'],
  remediation: 'Re-enable any disabled violation types in the App Firewall policy.',
  referenceUrl: `${DOCS}/how-to/app-security/cfg-waf`,
  check: (obj) => {
    const p = getWafPosture(obj);
    if (!p.hasDetectionSettings) return skip('WAF policy detail unavailable');
    return p.disabledViolations > 0
      ? warn(`${p.disabledViolations} violation type(s) disabled`, `${p.disabledViolations} disabled`, 'None disabled')
      : pass('All violation types enabled', 'None disabled', 'None disabled');
  },
};

const WAF_COOKIE: SecurityRule = {
  id: 'WAFP-07',
  name: 'WAF Cookie Protection',
  description: 'The WAF can enforce Secure/HttpOnly/SameSite on cookies it manages. Recommended for session security.',
  category: 'CLIENT_SECURITY', severity: 'LOW', risk: 'Low', entitlement: 'Base',
  expectedDisplay: 'Cookie protection enabled',
  appliesTo: ['app_firewall'],
  remediation: 'Enable cookie protection (Secure / HttpOnly / SameSite) in the App Firewall policy.',
  referenceUrl: `${DOCS}/how-to/app-security/cfg-waf`,
  check: (obj) => {
    const p = getWafPosture(obj);
    if (p.cookieProtection === 'enabled') return pass('WAF cookie protection is enabled', 'Enabled', 'Enabled');
    if (p.cookieProtection === 'disabled') return warn('WAF cookie protection not enabled', 'Disabled', 'Enabled');
    return skip('WAF policy detail unavailable — could not read cookie settings');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// SERVICE POLICY — expanded
// ═══════════════════════════════════════════════════════════════════════════

const SP_BROAD_PREFIX: SecurityRule = {
  id: 'SP-02',
  name: 'No Allow-All IP Prefix',
  description: 'An ALLOW rule whose IP prefix list contains 0.0.0.0/0 trusts every source, negating the allow-list.',
  category: 'ACCESS_CONTROL', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'No 0.0.0.0/0 in allow rules',
  appliesTo: ['service_policy'],
  remediation: 'Replace 0.0.0.0/0 in ALLOW rules with the specific trusted prefixes.',
  referenceUrl: `${DOCS}/how-to/app-security/service-policy`,
  check: (obj) => {
    const p = getServicePolicyPosture(obj);
    return p.hasBroadAllowPrefix
      ? fail('An ALLOW rule trusts 0.0.0.0/0 (all sources)', '0.0.0.0/0', 'Specific prefixes')
      : pass('No allow-all (0.0.0.0/0) prefix in ALLOW rules', 'Scoped', 'Specific prefixes');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// CERTIFICATE — expanded
// ═══════════════════════════════════════════════════════════════════════════

const CERT_KEY: SecurityRule = {
  id: 'CERT-03',
  name: 'Certificate Key Strength',
  description: 'TLS certificate keys should be RSA ≥ 2048-bit or ECDSA. Weak (RSA-1024) keys are breakable.',
  category: 'TLS_SSL', severity: 'MEDIUM', risk: 'Med', entitlement: 'Config',
  expectedDisplay: 'RSA ≥ 2048 or ECDSA',
  appliesTo: ['certificate'],
  remediation: 'Reissue the certificate with an RSA ≥ 2048-bit or ECDSA P-256 key.',
  referenceUrl: `${DOCS}/how-to/app-security/manage-certificates`,
  check: (obj) => {
    const p = getCertPosture(obj);
    if (p.weakKey === null) return skip('Certificate key algorithm not available');
    return p.weakKey
      ? fail(`Weak certificate key (${p.keyAlgorithm})`, p.keyAlgorithm, 'RSA ≥ 2048 / ECDSA')
      : pass(`Certificate key strength OK (${p.keyAlgorithm})`, p.keyAlgorithm, 'RSA ≥ 2048 / ECDSA');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// v2 — mTLS (downstream client certificate)
// ═══════════════════════════════════════════════════════════════════════════

const LB_MTLS_CRL: SecurityRule = {
  id: 'TLS-05',
  name: 'mTLS Client Cert Revocation (CRL)',
  description: 'Where client-certificate mTLS is enforced, revoked certificates must be rejected. Without a CRL a compromised client cert stays valid until natural expiry.',
  category: 'TLS_SSL', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'CRL attached wherever mTLS is enforced',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Create a CRL object (Manage → Load Balancers → Certificate Revocation List) with an appropriate refresh interval and attach it under the LB mTLS settings.',
  referenceUrl: `${DOCS}/how-to/app-security/manage-certificates`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    if (!a.mtlsEnabled) return skip('Client-certificate mTLS is not enforced on this load balancer');
    return a.mtlsCrlAttached
      ? pass('A CRL is attached to the mTLS configuration', 'CRL attached', 'CRL attached')
      : warn('mTLS is enforced but no CRL is attached — revoked client certs stay valid until expiry', 'no_crl', 'CRL attached');
  },
};

const LB_MTLS_OPTIONAL: SecurityRule = {
  id: 'TLS-06',
  name: 'mTLS Not Silently Optional',
  description: 'client_certificate_optional admits clients WITHOUT a certificate — an unauthenticated fallback path that is easy to forget after a migration phase.',
  category: 'TLS_SSL', severity: 'LOW', risk: 'Low', entitlement: 'Config',
  expectedDisplay: 'Client cert required (optional only during migration)',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Disable "client certificate optional" once all clients hold certs; forward XFCC so the origin can apply its own check during the transition.',
  referenceUrl: `${DOCS}/how-to/app-security/manage-certificates`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    if (!a.mtlsEnabled) return skip('Client-certificate mTLS is not enforced');
    return a.mtlsClientCertOptional
      ? info('Client certificate is OPTIONAL — confirm this is intentional (e.g. a staged rollout) and time-boxed', 'optional', 'Required')
      : pass('Client certificate is required', 'required', 'Required');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// v2 — Exposure & advertisement
// ═══════════════════════════════════════════════════════════════════════════

const LB_ADVERTISE: SecurityRule = {
  id: 'EXP-01',
  name: 'VIP Advertisement Scope Matches Exposure Intent',
  description: 'Advertisement determines who can reach the LB: the public default VIP is internet-facing. Internal-only apps must not sit on it; a defined-but-dark LB is config debt.',
  category: 'EXPOSURE', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Advertisement scope = documented exposure intent',
  appliesTo: ['http_loadbalancer'],
  remediation: 'For internal apps use Custom advertisement to CE sites/inside networks; reserve the public VIP for genuinely public apps.',
  referenceUrl: `${DOCS}/how-to/app-networking/http-load-balancer`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    if (a.advertiseScope === 'public_default' || a.advertiseScope === 'public_custom')
      return info('Advertised on a public VIP — confirm the app is intended to be internet-facing', a.advertiseScope === 'public_default' ? 'Public (default VIP)' : 'Public (custom VIP)', 'Public only if intended');
    if (a.advertiseScope === 'custom_internal') return pass('Advertised to custom (internal) sites/networks', 'Custom (internal)', 'Scope = intent');
    if (a.advertiseScope === 'none') return warn('Load balancer is not advertised (dark) — verify it is not stale config', 'Not advertised', 'Scope = intent');
    return info('Advertisement scope could not be determined — verify exposure intent', 'Unknown', 'Scope = intent');
  },
};

const LB_DOMAIN_MATCH: SecurityRule = {
  id: 'EXP-02',
  name: 'No Overly-Broad Domain Match',
  description: 'Wildcard domains route every matching host through one LB and one security posture; a bare "*" catch-all can absorb unintended hosts on shared VIPs.',
  category: 'EXPOSURE', severity: 'LOW', risk: 'Low', entitlement: 'Config',
  expectedDisplay: 'Explicit FQDNs; wildcards only by documented design',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Split distinct apps/subdomains onto separate LBs with right-sized WAF, API, and bot policies.',
  referenceUrl: `${DOCS}/how-to/app-networking/http-load-balancer`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    if (a.domainWildcard === 'bare') return warn('A bare "*" catch-all domain can absorb unintended hosts', '*', 'Explicit FQDNs');
    if (a.domainWildcard === 'subdomain') return info('Wildcard subdomain match — confirm one WAF/API/bot posture fits all subdomains', '*.domain', 'Explicit FQDNs / by design');
    return pass('Domains are explicit FQDNs', 'Explicit', 'Explicit FQDNs');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// v2 — Access control additions
// ═══════════════════════════════════════════════════════════════════════════

const LB_TRUST_CLIENT_IP: SecurityRule = {
  id: 'AC-05',
  name: 'Trusted Client IP Headers Where Behind CDN/Proxy',
  description: 'Behind a CDN/proxy the connection source IP is the proxy. IP reputation, rate limiting, malicious-user detection, service-policy IP rules and logs all key on the WRONG address unless the real client IP is extracted.',
  category: 'ACCESS_CONTROL', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'Configured iff a trusted proxy/CDN fronts the LB',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Configure Trusted Client IP Headers with the exact header the fronting tier sets; verify that tier overwrites any client-supplied value before forwarding.',
  referenceUrl: `${DOCS}/how-to/advanced-security/user-identification`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    return a.trustClientIpHeaders
      ? info('Trusted Client IP Headers configured — verify the fronting tier authoritatively sets/strips the header (a client-spoofable header is an allowlist bypass)', 'Configured', 'Specific header from a trusted hop')
      : info('No Trusted Client IP Headers — if a CDN/proxy fronts this LB, all IP-keyed controls are grading the proxy address (treat as a gap)', 'Not configured', 'Configured if fronted by a proxy/CDN');
  },
};

const LB_CHALLENGE: SecurityRule = {
  id: 'AC-06',
  name: 'Challenge Posture Defined',
  description: 'JS/Captcha challenge (or policy-based challenge rules) provides a graduated response between allow and hard block for suspect automation; the posture should be a decision, not an unexamined default.',
  category: 'ACCESS_CONTROL', severity: 'LOW', risk: 'Low', entitlement: 'Base',
  expectedDisplay: 'Deliberate, documented challenge posture',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Prefer policy-based challenge for granular per-source rules; coordinate with Bot Defense to avoid double-challenging legitimate users.',
  referenceUrl: `${DOCS}/how-to/app-security`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    return a.challengeConfigured
      ? pass('A challenge posture (JS/Captcha/policy-based) is configured', 'Configured', 'Configured')
      : info('No challenge configured — confirm deliberate (a dedicated Bot Defense policy may legitimately supersede LB challenges)', 'no_challenge', 'Deliberate posture');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// v2 — API security depth
// ═══════════════════════════════════════════════════════════════════════════

const LB_OAS_ENFORCED: SecurityRule = {
  id: 'API-03',
  name: 'OpenAPI Validation Enforced (Block + Fall-Through)',
  description: 'An attached OpenAPI spec enforces nothing on its own: validation must run in Block mode, and fall-through must not wave unknown endpoints past the positive-security model.',
  category: 'API_SECURITY', severity: 'HIGH', risk: 'High', entitlement: 'Entitlement',
  expectedDisplay: 'Request validation Block; fall-through custom',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Set OpenAPI Validation → All Endpoints, Request Processing = Validate, Enforcement = Block; define custom fall-through; enable response validation where schemas are reliable.',
  referenceUrl: `${DOCS}/how-to/app-security/api-protection`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    if (a.openApiValidation === 'none') return skip('No API definition / OpenAPI spec attached (see API-02)');
    if (a.openApiValidation === 'disabled') return fail('OpenAPI validation is disabled — the attached spec enforces nothing', 'Disabled', 'Block');
    if (a.openApiValidation === 'report') return warn('OpenAPI validation is in Report mode — violations are logged but not blocked', 'Report', 'Block');
    if (a.openApiFallThroughAllow) return warn('Validation is Block but fall-through allows unlisted endpoints past the model', 'Block + allow fall-through', 'Block + custom fall-through');
    return pass('OpenAPI validation enforced in Block mode with controlled fall-through', 'Block', 'Block');
  },
};

const LB_JWT: SecurityRule = {
  id: 'API-04',
  name: 'JWT Validation on Authenticated APIs',
  description: 'Edge JWT validation (signature via JWKS, exp/nbf checks) rejects tampered, expired or not-yet-valid tokens before they reach origin APIs and kills replay/alg-confusion at the LB.',
  category: 'API_SECURITY', severity: 'MEDIUM', risk: 'Med', entitlement: 'Entitlement',
  expectedDisplay: 'Configured with Block action for JWT-bearing APIs',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Configure JWT Validation: target the authenticated API groups/base paths, attach the IdP JWKS, validate reserved claims (exp, nbf), action = Block. Keep JWKS in sync with IdP key rotation.',
  referenceUrl: `${DOCS}/how-to/app-security/api-protection`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    if (a.jwtValidation === 'block') return pass('JWT validation configured with Block action', 'Block', 'Block');
    if (a.jwtValidation === 'report') return warn('JWT validation is in Report mode — invalid tokens are logged but not blocked', 'Report', 'Block');
    if (!a.servesApi) return skip('Load balancer does not appear to serve token-authenticated APIs');
    return info('No JWT validation on an API-serving LB — add it where APIs are token-authenticated', 'None', 'Block for JWT-bearing APIs');
  },
};

const LB_API_PROTECTION: SecurityRule = {
  id: 'API-05',
  name: 'API Protection Rules Gate Sensitive Groups',
  description: 'Endpoint/base-path allow-deny rules restrict sensitive API groups (admin, internal, write-scope) by client IP/ASN/TLS fingerprint/headers. Endpoint rules evaluate first, then group rules.',
  category: 'API_SECURITY', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Admin/internal API groups deny-by-exception',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Define API groups from the discovered inventory; add deny rules with narrow allow exceptions for admin and internal groups.',
  referenceUrl: `${DOCS}/how-to/app-security/api-protection`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    if (!a.servesApi) return skip('Load balancer does not appear to serve APIs');
    return a.apiProtectionRuleCount > 0
      ? pass(`${a.apiProtectionRuleCount} API protection rule(s) configured`, `${a.apiProtectionRuleCount} rule(s)`, 'Sensitive groups gated')
      : info('No API protection rules on an API-serving LB — gate admin/internal groups deny-by-exception', 'None', 'Sensitive groups gated');
  },
};

const LB_SENSITIVE_DATA: SecurityRule = {
  id: 'API-06',
  name: 'Sensitive Data Discovery Aligned to Compliance Scope',
  description: 'Sensitive-data discovery labels PII/PCI/credential exposure per endpoint in the API inventory (PCI, GDPR, HIPAA tagging). Distinct from Data Guard masking (DG-01).',
  category: 'API_SECURITY', severity: 'MEDIUM', risk: 'Med', entitlement: 'Entitlement',
  expectedDisplay: 'Custom policy matching the compliance scope',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Define a sensitive data discovery policy for the relevant frameworks; review flagged endpoints in API inventory; apply DG-01 masking or schema fixes on confirmed leaks.',
  referenceUrl: `${DOCS}/how-to/app-security/api-discovery`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    const lb = getLBPosture(obj);
    if (!lb.apiDiscoveryEnabled && !a.servesApi) return skip('API Discovery is off / no APIs detected (see API-01)');
    if (a.sensitiveDataPolicy === 'custom') return pass('A custom sensitive-data discovery policy is configured', 'Custom policy', 'Custom policy for compliance scope');
    if (a.sensitiveDataPolicy === 'default') return info('Running the default sensitive-data policy — verify default detectors cover the data classes this app handles', 'Default policy', 'Custom policy for compliance scope');
    return info('No sensitive-data discovery policy — enable detection for your compliance frameworks (PCI/GDPR/HIPAA)', 'None', 'Custom policy for compliance scope');
  },
};

const LB_GRAPHQL: SecurityRule = {
  id: 'API-07',
  name: 'GraphQL Inspection Where GraphQL Is Served',
  description: 'GraphQL endpoints need structural limits (query depth, batched queries) and introspection disabled in production; generic WAF signatures do not parse query structure.',
  category: 'API_SECURITY', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Introspection disabled; depth and batch limits set',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Add a GraphQL rule on the GraphQL route; disable introspection in production; set max depth and max batched queries to observed application norms.',
  referenceUrl: `${DOCS}/how-to/app-security/api-protection`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    if (a.graphqlRuleCount === 0) return skip('No GraphQL rules / GraphQL endpoint detected on this load balancer');
    if (!a.graphqlIntrospectionDisabled) return warn('GraphQL rule present but introspection is not disabled — schema reconnaissance is possible', 'Introspection enabled', 'Introspection disabled + limits');
    if (!a.graphqlHasLimits) return warn('GraphQL introspection disabled but no depth/batch limits set — resource exhaustion is possible', 'No depth/batch limits', 'Introspection disabled + limits');
    return pass('GraphQL inspection: introspection disabled with depth/batch limits', 'Hardened', 'Introspection disabled + limits');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// v2 — Bot / abuse depth
// ═══════════════════════════════════════════════════════════════════════════

const LB_MAL_USER_MITIGATION: SecurityRule = {
  id: 'BOT-03',
  name: 'Malicious User Mitigation Wired to Actions',
  description: 'Detection without an action only annotates logs. A mitigation policy maps threat level → action ladder (low = JS challenge, medium = Captcha, high = temporary block).',
  category: 'BOT_DEFENSE', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Threat-level → action ladder active',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Attach a malicious-user mitigation policy (the default ladder is a sane start); ensure user identification is policy-based (UID-01) so actions hit users, not NAT pools.',
  referenceUrl: `${DOCS}/how-to/app-security/malicious-users`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    if (!a.maliciousUserDetectionEnabled) return skip('Malicious User Detection is off (see BOT-02)');
    if (a.maliciousUserMitigation === 'policy') return pass('A malicious-user mitigation policy is attached', 'Policy', 'Action ladder active');
    if (a.maliciousUserMitigation === 'default') return pass('Default malicious-user mitigation ladder is active', 'Default ladder', 'Action ladder active');
    return warn('Detection is on but no mitigation action is wired — findings are only logged', 'None', 'Action ladder active');
  },
};

const LB_BOT_AI: SecurityRule = {
  id: 'BOT-04',
  name: 'Known & AI Bot Policy Reviewed',
  description: 'Bot Defense supports per-bot allow/deny for known bots including AI crawlers/agents. Scraping and content-rights posture toward AI bots should be an explicit decision.',
  category: 'BOT_DEFENSE', severity: 'LOW', risk: 'Low', entitlement: 'Entitlement',
  expectedDisplay: 'Explicit allow/deny stance per known/AI bot',
  verify: 'manual',
  verifyNote: 'Per-bot AI/known-bot policy intent cannot be judged from config — review against business intent (content licensing, SEO, scraping tolerance).',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Set per-bot actions for AI bots in the Bot Defense policy; review the known-bot dashboard on a regular cadence.',
  referenceUrl: `${DOCS}/how-to/app-security/bot-defense`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    if (!a.botDefenseEnabled) return skip('Bot Defense is not attached (see BOT-01)');
    return info('Manual review — verify a per-bot policy exists for AI bots/crawlers and matches business intent (content licensing, SEO, scraping tolerance)', 'Bot Defense on', 'Explicit AI-bot stance');
  },
};

const LB_CSD_DEPTH: SecurityRule = {
  id: 'CSD-02',
  name: 'CSD New-Script Alerting & PCI Compliance Status',
  description: 'CSD inventories all inline JavaScript, can alert on new scripts, and supports per-script PCI compliance status — direct evidence for PCI DSS 6.4.3 / 11.6.1.',
  category: 'CLIENT_SECURITY', severity: 'LOW', risk: 'Low', entitlement: 'Entitlement',
  expectedDisplay: 'New-script alerts on; PCI status maintained',
  verify: 'manual',
  verifyNote: 'New-script alerting and per-script PCI status are operational/process controls — verify in the CSD dashboard, not derivable from config.',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Enable new-script alerting; assign and review per-script compliance status on release cadence.',
  referenceUrl: `${DOCS}/how-to/app-security/client-side-defense`,
  check: (obj) => {
    const a = getLBAdvancedPosture(obj);
    if (!a.clientSideDefenseEnabled) return skip('Client-Side Defense is not enabled (see CSD-01)');
    return info('Manual review — verify new-script alerts route to a monitored receiver and payment-page scripts carry a PCI compliance status', 'CSD on', 'Alerts on; PCI status maintained');
  },
};

const LB_API_RATE_LIMIT: SecurityRule = {
  id: 'RL-02',
  name: 'API Endpoint Rate Limits on Sensitive Endpoints',
  description: 'An LB-wide rate limit is not a login/OTP/search/export budget. Per-endpoint limits with the right user identifier break credential-stuffing and scraping economics where it matters.',
  category: 'RATE_LIMITING', severity: 'MEDIUM', risk: 'Med', entitlement: 'Entitlement',
  expectedDisplay: 'Endpoint budgets on login/OTP/reset/search',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Add api_endpoint_rules for login, OTP, password reset and expensive read endpoints; key on the UID-01 identifier, not bare client IP.',
  referenceUrl: `${DOCS}/how-to/app-security/rate-limiting`,
  check: (obj) => {
    const lb = getLBPosture(obj);
    const a = getLBAdvancedPosture(obj);
    if (!lb.rateLimitEnabled && a.apiEndpointRateLimitCount === 0) return skip('No rate limiting configured at all (see RL-01)');
    return a.apiEndpointRateLimitCount > 0
      ? pass(`${a.apiEndpointRateLimitCount} per-endpoint API rate-limit rule(s) configured`, `${a.apiEndpointRateLimitCount} rule(s)`, 'Endpoint budgets on sensitive paths')
      : info('LB-wide rate limiting only — add per-endpoint budgets on login/OTP/reset/search from the API inventory', 'LB-wide only', 'Endpoint budgets on sensitive paths');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// v2 — Origin pool additions
// ═══════════════════════════════════════════════════════════════════════════

const OP_SNI: SecurityRule = {
  id: 'OP-08',
  name: 'SNI Set When Verifying Origin TLS',
  description: 'Server-cert verification without correct SNI either fails or fetches the wrong certificate on multi-tenant origins/CDNs; disable_sni alongside verification is brittle.',
  category: 'TLS_SSL', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'SNI = host header or explicit name',
  appliesTo: ['origin_pool'],
  remediation: 'Enable Use Host Header as SNI (or set an explicit SNI value) on TLS origin pools that verify server certs.',
  referenceUrl: `${DOCS}/how-to/app-networking/origin-pools`,
  check: (obj) => {
    const a = getOriginAdvancedPosture(obj);
    if (!a.tlsEnabled) return skip('No TLS to origin (see OP-01)');
    if (a.sniMode === 'host_header' || a.sniMode === 'explicit') return pass(`Origin SNI is set (${a.sniMode === 'host_header' ? 'host header' : 'explicit'})`, a.sniMode, 'SNI set');
    if (a.serverVerifying && a.sniMode === 'disabled') return warn('Server verification is enabled but SNI is disabled — brittle / may fetch the wrong cert', 'disable_sni + verify', 'SNI set');
    return warn('Origin SNI is not configured', 'None', 'SNI set');
  },
};

const OP_MTLS: SecurityRule = {
  id: 'OP-09',
  name: 'mTLS to Origin for Internet-Reachable Origins',
  description: 'The origin authenticating the XC data plane via client certificate prevents direct-to-origin bypass even if the origin address leaks — the strongest pairing with origin cloaking.',
  category: 'ORIGIN', severity: 'LOW', risk: 'Low', entitlement: 'Config',
  expectedDisplay: 'mTLS where the origin is internet-reachable',
  appliesTo: ['origin_pool'],
  remediation: 'Issue a client cert for the XC→origin leg, attach under origin pool TLS, and configure the origin to require it (accept only XC).',
  referenceUrl: `${DOCS}/how-to/app-networking/origin-pools`,
  check: (obj) => {
    const a = getOriginAdvancedPosture(obj);
    if (!a.tlsEnabled) return skip('No TLS to origin (see OP-01)');
    if (a.originMtls) return pass('Origin-side client certificate (mTLS) is configured', 'use_mtls', 'mTLS for reachable origins');
    return info('No origin mTLS — recommended where the origin is reachable from the internet (pairs with origin cloaking, OP-10)', 'no_mtls', 'mTLS for reachable origins');
  },
};

const OP_CLOAKING: SecurityRule = {
  id: 'OP-10',
  name: 'Origin Cloaking / Private Connectivity',
  description: 'Origins addressed by public IP/DNS are directly attackable — bypassing every LB-layer control — unless firewalled to XC source ranges. Private origins remove the exposed surface entirely.',
  category: 'ORIGIN', severity: 'MEDIUM', risk: 'Med', entitlement: 'Base',
  expectedDisplay: 'Private origins, or public origins firewalled to XC ranges',
  appliesTo: ['origin_pool'],
  remediation: 'Prefer CE/site private connectivity for origins; otherwise allowlist the published F5 XC IP ranges at the origin firewall and enable OP-09 mTLS.',
  referenceUrl: `${DOCS}/how-to/app-networking/origin-pools`,
  check: (obj) => {
    const a = getOriginAdvancedPosture(obj);
    if (a.exposure === 'none') return skip('No origin servers defined');
    if (a.exposure === 'private') return pass('Origins use private (site/CE) connectivity', 'Private', 'Private or firewalled');
    if (a.exposure === 'mixed') return warn('Mixed public and private origins — confirm the public ones are firewalled to XC ranges', 'Mixed', 'Private or firewalled');
    return info('Public origin addresses — verify the origin firewall restricts ingress to published XC RE source ranges (and enable OP-09 mTLS)', 'Public', 'Private or firewalled');
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// v2 — Tenant-wide: logging, DNS, IAM
// ═══════════════════════════════════════════════════════════════════════════

const TENANT_LOG_TYPES: SecurityRule = {
  id: 'TENANT-LOG-02',
  name: 'Security Events + Audit Logs Streamed to SIEM',
  description: 'A receiver carrying only request/access logs misses WAF security events and platform audit logs (config changes, logins) — exactly the streams IR and forensics need.',
  category: 'LOGGING', severity: 'HIGH', risk: 'High', entitlement: 'Base',
  expectedDisplay: 'Receivers for security events and audit logs (plus access)',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Add Global Log Receivers in the shared/system namespace for each missing event type, pointed at the SIEM.',
  referenceUrl: `${DOCS}/how-to/app-security/global-log-receiver`,
  check: (_obj, context: AuditContext) => {
    const receivers = [...context.configs.globalLogReceivers.values()];
    if (receivers.length === 0) return skip('No global log receiver configured (see TENANT-LOG-01)');
    let security = false, audit = false;
    for (const r of receivers) {
      const t = getLogReceiverTypes(r);
      if (t.security) security = true;
      if (t.audit) audit = true;
    }
    if (security && audit) return pass('Security events and audit logs are each streamed to a SIEM', 'Security + Audit', 'Security + Audit + Access');
    const missing = [!security ? 'security events' : '', !audit ? 'audit logs' : ''].filter(Boolean).join(' and ');
    return warn(`Log streaming is missing ${missing} — only access logs may be covered`, `Missing ${missing}`, 'Security + Audit + Access');
  },
};

const TENANT_DNSSEC: SecurityRule = {
  id: 'TENANT-DNS-01',
  name: 'DNSSEC on XC-Hosted Primary Zones',
  description: 'Zones authoritative on XC DNS should sign responses: cache poisoning of an app hostname hijacks traffic upstream of every LB-layer control.',
  category: 'DNS', severity: 'MEDIUM', risk: 'Med', entitlement: 'Config',
  expectedDisplay: 'DNSSEC enabled with DS published at parent',
  appliesTo: ['http_loadbalancer'],
  remediation: 'Enable DNSSEC on the primary zone; publish the DS record at the registrar; verify the chain (dig +dnssec / DNSViz).',
  referenceUrl: `${DOCS}/how-to/app-networking/dns`,
  check: (_obj, context: AuditContext) => {
    const zones = [...context.configs.dnsZones.entries()];
    const primary = zones.filter(([, z]) => getDnsZoneDnssec(z) !== 'unknown');
    if (primary.length === 0) return skip('No XC-hosted primary DNS zones found (or DNS not delegated to XC)');
    const unsigned = primary.filter(([, z]) => getDnsZoneDnssec(z) === 'disabled').map(([k]) => k.split('/').pop());
    if (unsigned.length === 0) return pass(`DNSSEC enabled on ${primary.length} primary zone(s) — verify DS is published at the registrar`, 'Enabled', 'Enabled + DS published');
    return warn(`DNSSEC is disabled on ${unsigned.length} zone(s): ${unsigned.slice(0, 5).join(', ')}`, `${unsigned.length} unsigned`, 'Enabled + DS published');
  },
};

// IAM controls are tenant-governance items that cannot be read from LB config —
// surfaced as manual-review (INFO) items with the exact place to check.
const tenantManual = (id: string, name: string, description: string, severity: SecurityRule['severity'], expectedDisplay: string, remediation: string, reviewMsg: string): SecurityRule => ({
  id, name, description, category: 'IAM', severity, risk: severity === 'HIGH' ? 'High' : severity === 'MEDIUM' ? 'Med' : 'Low',
  entitlement: 'Base', expectedDisplay, appliesTo: ['http_loadbalancer'], remediation,
  // Tenant IAM/SSO/session governance lives outside the LB config graph — not inspectable here.
  verify: 'manual',
  verifyNote: 'Tenant-level IAM setting — verify in tenant Administration; it cannot be read from load-balancer config.',
  referenceUrl: `${DOCS}/how-to/user-mgmt`,
  check: () => info(reviewMsg, 'Manual review', expectedDisplay),
});

const TENANT_IAM_EXPIRY = tenantManual(
  'TENANT-IAM-01', 'Credential Expiry Policy Enforced',
  'Tenant policy should cap the lifetime of API tokens, API certificates and kubeconfigs (system default 90 days; admins can extend to 365). Long-lived API tokens are a standing risk.',
  'HIGH', '≤ 90 days maximum credential lifetime',
  'Administration → Tenant Settings → Credential Expiry Policy: set maximum expiry ≤ 90 days for tokens, certificates and kubeconfigs.',
  'Manual review — confirm a Credential Expiry Policy is set to ≤ 90 days per credential type (Tenant Settings → Credential Expiry Policy).',
);
const TENANT_IAM_STALE = tenantManual(
  'TENANT-IAM-02', 'No Stale or Over-Privileged Credentials',
  'Personal API tokens inherit the creator\'s full RBAC; departed-user tokens, unused credentials and automation on personal tokens are standing access nobody watches.',
  'HIGH', 'No stale credentials; automation on scoped service credentials',
  'Revoke stale credentials; migrate automation to Service Credentials with namespace-scoped least-privilege roles; review quarterly.',
  'Manual review — audit IAM → Credentials and Service Credentials for credentials bound to departed users, unused > 90 days, or automation running on personal tokens.',
);
const TENANT_IAM_SSO = tenantManual(
  'TENANT-IAM-03', 'SSO + MFA Enforcement',
  'Console access should ride corporate SSO with IdP-enforced MFA; local accounts minimized to break-glass. Note: MFA cannot be enforced on local logins of SSO-provisioned users (except Tenant Owner).',
  'HIGH', 'SSO + IdP MFA; minimal, MFA-protected local accounts',
  'Configure SSO (SAML/OIDC); enable MFA on every remaining local account; document and test the break-glass procedure.',
  'Manual review — confirm SSO is enforced with IdP MFA and local accounts are limited to documented, MFA-protected break-glass.',
);
const TENANT_IAM_SESSION = tenantManual(
  'TENANT-IAM-04', 'Console Session Timeouts Configured',
  'Idle and absolute console session timeouts are tenant-configurable. Unattended sessions holding WAF-admin rights are a real risk in shared SOC/NOC environments.',
  'MEDIUM', 'Idle + absolute timeouts per org policy',
  'Administration → Tenant Configuration → set idle and absolute session timeouts (e.g. idle ≤ 30 min for admin roles).',
  'Manual review — confirm idle and absolute console session timeouts are set per org policy (Administration → Tenant Configuration → Session Timeout).',
);

// ═══════════════════════════════════════════════════════════════════════════
// Export
// ═══════════════════════════════════════════════════════════════════════════

export const catalogRules: SecurityRule[] = [
  // TLS / transport
  LB_HTTPS, LB_REDIRECT, LB_HSTS, LB_TLS_LEVEL,
  // WAF (LB) + hardening
  LB_WAF, LB_WAF_EXCLUSIONS, LB_MALWARE, LB_ROUTE_WAF, LB_PATH_NORMALIZE,
  // Access control / threat intel
  LB_SERVICE_POLICY, LB_IP_REPUTATION, LB_THREAT_MESH, LB_TRUSTED_CLIENT_WAF, LB_CORS,
  // DDoS
  LB_DDOS, LB_SLOW_DDOS, LB_REQUEST_SIZE,
  // Bot / abuse
  LB_BOT, LB_MAL_USER, LB_RATE_LIMIT, LB_CSD,
  // API / identity / data
  LB_API_DISCOVERY, LB_API_DEF, LB_USER_ID, LB_DATA_GUARD,
  // Client-side hardening (LB)
  LB_CSRF, LB_SEC_HEADERS, LB_SERVER_HEADER, LB_LOCATION_HEADER, LB_PROTECTED_COOKIES,
  // Origin pool
  OP_TLS, OP_VERIFY, OP_HA, OP_HC, OP_TLS_LEVEL, OP_OUTLIER, OP_CIRCUIT_BREAKER,
  // Health check
  HC_HTTP,
  // Certificate
  CERT_EXPIRY, CERT_BLINDFOLD, CERT_KEY,
  // App firewall object
  WAF_MODE, WAF_THREAT_CAMPAIGNS, WAF_HM_SIGNATURES, WAF_BOT_SIG, WAF_ATTACK_TYPES, WAF_VIOLATIONS, WAF_COOKIE,
  // Service policy
  SP_ALLOW_ALL, SP_BROAD_PREFIX,
  // Tenant-wide
  TENANT_SIEM, TENANT_ALERTS,
  // ── v2 additions ──
  // mTLS
  LB_MTLS_CRL, LB_MTLS_OPTIONAL,
  // Exposure
  LB_ADVERTISE, LB_DOMAIN_MATCH,
  // Access control
  LB_TRUST_CLIENT_IP, LB_CHALLENGE,
  // API security depth
  LB_OAS_ENFORCED, LB_JWT, LB_API_PROTECTION, LB_SENSITIVE_DATA, LB_GRAPHQL,
  // Bot / abuse
  LB_MAL_USER_MITIGATION, LB_BOT_AI, LB_CSD_DEPTH, LB_API_RATE_LIMIT,
  // Origin pool
  OP_SNI, OP_MTLS, OP_CLOAKING,
  // Tenant-wide v2
  TENANT_LOG_TYPES, TENANT_DNSSEC,
  TENANT_IAM_EXPIRY, TENANT_IAM_STALE, TENANT_IAM_SSO, TENANT_IAM_SESSION,
];
