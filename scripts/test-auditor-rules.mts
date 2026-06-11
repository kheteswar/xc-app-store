// Fixture-based verification of the Security Auditor rules against realistic
// XC config JSON. Proves each fixed rule returns the correct PASS/FAIL/WARN/SKIP.
// Run via: node_modules/.bin/esbuild --bundle --platform=node --format=esm → node
import { catalogRules } from '../src/services/security-auditor/rules/catalog.rules';
import type { AuditContext } from '../src/services/security-auditor/types';

const ctx = { configs: { globalLogReceivers: new Map(), alertPolicies: new Map(), alertReceivers: new Map() } } as unknown as AuditContext;
const byId = new Map(catalogRules.map((r) => [r.id, r]));

let pass = 0, fail = 0;
function check(id: string, cfg: unknown, expected: string, label: string) {
  const rule = byId.get(id);
  if (!rule) { console.log(`  ✗ ${id} ${label}: RULE NOT FOUND`); fail++; return; }
  const res = rule.check(cfg, ctx);
  const ok = res.status === expected;
  if (ok) pass++; else fail++;
  console.log(`  ${ok ? '✓' : '✗'} ${id} [${label}] → ${res.status}${ok ? '' : ` (expected ${expected})`}  "${res.message}"`);
}

const lb = (spec: Record<string, unknown>) => ({ metadata: { name: 'test-lb' }, spec });
const af = (spec: Record<string, unknown>) => ({ metadata: { name: 'test-waf' }, spec });
const op = (spec: Record<string, unknown>) => ({ metadata: { name: 'test-pool' }, spec });

console.log('\nTLS-04 — TLS preset legacy-TLS detection (F5 TLS Reference)');
check('TLS-04', lb({ https: { tls_cert_params: { tls_config: { default_security: {} } } } }), 'PASS', 'default_security');
check('TLS-04', lb({ https: { tls_cert_params: { tls_config: { medium_security: {} } } } }), 'WARN', 'medium_security (TLS 1.0+)');
check('TLS-04', lb({ https: { tls_cert_params: { tls_config: { low_security: {} } } } }), 'FAIL', 'low_security');
check('TLS-04', lb({ https: { tls_cert_params: { tls_config: { custom_security: { min_version: 'TLSv1_2' } } } } }), 'PASS', 'custom min TLS 1.2');
check('TLS-04', lb({ http: {} }), 'SKIP', 'HTTP-only');

console.log('\nAC-03 — Threat Mesh (console default = DISABLED)');
check('AC-03', lb({}), 'FAIL', 'neither key (default off)');
check('AC-03', lb({ enable_threat_mesh: {} }), 'PASS', 'enable_threat_mesh');
check('AC-03', lb({ disable_threat_mesh: {} }), 'FAIL', 'disable_threat_mesh');

console.log('\nWAF-03 — Malware Protection (licensed add-on, off by default)');
check('WAF-03', lb({ malware_protection_settings: { foo: 1 } }), 'PASS', 'malware_protection_settings');
check('WAF-03', lb({}), 'WARN', 'not configured');
check('WAF-03', lb({ disable_malware_protection: {} }), 'WARN', 'disabled');

console.log('\nWAF-05 — Path Normalization (multi-location, SKIP when absent)');
check('WAF-05', lb({ https: { enable_path_normalize: {} } }), 'PASS', 'https.enable_path_normalize');
check('WAF-05', lb({ https: {}, disable_path_normalize: {} }), 'WARN', 'spec.disable_path_normalize');
check('WAF-05', lb({ https: {} }), 'SKIP', 'absent → default applies');

console.log('\nWAF-02 — Broad WAF exclusions (both legacy + wrapper shapes)');
check('WAF-02', lb({ app_firewall: { name: 'w' }, waf_exclusion: { waf_exclusion_inline_rules: { rules: [{ any_domain: {}, any_path: {} }] } } }), 'FAIL', 'wrapper broad exclusion');
check('WAF-02', lb({ app_firewall: { name: 'w' }, waf_exclusion_rules: [{ any_domain: {}, path_regex: '.*' }] }), 'FAIL', 'legacy flat broad');
check('WAF-02', lb({ app_firewall: { name: 'w' }, waf_exclusion: { waf_exclusion_inline_rules: { rules: [{ exact_value: 'x.com', path_prefix: '/a' }] } } }), 'PASS', 'wrapper narrow exclusion');
check('WAF-02', lb({ app_firewall: { name: 'w' } }), 'PASS', 'no exclusions');

console.log('\nDDOS-01 — L7 DDoS / detection (incl. app-profile path)');
check('DDOS-01', lb({ l7_ddos_protection: { rps_threshold: 5000 } }), 'PASS', 'l7_ddos_protection');
check('DDOS-01', lb({ enable_ddos_detection: {} }), 'PASS', 'enable_ddos_detection');
check('DDOS-01', lb({ single_lb_app: { enable_ddos_detection: true } }), 'PASS', 'single_lb_app.enable_ddos_detection');
check('DDOS-01', lb({}), 'WARN', 'none');

console.log('\nCSRF-01 — csrf_policy.disabled is a oneof object, not boolean');
check('CSRF-01', lb({ csrf_policy: { disabled: {} } }), 'FAIL', 'disabled: {}');
check('CSRF-01', lb({ csrf_policy: { all_load_balancer_domains: {} } }), 'PASS', 'allowed domains');
check('CSRF-01', lb({}), 'WARN', 'not configured');

console.log('\nDDOS-02 — slow-DDoS system defaults apply when absent');
check('DDOS-02', lb({}), 'PASS', 'absent → system default');
check('DDOS-02', lb({ slow_ddos_mitigation: { request_headers_timeout: 8000 } }), 'PASS', 'configured');
check('DDOS-02', lb({ slow_ddos_mitigation: { disable_request_timeout: {} } }), 'WARN', 'request timeout disabled');

console.log('\nAC-04 — trusted-client broad WAF bypass (empty prefix no longer false-positives)');
check('AC-04', lb({ trusted_clients: [{ as_number: 64512, actions: ['SKIP_PROCESSING_WAF'] }] }), 'PASS', 'ASN-scoped (no ip_prefix)');
check('AC-04', lb({ trusted_clients: [{ ip_prefix: '0.0.0.0/0', actions: ['SKIP_PROCESSING_WAF'] }] }), 'FAIL', '0.0.0.0/0 WAF skip');

console.log('\nWAFP-02/03/05/06 — default_detection_settings = secure baseline (PASS not SKIP)');
check('WAFP-02', af({ blocking: {}, default_detection_settings: {} }), 'PASS', 'threat campaigns (default)');
check('WAFP-03', af({ blocking: {}, default_detection_settings: {} }), 'PASS', 'high/med sigs (default)');
check('WAFP-05', af({ blocking: {}, default_detection_settings: {} }), 'PASS', 'no attack types disabled (default)');
check('WAFP-06', af({ blocking: {}, default_detection_settings: {} }), 'PASS', 'no violations disabled (default)');
check('WAFP-02', af({ blocking: {}, detection_settings: { disable_threat_campaigns: {} } }), 'FAIL', 'custom: threat campaigns OFF');

console.log('\nOP-05 — origin TLS preset legacy detection');
check('OP-05', op({ use_tls: { tls_config: { medium_security: {} } } }), 'WARN', 'origin medium_security');
check('OP-05', op({ use_tls: { tls_config: { default_security: {} } } }), 'PASS', 'origin default_security');

console.log(`\n${'='.repeat(60)}\nRESULT: ${pass} passed, ${fail} failed\n`);
process.exit(fail > 0 ? 1 : 0);
