// Fixture verification for the v2 ruleset additions + INFO outcome.
import { catalogRules } from '../src/services/security-auditor/rules/catalog.rules';
import type { AuditContext } from '../src/services/security-auditor/types';

const mkCtx = (glr: unknown[] = [], zones: unknown[] = []): AuditContext => ({
  configs: {
    globalLogReceivers: new Map(glr.map((r, i) => [`shared/r${i}`, r])),
    dnsZones: new Map(zones.map((z, i) => [`system/z${i}`, z])),
    alertPolicies: new Map(), alertReceivers: new Map(),
  },
} as unknown as AuditContext);

const byId = new Map(catalogRules.map((r) => [r.id, r]));
let pass = 0, fail = 0;
function check(id: string, cfg: unknown, expected: string, label: string, ctx: AuditContext = mkCtx()) {
  const rule = byId.get(id);
  if (!rule) { console.log(`  ✗ ${id} ${label}: NOT FOUND`); fail++; return; }
  const res = rule.check(cfg, ctx);
  const ok = res.status === expected;
  ok ? pass++ : fail++;
  console.log(`  ${ok ? '✓' : '✗'} ${id} [${label}] → ${res.status}${ok ? '' : ` (expected ${expected})`}`);
}
const lb = (spec: Record<string, unknown>) => ({ metadata: { name: 'lb' }, spec });
const op = (spec: Record<string, unknown>) => ({ metadata: { name: 'pool' }, spec });

console.log('\nTLS-05/06 — downstream mTLS');
check('TLS-05', lb({ https: { tls_cert_params: { use_mtls: { crl: { name: 'crl1' } } } } }), 'PASS', 'mtls + CRL');
check('TLS-05', lb({ https: { tls_cert_params: { use_mtls: { no_crl: {} } } } }), 'WARN', 'mtls no CRL');
check('TLS-05', lb({ https: { tls_cert_params: {} } }), 'SKIP', 'no mtls');
check('TLS-06', lb({ https: { tls_cert_params: { use_mtls: { client_certificate_optional: true } } } }), 'INFO', 'cert optional');
check('TLS-06', lb({ https: { tls_cert_params: { use_mtls: {} } } }), 'PASS', 'cert required');

console.log('\nEXP-01/02 — exposure');
check('EXP-01', lb({ advertise_on_public_default_vip: {} }), 'INFO', 'public default VIP');
check('EXP-01', lb({ advertise_custom: { advertise_where: [] } }), 'PASS', 'custom internal');
check('EXP-01', lb({ do_not_advertise: {} }), 'WARN', 'dark LB');
check('EXP-02', lb({ domains: ['*'] }), 'WARN', 'bare wildcard');
check('EXP-02', lb({ domains: ['*.example.com'] }), 'INFO', 'subdomain wildcard');
check('EXP-02', lb({ domains: ['app.example.com'] }), 'PASS', 'explicit FQDN');

console.log('\nAC-05/06 — trusted IP headers + challenge');
check('AC-05', lb({ enable_trust_client_ip_headers: { client_ip_headers: ['x-f5-true-client-ip'] } }), 'INFO', 'trust headers set');
check('AC-05', lb({}), 'INFO', 'no trust headers');
check('AC-06', lb({ policy_based_challenge: {} }), 'PASS', 'policy challenge');
check('AC-06', lb({ no_challenge: {} }), 'INFO', 'no challenge');

console.log('\nAPI-03..07 — API depth');
check('API-03', lb({ api_specification: { validation_all_spec_endpoints: { validation_mode: { validation_mode_active: { enforcement_block: {} } } } } }), 'PASS', 'OAS block');
check('API-03', lb({ api_specification: { validation_all_spec_endpoints: { validation_mode: { validation_mode_active: { enforcement_report: {} } } } } }), 'WARN', 'OAS report');
check('API-03', lb({ api_specification: { validation_disabled: {} } }), 'FAIL', 'OAS disabled');
check('API-03', lb({}), 'SKIP', 'no OAS');
check('API-04', lb({ jwt_validation: { action: { block: {} } } }), 'PASS', 'JWT block');
check('API-04', lb({ enable_api_discovery: {} }), 'INFO', 'no JWT on API LB');
check('API-04', lb({}), 'SKIP', 'no API');
check('API-05', lb({ enable_api_discovery: {}, api_protection_rules: { api_endpoint_rules: [{}] } }), 'PASS', 'API prot rules');
check('API-05', lb({ enable_api_discovery: {} }), 'INFO', 'no API prot rules');
check('API-07', lb({ graphql_rules: [{ graphql_settings: { disable_introspection: {}, max_depth: 5 } }] }), 'PASS', 'graphql hardened');
check('API-07', lb({ graphql_rules: [{ graphql_settings: { max_depth: 5 } }] }), 'WARN', 'graphql introspection on');
check('API-07', lb({}), 'SKIP', 'no graphql');

console.log('\nBOT-03/RL-02 — mitigation + endpoint limits');
check('BOT-03', lb({ enable_malicious_user_detection: {}, malicious_user_mitigation: { name: 'm' } }), 'PASS', 'mitigation policy');
check('BOT-03', lb({ enable_malicious_user_detection: {} }), 'PASS', 'default ladder');
check('BOT-03', lb({}), 'SKIP', 'detection off');
check('RL-02', lb({ api_rate_limit: { api_endpoint_rules: [{}] } }), 'PASS', 'endpoint limits');
check('RL-02', lb({ rate_limit: { rate_limiter: { total_number: 100 } } }), 'INFO', 'LB-wide only');

console.log('\nHDR-02 — server header oneof');
check('HDR-02', lb({ more_option: { pass_through: {} } }), 'FAIL', 'pass_through');
check('HDR-02', lb({ more_option: { server_name: 'x' } }), 'PASS', 'overwrite');
check('HDR-02', lb({ more_option: { default_header: {} } }), 'WARN', 'default volt-adc');

console.log('\nOP-08/09/10 — origin');
check('OP-08', op({ use_tls: { use_host_header_as_sni: {} } }), 'PASS', 'SNI host header');
check('OP-08', op({ use_tls: { volterra_trusted_ca: {}, disable_sni: {} } }), 'WARN', 'verify + disable_sni');
check('OP-09', op({ use_tls: { use_mtls: { name: 'c' } } }), 'PASS', 'origin mtls');
check('OP-09', op({ use_tls: { no_mtls: {} } }), 'INFO', 'no origin mtls');
check('OP-10', op({ origin_servers: [{ private_ip: { ip: '10.0.0.1' } }] }), 'PASS', 'private origin');
check('OP-10', op({ origin_servers: [{ public_name: { dns_name: 'o.example.com' } }] }), 'INFO', 'public origin');

console.log('\nTENANT-LOG-02 / DNS-01 — context-based');
check('TENANT-LOG-02', {}, 'PASS', 'security+audit streamed', mkCtx([{ spec: { security_events: {} } }, { spec: { audit_logs: {} } }]));
check('TENANT-LOG-02', {}, 'WARN', 'only access logs', mkCtx([{ spec: { http_access_logs: {} } }]));
check('TENANT-DNS-01', {}, 'WARN', 'dnssec disabled', mkCtx([], [{ spec: { primary: { dnssec_mode: { disable: {} } } } }]));
check('TENANT-DNS-01', {}, 'PASS', 'dnssec enabled', mkCtx([], [{ spec: { primary: { dnssec_mode: { enable: {} } } } }]));

console.log('\nTENANT-IAM — manual review');
check('TENANT-IAM-01', {}, 'INFO', 'credential expiry (manual)');
check('TENANT-IAM-03', {}, 'INFO', 'SSO+MFA (manual)');

console.log('\nRegression — prior fixes still hold');
check('TLS-04', lb({ https: { tls_cert_params: { tls_config: { medium_security: {} } } } }), 'WARN', 'medium TLS still WARN');
check('AC-03', lb({}), 'FAIL', 'threat mesh default off still FAIL');
check('DDOS-02', lb({}), 'INFO', 'slow-ddos default now INFO');

console.log(`\n${'='.repeat(56)}\nRESULT: ${pass} passed, ${fail} failed\n`);
process.exit(fail > 0 ? 1 : 0);
