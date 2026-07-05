/**
 * Signature attack-type classification for FP/TP scoring.
 *
 * Signatures (unlike violations, which have ALWAYS_TP_VIOLATIONS) carried no TP bias from their
 * attack_type. That let recon/enumeration signatures (e.g. ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION
 * directory scanning) slip to "Likely FP" purely because the AI rated req_risk low. These sets give
 * the engine attack-type awareness — see SCANNER_ENUMERATION override and the AI-low discount.
 *
 * The sets are deliberately narrow and DISJOINT between TP-bias and FP-prone, enforced at load.
 */

// Recon / resource-enumeration classes — the ONLY types that arm the SCANNER_ENUMERATION cap
// (few clients enumerating many distinct paths). Kept tight on purpose.
export const RECON_ATTACK_TYPES = new Set<string>([
  'ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION',
  'ATTACK_TYPE_FORCEFUL_BROWSING',
  'ATTACK_TYPE_DETECTION_EVASION',
]);

// Inherently-malicious classes — allowed to CANCEL an unwarranted AI low-risk FP boost (never to add
// TP-ward pressure on their own). Superset of the recon set.
export const TP_BIAS_ATTACK_TYPES = new Set<string>([
  ...RECON_ATTACK_TYPES,
  'ATTACK_TYPE_PATH_TRAVERSAL',
  'ATTACK_TYPE_DIRECTORY_INDEXING',
  'ATTACK_TYPE_REMOTE_CODE_EXECUTION',
  'ATTACK_TYPE_SERVER_SIDE_REQUEST_FORGERY',
  'ATTACK_TYPE_REMOTE_FILE_INCLUDE',
  'ATTACK_TYPE_COMMAND_EXECUTION',
  'ATTACK_TYPE_CODE_INJECTION',
  // High-severity exploit classes seen dismissed-as-FP across reports (WordPress/Confluence RCE,
  // Airflow/Tomcat auth bypass) — rarely a benign FP, so a TARGETED (few-client) hit must not floor to FP.
  'ATTACK_TYPE_SERVER_SIDE_CODE_INJECTION',
  'ATTACK_TYPE_AUTHENTICATION_AUTHORIZATION_ATTACKS',
]);

// High-FP classes — these get ZERO TP delta/override and are scored exactly as before. Listed so the
// disjointness invariant can guard against accidentally TP-biasing a noisy family.
export const FP_PRONE_ATTACK_TYPES = new Set<string>([
  'ATTACK_TYPE_CROSS_SITE_SCRIPTING',
  'ATTACK_TYPE_SQL_INJECTION',
  'ATTACK_TYPE_INFORMATION_LEAKAGE',
  'ATTACK_TYPE_NON_BROWSER_CLIENT',
  'ATTACK_TYPE_HTTP_PARSER_ATTACK',
  'ATTACK_TYPE_BUFFER_OVERFLOW',
  'ATTACK_TYPE_ABUSE_OF_FUNCTIONALITY',
]);

// Classes that may arm the DISTRIBUTED_SCAN override (many clients enumerating many distinct unsuccessful
// paths). DELIBERATELY a hand-picked set — NOT the TP_BIAS spread — because TP_BIAS carries COMMAND_EXECUTION
// and SERVER_SIDE_REQUEST_FORGERY, which produce broad genuine FPs (e.g. a liveness cmd-exec hit, a URL-proxy
// endpoint that 404s dead links); those must never be flippable to TP by distribution alone. INFORMATION_
// LEAKAGE is included as the carrier for /.git, /.env, phpinfo scanning (FP-prone for a single hit, TP when
// distributed-enumerated) — the one documented FP_PRONE member here.
export const DISTRIBUTED_SCAN_ATTACK_TYPES = new Set<string>([
  ...RECON_ATTACK_TYPES,
  'ATTACK_TYPE_PATH_TRAVERSAL', 'ATTACK_TYPE_DIRECTORY_INDEXING',
  'ATTACK_TYPE_REMOTE_CODE_EXECUTION', 'ATTACK_TYPE_REMOTE_FILE_INCLUDE', 'ATTACK_TYPE_CODE_INJECTION',
  'ATTACK_TYPE_SERVER_SIDE_CODE_INJECTION', 'ATTACK_TYPE_AUTHENTICATION_AUTHORIZATION_ATTACKS',
  'ATTACK_TYPE_INFORMATION_LEAKAGE',
]);

// Bounding contracts (enforced at module load):
// 1. TP-bias and FP-prone must never overlap, or a noisy family could get a TP nudge.
for (const t of TP_BIAS_ATTACK_TYPES) {
  if (FP_PRONE_ATTACK_TYPES.has(t)) throw new Error(`attack-types: ${t} is in both TP_BIAS and FP_PRONE`);
}
// 2. The distributed-scan set MUST exclude the broad-FP-producing families.
for (const t of ['ATTACK_TYPE_COMMAND_EXECUTION', 'ATTACK_TYPE_SQL_INJECTION', 'ATTACK_TYPE_SERVER_SIDE_REQUEST_FORGERY']) {
  if (DISTRIBUTED_SCAN_ATTACK_TYPES.has(t)) throw new Error(`distributed-scan set must exclude ${t}`);
}
// 3. It may touch FP_PRONE only via the documented INFORMATION_LEAKAGE carrier.
for (const t of DISTRIBUTED_SCAN_ATTACK_TYPES) {
  if (FP_PRONE_ATTACK_TYPES.has(t) && t !== 'ATTACK_TYPE_INFORMATION_LEAKAGE') throw new Error(`distributed-scan: ${t} is FP_PRONE`);
}
