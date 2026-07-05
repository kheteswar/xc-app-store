/**
 * Matching Info Analyzer
 *
 * Classifies WAF signature matching_info values as clearly malicious,
 * clearly benign, or ambiguous. Used to color-code matching info in the UI
 * and inform human review.
 */

export type MatchingInfoClassification = 'clearly_malicious' | 'clearly_benign' | 'ambiguous';

export interface MatchingInfoResult {
  classification: MatchingInfoClassification;
  reason: string;
}

// ─── Malicious Patterns ───
const MALICIOUS_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\/etc\/passwd/i, reason: 'Path traversal to /etc/passwd' },
  { pattern: /\/etc\/shadow/i, reason: 'Path traversal to /etc/shadow' },
  { pattern: /\.\.\/\.\.\//i, reason: 'Directory traversal sequence' },
  { pattern: /\.\.\\\.\.\\/, reason: 'Windows directory traversal' },
  { pattern: /php:\/\//i, reason: 'PHP stream wrapper' },
  { pattern: /data:text\/html/i, reason: 'Data URI XSS' },
  { pattern: /javascript:/i, reason: 'JavaScript protocol URI' },
  { pattern: /<script[\s>]/i, reason: 'Script injection tag' },
  { pattern: /on(error|load|click|mouseover|focus)\s*=/i, reason: 'Event handler injection' },
  { pattern: /union\s+(all\s+)?select/i, reason: 'SQL UNION injection' },
  { pattern: /;\s*(drop|delete|update|insert)\s/i, reason: 'SQL injection statement' },
  { pattern: /'\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i, reason: 'SQL boolean injection' },
  { pattern: /exec\s*\(/i, reason: 'Code execution attempt' },
  { pattern: /eval\s*\(/i, reason: 'Dynamic code evaluation' },
  { pattern: /system\s*\(/i, reason: 'System command execution' },
  { pattern: /cmd\.exe|\/bin\/sh|\/bin\/bash/i, reason: 'Shell command injection' },
  { pattern: /\$\{.*\}/i, reason: 'Template/expression injection (${})' },
  { pattern: /\{\{.*\}\}/i, reason: 'Template injection ({{}})' },
  { pattern: /%00/i, reason: 'Null byte injection' },
  { pattern: /\x00/, reason: 'Null byte in value' },
  // F2b: payloads the heuristics above miss — URL-encoded directory traversal (single + double encoded).
  { pattern: /\.\.%2f|\.\.%5c/i, reason: 'URL-encoded directory traversal' },
  { pattern: /%2e%2e(?:%2f|%5c|\/|\\)/i, reason: 'Double-encoded directory traversal' },
  // A request path that targets an INTERNAL / cloud-metadata host (SSRF). Deliberately NOT any full URL:
  // a legitimate redirect_uri=https://public-host stays ambiguous (flagging it malicious + a 2xx would
  // wrongly trip the successful-exploit guard and cap a real FP to TP).
  { pattern: /^\/?(?:https?:)?\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|metadata\.google\.internal|10\.\d{1,3}\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/i, reason: 'Request path targets an internal/metadata host (SSRF)' },
];

// F2: sensitive-file / secret / app-internal recon PATHS. These are clearly malicious recon targets that
// the "short safe value" benign heuristic would otherwise mis-read as benign (e.g. /composer.json,
// /.git/config). No legitimate request serves these. Conservative on purpose — only unambiguous targets.
const SENSITIVE_PATH_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /(^|\/)\.(git|svn|hg|bzr)(\/|$)/i, reason: 'Exposed VCS directory (recon)' },
  { pattern: /(^|\/)\.(env|aws|ssh|netrc|htpasswd|htaccess)(\/|\.|$)/i, reason: 'Sensitive dotfile / credentials (recon)' },
  { pattern: /(^|\/)(auth\.json|composer\.(json|lock)|wp-config\.php|web\.config|id_rsa|id_dsa|\.htpasswd|credentials|secrets?\.(ya?ml|json|txt))(\/|$)/i, reason: 'Sensitive config / credential file (recon)' },
  { pattern: /(^|\/)(WEB-INF|META-INF)(\/|$)/i, reason: 'Java application internals (recon)' },
  { pattern: /service\.pwd|(^|\/)_?vti_(pvt|bin)(\/|$)|\.pwd($|\/)/i, reason: 'IIS/FrontPage password file (recon)' },
  { pattern: /phpinfo\.php|(^|\/)app_dev\.php|\/_profiler\//i, reason: 'Debug / info-disclosure endpoint (recon)' },
  { pattern: /(^|\/)(tmp|temp)\/[^?]*\.(json|ya?ml|env|conf|cfg|ini|log|bak|key|pem)/i, reason: 'Sensitive file under a temp/system dir (recon)' },
  // Source / compiled-class / backup file disclosure (e.g. Apache Tapestry AppModule.class read).
  { pattern: /\.(class|java|jar|war|inc|bak|swp|old|orig|sql|key|pem|sql\.gz)(\/|$)/i, reason: 'Source/compiled/backup file disclosure (recon)' },
  { pattern: /(^|\/)(server-status|server-info)(\/|$)/i, reason: 'Server-internals endpoint (recon)' },
];

// ─── Benign Patterns ───
const BENIGN_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /^[a-zA-Z0-9_-]{1,50}$/, reason: 'Simple alphanumeric value' },
  { pattern: /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i, reason: 'UUID format' },
  { pattern: /^[a-zA-Z0-9+/]+=*$/, reason: 'Base64-encoded value' },
  { pattern: /^\d+$/, reason: 'Pure numeric ID' },
  { pattern: /^\d+\.\d+\.\d+$/, reason: 'Version number' },
  { pattern: /^[a-zA-Z][a-zA-Z0-9_.]*\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map)$/i, reason: 'Static asset filename' },
  { pattern: /^(true|false|null|undefined|none)$/i, reason: 'Boolean/null literal' },
  { pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$/i, reason: 'HTTP method' },
  { pattern: /^(application|text|image|font|audio|video)\//i, reason: 'Content-Type value' },
  { pattern: /^[a-zA-Z]{2,10}$/, reason: 'Single common word' },
];

// Bare attack-ish keywords that the benign "single common word" / "simple alphanumeric" patterns
// would otherwise mis-classify as clearly_benign. They are NOT clearly malicious on their own either
// (e.g. a legitimate form field value "select"), so they fall through to AMBIGUOUS for human review.
const AMBIGUOUS_KEYWORDS = new Set([
  'select', 'union', 'insert', 'update', 'delete', 'drop', 'exec', 'eval', 'system', 'script', 'alert',
  'prompt', 'onerror', 'onload', 'onclick', 'iframe', 'object', 'embed', 'svg', 'cookie', 'document',
  'window', 'passwd', 'shadow', 'cmd', 'bash', 'curl', 'wget', 'base64', 'concat', 'char', 'substring',
  'sleep', 'benchmark', 'waitfor', 'load_file', 'outfile',
]);

/**
 * Classify a matching_info value as clearly malicious, clearly benign,
 * or ambiguous.
 */
export function classifyMatchingInfo(value: string): MatchingInfoResult {
  if (!value || value.trim().length === 0) {
    return { classification: 'ambiguous', reason: 'Empty value' };
  }

  const trimmed = value.trim();

  // Check malicious patterns first (payloads + sensitive-file recon paths)
  for (const { pattern, reason } of MALICIOUS_PATTERNS) {
    if (pattern.test(trimmed)) {
      return { classification: 'clearly_malicious', reason };
    }
  }
  for (const { pattern, reason } of SENSITIVE_PATH_PATTERNS) {
    if (pattern.test(trimmed)) {
      return { classification: 'clearly_malicious', reason };
    }
  }

  // A bare attack-ish keyword is neither clearly benign nor clearly malicious — needs review.
  if (AMBIGUOUS_KEYWORDS.has(trimmed.toLowerCase())) {
    return { classification: 'ambiguous', reason: `Bare keyword "${trimmed}" — could be a legitimate value or an attack token; needs review` };
  }

  // Check benign patterns
  for (const { pattern, reason } of BENIGN_PATTERNS) {
    if (pattern.test(trimmed)) {
      return { classification: 'clearly_benign', reason };
    }
  }

  // Heuristic: short values (< 20 chars) with no special chars are likely benign — but a protocol-relative
  // URL (//host) is made of safe chars yet is a redirect/SSRF target, so exclude it.
  if (trimmed.length < 20 && /^[a-zA-Z0-9._\-/]+$/.test(trimmed) && !/^\/\//.test(trimmed)) {
    return { classification: 'clearly_benign', reason: 'Short value with safe characters' };
  }

  // Heuristic: long values with many special chars are suspicious
  const specialCount = (trimmed.match(/[<>'"`;|&${}()\\]/g) || []).length;
  if (specialCount >= 3) {
    return { classification: 'clearly_malicious', reason: `Contains ${specialCount} special characters` };
  }

  return { classification: 'ambiguous', reason: 'Does not match known patterns' };
}
