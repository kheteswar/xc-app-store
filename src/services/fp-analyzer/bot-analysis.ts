/**
 * Bot classification analysis — AGGREGATION-NATIVE.
 *
 * F5 XC Bot Defense classifies each request's client as Malicious / Suspicious /
 * Benign(Good) / Human. Typically only **Malicious** bots are blocked; Good and
 * Suspicious are ignored. Before enabling bot blocking we must confirm the Malicious
 * classifications are TRUE positives — i.e. blocking them won't take out a known-good
 * bot (Googlebot, etc.) or a real user.
 *
 * The malicious-bot breakdown is tallied (`computeBotAggregatesFromEvents`) directly from the WAF
 * security events the analyzer already collects — which include the malicious bots. (The earlier
 * server-side aggregation API did not reliably accept `bot_info.*` group-by fields and silently
 * returned nothing, so the Malicious Bots tab never populated.) Security events are fully collected
 * (not sampled), so the distributions are complete and answer "is it safe to block?" — if no
 * known-good bot name or real-browser UA appears in the Malicious set, blocking is safe.
 */
import type { BotAnalysisResult, BotAggBucket, BotFpRiskFlag } from './types';

const KNOWN_GOOD_BOT_RE = /bingbot|googlebot|google[\s-]?bot|adsbot-google|google-inspectiontool|yandexbot|baiduspider|slurp|duckduckbot|facebot|facebookexternalhit|applebot|linkedinbot|twitterbot|pinterest|ahrefsbot|semrushbot|bingpreview/i;
const REAL_BROWSER_RE = /mozilla|chrome|firefox|safari|edge|opera/i;
const BOT_UA_RE = /bot|spider|crawl|scan|http|curl|wget|python|java|go-http|scrapy|sqlmap|nuclei|nikto|acunetix|nessus|qualys|openvas|nmap|masscan|zgrab|zmap|wpscan|gobuster|dirbuster|ffuf|feroxbuster|testssl|burp|nettcr|hydra|metasploit|w3af|skipfish|arachni|netsparker|whatweb|httpx|interactsh|semgrep/i;

export type BotClass = 'malicious' | 'suspicious' | 'benign' | 'human' | 'unknown';

/** Map a bot classification token (raw `bot_info.classification` OR aggregated `bot_class`) to a bucket. */
export function classifyBot(raw: unknown): BotClass {
  const s = String(raw ?? '').toLowerCase();
  if (!s) return 'unknown';
  if (s.includes('malicious')) return 'malicious';
  if (s.includes('suspicious')) return 'suspicious';
  if (/benign|good|trusted/.test(s)) return 'benign';      // e.g. "good_bot"
  if (/human|clean|none/.test(s)) return 'human';          // "clean" = legit human traffic
  return 'unknown';
}

export interface BotAggregateInput {
  /** bot_info.classification distribution over ALL WAF events: token → count. */
  classDistribution: BotAggBucket[];
  /** Malicious-only terms buckets (bot_info.classification = malicious). */
  byIp: BotAggBucket[];
  byBotName: BotAggBucket[];        // bot_info.name
  byUserAgent: BotAggBucket[];
  byCountry: BotAggBucket[];
  byBotType?: BotAggBucket[];       // bot_info.type — e.g. "Vulnerability Scanner"
  byDetection?: BotAggBucket[];     // risk_score_info.source — e.g. "Bot Signature: testssl"
  byAsOrg?: BotAggBucket[];         // as_org — network hosting the bots
  byReqRisk?: BotAggBucket[];       // req_risk among the malicious bots
  byAction?: BotAggBucket[];        // action — what the WAF did (allow in monitoring mode)
  byRecommendation?: BotAggBucket[]; // recommended_action — what F5 AI recommends (block)
  byPath?: BotAggBucket[];          // req_path — the paths the malicious bots targeted
  /** The topk used for the src_ip bucket (to detect an undercount). */
  ipTopk: number;
}

type RawRec = Record<string, unknown>;

const str = (v: unknown) => (v == null ? '' : String(v));

/**
 * Read a possibly-nested security-event field. F5's app_security/events API is inconsistent about
 * how it returns objects like `bot_info` and `risk_score_info` — depending on tenant/endpoint it
 * may be a nested object (`e.bot_info.classification`), a flattened dotted key
 * (`e["bot_info.classification"]`), or a stringified JSON blob (`e.bot_info = "{...}"`). The old
 * code only handled the nested case, so on tenants that flatten/stringify, EVERY bot row read as
 * `unknown` → nothing classified as malicious → the Malicious Bots tab stayed empty. Handle all three.
 */
function nestedField(e: RawRec, parent: string, child: string): string {
  const p = e[parent];
  if (p && typeof p === 'object' && !Array.isArray(p)) return str((p as RawRec)[child]);
  if (typeof p === 'string' && p.trim().startsWith('{')) {
    try { return str((JSON.parse(p) as RawRec)?.[child]); } catch { /* not JSON — fall through */ }
  }
  return str(e[`${parent}.${child}`]); // flattened dotted key
}

/** The raw `bot_info.classification` of an event, handling nested/flattened/stringified shapes
 *  (plus the `bot_class` access-log alias). Use with `classifyBot()` for the bucket. */
export function botClassificationRaw(e: Record<string, unknown>): string {
  return nestedField(e, 'bot_info', 'classification') || str(e['bot_class']);
}

/** Tally a string field across events into sorted {key,count} buckets (blanks skipped). */
function tallyField(events: RawRec[], pick: (e: RawRec) => string): BotAggBucket[] {
  const m = new Map<string, number>();
  for (const e of events) { const k = pick(e).trim(); if (k) m.set(k, (m.get(k) ?? 0) + 1); }
  return [...m.entries()].map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count);
}

/** Top-level string field with an access-log alias fallback (e.g. as_org). */
const top = (e: RawRec, ...keys: string[]): string => { for (const k of keys) { const v = str(e[k]); if (v) return v; } return ''; };

/**
 * Build the malicious-bot aggregates directly from the WAF security events we already collected.
 * Reliable alternative to the server-side aggregation API, which does not consistently accept
 * `bot_info.*` group-by fields. Returns null when there are no Malicious-classified bots.
 */
// Always returns an aggregate (never null) so the Malicious Bots section/tab is ALWAYS present — when
// there are no malicious bots it simply reports maliciousEvents = 0. The malicious-only buckets are
// empty in that case; classDistribution still shows the overall bot classification distribution.
export function computeBotAggregatesFromEvents(events: RawRec[], ipTopk = 25): BotAggregateInput {
  const cls = (e: RawRec) => nestedField(e, 'bot_info', 'classification') || top(e, 'bot_class');
  const mal = events.filter(e => classifyBot(cls(e)) === 'malicious');
  return {
    // Count events with no bot classification under an "unknown" sentinel so the classification tiles
    // sum to the total flagged events (the sentinel maps to 'unknown' via classifyBot — it must avoid
    // the human/clean/none/benign/good substrings the classifier keys on).
    classDistribution: tallyField(events, e => cls(e) || '(unclassified)'),
    byIp: tallyField(mal, e => top(e, 'src_ip', 'src_ip_str')).slice(0, ipTopk),
    byBotName: tallyField(mal, e => nestedField(e, 'bot_info', 'name') || top(e, 'bot_name')),
    byBotType: tallyField(mal, e => nestedField(e, 'bot_info', 'type')),
    byDetection: tallyField(mal, e => nestedField(e, 'risk_score_info', 'source')),
    byUserAgent: tallyField(mal, e => top(e, 'user_agent')),
    byCountry: tallyField(mal, e => top(e, 'country')),
    byAsOrg: tallyField(mal, e => top(e, 'as_org')),
    byReqRisk: tallyField(mal, e => top(e, 'req_risk')),
    byAction: tallyField(mal, e => top(e, 'action')),
    byRecommendation: tallyField(mal, e => top(e, 'recommended_action')),
    byPath: tallyField(mal, e => top(e, 'req_path', 'original_path')),
    ipTopk,
  };
}

const isMeaningfulName = (k: string) => k && k.toUpperCase() !== 'UNKNOWN' && k !== '-' && k !== 'N/A';

export function computeBotAnalysisFromAggregates(input: BotAggregateInput): BotAnalysisResult {
  const counts = { malicious: 0, suspicious: 0, benign: 0, human: 0, unknown: 0 };
  for (const b of input.classDistribution) counts[classifyBot(b.key)] += b.count;

  const byIp = [...input.byIp].sort((a, b) => b.count - a.count);
  const maliciousIps = byIp.length;
  const maliciousEvents = counts.malicious || byIp.reduce((a, b) => a + b.count, 0);
  const ipsCapped = input.ipTopk > 0 && byIp.length >= input.ipTopk;

  // FP-risk: known-good bot names and real-browser UAs appearing in the Malicious set.
  const fpRiskFlags: BotFpRiskFlag[] = [];
  for (const b of input.byBotName) {
    if (isMeaningfulName(b.key) && KNOWN_GOOD_BOT_RE.test(b.key)) fpRiskFlags.push({ kind: 'known_good_bot', label: b.key, count: b.count });
  }
  for (const b of input.byUserAgent) {
    if (KNOWN_GOOD_BOT_RE.test(b.key)) { fpRiskFlags.push({ kind: 'known_good_bot', label: b.key, count: b.count }); continue; }
    if (REAL_BROWSER_RE.test(b.key) && !BOT_UA_RE.test(b.key)) fpRiskFlags.push({ kind: 'real_browser', label: b.key, count: b.count });
  }
  // De-dupe by label, keep the highest count, surface biggest first.
  const seen = new Map<string, BotFpRiskFlag>();
  for (const f of fpRiskFlags) { const e = seen.get(f.label); if (!e || f.count > e.count) seen.set(f.label, f); }
  const flags = [...seen.values()].sort((a, b) => b.count - a.count).slice(0, 20);

  const haveUaNameEvidence = input.byUserAgent.length > 0 || input.byBotName.some(b => isMeaningfulName(b.key));
  let recommendation: string;
  if (maliciousEvents === 0) {
    recommendation = 'No Malicious-classified bots in this window — nothing to block.';
  } else if (flags.length === 0 && !haveUaNameEvidence) {
    // Malicious bots exist but no user-agent/bot-name detail was collected to vet them — don't claim SAFE.
    recommendation = `${maliciousEvents.toLocaleString()} Malicious bot event(s) detected, but no user-agent / bot-name detail was collected to verify them against known-good bots — review the Malicious set before enabling Malicious-bot blocking.`;
  } else if (flags.length === 0) {
    const ipClause = maliciousIps > 0 ? `all ${maliciousIps.toLocaleString()}${ipsCapped ? '+' : ''} malicious client(s)` : 'the malicious clients';
    recommendation = `Blocking Malicious bots is SAFE — ${ipClause} carry scanner/unknown user-agents; no known-good bot or real-browser client appears in the Malicious set, so no legitimate traffic is at risk.`;
  } else {
    const known = flags.filter(f => f.kind === 'known_good_bot').map(f => f.label);
    const real = flags.filter(f => f.kind === 'real_browser').length;
    const bits: string[] = [];
    if (known.length) bits.push(`known-good bot${known.length > 1 ? 's' : ''} (${known.slice(0, 3).join(', ')})`);
    if (real) bits.push(`${real} real-browser user-agent${real > 1 ? 's' : ''}`);
    recommendation = `REVIEW before blocking Malicious bots — the Malicious set includes ${bits.join(' and ')}, which may be false positives that would block legitimate traffic. Confirm these are not legitimate before enabling Malicious-bot blocking.`;
  }

  return {
    classificationCounts: counts,
    maliciousEvents,
    maliciousIps,
    ipsCapped,
    topMaliciousIps: byIp.slice(0, 25),
    topBotNames: input.byBotName.filter(b => isMeaningfulName(b.key)).slice(0, 25),
    topUserAgents: input.byUserAgent.slice(0, 25),
    topCountries: input.byCountry.slice(0, 25),
    topBotTypes: (input.byBotType ?? []).filter(b => isMeaningfulName(b.key)).slice(0, 25),
    topDetectionSources: (input.byDetection ?? []).filter(b => isMeaningfulName(b.key)).slice(0, 25),
    topAsOrgs: (input.byAsOrg ?? []).filter(b => isMeaningfulName(b.key)).slice(0, 25),
    topPaths: (input.byPath ?? []).filter(b => isMeaningfulName(b.key)).slice(0, 25),
    reqRiskDist: (input.byReqRisk ?? []).slice(0, 6),
    actionDist: (input.byAction ?? []).slice(0, 6),
    recommendationDist: (input.byRecommendation ?? []).slice(0, 6),
    fpRiskFlags: flags,
    recommendation,
    aggregated: true,
  };
}
