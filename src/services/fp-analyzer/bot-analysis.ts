/**
 * Bot classification analysis — AGGREGATION-NATIVE.
 *
 * F5 XC Bot Defense classifies each request's client as Malicious / Suspicious /
 * Benign(Good) / Human. Typically only **Malicious** bots are blocked; Good and
 * Suspicious are ignored. Before enabling bot blocking we must confirm the Malicious
 * classifications are TRUE positives — i.e. blocking them won't take out a known-good
 * bot (Googlebot, etc.) or a real user.
 *
 * To avoid downloading the (potentially enormous) raw malicious-bot logs, this works
 * entirely from **server-side aggregations**: a bot_class distribution over all WAF
 * events, plus terms buckets (src_ip / bot_name / user_agent / country) over the
 * Malicious-only slice. We can't correlate fields per request, but the bucket
 * distributions are enough to answer "is it safe to block?" — if no known-good bot
 * name or real-browser UA appears in the Malicious set, blocking is safe.
 */
import type { BotAnalysisResult, BotAggBucket, BotFpRiskFlag } from './types';

const KNOWN_GOOD_BOT_RE = /bingbot|googlebot|google[\s-]?bot|adsbot-google|google-inspectiontool|yandexbot|baiduspider|slurp|duckduckbot|facebot|facebookexternalhit|applebot|linkedinbot|twitterbot|pinterest|ahrefsbot|semrushbot|bingpreview/i;
const REAL_BROWSER_RE = /mozilla|chrome|firefox|safari|edge|opera/i;
const BOT_UA_RE = /bot|spider|crawl|scan|http|curl|wget|python|java|go-http|scrapy|sqlmap|nuclei|nikto/i;

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
  /** bot_class distribution over ALL WAF events: token → count. */
  classDistribution: BotAggBucket[];
  /** Malicious-only terms buckets. */
  byIp: BotAggBucket[];
  byBotName: BotAggBucket[];
  byUserAgent: BotAggBucket[];
  byCountry: BotAggBucket[];
  /** The topk used for the src_ip bucket (to detect an undercount). */
  ipTopk: number;
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

  let recommendation: string;
  if (maliciousEvents === 0 || maliciousIps === 0) {
    recommendation = 'No Malicious-classified bots in this window — nothing to block.';
  } else if (flags.length === 0) {
    recommendation = `Blocking Malicious bots is SAFE — all ${maliciousIps.toLocaleString()}${ipsCapped ? '+' : ''} malicious client(s) carry scanner/unknown user-agents; no known-good bot or real-browser client appears in the Malicious set, so no legitimate traffic is at risk.`;
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
    fpRiskFlags: flags,
    recommendation,
    aggregated: true,
  };
}
