/**
 * FP Signals v2 — single-mode scoring for the revamped FP Analyzer.
 *
 * Design goals (2026 redesign):
 *  - No Quick/Hybrid modes — one flow.
 *  - WAF Signatures + Violations only.
 *  - Client-behavior centric: instead of downloading the whole LB's access logs,
 *    we pull each FLAGGED IP's own traffic and score from that behavioral profile.
 *  - Response-code aware: 200 leans FP, 404/4xx leans TP — but a 200 on a
 *    clearly-malicious payload is surfaced as a possible successful exploit (TP).
 *
 * Convention (unchanged): higher signal score = more likely FALSE POSITIVE.
 */
import type { SignalScore, FPVerdict, IPBehaviorProfile, FpSignals } from './types';
import { scorePathBreadth, scoreContext, scoreSignatureAccuracy } from './signal-calculator';
import type { AiSignalInput } from './ai-signals';
import { isAutoSuppressedState } from './ai-signals';
import { classifyMatchingInfo } from './matching-info-analyzer';

const REAL_BROWSER_RE = /chrome|firefox|safari|edge|opera/i;
const BOT_RE = /bot|spider|crawler|crawl/i;
const SCRIPTING_TOOL_RE = /python|curl|wget|httpie|go-http|java|axios|node-fetch|ruby|perl|scrapy|nikto|sqlmap|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|wpscan/i;
export const EXPLOIT_PATH_RE = /\/wp-admin|\/wp-login|\/phpmyadmin|\/\.env|\/cgi-bin|\/actuator|\/\.git|\/\.aws|\/\.ssh|\/admin|\/shell|\/eval|\/exec|\/console|\/backup|\/\.svn|\/vendor\//i;

function sig(score: number, rawValue: number | string, reason: string): SignalScore {
  return { score: Math.max(0, Math.min(100, Math.round(score))), rawValue, reason };
}

// ── Signal 1: Client Breadth — how broadly does it affect the path's users ──
// When we know how many DISTINCT users actually use this path (from per-path access logs),
// the fraction that trip the WAF is the strongest breadth signal: most users → the path's
// normal traffic trips it (FP); one of many → targeted (TP). Falls back to absolute count.
export function scoreClientBreadth(distinctIPs: number, distinctUsers: number, pathTotalUsers?: number): SignalScore {
  const flagged = Math.max(distinctIPs, distinctUsers);

  if (pathTotalUsers && pathTotalUsers >= 5) {
    const ratio = Math.min(1, flagged / pathTotalUsers);
    const p = `${(ratio * 100).toFixed(0)}%`;
    if (ratio >= 0.5) return sig(92, ratio, `${flagged} of ${pathTotalUsers} users on this path trip the WAF (${p}) — the path's normal traffic, strong FP`);
    if (ratio >= 0.25) return sig(76, ratio, `${flagged}/${pathTotalUsers} users (${p}) on this path trip the WAF — broad`);
    if (ratio >= 0.1) return sig(54, ratio, `${flagged}/${pathTotalUsers} users (${p}) on this path — mixed`);
    if (flagged <= 2) return sig(10, ratio, `only ${flagged} of ${pathTotalUsers} users on this path trip the WAF — targeted, not the path's normal traffic (TP)`);
    return sig(28, ratio, `${flagged}/${pathTotalUsers} users (${p}) on this path — narrow`);
  }

  // Fallback: absolute distinct-client count (no per-path denominator available).
  const n = flagged;
  if (n > 200) return sig(95, n, `${n} distinct clients trigger this — very broad, strong FP`);
  if (n > 100) return sig(88, n, `${n} distinct clients — broad, strong FP`);
  if (n > 50) return sig(78, n, `${n} distinct clients — broad`);
  if (n > 20) return sig(64, n, `${n} distinct clients — moderately broad`);
  if (n > 10) return sig(50, n, `${n} distinct clients — mixed`);
  if (n > 5) return sig(34, n, `${n} distinct clients — narrow`);
  if (n > 2) return sig(18, n, `${n} clients — narrow, leans targeted`);
  return sig(6, n, `${n} client(s) — single source, likely targeted attack`);
}

// ── Signal 4: Matching Evidence — are the flagged values benign or malicious? ──
export function scoreMatchingEvidence(samples: string[]): SignalScore {
  const vals = (samples || []).filter(v => v && v.trim());
  if (vals.length === 0) return sig(50, 0, 'No matching values captured — cannot judge content');
  let malicious = 0, benign = 0, ambiguous = 0;
  for (const v of vals) {
    const c = classifyMatchingInfo(v).classification;
    if (c === 'clearly_malicious') malicious++;
    else if (c === 'clearly_benign') benign++;
    else ambiguous++;
  }
  const total = vals.length;
  const malPct = malicious / total, benPct = benign / total;
  if (malPct >= 0.5) return sig(8, malPct, `${malicious}/${total} flagged values are clearly malicious — real attack content`);
  if (malPct >= 0.2) return sig(28, malPct, `${malicious}/${total} flagged values look malicious`);
  if (benPct >= 0.7) return sig(85, benPct, `${benign}/${total} flagged values are clearly benign — legitimate input`);
  if (benPct >= 0.4) return sig(66, benPct, `${benign}/${total} flagged values look benign`);
  return sig(50, ambiguous, `Flagged values ambiguous (${benign} benign / ${malicious} malicious / ${ambiguous} unclear)`);
}

// ── Signal 5: Origin Response — 200 vs 404 of the flagged requests ──
// Combined with matching evidence: 2xx + malicious payload = possible successful exploit (TP).
export interface OriginResponseResult {
  signal: SignalScore;
  possibleSuccessfulExploit: boolean;
}
export function scoreOriginResponse(rspCodes: Record<string, number>, matchingScore: number): OriginResponseResult {
  const total = Object.values(rspCodes).reduce((a, b) => a + b, 0);
  if (total === 0) return { signal: sig(50, 0, 'No response-code data on flagged requests'), possibleSuccessfulExploit: false };

  let c2xx = 0, c404 = 0, cOther4xx = 0, c5xx = 0;
  for (const [code, n] of Object.entries(rspCodes)) {
    const cc = parseInt(code, 10);
    if (cc >= 200 && cc < 300) c2xx += n;
    else if (cc === 404) c404 += n;
    else if (cc >= 400 && cc < 500) cOther4xx += n;
    else if (cc >= 500) c5xx += n;
  }
  const okPct = c2xx / total, nfPct = c404 / total, e4Pct = cOther4xx / total, e5Pct = c5xx / total;
  const looksMalicious = matchingScore <= 20; // matchingEvidence said "clearly malicious"

  // Successful-exploit guard (best practice): high 2xx + malicious payload ⇒ TP, not FP.
  if (okPct >= 0.5 && looksMalicious) {
    return {
      signal: sig(15, okPct, `Origin returned 2xx for ${(okPct * 100).toFixed(0)}% of flagged requests AND payloads look malicious — possible SUCCESSFUL EXPLOIT (treat as TP, do not exclude)`),
      possibleSuccessfulExploit: true,
    };
  }
  if (okPct >= 0.8) return { signal: sig(85, okPct, `Origin accepted ${(okPct * 100).toFixed(0)}% with 2xx — app processed the input (leans FP)`), possibleSuccessfulExploit: false };
  if (okPct >= 0.5) return { signal: sig(66, okPct, `Origin returned 2xx for ${(okPct * 100).toFixed(0)}% — mostly accepted`), possibleSuccessfulExploit: false };
  if (nfPct >= 0.5) return { signal: sig(20, nfPct, `${(nfPct * 100).toFixed(0)}% returned 404 — probing non-existent resources (leans TP)`), possibleSuccessfulExploit: false };
  if (e4Pct >= 0.5) return { signal: sig(32, e4Pct, `${(e4Pct * 100).toFixed(0)}% returned non-404 4xx — rejected/blocked requests`), possibleSuccessfulExploit: false };
  if (e5Pct >= 0.3) return { signal: sig(42, e5Pct, `${(e5Pct * 100).toFixed(0)}% returned 5xx — requests caused server errors`), possibleSuccessfulExploit: false };
  return { signal: sig(50, okPct, `Mixed responses (${(okPct * 100).toFixed(0)}% 2xx, ${(nfPct * 100).toFixed(0)}% 404)`), possibleSuccessfulExploit: false };
}

// ── Signal 6: Client Behavior — the centerpiece, from each flagged IP's whole traffic ──
// `botClassifications` is a tally of F5 Bot Defense verdicts (malicious/suspicious/benign/…)
// across the flagged clients; it sharpens the behavior read even when per-IP enrichment is absent.
export function scoreClientBehavior(profiles: IPBehaviorProfile[], botClassifications?: Record<string, number>): SignalScore {
  const en = (profiles || []).filter(p => p.enriched && p.totalRequests > 0);

  let score = 50;
  const reasons: string[] = [];

  if (en.length > 0) {
    const avg = (f: (p: IPBehaviorProfile) => number) => en.reduce((a, p) => a + f(p), 0) / en.length;
    const avgSuccess = avg(p => p.successRatio);
    const avgNotFound = avg(p => p.notFoundRatio);
    const avgWafRatio = avg(p => p.wafEventRatio);
    const avgPaths = avg(p => p.uniquePaths);
    const avgReqHr = avg(p => p.reqPerHour);
    const exploitProbers = en.filter(p => p.exploitPathHits > 0).length;
    const scripted = en.filter(p => SCRIPTING_TOOL_RE.test(p.topUserAgent)).length;
    const realBrowsers = en.filter(p => REAL_BROWSER_RE.test(p.topUserAgent) && !BOT_RE.test(p.topUserAgent)).length;

    if (avgSuccess > 0.8) { score += 22; reasons.push(`${(avgSuccess * 100).toFixed(0)}% of clients' traffic succeeds (2xx) — normal usage`); }
    else if (avgSuccess < 0.3) { score -= 22; reasons.push(`only ${(avgSuccess * 100).toFixed(0)}% of clients' traffic succeeds — mostly errors`); }

    if (avgNotFound > 0.3) { score -= 18; reasons.push(`${(avgNotFound * 100).toFixed(0)}% of clients' requests 404 — probing non-existent paths`); }

    if (avgWafRatio > 0.8) { score -= 20; reasons.push(`≈${(avgWafRatio * 100).toFixed(0)}% of clients' total traffic tripped WAF — dedicated-attacker behavior`); }
    else if (avgWafRatio < 0.1) { score += 18; reasons.push(`only ${(avgWafRatio * 100).toFixed(0)}% of clients' traffic tripped WAF — mostly-legitimate clients occasionally flagged`); }

    if (avgPaths > 30) { score -= 12; reasons.push(`clients hit ${avgPaths.toFixed(0)} distinct paths on avg — scanning pattern`); }
    if (exploitProbers > 0) { score -= 15; reasons.push(`${exploitProbers}/${en.length} clients probed exploit paths (wp-admin/.env/.git)`); }

    if (realBrowsers / en.length > 0.7) { score += 12; reasons.push(`${realBrowsers}/${en.length} clients use real browsers`); }
    else if (scripted / en.length > 0.5) { score -= 15; reasons.push(`${scripted}/${en.length} clients use scripting/scanner tools`); }

    if (avgReqHr > 1000) { score -= 8; reasons.push(`high request rate (~${avgReqHr.toFixed(0)}/hr) — automation`); }
  }

  // Bot classification — available from the security events themselves, even with no per-IP enrichment.
  if (botClassifications) {
    let mal = 0, susp = 0, benign = 0, total = 0;
    for (const [k, v] of Object.entries(botClassifications)) {
      const c = k.toLowerCase();
      if (c === 'unknown' || c === 'human') continue; // not a bot verdict
      total += v;
      if (c.includes('malicious')) mal += v;
      else if (c.includes('suspicious')) susp += v;
      else if (/benign|good|trusted/.test(c)) benign += v;
    }
    if (total > 0) {
      if (mal / total > 0.5) { score -= 18; reasons.push(`F5 Bot Defense classifies most flagged clients as Malicious bots`); }
      else if (benign / total > 0.5) { score += 15; reasons.push(`F5 Bot Defense classifies most flagged clients as Benign/Good bots — legitimate bots being flagged`); }
      else if (susp / total > 0.5) { score -= 8; reasons.push(`F5 Bot Defense classifies most flagged clients as Suspicious bots`); }
    }
  }

  if (en.length === 0 && reasons.length === 0) return sig(50, 0, 'No per-IP behavioral data (clients not enriched)');
  const prefix = en.length > 0 ? `[${en.length} IPs] ` : '[bot signal] ';
  return sig(score, en.length, reasons.length ? `${prefix}${reasons.join('; ')}` : `${en.length} IPs analyzed — neutral behavior`);
}

// ── Violation severity (moved from the now-removed violation-analyzer) ──
const ALWAYS_TP_VIOLATIONS = new Set([
  'VIOL_EVASION_DIRECTORY_TRAVERSALS', 'VIOL_EVASIONS_DIRECTORY_TRAVERSALS', 'VIOL_EVASION_BAD_UNESCAPE',
  'VIOL_EVASION_MULTIPLE_DECODING', 'VIOL_EVASION_APACHE_WHITESPACE', 'VIOL_EVASION_IIS_BACKSLASHES',
  'VIOL_ATTACK_SIGNATURE',
]);
const OFTEN_FP_VIOLATIONS = new Set([
  'VIOL_JSON_MALFORMED', 'VIOL_XML_MALFORMED', 'VIOL_HTTP_PROTOCOL', 'VIOL_PARAMETER_VALUE_LENGTH',
  'VIOL_PARAMETER_DATA_TYPE', 'VIOL_PARAMETER_NUMERIC_VALUE', 'VIOL_URL_LENGTH', 'VIOL_HEADER_LENGTH',
  'VIOL_POST_DATA_LENGTH', 'VIOL_REQUEST_MAX_LENGTH', 'VIOL_COOKIE_LENGTH', 'VIOL_FILETYPE',
]);
export function isAlwaysTpViolation(name: string): boolean { return ALWAYS_TP_VIOLATIONS.has(name); }
export function scoreViolationSeverity(violationName: string): SignalScore {
  if (ALWAYS_TP_VIOLATIONS.has(violationName)) return sig(5, violationName, `${violationName} is an always-TP violation — never exclude`);
  if (OFTEN_FP_VIOLATIONS.has(violationName)) return sig(80, violationName, `${violationName} is an often-FP violation — protocol/format mismatch`);
  if (violationName.startsWith('VIOL_HTTP_PROTOCOL')) return sig(70, violationName, 'HTTP protocol violation — often caused by non-standard clients');
  return sig(50, violationName, 'Unknown violation severity — needs investigation');
}

// ── Composite (FpSignals interface lives in types.ts to avoid an import cycle) ──

export const FP_WEIGHTS = {
  clientBreadth: 0.15,
  pathBreadth: 0.10,
  context: 0.10,
  matchingEvidence: 0.15,
  originResponse: 0.15,
  clientBehavior: 0.20,
  detectionConfidence: 0.15,
} as const;

export interface FpSignalsInput {
  distinctIPs: number;
  distinctUsers: number;
  pathCount: number;
  totalAppPaths: number;
  contextType: string;
  contextName: string;
  sampleMatchingInfos: string[];
  rspCodes: Record<string, number>;
  ipProfiles: IPBehaviorProfile[];
  accuracy: string;
  sigState: string;
  aiConfirmed: boolean;
  violationRatings: number[];
  aiInput?: AiSignalInput;
  /** When set (violations), replaces the detection-confidence signal with severity. */
  violationName?: string;
  /** Distinct users who use this path (from per-path access logs) — enables the
   *  "what fraction of the path's users trip the WAF" breadth ratio. */
  pathTotalUsers?: number;
  /** Tally of F5 Bot Defense classifications across this finding's flagged clients. */
  botClassifications?: Record<string, number>;
}

export function scoreToVerdict(score: number): FPVerdict {
  if (score > 75) return 'highly_likely_fp';
  if (score > 55) return 'likely_fp';
  if (score > 35) return 'ambiguous';
  if (score > 15) return 'likely_tp';
  return 'confirmed_tp';
}

export function computeFpSignals(input: FpSignalsInput): FpSignals {
  const clientBreadth = scoreClientBreadth(input.distinctIPs, input.distinctUsers, input.pathTotalUsers);
  const pathBreadth = scorePathBreadth(input.pathCount, input.totalAppPaths);
  const context = scoreContext(input.contextType, input.contextName);
  const matchingEvidence = scoreMatchingEvidence(input.sampleMatchingInfos);
  const origin = scoreOriginResponse(input.rspCodes, matchingEvidence.score);
  const clientBehavior = scoreClientBehavior(input.ipProfiles, input.botClassifications);
  const detectionConfidence = input.violationName
    ? scoreViolationSeverity(input.violationName)
    : scoreSignatureAccuracy(input.accuracy, input.sigState, input.aiConfirmed, input.violationRatings, input.aiInput);

  let composite = Math.round(
    clientBreadth.score * FP_WEIGHTS.clientBreadth +
    pathBreadth.score * FP_WEIGHTS.pathBreadth +
    context.score * FP_WEIGHTS.context +
    matchingEvidence.score * FP_WEIGHTS.matchingEvidence +
    origin.signal.score * FP_WEIGHTS.originResponse +
    clientBehavior.score * FP_WEIGHTS.clientBehavior +
    detectionConfidence.score * FP_WEIGHTS.detectionConfidence,
  );

  const result: FpSignals = {
    clientBreadth, pathBreadth, context, matchingEvidence,
    originResponse: origin.signal, clientBehavior, detectionConfidence,
    compositeScore: composite, verdict: scoreToVerdict(composite),
    possibleSuccessfulExploit: origin.possibleSuccessfulExploit,
  };

  // F5 already determined this is a false positive (the strongest single FP signal):
  // AutoSuppressed by the ML tuning, or req_risk explicitly "false positive". When the
  // flagged content isn't malicious and the origin accepted the request, treat it as at
  // least likely-FP even on low breadth — one client can still be an obvious false positive.
  const rc = input.aiInput?.riskCounts;
  const knownRisk = rc ? rc.high + rc.medium + rc.low : 0;
  const aiSaysFp = !!input.aiInput?.reasonVerdict?.aiSuggestsFp || (knownRisk > 0 && rc!.low / knownRisk >= 0.6);
  const f5ConfirmedFp = (isAutoSuppressedState(input.sigState) || aiSaysFp)
    && matchingEvidence.score >= 40            // content not clearly malicious
    && origin.signal.score >= 50;              // origin accepted (not 404/error-heavy)

  // Guardrails (caps & floors), in priority order.
  if (origin.possibleSuccessfulExploit) {
    result.compositeScore = Math.min(result.compositeScore, 25);
    result.verdict = scoreToVerdict(result.compositeScore);
    result.override = 'POSSIBLE_SUCCESSFUL_EXPLOIT';
    result.overrideReason = 'Origin returned 2xx for a malicious-looking payload — capped to TP so it is not excluded.';
  } else if (input.violationName && isAlwaysTpViolation(input.violationName)) {
    result.compositeScore = Math.min(result.compositeScore, 15);
    result.verdict = 'confirmed_tp';
    result.override = 'ALWAYS_TP_VIOLATION';
    result.overrideReason = `${input.violationName} is classified always-TP — never exclude.`;
  } else if (f5ConfirmedFp && result.compositeScore < 60) {
    result.compositeScore = 60;
    result.verdict = scoreToVerdict(60);
    result.override = 'F5_CONFIRMED_FP';
    result.overrideReason = 'F5 AutoSuppressed / AI rated false-positive, content not malicious, origin accepted — treated as likely FP.';
  }

  return result;
}
