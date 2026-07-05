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
import { isAutoSuppressedState, scoreAiRisk } from './ai-signals';
import { classifyMatchingInfo } from './matching-info-analyzer';
import { RECON_ATTACK_TYPES, TP_BIAS_ATTACK_TYPES, DISTRIBUTED_SCAN_ATTACK_TYPES } from './attack-types';

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
export function scoreClientBreadth(distinctIPs: number, distinctUsers: number, pathTotalUsers?: number, pathCount = 1): SignalScore {
  const flagged = Math.max(distinctIPs, distinctUsers);

  // The per-path ratio is only meaningful when the finding is SINGLE-path: pathTotalUsers is one
  // path's user population, so the numerator must also be scoped to that path AND be a user count
  // (not max(IPs,users) across all paths — a distributed multi-path scanner would otherwise pin the
  // ratio to ~1 and be falsely scored as a broad FP).
  if (pathCount === 1 && pathTotalUsers && pathTotalUsers >= 5) {
    const flaggedUsers = Math.min(distinctUsers || flagged, pathTotalUsers);
    const ratio = Math.min(1, flaggedUsers / pathTotalUsers);
    const p = `${(ratio * 100).toFixed(0)}%`;
    if (ratio >= 0.5) return sig(92, ratio, `${flaggedUsers} of ${pathTotalUsers} users on this path trip the WAF (${p}) — the path's normal traffic, strong FP`);
    if (ratio >= 0.25) return sig(76, ratio, `${flaggedUsers}/${pathTotalUsers} users (${p}) on this path trip the WAF — broad`);
    if (ratio >= 0.1) return sig(54, ratio, `${flaggedUsers}/${pathTotalUsers} users (${p}) on this path — mixed`);
    if (flaggedUsers <= 2) return sig(10, ratio, `only ${flaggedUsers} of ${pathTotalUsers} users on this path trip the WAF — targeted, not the path's normal traffic (TP)`);
    return sig(28, ratio, `${flaggedUsers}/${pathTotalUsers} users (${p}) on this path — narrow`);
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
  /** Fraction of flagged requests the origin answered 404 — a non-existent path → TP-ward. */
  notFoundPct: number;
  /** Fraction the origin SERVED with 2xx (of the requests that actually reached the origin). */
  okPct: number;
  /** Requests that actually reached the origin (total minus F5-blocked code "0"). */
  served: number;
}
export function scoreOriginResponse(rspCodes: Record<string, number>, matchingScore: number): OriginResponseResult {
  const total = Object.values(rspCodes).reduce((a, b) => a + b, 0);
  if (total === 0) return { signal: sig(50, 0, 'No response-code data on flagged requests'), possibleSuccessfulExploit: false, notFoundPct: 0, okPct: 0, served: 0 };

  // F5 records rsp_code "0" (or non-numeric) when IT blocked the request before the origin answered —
  // there is no origin verdict. Rebase the ratios on the requests that ACTUALLY reached the origin, so
  // a fully-enforced signature (all "0") abstains at neutral instead of being read as "Mixed 2xx/404".
  let c2xx = 0, c404 = 0, cOther4xx = 0, c5xx = 0, cBlocked = 0;
  for (const [code, n] of Object.entries(rspCodes)) {
    const cc = parseInt(code, 10);
    if (isNaN(cc) || cc === 0) cBlocked += n;
    else if (cc >= 200 && cc < 300) c2xx += n;
    else if (cc === 404) c404 += n;
    else if (cc >= 400 && cc < 500) cOther4xx += n;
    else if (cc >= 500) c5xx += n;
  }
  const served = total - cBlocked;
  if (served === 0) return { signal: sig(50, 0, `No origin verdict — all ${total} flagged requests were WAF-blocked (rsp_code 0)`), possibleSuccessfulExploit: false, notFoundPct: 0, okPct: 0, served: 0 };

  const okPct = c2xx / served, nfPct = c404 / served, e4Pct = cOther4xx / served, e5Pct = c5xx / served;
  const looksMalicious = matchingScore <= 20; // matchingEvidence said "clearly malicious"
  const p = (x: number) => (x * 100).toFixed(0);
  const ret = (score: number, raw: number, reason: string, exploit = false): OriginResponseResult =>
    ({ signal: sig(score, raw, reason), possibleSuccessfulExploit: exploit, notFoundPct: nfPct, okPct, served });

  // Successful-exploit guard (best practice): high 2xx + malicious payload ⇒ TP, not FP.
  if (okPct >= 0.5 && looksMalicious) {
    return ret(15, okPct, `Origin returned 2xx for ${p(okPct)}% of flagged requests AND payloads look malicious — possible SUCCESSFUL EXPLOIT (treat as TP, do not exclude)`, true);
  }

  // Origin SERVED the request (2xx) → the path exists and the app processed the input → FP-ward.
  // Any 404 share discounts it (those specific paths/resources don't exist).
  if (okPct >= 0.8) return ret(85, okPct, `Origin accepted ${p(okPct)}% with 2xx — app processed the input (leans FP)`);
  if (okPct >= 0.5) return ret(Math.round(66 - nfPct * 32), okPct, `Origin served ${p(okPct)}% (2xx); ${p(nfPct)}% hit non-existent paths (404)`);

  // Origin did NOT serve it. A 404 means the path/resource does not exist — no legitimate
  // traffic uses it, so blocking is harmless and it leans TRUE POSITIVE. Graduated by prevalence:
  // the more of the flagged traffic 404s, the stronger the TP signal.
  if (nfPct >= 0.5) return ret(Math.round(22 - (nfPct - 0.5) * 24), nfPct, `${p(nfPct)}% returned 404 — non-existent paths, safe to block (strong TP)`);
  if (nfPct >= 0.2) return ret(Math.round(45 - nfPct * 40), nfPct, `${p(nfPct)}% returned 404 — probing non-existent resources (leans TP)`);

  if (e4Pct >= 0.5) return ret(32, e4Pct, `${p(e4Pct)}% returned non-404 4xx — rejected/blocked requests`);
  if (e5Pct >= 0.3) return ret(42, e5Pct, `${p(e5Pct)}% returned 5xx — requests caused server errors`);

  // Mixed — even a minority 404 share still pulls toward TP (those paths don't exist).
  return ret(Math.round(50 - nfPct * 40), okPct, `Mixed responses (${p(okPct)}% 2xx, ${p(nfPct)}% 404${nfPct > 0 ? ' — 404s lean TP' : ''})`);
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
export function scoreViolationSeverity(violationName: string, aiInput?: AiSignalInput): SignalScore {
  let score: number;
  let reason: string;
  if (ALWAYS_TP_VIOLATIONS.has(violationName)) { score = 5; reason = `${violationName} is an always-TP violation — never exclude`; }
  else if (OFTEN_FP_VIOLATIONS.has(violationName)) { score = 80; reason = `${violationName} is an often-FP violation — protocol/format mismatch`; }
  else if (violationName.startsWith('VIOL_HTTP_PROTOCOL')) { score = 70; reason = 'HTTP protocol violation — often caused by non-standard clients'; }
  else { score = 50; reason = 'Unknown violation severity — needs investigation'; }

  // Blend F5's per-request AI verdict (req_risk / reasons) into the violation's detection-confidence,
  // exactly as signatures do — EXCEPT always-TP violations, whose hard severity must not be softened
  // by an AI "benign" read. Bounded to [0,100].
  if (aiInput && !ALWAYS_TP_VIOLATIONS.has(violationName)) {
    const ai = scoreAiRisk(aiInput);
    if (ai.delta !== 0) {
      score = Math.max(0, Math.min(100, score + ai.delta));
      if (ai.reasons.length) reason += ` · ${ai.reasons[0]}`;
    }
  }
  return sig(score, violationName, reason);
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
  /** F5 signature attack_type (e.g. ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION) — drives the
   *  scanner-enumeration override and the AI-low FP-boost discount for malicious attack classes. */
  attackType?: string;
  /** Total flagged events for this finding — lets the distributed-scan override use events-per-path
   *  (low = enumeration, high = a concentrated/popular endpoint) as a regression guard. */
  eventCount?: number;
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
  const clientBreadth = scoreClientBreadth(input.distinctIPs, input.distinctUsers, input.pathTotalUsers, input.pathCount);
  const pathBreadth = scorePathBreadth(input.pathCount, input.totalAppPaths);
  const context = scoreContext(input.contextType, input.contextName);
  const matchingEvidence = scoreMatchingEvidence(input.sampleMatchingInfos);
  const origin = scoreOriginResponse(input.rspCodes, matchingEvidence.score);
  const clientBehavior = scoreClientBehavior(input.ipProfiles, input.botClassifications);
  const detectionConfidence = input.violationName
    ? scoreViolationSeverity(input.violationName, input.aiInput)
    : scoreSignatureAccuracy(input.accuracy, input.sigState, input.aiConfirmed, input.violationRatings, input.aiInput, input.attackType);

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
  // F5-confirmed FP floor. aiSaysFp now requires the EXPLICIT "false positive" verdict (not a generic
  // low req_risk, which a scanner also gets). AutoSuppressed = ML-confirmed FP and keeps the floor even
  // without origin data; an AI-FP read additionally requires real 2xx acceptance (okPct ≥ 0.5) so a
  // WAF-blocked recon scan (no origin verdict) can't be floored to FP.
  const rc = input.aiInput?.riskCounts;
  const knownRisk = rc ? rc.high + rc.medium + rc.low : 0;
  const aiSaysFp = !!input.aiInput?.reasonVerdict?.aiSuggestsFp
    || (knownRisk > 0 && (rc!.falsePositive ?? 0) / knownRisk >= 0.5);
  const distinctClients = Math.max(input.distinctIPs, input.distinctUsers);
  const aiOrMlDismissed = isAutoSuppressedState(input.sigState) || (aiSaysFp && origin.okPct >= 0.5);
  // F1: a TARGETED exploit of an inherently-malicious attack type — few clients (≤3), high-severity
  // class. The F5 ML/AI may dismiss it (app not vulnerable → benign-looking), but the REQUEST is a known
  // exploit attempt, so it must NOT be floored to "Likely FP". Gate the floor for these. BROAD FPs on the
  // same types (e.g. 18-IP liveness cmd-exec) have distinctClients > 3, keep the floor, and stay FP.
  const targetedExploit = !!input.attackType && TP_BIAS_ATTACK_TYPES.has(input.attackType) && distinctClients <= 3;
  const f5ConfirmedFp = !origin.possibleSuccessfulExploit
    && matchingEvidence.score >= 40            // content not clearly malicious
    && !targetedExploit                        // F1: never floor a targeted high-severity exploit to FP
    && aiOrMlDismissed;

  // F3: DISTRIBUTED scan — many clients enumerating MANY distinct paths the origin did NOT serve, under a
  // scanning-prone attack type, with LOW events-per-path (enumeration, not a concentrated/popular endpoint).
  // Covers /.git, /.env, JSP-EL scanning across dozens of IPs that the ≤2-client scannerEnumeration misses.
  const eventsPerPath = input.eventCount && input.pathCount ? input.eventCount / input.pathCount : 0;
  const distributedScan =
    !origin.possibleSuccessfulExploit
    && distinctClients >= 3                                             // ≤2 is handled by scannerEnumeration
    && input.pathCount >= 20                                            // many distinct paths
    && origin.okPct < 0.5                                              // origin did NOT serve them
    && (!input.eventCount || eventsPerPath < 4)                         // low concentration = enumeration (guard vs popular endpoints)
    && !!input.attackType && DISTRIBUTED_SCAN_ATTACK_TYPES.has(input.attackType);

  // Scanner / resource enumeration: a few clients requesting MANY distinct paths under a recon attack
  // type, where the origin did NOT serve them — directory/resource enumeration, a true positive. This
  // is the keystone that flips the scanner anchor; it is CAP-ONLY (can never raise a score into FP).
  const scannerEnumeration =
    !origin.possibleSuccessfulExploit                                    // defer to the successful-exploit guard
    && distinctClients <= 2                                              // few sources (excludes broad multi-user FPs)
    && input.pathCount >= 20                                             // many distinct paths (not a single endpoint)
    && !!input.attackType && RECON_ATTACK_TYPES.has(input.attackType)    // recon class only
    && origin.okPct < 0.5;                                              // origin did NOT serve the paths (no real FP to protect)
  // NB: no matching-evidence gate — for a CONTEXT_URL recon match the "value" IS the path, which an
  // injection classifier reads as benign; the okPct<0.5 + exploit guards already exclude served FPs.

  // A non-existent path (origin 404) carries no legitimate traffic to protect — excluding it
  // adds no value and blocking it adds no risk. When the flagged requests overwhelmingly 404,
  // the path simply does not exist, so steer the verdict to TRUE POSITIVE / safe-to-block.
  // Require a real served sample (>= 5) so a 2-of-2 served-404 behind a blocked majority can't trip it.
  const nonExistentPath = origin.notFoundPct >= 0.8 && origin.served >= 5 && !origin.possibleSuccessfulExploit;

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
  } else if (nonExistentPath) {
    result.compositeScore = Math.min(result.compositeScore, 30);
    result.verdict = scoreToVerdict(result.compositeScore);
    result.override = 'NON_EXISTENT_PATH';
    result.overrideReason = `Origin returned 404 for ${Math.round(origin.notFoundPct * 100)}% of flagged requests — the path does not exist, so blocking adds no risk and excluding adds no value (treated as TP / safe to block).`;
  } else if (scannerEnumeration) {
    result.compositeScore = Math.min(result.compositeScore, 30);
    result.verdict = scoreToVerdict(result.compositeScore);
    result.override = 'SCANNER_ENUMERATION';
    result.overrideReason = `${distinctClients} client(s) requested ${input.pathCount} distinct paths under a recon attack type (${input.attackType}) without the origin serving them — directory/resource enumeration, not the path's normal traffic (treated as TP / safe to block).`;
  } else if (distributedScan) {
    result.compositeScore = Math.min(result.compositeScore, 30);
    result.verdict = scoreToVerdict(result.compositeScore);
    result.override = 'DISTRIBUTED_SCAN';
    result.overrideReason = `${distinctClients} clients enumerated ${input.pathCount} distinct paths the origin did not serve, under a scanning attack type (${input.attackType}) — distributed reconnaissance/scanning (treated as TP / safe to block).`;
  } else if (targetedExploit && aiOrMlDismissed) {
    // F1: at most Ambiguous (never Likely FP); never raises a score that is already TP-ward.
    result.compositeScore = Math.min(result.compositeScore, 50);
    result.verdict = scoreToVerdict(result.compositeScore);
    result.override = 'AI_DISMISSED_EXPLOIT';
    result.overrideReason = `F5 ${isAutoSuppressedState(input.sigState) ? 'auto-suppressed' : 'rated false-positive'} this ${input.attackType} signature, but it is a targeted exploit attempt from ${distinctClients} client(s) — verify the application is not vulnerable before excluding; keep blocking.`;
  } else if (f5ConfirmedFp && result.compositeScore < 60) {
    result.compositeScore = 60;
    result.verdict = scoreToVerdict(60);
    result.override = 'F5_CONFIRMED_FP';
    result.overrideReason = 'F5 AutoSuppressed / AI rated false-positive, content not malicious, origin accepted — treated as likely FP.';
  }

  return result;
}
