/**
 * Blocking-Mode (Enforcement) Comparison
 *
 * The goal of FP analysis is to answer: "If I flip enforcement to Blocking, which
 * requests get blocked, how many of those blocks are false positives, and therefore
 * how many WAF exclusion rules will I have to write to clear them?"
 *
 * This module runs that simulation for THREE candidate blocking policies over the
 * security events the analyzer already pulled — covering BOTH WAF signatures and WAF
 * violations on each request — and compares them so the user can pick the policy that
 * stops the real attacks with the least exclusion overhead.
 *
 *   - legacy_accuracy  → block when a matched signature is High/Medium ACCURACY (not
 *                        Staging), OR a violation is enforced (not Staging). The classic
 *                        posture. It has no AI tuning, so AutoSuppressed signatures still
 *                        block here — which is exactly why it tends to over-block.
 *   - ai_risk_high     → block when req_risk = High (AI-powered, per-request).
 *   - ai_risk_high_med → block when req_risk ∈ {High, Medium}.
 *
 * FP vs TP of a block is decided by the SAME enriched per-detection verdict the rest of
 * the FP engine produces (full-engine basis): a block is a true positive if the request
 * carries ≥1 TP-ward signature/violation (a real attack is present, so blocking is
 * justified); it is a false positive only if EVERY firing detection is FP-ward. The
 * exclusion overhead is computed with the very same rollup the tool uses to generate the
 * real policy, so the "rules needed" number matches what the user would actually create.
 */
import type { FPVerdict, BlockingPolicyId, PolicyOutcome, EnforcementComparisonResult, WafExclusionRule } from './types';
import { parseReqRisk } from './ai-signals';
import {
  buildSignatureExclusionsWithRollup, generateViolationExclusion, groupExclusionRules,
  type SigExclusionIntent,
} from './exclusion-generator';

/** One signature reference inside an event (the fields the simulation needs). */
export interface ComparisonSignatureRef {
  id: string;
  accuracy: string;
  state: string;
}

/** One violation reference inside an event (violations have no accuracy tier). */
export interface ComparisonViolationRef {
  name: string;
  state: string;
}

/** A single security event reduced to what the blocking simulation reads. */
export interface ComparisonEvent {
  reqRisk: string;
  signatures: ComparisonSignatureRef[];
  violations: ComparisonViolationRef[];
  /** Request is a Malicious-classified bot (Bot Signature). The traditional WAF/Bot-Defense would
   *  block it; it is a true positive (safe to block), never a false positive. */
  maliciousBot?: boolean;
}

/** Per-signature metadata + enriched FP verdict, used for FP attribution + exclusion rollup. */
export interface SignatureMeta {
  sigId: string;
  name: string;
  verdict: FPVerdict;
  attackType: string;
  contextType: string;
  contextName: string;
  path: string;
  methods: string[];
}

/** Per-violation metadata + enriched FP verdict. */
export interface ViolationMeta {
  name: string;
  verdict: FPVerdict;
  path: string;
  methods: string[];
}

const POLICY_LABEL: Record<BlockingPolicyId, string> = {
  legacy_accuracy: 'Legacy — accuracy sigs + violations + malicious bots',
  ai_risk_high: 'AI risk — High only',
  ai_risk_high_med: 'AI risk — High + Medium',
};
const POLICY_DESC: Record<BlockingPolicyId, string> = {
  legacy_accuracy: 'Traditional WAF + Bot Defense: block when a signature is High/Medium accuracy (not Staging), a violation is enforced (not Staging), OR the client is a malicious bot — no AI tuning.',
  ai_risk_high: 'Block when the AI rates the request req_risk = High (also blocks malicious bots, which score High).',
  ai_risk_high_med: 'Block when the AI rates the request req_risk = High or Medium.',
};

function isFpVerdict(v: FPVerdict | undefined): boolean {
  return v === 'highly_likely_fp' || v === 'likely_fp';
}
function isTpVerdict(v: FPVerdict | undefined): boolean {
  return v === 'likely_tp' || v === 'confirmed_tp';
}
function isHighOrMedAccuracy(accuracy: string): boolean {
  const a = (accuracy || '').toLowerCase();
  return a.includes('high') || a.includes('medium');
}
function isStaging(state: string): boolean {
  return /stag/i.test(state || '');
}

type RequestClass = 'tp' | 'fp' | 'ambiguous';

/** A per-policy accumulator built up over the event stream. */
interface PolicyAcc {
  blocked: number;
  tp: number;
  fp: number;
  ambiguous: number;
  /** sigId → count of FP-blocked events attributed to it. */
  fpSigBlockedEvents: Map<string, number>;
  /** violationName → count of FP-blocked events attributed to it. */
  fpViolBlockedEvents: Map<string, number>;
}
function emptyAcc(): PolicyAcc {
  return { blocked: 0, tp: 0, fp: 0, ambiguous: 0, fpSigBlockedEvents: new Map(), fpViolBlockedEvents: new Map() };
}

interface RequestVerdict {
  cls: RequestClass;
  /** FP-ward detections, full set (used by the AI policies). */
  fpSigIdsAll: string[];
  fpViolNamesAll: string[];
  /** FP-ward detections legacy would actually block (High/Med-acc non-staging sigs; enforced viols). */
  fpSigIdsLegacy: string[];
  fpViolNamesLegacy: string[];
}

/**
 * Classify a request as TP / FP / ambiguous from the enriched verdicts of every signature
 * AND violation it triggered. TP if any detection is TP-ward; FP only if every detection is
 * FP-ward; otherwise ambiguous. Also returns which FP detections each policy would block.
 */
function classifyRequest(ev: ComparisonEvent, sigMeta: Map<string, SignatureMeta>, violMeta: Map<string, ViolationMeta>): RequestVerdict {
  let hasTp = false;
  let detCount = 0;
  let allFp = true;
  const fpSigIdsAll: string[] = [];
  const fpSigIdsLegacy: string[] = [];
  const fpViolNamesAll: string[] = [];
  const fpViolNamesLegacy: string[] = [];

  for (const s of ev.signatures) {
    if (!s.id) continue;
    detCount++;
    const v = sigMeta.get(s.id)?.verdict;
    if (isTpVerdict(v)) hasTp = true;
    if (isFpVerdict(v)) {
      fpSigIdsAll.push(s.id);
      if (isHighOrMedAccuracy(s.accuracy) && !isStaging(s.state)) fpSigIdsLegacy.push(s.id);
    } else {
      allFp = false;
    }
  }
  for (const vo of ev.violations) {
    if (!vo.name) continue;
    detCount++;
    const v = violMeta.get(vo.name)?.verdict;
    if (isTpVerdict(v)) hasTp = true;
    if (isFpVerdict(v)) {
      fpViolNamesAll.push(vo.name);
      if (!isStaging(vo.state)) fpViolNamesLegacy.push(vo.name);
    } else {
      allFp = false;
    }
  }

  const cls: RequestClass = hasTp ? 'tp' : (detCount > 0 && allFp ? 'fp' : 'ambiguous');
  return { cls, fpSigIdsAll, fpViolNamesAll, fpSigIdsLegacy, fpViolNamesLegacy };
}

/** Distinct exclusion rules to clear a set of FP signatures + violations (real generator's rollup). */
function rulesForFpDetections(
  sigIds: Iterable<string>, violNames: Iterable<string>,
  sigMeta: Map<string, SignatureMeta>, violMeta: Map<string, ViolationMeta>, domain: string,
): number {
  const rules: WafExclusionRule[] = [];
  const sigIntents: SigExclusionIntent[] = [];
  for (const id of sigIds) {
    const m = sigMeta.get(id);
    if (!m) continue;
    sigIntents.push({
      signatureId: m.sigId, attackType: m.attackType, contextType: m.contextType,
      contextName: m.contextName, path: m.path || '/', methods: m.methods.length ? m.methods : ['GET'],
    });
  }
  if (sigIntents.length) rules.push(...buildSignatureExclusionsWithRollup(sigIntents, domain));
  for (const name of violNames) {
    const m = violMeta.get(name);
    if (!m) continue;
    rules.push(generateViolationExclusion(m.name, 'CONTEXT_ANY', '', domain, m.path || '/', m.methods.length ? m.methods : ['GET']));
  }
  if (rules.length === 0) return 0;
  // Merge signature + violation rules sharing a domain/path/methods into one rule, like the real policy.
  return groupExclusionRules(rules).length;
}

export function computeEnforcementComparison(
  events: ComparisonEvent[],
  sigMeta: Map<string, SignatureMeta>,
  violMeta: Map<string, ViolationMeta> = new Map(),
  domain = '',
): EnforcementComparisonResult {
  const acc: Record<BlockingPolicyId, PolicyAcc> = {
    legacy_accuracy: emptyAcc(),
    ai_risk_high: emptyAcc(),
    ai_risk_high_med: emptyAcc(),
  };

  let totalTp = 0, totalFp = 0;
  let legacyOnly = 0, aiHighOnly = 0;
  // Legacy-only blocks split by which AI policy is the comparison + how many are false positives,
  // so the headline can quote the delta against the ACTUAL recommended policy with a backed FP count.
  let legacyOnlyFp = 0, legacyOnlyHM = 0, legacyOnlyHMFp = 0;
  let considered = 0;

  for (const ev of events) {
    const sigs = ev.signatures || [];
    const viols = ev.violations || [];
    const malBot = !!ev.maliciousBot;
    if (sigs.length === 0 && viols.length === 0 && !malBot) continue;
    considered++;

    // A malicious bot is a real attack (true positive, safe to block) and generates NO false-positive
    // exclusion detections. Otherwise classify by the signature/violation verdicts.
    const r = classifyRequest(ev, sigMeta, violMeta);
    const cls: RequestClass = malBot ? 'tp' : r.cls;
    const fpSigsLegacy = malBot ? [] : r.fpSigIdsLegacy;
    const fpViolsLegacy = malBot ? [] : r.fpViolNamesLegacy;
    const fpSigsAll = malBot ? [] : r.fpSigIdsAll;
    const fpViolsAll = malBot ? [] : r.fpViolNamesAll;
    if (cls === 'tp') totalTp++;
    else if (cls === 'fp') totalFp++;

    // Traditional WAF blocks an enforced accuracy signature, an enforced violation, OR a malicious
    // bot (Bot Defense). The AI policies decide from the per-request risk score.
    const legacyBlock = malBot
      || sigs.some(s => isHighOrMedAccuracy(s.accuracy) && !isStaging(s.state))
      || viols.some(vo => !!vo.name && !isStaging(vo.state));
    const level = parseReqRisk(ev.reqRisk);
    const aiHighBlock = level === 'high';
    const aiHighMedBlock = level === 'high' || level === 'medium';

    if (legacyBlock && !aiHighBlock) { legacyOnly++; if (cls === 'fp') legacyOnlyFp++; }
    if (!legacyBlock && aiHighBlock) aiHighOnly++;
    if (legacyBlock && !aiHighMedBlock) { legacyOnlyHM++; if (cls === 'fp') legacyOnlyHMFp++; }

    const apply = (policy: BlockingPolicyId, blocked: boolean, fpSigIds: string[], fpViolNames: string[]) => {
      if (!blocked) return;
      const a = acc[policy];
      a.blocked++;
      a[cls === 'tp' ? 'tp' : cls === 'fp' ? 'fp' : 'ambiguous']++;
      if (cls === 'fp') {
        for (const id of fpSigIds) a.fpSigBlockedEvents.set(id, (a.fpSigBlockedEvents.get(id) || 0) + 1);
        for (const nm of fpViolNames) a.fpViolBlockedEvents.set(nm, (a.fpViolBlockedEvents.get(nm) || 0) + 1);
      }
    };
    apply('legacy_accuracy', legacyBlock, fpSigsLegacy, fpViolsLegacy);
    apply('ai_risk_high', aiHighBlock, fpSigsAll, fpViolsAll);
    apply('ai_risk_high_med', aiHighMedBlock, fpSigsAll, fpViolsAll);
  }

  const policies: PolicyOutcome[] = (Object.keys(acc) as BlockingPolicyId[]).map(policy => {
    const a = acc[policy];
    const fpDetections = [
      ...[...a.fpSigBlockedEvents.entries()].map(([id, blockedEvents]) => ({
        kind: 'signature' as const, id, name: sigMeta.get(id)?.name || id, blockedEvents, verdict: sigMeta.get(id)?.verdict || ('ambiguous' as FPVerdict),
      })),
      ...[...a.fpViolBlockedEvents.entries()].map(([name, blockedEvents]) => ({
        kind: 'violation' as const, id: name, name, blockedEvents, verdict: violMeta.get(name)?.verdict || ('ambiguous' as FPVerdict),
      })),
    ].sort((x, y) => y.blockedEvents - x.blockedEvents);
    return {
      policy,
      label: POLICY_LABEL[policy],
      description: POLICY_DESC[policy],
      blockedRequests: a.blocked,
      tpBlocked: a.tp,
      fpBlocked: a.fp,
      ambiguousBlocked: a.ambiguous,
      exclusionRulesNeeded: rulesForFpDetections(a.fpSigBlockedEvents.keys(), a.fpViolBlockedEvents.keys(), sigMeta, violMeta, domain),
      attacksMissed: Math.max(0, totalTp - a.tp),
      // Null = "not applicable": with no real attacks in the dataset, attack coverage is undefined
      // (reporting 100% would falsely imply the policy stops attacks that do not exist).
      attackCoveragePct: totalTp > 0 ? a.tp / totalTp : null,
      fpDetections,
    };
  });

  const { recommended, recommendationReason } = recommend(policies, totalTp);
  const headline = buildHeadline(policies, recommended, {
    ai_risk_high: { only: legacyOnly, fp: legacyOnlyFp },
    ai_risk_high_med: { only: legacyOnlyHM, fp: legacyOnlyHMFp },
  });
  const narrative = buildNarrative(policies, { total: considered, tp: totalTp, fp: totalFp }, recommended);

  return {
    totalRequests: considered,
    totalTpRequests: totalTp,
    totalFpRequests: totalFp,
    policies,
    legacyOnlyBlocked: legacyOnly,
    aiHighOnlyBlocked: aiHighOnly,
    recommended,
    narrative,
    recommendationReason,
    headline,
  };
}

/**
 * Pick the policy that protects against (nearly) all real attacks for the least exclusion
 * overhead. Among policies that block ≥90% of all TP requests, choose the fewest exclusion
 * rules (tie-break: more attacks blocked, then fewer FP blocks). If none clear 90% coverage,
 * fall back to the highest attack coverage (so protection wins when there's a real gap).
 */
function recommend(policies: PolicyOutcome[], totalTp: number): { recommended: BlockingPolicyId; recommendationReason: string } {
  const byId = (id: BlockingPolicyId) => policies.find(p => p.policy === id)!;
  const COVERAGE_BAR = 0.9;

  if (totalTp === 0) {
    // No real attacks in this window — every block would be a false-positive over-block. Attack
    // coverage is N/A, so just recommend the policy with the fewest exclusion rules (least over-block).
    const best = [...policies].sort((a, b) => (a.exclusionRulesNeeded - b.exclusionRulesNeeded) || (a.fpBlocked - b.fpBlocked))[0];
    return { recommended: best.policy, recommendationReason: `No real attacks in this window — every block would be a false-positive over-block. "${best.label}" needs the fewest exclusion rules (${best.exclusionRulesNeeded}).` };
  }

  const cov = (p: PolicyOutcome) => p.attackCoveragePct == null ? 0 : p.attackCoveragePct;
  const eligible = totalTp > 0 ? policies.filter(p => cov(p) >= COVERAGE_BAR) : policies.slice();

  // When ≥1 policy clears the coverage bar: among them pick the fewest exclusion rules
  // (tie-break more attacks blocked, then fewer FP blocks). When NONE clear the bar there is a real
  // protection gap, so protection wins — pick the HIGHEST coverage first (the previous code sorted by
  // rule-count in both cases, so the fallback chose the LEAST-protective policy while the reason text
  // claimed it was the most-protective).
  const byRulesThenTpThenFp = (a: PolicyOutcome, b: PolicyOutcome) =>
    (a.exclusionRulesNeeded - b.exclusionRulesNeeded) || (b.tpBlocked - a.tpBlocked) || (a.fpBlocked - b.fpBlocked);
  const byCoverageThenRulesThenFp = (a: PolicyOutcome, b: PolicyOutcome) =>
    (cov(b) - cov(a)) || (a.exclusionRulesNeeded - b.exclusionRulesNeeded) || (a.fpBlocked - b.fpBlocked);
  const best = eligible.length > 0
    ? [...eligible].sort(byRulesThenTpThenFp)[0]
    : [...policies].sort(byCoverageThenRulesThenFp)[0];

  const legacy = byId('legacy_accuracy');
  const savedRules = legacy.exclusionRulesNeeded - best.exclusionRulesNeeded;
  let reason: string;
  if (best.policy === 'legacy_accuracy') {
    reason = `Legacy blocking already needs the fewest exclusion rules (${best.exclusionRulesNeeded}) while covering ${pct(best.attackCoveragePct)} of attacks — AI risk blocking would not reduce tuning overhead here.`;
  } else if (eligible.length > 0) {
    reason = `${best.label} blocks ${pct(best.attackCoveragePct)} of real attacks but needs only ${best.exclusionRulesNeeded} exclusion rule(s)` +
      (savedRules > 0 ? `, ${savedRules} fewer than legacy (${legacy.exclusionRulesNeeded}) — least overhead for equivalent protection.` : ` — least overhead at full protection.`);
  } else {
    reason = `No policy blocks ≥${Math.round(COVERAGE_BAR * 100)}% of attacks; ${best.label} gives the highest coverage (${pct(best.attackCoveragePct)}) — protection takes priority over the ${best.exclusionRulesNeeded}-rule overhead.`;
  }
  return { recommended: best.policy, recommendationReason: reason };
}

type LegacyDelta = { only: number; fp: number };
function buildHeadline(
  policies: PolicyOutcome[],
  recommended: BlockingPolicyId,
  deltas: { ai_risk_high: LegacyDelta; ai_risk_high_med: LegacyDelta },
): string {
  const rec = policies.find(p => p.policy === recommended)!;
  const legacy = policies.find(p => p.policy === 'legacy_accuracy')!;
  if (recommended !== 'legacy_accuracy' && legacy.exclusionRulesNeeded > rec.exclusionRulesNeeded) {
    // Quote the delta against the ACTUALLY recommended AI policy, and back the false-positive claim
    // with the real FP count among those legacy-only blocks (instead of an unproven "most are FPs").
    const d = recommended === 'ai_risk_high' ? deltas.ai_risk_high : deltas.ai_risk_high_med;
    const fpClause = d.fp > 0
      ? ` — ${d.fp.toLocaleString()} of them false-positive block(s) you would have to tune out`
      : '';
    return `Recommend "${rec.label}": same attack coverage with ${legacy.exclusionRulesNeeded - rec.exclusionRulesNeeded} fewer exclusion rule(s). Legacy would block ${d.only.toLocaleString()} extra request(s) that "${rec.label}" does not${fpClause}.`;
  }
  return `Recommend "${rec.label}": blocks ${pct(rec.attackCoveragePct)} of real attacks for ${rec.exclusionRulesNeeded} exclusion rule(s) of tuning overhead.`;
}

// Floor (not round) so the displayed % can never overstate the 0.90 coverage eligibility bar
// (a true 89.6% policy is excluded yet must not render as "90%"). Null = not applicable.
/** Plain-language findings + reasoning, computed from the actual numbers, to make the table self-explanatory. */
function buildNarrative(policies: PolicyOutcome[], totals: { total: number; tp: number; fp: number }, recommended: BlockingPolicyId): string[] {
  const by = (id: BlockingPolicyId) => policies.find(p => p.policy === id)!;
  const legacy = by('legacy_accuracy'), high = by('ai_risk_high'), hm = by('ai_risk_high_med');
  const rec = by(recommended);
  const num = (x: number) => x.toLocaleString();
  const cov = (p: PolicyOutcome) => p.attackCoveragePct == null ? 'n/a' : `${Math.floor(p.attackCoveragePct * 100)}%`;
  const out: string[] = [];

  out.push(`What was analysed: of ${num(totals.total)} flagged requests, ${num(totals.tp)} carry a real attack (including malicious bots) and ${num(totals.fp)} are false positives — benign requests the WAF over-matched. The question is which blocking policy stops the attacks with the least false-positive (exclusion-rule) overhead.`);

  out.push(`Legacy / traditional WAF (any enforced signature, enforced violation, or malicious bot) would block ${num(legacy.blockedRequests)} requests at ${cov(legacy)} attack coverage, but it also blocks ${num(legacy.fpBlocked)} false positive(s) — clearing those needs ${num(legacy.exclusionRulesNeeded)} WAF exclusion rule(s) of ongoing tuning.`);

  out.push(`AI — High risk only blocks ${num(high.blockedRequests)} (${cov(high)} coverage) with ${num(high.exclusionRulesNeeded)} exclusion rule(s), but misses ${num(high.attacksMissed)} real attack(s) — the Medium-risk attacks it does not block.`);

  out.push(`AI — High + Medium blocks ${num(hm.blockedRequests)} (${cov(hm)} coverage, missing ${num(hm.attacksMissed)}) with ${num(hm.exclusionRulesNeeded)} exclusion rule(s): the AI's per-request risk score allows the false positives instead of blocking them, so there is little or nothing to tune out.`);

  if (recommended === 'ai_risk_high_med') {
    const saved = Math.max(0, legacy.exclusionRulesNeeded - hm.exclusionRulesNeeded);
    out.push(`Why "${rec.label}": it matches the traditional engine's protection to within ${num(hm.attacksMissed)} attack while removing ${num(saved)} exclusion rule(s) of overhead — the AI auto-allows the false positives that legacy would block. Choose AI — High only if you can accept the ${num(high.attacksMissed)} missed attack(s) in exchange for zero Medium-risk blocking; choose Legacy only if you must keep signature-based blocking and will maintain its ${num(legacy.exclusionRulesNeeded)} exclusion rule(s).`);
  } else if (recommended === 'ai_risk_high') {
    out.push(`Why "${rec.label}": it covers the real attacks at the High threshold with ${num(high.exclusionRulesNeeded)} exclusion rule(s); adding Medium risk would not improve coverage enough to justify the extra blocking.`);
  } else {
    out.push(`Why "${rec.label}": ${rec.exclusionRulesNeeded === 0 ? 'it already needs no exclusion rules' : `it needs the fewest exclusion rules (${num(rec.exclusionRulesNeeded)})`} while covering ${cov(rec)} of attacks — AI risk blocking would not reduce the tuning overhead here.`);
  }
  return out;
}

function pct(x: number | null): string {
  if (x == null) return 'n/a';
  return `${Math.floor(x * 100)}%`;
}
