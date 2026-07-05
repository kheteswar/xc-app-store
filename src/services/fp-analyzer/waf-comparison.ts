/**
 * Traditional vs AI-Powered WAF comparison.
 *
 * F5 XC's AI risk scoring complements — does not replace — the signature engine.
 * For each request it re-classifies the signature match into a risk verdict
 * (req_risk: high/medium/low/"false positive") and AutoSuppresses the ones its ML
 * judges to be false positives. This module compares the two "deciders":
 *
 *   - Signature engine      → signatures[].state (Enabled = active, AutoSuppressed = AI tuned out)
 *   - AI risk engine        → req_risk (high/medium = attack, low / "false positive" = benign)
 *
 * Where they DISAGREE tells you whether enabling AI-based action would improve accuracy:
 *   - Enabled signature + AI-benign  → the signature is still flagging traffic the AI rates
 *     legitimate. In Blocking mode these are potential false-positive blocks that AI-based
 *     action would avoid. Corroborated when the origin returned 200 (it served the request).
 *
 * Goal: decision support for "should AI-powered WAF (Automatic Attack Signature Tuning) be enabled?"
 */
import { parseReqRisk } from './ai-signals';
import { botClassificationRaw } from './bot-analysis';

type Ev = Record<string, unknown>;
// Coerce to string so rsp_code === '200' etc. hold on tenants that emit numeric response codes.
const str = (e: Ev, k: string): string => { const v = e[k]; return v == null ? '' : String(v); };

export type WafRecommendation = 'enable_ai_blocking' | 'monitor' | 'investigate' | 'ai_data_sparse';

export interface WafSignatureDivergence {
  sigId: string;
  name: string;
  events: number;
  enabled: number;
  autoSuppressed: number;
  staging: number;
  aiAttack: number;
  aiBenign: number;            // req_risk low OR "false positive"
  aiFalsePositive: number;     // req_risk == "false positive" specifically (the AI's explicit FP verdict)
  aiUnknown: number;
  origin200Pct: number;
  /** Engine still active (Enabled) but AI rates benign — the tuning-candidate count. */
  engineActiveAiBenign: number;
}

export interface WafComparisonResult {
  totalEvents: number;
  /** Fraction of flagged events that carry a usable AI req_risk verdict. */
  aiDataCoveragePct: number;
  enforcementMode: 'blocking' | 'monitoring' | 'unknown';
  stateCounts: { enabled: number; autoSuppressed: number; staging: number; other: number };
  riskCounts: { high: number; medium: number; low: number; falsePositive: number; unknown: number };
  actionCounts: { block: number; report: number; allow: number; other: number };
  /** Engine state × AI verdict confusion matrix. */
  matrix: {
    bothAttack: number;             // Enabled + AI attack — agree
    engineActiveAiBenign: number;   // Enabled + AI benign — AI would prevent a likely FP block
    aiSuppressedRiskAttack: number; // AutoSuppressed + AI attack — conflict (rare)
    bothBenign: number;             // AutoSuppressed + AI benign — agree (AI working)
    other: number;                  // staging / no AI verdict
  };
  alreadySuppressedByAi: number;
  wouldPreventIfAiBlocking: number;
  agreementPct: number;
  fpReductionOpportunityPct: number;
  /** Of AI-benign events, the % the origin answered 200 (corroborates the AI's benign calls). */
  aiBenignOrigin200Pct: number;
  recommendation: WafRecommendation;
  recommendationReason: string;
  /** One-line plain-language takeaway. */
  headline: string;
  /** Surfaced when the WAF is monitoring but the AI confirms attacks (not being blocked). */
  enforcementNote?: string;
  aiAttackCount: number;       // req_risk high + medium
  aiBenignCount: number;       // req_risk low + false positive
  aiAttackNotBlocked: number;  // AI-attack events the WAF did not block
  /**
   * Customer-facing AI advantage: false positives the AI-powered WAF correctly ALLOWS that the
   * traditional (Enabled) signature WAF BLOCKS — so the AI spares you manual exclusion rules.
   * This is the win even when a signature is mixed Enabled/AutoSuppressed but AI rates it benign.
   */
  aiAdvantage: {
    /** Distinct enforced signatures + violations the AI rates benign (traditional blocks, AI allows). */
    detectionsPreventingFp: number;
    /** Total requests AI would correctly allow that the traditional signature/violation WAF blocks. */
    fpRequestsPrevented: number;
    /** Approx. manual exclusion rules the traditional model needs for these FPs that AI tuning avoids. */
    exclusionRulesAvoided: number;
  };
  /**
   * Per-request BLOCK vs ALLOW comparison over EVERY flagged request (signatures, violations,
   * and bot detections — a 1-to-1 view). Traditional WAF blocks a request if ANY of its
   * signatures OR violations is enforced (Enabled), OR it is a malicious bot (bot-signature
   * detection); AI-powered WAF decides from the single per-request req_risk score. The 2x2 of
   * these two decisions is in `matrix`.
   */
  perRequest: {
    total: number;              // requests with >= 1 signature, violation, or malicious-bot detection
    traditionalBlocks: number;  // enforced signature/violation OR a malicious bot
    traditionalAllows: number;  // none enforced (all AutoSuppressed / Staging / benign)
    aiBlocks: number;           // req_risk high / medium
    aiAllows: number;           // req_risk low / false-positive
    aiUnknown: number;          // no req_risk verdict
    maliciousBots: number;      // requests included because they are malicious-bot detections
  };
  /**
   * Side-by-side blocking-approach comparison over the SAME requests (the easy table):
   * Traditional-Enabled vs AI-High vs AI-High+Medium — who blocks more, who over-blocks more FPs.
   */
  approaches: {
    totalAttacks: number;          // req_risk attack (high/medium)
    totalFalsePositives: number;   // req_risk benign (low / false-positive)
    rows: Array<{
      key: 'traditional' | 'ai_high' | 'ai_high_med';
      label: string;
      blocked: number;             // requests this approach would block
      attacksBlocked: number;      // of those, real attacks
      fpBlocked: number;           // of those, false positives it would OVER-block
      attacksMissed: number;       // real attacks it does NOT block
    }>;
  };
  /**
   * Which WAF catches each false positive: the traditional engine via signature state =
   * AutoSuppressed, vs the AI via req_risk == "false positive". A signature appears here when
   * EITHER engine flagged a false positive on it.
   */
  fpSuppression: Array<{
    sigId: string;
    name: string;
    events: number;
    autoSuppressed: number;     // events with signature state = AutoSuppressed (traditional ML FP)
    aiFalsePositive: number;    // events with req_risk == "false positive" (the AI's explicit FP verdict)
    stillEnabled: number;       // events still Enabled (traditional would still block)
    verdict: string;            // which engine caught the FP (and the AI-win callout)
  }>;
  bySignature: WafSignatureDivergence[];
}

function isSuppressed(state: string): boolean { return /autosuppress|auto[\s_-]*suppress|suppress/i.test(state); }
function isStaging(state: string): boolean { return /stag/i.test(state); }

/**
 * Would the TRADITIONAL signature/violation engine BLOCK this request? True if ANY signature
 * OR violation is enforced (Enabled — i.e. not AutoSuppressed and not Staging). This is the
 * per-request traditional decision the user described: one enabled detection blocks the request,
 * whereas the AI-powered WAF decides from the single per-request req_risk score.
 */
/** A malicious bot — detected by a Bot Signature; the traditional WAF/Bot-Defense would block it.
 *  Uses the shared robust classifier (handles nested / flattened / stringified bot_info). */
function isMaliciousBot(e: Ev): boolean {
  return /malicious/i.test(botClassificationRaw(e as Record<string, unknown>));
}

/** The signature/violation engine's block decision alone (NO bot). An enforced (Enabled/empty-state)
 *  signature or violation is what an exclusion rule would have to clear — only these can be false
 *  positives. A malicious bot is a true positive (safe to block), never an FP. */
function enforcedDetection(e: Ev): boolean {
  const enforced = (arr: unknown): boolean =>
    Array.isArray(arr) && arr.some(d => {
      const st = String((d as Record<string, unknown>).state || '');
      return !isSuppressed(st) && !isStaging(st); // Enabled / empty → enforced → blocks
    });
  return enforced(e.signatures) || enforced(e.violations);
}

/** The event's overall engine activity: Enabled wins (engine would act), else staging, else suppressed. */
function eventEngineState(e: Ev): 'enabled' | 'autoSuppressed' | 'staging' | 'other' {
  const sigs = (e.signatures as Array<Record<string, unknown>>) || [];
  let hasEnabled = false, hasStaging = false, hasAuto = false;
  for (const s of sigs) {
    const st = String(s.state || '');
    if (isSuppressed(st)) hasAuto = true;
    else if (isStaging(st)) hasStaging = true;
    else hasEnabled = true; // Enabled / empty / unknown → active
  }
  if (hasEnabled) return 'enabled';
  if (hasStaging) return 'staging';
  if (hasAuto) return 'autoSuppressed';
  return 'other';
}

type AiVerdict = 'attack' | 'benign' | 'unknown';
function aiVerdictOf(rawRisk: string): AiVerdict {
  const level = parseReqRisk(rawRisk);
  if (level === 'unknown') return 'unknown';
  return level === 'high' || level === 'medium' ? 'attack' : 'benign';
}

interface SigAcc extends WafSignatureDivergence {
  origin200Count: number;
  fpEnabled: number;         // events that are BOTH req_risk="false positive" AND signature Enabled (AI catches an FP the engine still blocks)
  fpAutoSuppressed: number;  // events that are BOTH req_risk="false positive" AND state=AutoSuppressed (both engines caught it)
}

export function computeWafComparison(
  events: Ev[],
  enforcementMode: 'blocking' | 'monitoring' | 'unknown',
): WafComparisonResult {
  const stateCounts = { enabled: 0, autoSuppressed: 0, staging: 0, other: 0 };
  const riskCounts = { high: 0, medium: 0, low: 0, falsePositive: 0, unknown: 0 };
  const actionCounts = { block: 0, report: 0, allow: 0, other: 0 };
  const matrix = { bothAttack: 0, engineActiveAiBenign: 0, aiSuppressedRiskAttack: 0, bothBenign: 0, other: 0 };
  let aiKnown = 0, aiBenignTotal = 0, aiBenignOrigin200 = 0, aiAttackNotBlocked = 0;
  // Genuine false positives the AI prevents: an Enabled signature/violation the AI rates benign,
  // EXCLUDING malicious bots (a malicious bot is a true positive, not an FP — crediting the AI for
  // "preventing" a bot block would overstate the AI advantage and the FP-reduction opportunity).
  let fpAiPrevented = 0;
  const bySig = new Map<string, SigAcc>();
  // detection key (s:<sigId> | v:<violName>) → distinct (context|path) of its enforced + AI-benign
  // events (the manual exclusions the traditional model would need, which the AI tuning avoids).
  const fpPreventMap = new Map<string, Set<string>>();
  const perRequest = { total: 0, traditionalBlocks: 0, traditionalAllows: 0, aiBlocks: 0, aiAllows: 0, aiUnknown: 0, maliciousBots: 0 };
  // Side-by-side approach tallies + overall attack/FP totals (req_risk-based).
  let totalAttacks = 0, totalFp = 0;
  const ap = { trad: { b: 0, a: 0, f: 0 }, high: { b: 0, a: 0, f: 0 }, highMed: { b: 0, a: 0, f: 0 } };

  for (const e of events) {
    const sigs = (e.signatures as Array<Record<string, unknown>>) || [];
    const viols = (e.violations as Array<Record<string, unknown>>) || [];
    const malBot = isMaliciousBot(e);
    // Include every flagged request: signatures, violations, AND bot detections (1-to-1 view).
    if (sigs.length === 0 && viols.length === 0 && !malBot) continue;
    if (malBot) perRequest.maliciousBots++;

    const state = eventEngineState(e);
    stateCounts[state]++;

    const rawRisk = str(e, 'req_risk');
    const isFalsePositive = /false[\s_-]*positive/i.test(rawRisk);
    const level = parseReqRisk(rawRisk);
    if (level === 'unknown') riskCounts.unknown++;
    else if (level === 'high') riskCounts.high++;
    else if (level === 'medium') riskCounts.medium++;
    else if (isFalsePositive) riskCounts.falsePositive++;
    else riskCounts.low++;

    const ai = aiVerdictOf(rawRisk);
    if (ai !== 'unknown') aiKnown++;

    const action = str(e, 'action').toLowerCase();
    if (action === 'block') actionCounts.block++;
    else if (action === 'report') actionCounts.report++;
    else if (action === 'allow') actionCounts.allow++;
    else actionCounts.other++;

    const origin200 = str(e, 'rsp_code') === '200' || /^2xx$/i.test(str(e, 'rsp_code_class'));

    // Per-request decision: Traditional blocks if ANY signature OR violation is enforced OR it is a
    // malicious bot. enforcedBlock is the signature/violation engine alone (FP accounting uses it).
    const enforcedBlock = enforcedDetection(e);
    const tradBlock = enforcedBlock || malBot;
    // FP/attack classification: a malicious bot is a TRUE POSITIVE (safe to block), never an FP —
    // even if F5's AI happens to rate its req_risk benign.
    const isFp = ai === 'benign' && !malBot;
    const isAttack = ai === 'attack' || malBot;
    perRequest.total++;
    if (tradBlock) perRequest.traditionalBlocks++; else perRequest.traditionalAllows++;
    if (ai === 'attack') perRequest.aiBlocks++;
    else if (ai === 'benign') perRequest.aiAllows++;
    else perRequest.aiUnknown++;

    // Traditional (block/allow) x AI (block/allow) decision matrix (over requests with a known AI verdict).
    if (ai === 'unknown') matrix.other++;
    else if (tradBlock && ai === 'attack') matrix.bothAttack++;            // both BLOCK — agree attack
    else if (tradBlock && ai === 'benign') matrix.engineActiveAiBenign++;  // trad BLOCK, AI ALLOW
    else if (!tradBlock && ai === 'attack') matrix.aiSuppressedRiskAttack++; // trad ALLOW, AI BLOCK — AI catches it
    else matrix.bothBenign++;                                             // both ALLOW — agree benign
    // Genuine FP the AI would prevent: enforced signature/violation, AI rates benign, NOT a bot.
    if (enforcedBlock && isFp) fpAiPrevented++;

    if (ai === 'benign') { aiBenignTotal++; if (origin200) aiBenignOrigin200++; }
    if (ai === 'attack' && action !== 'block') aiAttackNotBlocked++;

    // Side-by-side approach comparison: which approach blocks this request, and is it attack or FP?
    if (isAttack) totalAttacks++; else if (isFp) totalFp++;
    const tally = (slot: { b: number; a: number; f: number }, blocked: boolean) => {
      if (!blocked) return;
      slot.b++;
      if (isAttack) slot.a++; else if (isFp) slot.f++;
    };
    tally(ap.trad, tradBlock);
    tally(ap.high, level === 'high');
    tally(ap.highMed, level === 'high' || level === 'medium');

    // Track enforced violations that are a genuine FP the AI auto-allows (excl. malicious bots).
    if (isFp) {
      for (const v of viols) {
        const st = String(v.state || '');
        if (isSuppressed(st) || isStaging(st)) continue; // only enforced violations would block
        const name = String(v.name || '');
        if (!name) continue;
        const ctxKey = `${String(v.context || 'CONTEXT_ANY')}|${str(e, 'req_path')}`;
        let set = fpPreventMap.get('v:' + name);
        if (!set) { set = new Set(); fpPreventMap.set('v:' + name, set); }
        set.add(ctxKey);
      }
    }

    for (const s of sigs) {
      const id = String(s.id || '');
      if (!id) continue;
      let d = bySig.get(id);
      if (!d) {
        d = { sigId: id, name: String(s.name || ''), events: 0, enabled: 0, autoSuppressed: 0, staging: 0, aiAttack: 0, aiBenign: 0, aiFalsePositive: 0, aiUnknown: 0, origin200Pct: 0, engineActiveAiBenign: 0, origin200Count: 0, fpEnabled: 0, fpAutoSuppressed: 0 };
        bySig.set(id, d);
      }
      d.events++;
      const sst = String(s.state || '');
      const suppressed = isSuppressed(sst), staging = isStaging(sst);
      if (suppressed) d.autoSuppressed++; else if (staging) d.staging++; else d.enabled++;
      if (ai === 'attack') d.aiAttack++; else if (ai === 'benign') d.aiBenign++; else d.aiUnknown++;
      if (isFalsePositive) {
        d.aiFalsePositive++; // the AI's explicit req_risk = "false positive" verdict
        // Joint state×verdict counts drive an accurate "which engine caught this FP" verdict (the
        // marginal aiFalsePositive and enabled counts may describe DIFFERENT events).
        if (suppressed) d.fpAutoSuppressed++; else if (!staging) d.fpEnabled++;
      }
      if (!suppressed && !staging && isFp) {
        d.engineActiveAiBenign++;
        const ctxKey = `${String(s.context || '')}|${String(s.context_name || '')}|${str(e, 'req_path')}`;
        let set = fpPreventMap.get('s:' + id);
        if (!set) { set = new Set(); fpPreventMap.set('s:' + id, set); }
        set.add(ctxKey);
      }
      if (origin200) d.origin200Count++;
    }
  }

  const total = stateCounts.enabled + stateCounts.autoSuppressed + stateCounts.staging + stateCounts.other;
  const matrixTotal = matrix.bothAttack + matrix.engineActiveAiBenign + matrix.aiSuppressedRiskAttack + matrix.bothBenign;
  const agreement = matrix.bothAttack + matrix.bothBenign;
  const agreementPct = matrixTotal > 0 ? agreement / matrixTotal : 0;
  const fpReductionOpportunityPct = total > 0 ? fpAiPrevented / total : 0;
  const aiBenignOrigin200Pct = aiBenignTotal > 0 ? aiBenignOrigin200 / aiBenignTotal : 0;
  const aiDataCoveragePct = total > 0 ? aiKnown / total : 0;

  const bySignature: WafSignatureDivergence[] = [...bySig.values()]
    .map(d => { const { origin200Count, ...rest } = d; return { ...rest, origin200Pct: d.events > 0 ? origin200Count / d.events : 0 }; })
    .sort((a, b) => (b.engineActiveAiBenign - a.engineActiveAiBenign) || (b.events - a.events))
    .slice(0, 50);

  const mkApproach = (key: 'traditional' | 'ai_high' | 'ai_high_med', label: string, slot: { b: number; a: number; f: number }) =>
    ({ key, label, blocked: slot.b, attacksBlocked: slot.a, fpBlocked: slot.f, attacksMissed: Math.max(0, totalAttacks - slot.a) });
  const approaches = {
    totalAttacks, totalFalsePositives: totalFp,
    rows: [
      mkApproach('traditional', 'Traditional — Enabled (signature / violation / bot)', ap.trad),
      mkApproach('ai_high', 'AI — High risk', ap.high),
      mkApproach('ai_high_med', 'AI — High + Medium', ap.highMed),
    ],
  };
  // Which WAF catches each false positive: traditional (state = AutoSuppressed) vs AI (req_risk =
  // "false positive"). Verdict tells the user which engine handled the FP — and flags the AI win
  // (AI calls it a false positive while the engine still has it Enabled and would block it).
  // Verdict from PER-EVENT joins: fpEnabled = events that are both req_risk-FP AND Enabled (AI catches
  // an FP the engine still blocks); fpAutoSuppressed = events both req_risk-FP AND AutoSuppressed (both
  // caught it). A signature with only AutoSuppressed-non-FP events is "Traditional catches it".
  const fpVerdict = (d: SigAcc): string => {
    if (d.fpEnabled > 0 && d.fpAutoSuppressed > 0) return 'Mixed — AI catches some the engine still blocks';
    if (d.fpEnabled > 0) return 'AI catches it — traditional still blocks';
    if (d.fpAutoSuppressed > 0) return 'Both catch it';
    if (d.autoSuppressed > 0) return 'Traditional catches it';
    return '—';
  };
  const fpSuppression = [...bySig.values()]
    .filter(d => d.aiFalsePositive > 0 || d.autoSuppressed > 0)
    .map(d => ({
      sigId: d.sigId, name: d.name, events: d.events,
      autoSuppressed: d.autoSuppressed, aiFalsePositive: d.aiFalsePositive, stillEnabled: d.enabled,
      verdict: fpVerdict(d),
    }))
    .sort((a, b) => (b.aiFalsePositive + b.autoSuppressed) - (a.aiFalsePositive + a.autoSuppressed))
    .slice(0, 30);

  let recommendation: WafRecommendation;
  let recommendationReason: string;
  if (aiDataCoveragePct < 0.2) {
    recommendation = 'ai_data_sparse';
    recommendationReason = `Only ${(aiDataCoveragePct * 100).toFixed(0)}% of flagged events carry an AI req_risk verdict — enable AI-powered WAF (Automatic Attack Signature Tuning) to populate these signals before comparing.`;
  } else if (fpReductionOpportunityPct >= 0.15 && aiBenignOrigin200Pct >= 0.6) {
    recommendation = 'enable_ai_blocking';
    recommendationReason = `Signatures actively flag ${(fpReductionOpportunityPct * 100).toFixed(0)}% of events the AI rates benign, and ${(aiBenignOrigin200Pct * 100).toFixed(0)}% of AI-benign requests got a 200 OK from the origin — strong corroboration. Enabling AI-based blocking would avoid these likely false-positive blocks.`;
  } else if (agreementPct >= 0.8) {
    recommendation = 'monitor';
    recommendationReason = `The signature engine and AI agree on ${(agreementPct * 100).toFixed(0)}% of events — AI changes little here; keep monitoring and tune the divergent signatures.`;
  } else {
    recommendation = 'investigate';
    recommendationReason = `Signature engine and AI diverge on ${((1 - agreementPct) * 100).toFixed(0)}% of events but corroboration is mixed (${(aiBenignOrigin200Pct * 100).toFixed(0)}% origin-200) — review the top divergent signatures before changing enforcement.`;
  }

  const aiAttackCount = riskCounts.high + riskCounts.medium;
  const aiBenignCount = riskCounts.low + riskCounts.falsePositive;
  const pct = (x: number) => `${(x * 100).toFixed(0)}%`;

  let headline: string;
  if (recommendation === 'ai_data_sparse') {
    headline = `AI risk data is sparse (${pct(aiDataCoveragePct)} of events carry a req_risk) — enable AI-powered WAF to compare the engines.`;
  } else if (fpReductionOpportunityPct >= 0.15) {
    headline = `Signatures are over-flagging: the engine still acts on ${pct(fpReductionOpportunityPct)} of events the AI rates benign. AI-based action would cut these false positives.`;
  } else if (total > 0 && agreementPct >= 0.8 && aiAttackCount / total >= 0.8) {
    headline = `Strong agreement (${pct(agreementPct)}): both engines classify the large majority as real attacks — very low false-positive noise, the signatures are accurate here.`;
  } else {
    headline = `The two engines agree on ${pct(agreementPct)} of events; the rest diverge — review the divergent signatures below.`;
  }

  const enforcementNote = (enforcementMode === 'monitoring' && aiAttackNotBlocked > 0)
    ? `WAF is in MONITORING mode — ${aiAttackNotBlocked.toLocaleString()} AI-confirmed attack request(s) were logged but NOT blocked. Switch to Blocking to stop them.`
    : undefined;

  const aiAdvantage = {
    detectionsPreventingFp: fpPreventMap.size,
    fpRequestsPrevented: fpAiPrevented,
    exclusionRulesAvoided: [...fpPreventMap.values()].reduce((acc, set) => acc + set.size, 0),
  };

  return {
    totalEvents: total, aiDataCoveragePct, enforcementMode, stateCounts, riskCounts, actionCounts, matrix,
    alreadySuppressedByAi: stateCounts.autoSuppressed, wouldPreventIfAiBlocking: fpAiPrevented,
    agreementPct, fpReductionOpportunityPct, aiBenignOrigin200Pct, recommendation, recommendationReason,
    headline, enforcementNote, aiAttackCount, aiBenignCount, aiAttackNotBlocked, aiAdvantage, perRequest, approaches, fpSuppression, bySignature,
  };
}
