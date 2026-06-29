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

type Ev = Record<string, unknown>;
const str = (e: Ev, k: string): string => (e[k] as string) || '';

export type WafRecommendation = 'enable_ai_blocking' | 'monitor' | 'investigate' | 'ai_data_sparse';

export interface WafSignatureDivergence {
  sigId: string;
  name: string;
  events: number;
  enabled: number;
  autoSuppressed: number;
  staging: number;
  aiAttack: number;
  aiBenign: number;
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
  bySignature: WafSignatureDivergence[];
}

function isSuppressed(state: string): boolean { return /autosuppress|auto[\s_-]*suppress|suppress/i.test(state); }
function isStaging(state: string): boolean { return /stag/i.test(state); }

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

interface SigAcc extends WafSignatureDivergence { origin200Count: number; }

export function computeWafComparison(
  events: Ev[],
  enforcementMode: 'blocking' | 'monitoring' | 'unknown',
): WafComparisonResult {
  const stateCounts = { enabled: 0, autoSuppressed: 0, staging: 0, other: 0 };
  const riskCounts = { high: 0, medium: 0, low: 0, falsePositive: 0, unknown: 0 };
  const actionCounts = { block: 0, report: 0, allow: 0, other: 0 };
  const matrix = { bothAttack: 0, engineActiveAiBenign: 0, aiSuppressedRiskAttack: 0, bothBenign: 0, other: 0 };
  let aiKnown = 0, aiBenignTotal = 0, aiBenignOrigin200 = 0, aiAttackNotBlocked = 0;
  const bySig = new Map<string, SigAcc>();

  for (const e of events) {
    const sigs = (e.signatures as Array<Record<string, unknown>>) || [];
    if (sigs.length === 0) continue;

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

    const engineActive = state === 'enabled';
    if (ai === 'unknown') matrix.other++;
    else if (engineActive && ai === 'attack') matrix.bothAttack++;
    else if (engineActive && ai === 'benign') matrix.engineActiveAiBenign++;
    else if (state === 'autoSuppressed' && ai === 'attack') matrix.aiSuppressedRiskAttack++;
    else if (state === 'autoSuppressed' && ai === 'benign') matrix.bothBenign++;
    else matrix.other++;

    if (ai === 'benign') { aiBenignTotal++; if (origin200) aiBenignOrigin200++; }
    if (ai === 'attack' && action !== 'block') aiAttackNotBlocked++;

    for (const s of sigs) {
      const id = String(s.id || '');
      if (!id) continue;
      let d = bySig.get(id);
      if (!d) {
        d = { sigId: id, name: String(s.name || ''), events: 0, enabled: 0, autoSuppressed: 0, staging: 0, aiAttack: 0, aiBenign: 0, aiUnknown: 0, origin200Pct: 0, engineActiveAiBenign: 0, origin200Count: 0 };
        bySig.set(id, d);
      }
      d.events++;
      const sst = String(s.state || '');
      const suppressed = isSuppressed(sst), staging = isStaging(sst);
      if (suppressed) d.autoSuppressed++; else if (staging) d.staging++; else d.enabled++;
      if (ai === 'attack') d.aiAttack++; else if (ai === 'benign') d.aiBenign++; else d.aiUnknown++;
      if (!suppressed && !staging && ai === 'benign') d.engineActiveAiBenign++;
      if (origin200) d.origin200Count++;
    }
  }

  const total = stateCounts.enabled + stateCounts.autoSuppressed + stateCounts.staging + stateCounts.other;
  const matrixTotal = matrix.bothAttack + matrix.engineActiveAiBenign + matrix.aiSuppressedRiskAttack + matrix.bothBenign;
  const agreement = matrix.bothAttack + matrix.bothBenign;
  const agreementPct = matrixTotal > 0 ? agreement / matrixTotal : 0;
  const fpReductionOpportunityPct = total > 0 ? matrix.engineActiveAiBenign / total : 0;
  const aiBenignOrigin200Pct = aiBenignTotal > 0 ? aiBenignOrigin200 / aiBenignTotal : 0;
  const aiDataCoveragePct = total > 0 ? aiKnown / total : 0;

  const bySignature: WafSignatureDivergence[] = [...bySig.values()]
    .map(d => { const { origin200Count, ...rest } = d; return { ...rest, origin200Pct: d.events > 0 ? origin200Count / d.events : 0 }; })
    .sort((a, b) => (b.engineActiveAiBenign - a.engineActiveAiBenign) || (b.events - a.events))
    .slice(0, 50);

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
  } else if (total > 0 && aiAttackCount / total >= 0.8) {
    headline = `Strong agreement (${pct(agreementPct)}): both engines classify the large majority as real attacks — very low false-positive noise, the signatures are accurate here.`;
  } else {
    headline = `The two engines agree on ${pct(agreementPct)} of events; the rest diverge — review the divergent signatures below.`;
  }

  const enforcementNote = (enforcementMode === 'monitoring' && aiAttackNotBlocked > 0)
    ? `WAF is in MONITORING mode — ${aiAttackNotBlocked.toLocaleString()} AI-confirmed attack request(s) were logged but NOT blocked. Switch to Blocking to stop them.`
    : undefined;

  return {
    totalEvents: total, aiDataCoveragePct, enforcementMode, stateCounts, riskCounts, actionCounts, matrix,
    alreadySuppressedByAi: stateCounts.autoSuppressed, wouldPreventIfAiBlocking: matrix.engineActiveAiBenign,
    agreementPct, fpReductionOpportunityPct, aiBenignOrigin200Pct, recommendation, recommendationReason,
    headline, enforcementNote, aiAttackCount, aiBenignCount, aiAttackNotBlocked, bySignature,
  };
}
