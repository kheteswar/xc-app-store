/**
 * Prescriptive "Next Steps" for the FP Analysis report.
 *
 * The goal of the report is to move the customer SAFELY to Blocking mode with the
 * AI-powered WAF. So the recommendation is a concrete, ordered action plan, not a
 * "monitor vs block" verdict:
 *
 *   1. Add exclusion rules for the confirmed false positives.
 *   2. Investigate the ambiguous detections (with explicit instructions).
 *   3. Enable AI-powered WAF blocking at High (or High + Medium) risk.
 *   4. Switch Enforcement Mode from Monitoring to Blocking.
 */
import type {
  SignatureSummary, ViolationSummary, FPVerdict, FpRecommendations, RecoStep, BotAnalysisResult,
} from './types';
import type { WafComparisonResult } from './waf-comparison';

const isFp = (v: FPVerdict) => v === 'highly_likely_fp' || v === 'likely_fp';
const isTp = (v: FPVerdict) => v === 'likely_tp' || v === 'confirmed_tp';
const pct = (x: number) => `${(x * 100).toFixed(0)}%`;

export function buildFpRecommendations(input: {
  signatures: SignatureSummary[];
  violations: ViolationSummary[];
  comparison?: WafComparisonResult;
  enforcementMode: 'blocking' | 'monitoring' | 'unknown';
  botAnalysis?: BotAnalysisResult;
}): FpRecommendations {
  const { signatures, violations, comparison, enforcementMode, botAnalysis } = input;

  // F5 already auto-suppresses these → NO manual exclusion needed (just note them).
  const autoHandledList = signatures.filter(s => s.autoSuppressed)
    .map(s => ({ kind: 'signature', id: s.sigId, name: s.name }));
  const autoSet = new Set(autoHandledList.map(a => a.id));

  // Recommend a manual exclusion ONLY for high-confidence false positives that F5 is
  // NOT already auto-suppressing. Anything less certain goes to investigation.
  const excludeSigs = signatures.filter(s => s.fpVerdict === 'highly_likely_fp' && !autoSet.has(s.sigId));
  const excludeViols = violations.filter(v => v.fpVerdict === 'highly_likely_fp');
  const investigateSigs = signatures.filter(s => (s.fpVerdict === 'likely_fp' || s.fpVerdict === 'ambiguous') && !autoSet.has(s.sigId));
  const investigateViols = violations.filter(v => v.fpVerdict === 'likely_fp' || v.fpVerdict === 'ambiguous');
  const tpSigs = signatures.filter(s => isTp(s.fpVerdict));
  void isFp;

  const excludeList = [
    ...excludeSigs.map(s => ({ kind: 'signature' as const, id: s.sigId, name: s.name, verdict: s.fpVerdict })),
    ...excludeViols.map(v => ({ kind: 'violation' as const, id: v.violationName, name: v.violationName, verdict: v.fpVerdict })),
  ];

  const investigateList = [
    ...investigateSigs.map(s => ({ kind: 'signature', id: s.sigId, name: s.name, reason: `${s.fpVerdict === 'likely_fp' ? 'Likely FP' : 'Ambiguous'} (FP score ${s.fpScore}) — manually confirm whether the flagged input is legitimate before excluding or blocking.` })),
    ...investigateViols.map(v => ({ kind: 'violation', id: v.violationName, name: v.violationName, reason: `${v.fpVerdict === 'likely_fp' ? 'Likely FP' : 'Ambiguous'} (FP score ${v.fpScore}) — review the flagged requests and confirm.` })),
  ];
  if (comparison && comparison.matrix.aiSuppressedRiskAttack > 0) {
    investigateList.push({
      kind: 'conflict', id: '-', name: `${comparison.matrix.aiSuppressedRiskAttack} request(s) the traditional engine would NOT block but the AI rates as attacks`,
      reason: 'The signature/violation engine would let these through (AutoSuppressed, Staging, or no enforced detection), but the AI risk engine flags them as attacks — review whether the traditional WAF is missing a real threat.',
    });
  }

  // AI blocking threshold: start at High (safest); recommend High + Medium when the two
  // engines strongly agree and false-positive noise is minimal (medium-risk events are real).
  let aiBlockingThreshold: 'high' | 'high_medium' = 'high';
  let aiThresholdReason = 'Begin by blocking only High-risk requests — the safest threshold — then expand to Medium after a short monitoring window confirms no false positives in the Medium band.';
  if (comparison && comparison.aiDataCoveragePct >= 0.5 && comparison.agreementPct >= 0.9 && comparison.fpReductionOpportunityPct < 0.1) {
    aiBlockingThreshold = 'high_medium';
    aiThresholdReason = `The signature engine and AI agree on ${pct(comparison.agreementPct)} of events and false-positive noise is minimal (${pct(comparison.fpReductionOpportunityPct)}) — blocking High + Medium risk is safe here and gives broader protection.`;
  } else if (comparison && comparison.aiDataCoveragePct < 0.2) {
    aiThresholdReason = `Only ${pct(comparison.aiDataCoveragePct)} of events carry an AI risk verdict — first ensure AI-powered WAF (Automatic Attack Signature Tuning) is enabled, then start blocking at High risk.`;
  }

  const steps: RecoStep[] = [];
  let num = 1;
  if (investigateList.length > 0) {
    steps.push({
      num: num++, kind: 'investigate',
      title: `Investigate & manually confirm ${investigateList.length} finding${investigateList.length > 1 ? 's' : ''}`,
      detail: 'These are likely-FP or ambiguous — do NOT exclude them automatically. For each item in the Investigate table: open its detail and check the Matching Values (benign text vs real attack syntax like SQLi/XSS), the Origin Response (200 = app served it → leans FP; 404 = probing → leans attack), whether the WAF fired for other users on the same path or just this client, and the Client Behavior. Then mark "Confirm FP" or "Confirm TP".',
    });
  }
  if (excludeList.length > 0) {
    steps.push({
      num: num++, kind: 'exclude',
      title: `Review & add exclusion rules for ${excludeList.length} high-confidence false positive${excludeList.length > 1 ? 's' : ''}`,
      detail: 'Confirm each is legitimate, then use "Generate Exclusion Policy" (download) or "Stage to Tenant" (creates the policy unattached) for the signatures/violations in the Exclusions table. Attach the policy to the load balancer in the XC console.',
    });
  }
  steps.push({
    num: num++, kind: 'enable_ai',
    title: `Enable AI-powered WAF blocking at ${aiBlockingThreshold === 'high_medium' ? 'High + Medium' : 'High'} risk`,
    detail: `${aiThresholdReason} Keep Automatic Attack Signature Tuning ON so the AI continues to auto-suppress new false positives as traffic evolves.`,
  });
  if (botAnalysis && botAnalysis.maliciousEvents > 0) {
    // Prefer a distinct-client count, but fall back to the event count when src_ip wasn't collected
    // (maliciousIps can be 0 while maliciousEvents > 0) — the step must still appear.
    const ipLabel = botAnalysis.maliciousIps > 0
      ? `${botAnalysis.maliciousIps.toLocaleString()}${botAnalysis.ipsCapped ? '+' : ''} bad bot client${botAnalysis.maliciousIps > 1 ? 's' : ''}`
      : `${botAnalysis.maliciousEvents.toLocaleString()} malicious bot event${botAnalysis.maliciousEvents > 1 ? 's' : ''}`;
    if (botAnalysis.fpRiskFlags.length === 0) {
      steps.push({
        num: num++, kind: 'block_bots',
        title: `Enable Malicious-bot blocking — safe (${ipLabel})`,
        detail: `Every Malicious-classified client carries a scanner/unknown user-agent — no known-good crawler or real-browser client appears in the Malicious set, so blocking won't affect legitimate traffic. Set the Bot Defense action for Malicious to Block; keep Suspicious and Good/Benign on their default (allow/ignore).`,
      });
    } else {
      const labels = botAnalysis.fpRiskFlags.slice(0, 3).map(f => f.label).join(', ');
      steps.push({
        num: num++, kind: 'block_bots',
        title: `Review the Malicious set before enabling bot blocking (${botAnalysis.fpRiskFlags.length} false-positive risk${botAnalysis.fpRiskFlags.length > 1 ? 's' : ''})`,
        detail: `The Malicious set includes potentially legitimate clients (${labels}${botAnalysis.fpRiskFlags.length > 3 ? ', …' : ''}). In the Bot Classification section, confirm these known-good bots / real-browser user-agents are not legitimate, then set the Bot Defense action for Malicious to Block. Leave Suspicious and Good/Benign on allow/ignore.`,
      });
    }
  }
  if (enforcementMode === 'blocking') {
    steps.push({
      num: num++, kind: 'done',
      title: 'Confirm Blocking mode (already enabled)',
      detail: 'The WAF is already in Blocking mode. Verify the exclusions above are applied so legitimate traffic is not blocked, and confirm the AI risk threshold is configured.',
    });
  } else {
    steps.push({
      num: num++, kind: 'block',
      title: 'Switch Enforcement Mode from Monitoring to Blocking',
      detail: `Once the exclusions are applied${investigateList.length ? ' and the ambiguous items reviewed' : ''}, change the load balancer’s WAF Enforcement Mode from Monitoring to Blocking so real attacks are stopped, not just logged. ${comparison && comparison.aiAttackNotBlocked > 0 ? `Today ${comparison.aiAttackNotBlocked.toLocaleString()} AI-confirmed attack request(s) are being logged but NOT blocked.` : ''}`,
    });
  }

  return {
    enforcementMode, fpCount: excludeList.length, tpCount: tpSigs.length, ambiguousCount: investigateList.length,
    aiBlockingThreshold, aiThresholdReason, steps, excludeList, investigateList, autoHandledList,
  };
}
