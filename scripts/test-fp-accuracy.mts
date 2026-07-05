/**
 * Behavioral tests for the redesigned FP Analyzer (single-mode, client-behavior).
 * Run: npm run test:fp   (npx tsx scripts/test-fp-accuracy.mts)
 */
import { parseReqRisk, parseRiskReasons, scoreAiRisk, estimateActualCountFromRate, isAutoSuppressedState, isStagedState, emptyAiRiskCounts, tallyReqRisk, dominantRiskLabel } from '../src/services/fp-analyzer/ai-signals.ts';
import {
  computeFpSignals, scoreClientBreadth, scoreMatchingEvidence, scoreOriginResponse,
  scoreClientBehavior, scoreViolationSeverity,
} from '../src/services/fp-analyzer/fp-signals-v2.ts';
import type { FpSignalsInput } from '../src/services/fp-analyzer/fp-signals-v2.ts';
import { buildSignatureExclusionsWithRollup, generatePerPathExclusions } from '../src/services/fp-analyzer/exclusion-generator.ts';
import { scoreClientProfileQuick, scoreSignatureAccuracy } from '../src/services/fp-analyzer/signal-calculator.ts';
import { RECON_ATTACK_TYPES, TP_BIAS_ATTACK_TYPES, FP_PRONE_ATTACK_TYPES } from '../src/services/fp-analyzer/attack-types.ts';
import { classifyMatchingInfo } from '../src/services/fp-analyzer/matching-info-analyzer.ts';
import { computeWafComparison } from '../src/services/fp-analyzer/waf-comparison.ts';
import { computeEnforcementComparison } from '../src/services/fp-analyzer/enforcement-comparison.ts';
import type { ComparisonEvent, SignatureMeta, ViolationMeta } from '../src/services/fp-analyzer/enforcement-comparison.ts';
import { buildFpRecommendations } from '../src/services/fp-analyzer/recommendations.ts';
import { computeBotAnalysisFromAggregates, computeBotAggregatesFromEvents, classifyBot } from '../src/services/fp-analyzer/bot-analysis.ts';
import type { IPBehaviorProfile, SignatureSummary, FPVerdict, BotAggBucket } from '../src/services/fp-analyzer/types.ts';

let pass = 0, fail = 0;
function ok(name: string, cond: boolean, detail = '') {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name} ${detail}`); }
}

const ipProfile = (o: Partial<IPBehaviorProfile>): IPBehaviorProfile => ({
  ip: '1.2.3.4', enriched: true, totalRequests: 100, rspCodes: {}, successRatio: 0.9, notFoundRatio: 0,
  clientErrorRatio: 0, serverErrorRatio: 0, uniquePaths: 3, exploitPathHits: 0, reqPerHour: 50,
  topUserAgent: 'Mozilla/5.0 Chrome/120', country: 'US', asOrg: '', wafEventCount: 2, wafEventRatio: 0.02, ...o,
});

console.log('\n1) AI-WAF parsing (incl. real verdict-form req_risk)');
// req_risk has TWO forms: level (high/medium/low) AND verdict (e.g. "false positive").
ok('req_risk level form high/medium/low', parseReqRisk('high') === 'high' && parseReqRisk('Medium') === 'medium' && parseReqRisk('low') === 'low');
ok('req_risk "false positive" → low (FP-ward)  [real value]', parseReqRisk('false positive') === 'low');
ok('req_risk "malicious" → high (TP-ward)', parseReqRisk('malicious') === 'high');
ok('req_risk "suspicious" → medium', parseReqRisk('suspicious') === 'medium');
ok('req_risk high (level) → TP-ward delta', scoreAiRisk({ riskCounts: { high: 9, medium: 0, low: 1, unknown: 0 } }).delta < 0);
ok('req_risk_reasons "False-positive detected..." → suggestsFp  [real value]',
  parseRiskReasons(['False-positive detected by the Automatic Attack Signatures Tuning']).aiSuggestsFp === true);
ok('"100% cache hit" is NOT a confirmation', parseRiskReasons(['100% cache hit']).aiConfirmedAttack === false);
ok('confirmed attack detected', parseRiskReasons(['AI confirmed attack']).aiConfirmedAttack === true);
// req_risk=high also fires purely for BOT detection ("Malicious bot detected") — that is a bot, not
// a content attack, so it must NOT be scored as evidence the flagged signature is a true positive.
ok('req_risk_reasons "Malicious bot detected" → botDetected', parseRiskReasons(['Malicious bot detected']).botDetected === true);
ok('bot-driven HIGH req_risk is NOT scored as content-attack (neutral)', scoreAiRisk({ riskCounts: { high: 10, medium: 0, low: 0, unknown: 0 }, reasonVerdict: parseRiskReasons(['Malicious bot detected']) }).delta === 0);
ok('content-driven HIGH req_risk still scores TP-ward', scoreAiRisk({ riskCounts: { high: 10, medium: 0, low: 0, unknown: 0 }, reasonVerdict: parseRiskReasons(['SQLi attack indicator']) }).delta < 0);
ok('low-risk → FP-ward delta', scoreAiRisk({ riskCounts: { high: 0, medium: 1, low: 9, unknown: 0 } }).delta > 0);
// Mirrors the real anonymized event: AutoSuppressed command-exec sig, req_risk="false positive",
// req_risk_reasons FP, recommended_action=allow, 200 OK, no malicious matching_info captured.
const realDetConf = scoreAiRisk({
  riskCounts: { high: 0, medium: 0, low: 1, unknown: 0 },
  reasonVerdict: parseRiskReasons(['False-positive detected by the Automatic Attack Signatures Tuning']),
  recommendedAction: 'allow',
});
ok('real FP event → strong FP-ward AI delta', realDetConf.delta > 30, `got ${realDetConf.delta}`);

console.log('\n2) Client Breadth (path saturation + absolute fallback)');
ok('200 IPs (no path denom) → strong FP', scoreClientBreadth(200, 200).score > 80);
ok('1 IP (no path denom) → strong TP', scoreClientBreadth(1, 1).score < 15);
ok('path saturation: 8 of 10 path users trip WAF → strong FP', scoreClientBreadth(8, 8, 10).score > 80);
ok('path saturation: 1 of 50 path users → targeted TP', scoreClientBreadth(1, 1, 50).score < 20);

console.log('\n3) Matching Evidence (benign → FP, malicious → TP)');
ok('benign values → FP', scoreMatchingEvidence(['user123', 'product', 'hello']).score > 70);
ok('mixed (2/3 benign) still leans FP', scoreMatchingEvidence(['user123', 'search term', 'hello']).score > 55);
ok('malicious values → TP', scoreMatchingEvidence(["' UNION SELECT", '../../etc/passwd', '<script>alert(1)']).score < 20);

console.log('\n4) Origin Response (200 vs 404, + successful-exploit guard)');
ok('mostly 200 (benign) → FP', scoreOriginResponse({ '200': 90, '404': 10 }, 85).signal.score > 70);
ok('mostly 404 → TP', scoreOriginResponse({ '404': 90, '200': 10 }, 50).signal.score < 35);
// 404 = path does not exist → TP-ward even as a minority, and stronger the more it dominates.
ok('partial 404 (40%) pulls origin toward TP', scoreOriginResponse({ '404': 40, '500': 60 }, 85).signal.score < 45);
ok('graduated: more 404 = stronger TP', scoreOriginResponse({ '404': 95, '200': 5 }, 50).signal.score < scoreOriginResponse({ '404': 55, '200': 45 }, 50).signal.score);
ok('notFoundPct exposed for the guardrail', scoreOriginResponse({ '404': 80, '403': 20 }, 85).notFoundPct === 0.8);
ok('404 share leans more TP than neutral 5xx', scoreOriginResponse({ '404': 30, '500': 70 }, 85).signal.score < scoreOriginResponse({ '500': 100 }, 85).signal.score);
const exploit = scoreOriginResponse({ '200': 90 }, 8 /* matching=clearly malicious */);
ok('200 + malicious payload → possible successful exploit (TP)', exploit.possibleSuccessfulExploit === true && exploit.signal.score < 25);

console.log('\n5) Client Behavior (legit vs scanner)');
const legit = scoreClientBehavior([ipProfile({ successRatio: 0.95, notFoundRatio: 0.01, wafEventRatio: 0.02, uniquePaths: 4 })]);
const scanner = scoreClientBehavior([ipProfile({ successRatio: 0.1, notFoundRatio: 0.6, wafEventRatio: 0.9, uniquePaths: 80, exploitPathHits: 5, topUserAgent: 'python-requests/2.31' })]);
ok('legit-looking clients → FP', legit.score > 60, `got ${legit.score}`);
ok('scanner-looking clients → TP', scanner.score < 30, `got ${scanner.score}`);
ok('no enriched profiles → neutral 50', scoreClientBehavior([]).score === 50);

console.log('\n6) Violation severity');
ok('always-TP violation → low', scoreViolationSeverity('VIOL_ATTACK_SIGNATURE').score < 15);
ok('often-FP violation → high', scoreViolationSeverity('VIOL_JSON_MALFORMED').score > 70);

console.log('\n7) computeFpSignals end-to-end');
const base = (o: Partial<FpSignalsInput>): FpSignalsInput => ({
  distinctIPs: 5, distinctUsers: 5, pathCount: 1, totalAppPaths: 50, contextType: 'CONTEXT_PARAMETER', contextName: 'q',
  sampleMatchingInfos: [], rspCodes: {}, ipProfiles: [], accuracy: 'medium_accuracy', sigState: 'Enabled',
  aiConfirmed: false, violationRatings: [], ...o,
});
const broadBenign = computeFpSignals(base({
  distinctIPs: 150, distinctUsers: 150, pathCount: 20, sampleMatchingInfos: ['search', 'hello', 'user1'],
  rspCodes: { '200': 95, '404': 5 }, accuracy: 'low_accuracy',
  ipProfiles: [ipProfile({ successRatio: 0.95, wafEventRatio: 0.03 })],
}));
const targetedScanner = computeFpSignals(base({
  distinctIPs: 1, distinctUsers: 1, pathCount: 1, sampleMatchingInfos: ["' OR 1=1--", '<script>'],
  rspCodes: { '404': 80, '403': 20 }, accuracy: 'high_accuracy',
  ipProfiles: [ipProfile({ successRatio: 0.05, notFoundRatio: 0.7, wafEventRatio: 0.95, uniquePaths: 90, exploitPathHits: 4, topUserAgent: 'sqlmap/1.7' })],
}));
ok('broad benign traffic → likely FP', ['highly_likely_fp', 'likely_fp'].includes(broadBenign.verdict), `verdict=${broadBenign.verdict} score=${broadBenign.compositeScore}`);
ok('targeted scanner → likely TP', ['likely_tp', 'confirmed_tp'].includes(targetedScanner.verdict), `verdict=${targetedScanner.verdict} score=${targetedScanner.compositeScore}`);

const successfulExploit = computeFpSignals(base({
  distinctIPs: 100, sampleMatchingInfos: ["'; DROP TABLE users--", 'UNION SELECT password'], rspCodes: { '200': 95 },
  ipProfiles: [ipProfile({ successRatio: 0.9 })],
}));
ok('200 + malicious payload capped to TP (successful-exploit guard)', successfulExploit.compositeScore <= 25 && successfulExploit.possibleSuccessfulExploit === true, `score=${successfulExploit.compositeScore}`);
const alwaysTp = computeFpSignals(base({ distinctIPs: 200, rspCodes: { '200': 100 }, sampleMatchingInfos: ['x'], violationName: 'VIOL_ATTACK_SIGNATURE' }));
ok('always-TP violation capped to confirmed_tp', alwaysTp.verdict === 'confirmed_tp');
// Mirrors real sig 200003913: AutoSuppressed + req_risk "false positive" + 200, 1 IP, no malicious content
const f5fp = computeFpSignals(base({
  distinctIPs: 1, distinctUsers: 1, pathCount: 1, sigState: 'AutoSuppressed', rspCodes: { '200': 1 }, sampleMatchingInfos: [],
  aiInput: { riskCounts: { high: 0, medium: 0, low: 1, unknown: 0 }, reasonVerdict: parseRiskReasons(['False-positive detected by the Automatic Attack Signatures Tuning']), recommendedAction: 'allow' },
}));
ok('AutoSuppressed + AI-FP + 200 (low breadth) → floored to likely_fp', f5fp.verdict === 'likely_fp' && f5fp.override === 'F5_CONFIRMED_FP', `verdict=${f5fp.verdict} score=${f5fp.compositeScore}`);
// But AutoSuppressed + MALICIOUS content + 200 must NOT be floored (successful-exploit guard wins)
const f5notfp = computeFpSignals(base({
  distinctIPs: 1, sigState: 'AutoSuppressed', rspCodes: { '200': 1 }, sampleMatchingInfos: ["' UNION SELECT password--"],
  aiInput: { riskCounts: { high: 0, medium: 0, low: 1, unknown: 0 }, reasonVerdict: parseRiskReasons(['benign']), recommendedAction: 'allow' },
}));
ok('AutoSuppressed but malicious payload + 200 → NOT floored (capped TP)', f5notfp.verdict === 'confirmed_tp' || f5notfp.verdict === 'likely_tp');
// Non-existent path: even broad traffic that the origin 404s is safe to block (no real path → TP).
const nep = computeFpSignals(base({
  distinctIPs: 150, distinctUsers: 150, pathCount: 20, rspCodes: { '404': 95, '200': 5 },
  sampleMatchingInfos: ['x'], accuracy: 'low_accuracy', ipProfiles: [ipProfile({ successRatio: 0.05, notFoundRatio: 0.95 })],
}));
ok('95% 404 → NON_EXISTENT_PATH override, steered to TP despite broad traffic', nep.override === 'NON_EXISTENT_PATH' && ['likely_tp', 'confirmed_tp'].includes(nep.verdict), `override=${nep.override} verdict=${nep.verdict}`);
// A real, served path (mostly 200) must NOT trigger the non-existent-path guard.
const served = computeFpSignals(base({ distinctIPs: 150, distinctUsers: 150, pathCount: 20, rspCodes: { '200': 95, '404': 5 }, sampleMatchingInfos: ['hello', 'search'], accuracy: 'low_accuracy', ipProfiles: [ipProfile({ successRatio: 0.95 })] }));
ok('served path (95% 200) does NOT trigger NON_EXISTENT_PATH', served.override !== 'NON_EXISTENT_PATH');

// Signature-state detection must be tolerant of how F5 emits the value. The server-side
// parser (progressive-job.ts) once used a brittle `state === 'AutoSuppressed'`, which
// disagreed with the scorer's regex on any case/separator/whitespace variant — the sig
// would score FP yet be dropped from the auto-handled recommendations list. Lock the
// shared contract both paths now rely on.
console.log('\n7b) Signature-state detection (canonical helper — parser & scorer share it)');
for (const v of ['AutoSuppressed', 'autosuppressed', 'AUTOSUPPRESSED', 'Auto-Suppressed', 'auto_suppressed', 'Auto Suppressed', ' AutoSuppressed ']) {
  ok(`isAutoSuppressedState matches F5 variant "${v}"`, isAutoSuppressedState(v) === true);
}
for (const v of ['Enabled', 'Staging', '', 'Blocked']) {
  ok(`isAutoSuppressedState rejects non-suppressed "${v || '(empty)'}"`, isAutoSuppressedState(v) === false);
}
ok('isStagedState matches Staging variants', isStagedState('Staging') && isStagedState('staged') && !isStagedState('Enabled'));
// End-to-end: a variant-cased state must still trigger the F5_CONFIRMED_FP override.
const f5variant = computeFpSignals(base({
  distinctIPs: 1, distinctUsers: 1, pathCount: 1, sigState: 'auto_suppressed', rspCodes: { '200': 1 }, sampleMatchingInfos: [],
  aiInput: { riskCounts: { high: 0, medium: 0, low: 1, unknown: 0 }, reasonVerdict: parseRiskReasons(['False-positive detected by the Automatic Attack Signatures Tuning']), recommendedAction: 'allow' },
}));
ok('variant-cased sigState still floors to F5_CONFIRMED_FP', f5variant.override === 'F5_CONFIRMED_FP', `override=${f5variant.override}`);

console.log('\n8) Retained utilities');
ok('regex escape 1.2.3.4 → 1\\.2\\.3\\.4', '1.2.3.4'.replace(/\./g, '\\.') === '1\\.2\\.3\\.4');
ok('de-sample 100 @ rate 10 → 1000', estimateActualCountFromRate(100, 10) === 1000);
const intent = (id: string, at: string, path = '/api') => ({ signatureId: id, attackType: at, contextType: 'CONTEXT_PARAMETER', contextName: 'q', path, methods: ['GET'] });
const rolled = buildSignatureExclusionsWithRollup([intent('1', 'SQLI'), intent('2', 'SQLI'), intent('3', 'SQLI')], 'app.example.com', 3);
ok('3 same-attack-type sigs → 1 attack-type rule', rolled.length === 1 && rolled[0].app_firewall_detection_control.exclude_attack_type_contexts.length === 1);
ok('Suspicious bots lean TP', scoreClientProfileQuick({}, { Suspicious: 10 }, [], {}).score < 50);

console.log('\n9) Traditional vs AI-Powered WAF comparison');
const ev = (state: string, req_risk: string, rsp_code: string, action = 'allow') => ({
  signatures: [{ id: '200003913', name: 'Unix ls execution', state }],
  req_risk, rsp_code, rsp_code_class: rsp_code.startsWith('2') ? '2xx' : '4xx', action,
});
// Mirrors the real event en masse: Enabled signatures the AI rates "false positive", all 200 OK.
const wc1 = computeWafComparison(Array.from({ length: 10 }, () => ev('Enabled', 'false positive', '200')), 'blocking');
ok('Enabled + AI "false positive" + 200 → engineActiveAiBenign', wc1.matrix.engineActiveAiBenign === 10);
ok('FP-block reduction opportunity = 100%', wc1.fpReductionOpportunityPct === 1);
ok('AI-benign origin-200 corroboration = 100%', wc1.aiBenignOrigin200Pct === 1);
ok('recommendation = enable_ai_blocking', wc1.recommendation === 'enable_ai_blocking', `got ${wc1.recommendation}`);
ok('req_risk falsePositive counted', wc1.riskCounts.falsePositive === 10);
// AutoSuppressed + low risk → both agree benign (AI already working)
const wc2 = computeWafComparison([ev('AutoSuppressed', 'low', '200')], 'monitoring');
ok('AutoSuppressed + benign → bothBenign + alreadySuppressed', wc2.matrix.bothBenign === 1 && wc2.alreadySuppressedByAi === 1);
// Enabled + high risk → both agree attack
const wc3 = computeWafComparison([ev('Enabled', 'high', '403', 'block')], 'blocking');
ok('Enabled + AI high → bothAttack', wc3.matrix.bothAttack === 1);
// No req_risk at all → AI data sparse, can't compare
const wc4 = computeWafComparison([{ signatures: [{ id: '1', name: 'x', state: 'Enabled' }], rsp_code: '200' }], 'monitoring');
ok('no req_risk → recommendation ai_data_sparse', wc4.recommendation === 'ai_data_sparse');
// Your real case: monitoring mode, mostly AI-confirmed attacks, not blocked → enforcement note surfaces it
const wcMon = computeWafComparison(Array.from({ length: 5 }, () => ev('Enabled', 'high', '200', 'allow')), 'monitoring');
ok('monitoring + AI-attack not blocked → enforcementNote + count', !!wcMon.enforcementNote && wcMon.aiAttackNotBlocked === 5);
ok('mostly-attacks → low-FP-noise headline', /low false-positive noise|real attacks/i.test(wcMon.headline));
ok('over-flagging case → headline says signatures over-flagging', /over-flagging/i.test(wc1.headline));
// AI advantage: a signature mixed Enabled/AutoSuppressed but 100% false-positive per the AI.
// Traditional WAF blocks the Enabled part (needs an exclusion); AI allows it — quantify the win.
const wcAdv = computeWafComparison([
  ...Array.from({ length: 5 }, () => ev('Enabled', 'false positive', '200')),
  ...Array.from({ length: 3 }, () => ev('AutoSuppressed', 'false positive', '200')),
], 'monitoring');
ok('AI advantage: 5 FP requests prevented (the Enabled+benign ones)', wcAdv.aiAdvantage.fpRequestsPrevented === 5 && wcAdv.matrix.engineActiveAiBenign === 5, `prevented=${wcAdv.aiAdvantage.fpRequestsPrevented}`);
ok('AI advantage: 1 detection, ~1 exclusion rule avoided', wcAdv.aiAdvantage.detectionsPreventingFp === 1 && wcAdv.aiAdvantage.exclusionRulesAvoided === 1, `det=${wcAdv.aiAdvantage.detectionsPreventingFp} rules=${wcAdv.aiAdvantage.exclusionRulesAvoided}`);
ok('AI advantage: the AutoSuppressed part is already-tuned-out (bothBenign=3)', wcAdv.matrix.bothBenign === 3);
ok('no advantage when nothing Enabled+benign', computeWafComparison([ev('Enabled', 'high', '403', 'block')], 'monitoring').aiAdvantage.fpRequestsPrevented === 0);

// Per-request: Traditional blocks if ANY enabled signature OR violation; AI decides per req_risk.
const wcPR = computeWafComparison([
  { signatures: [], violations: [{ name: 'VIOL_X', state: 'Enabled' }], req_risk: 'false positive', rsp_code: '200' }, // viol blocks, AI allows → FP AI auto-allows
  { signatures: [{ id: '9', name: 's', state: 'AutoSuppressed' }], violations: [], req_risk: 'high', rsp_code: '403' },   // nothing enforced, AI attack → trad allows / AI blocks
  { signatures: [{ id: '8', name: 's2', state: 'Enabled' }], violations: [], req_risk: 'high', rsp_code: '403' },         // enabled sig + AI attack → both block
], 'monitoring');
ok('per-request: violation-only request counted (total=3)', wcPR.perRequest.total === 3, `total=${wcPR.perRequest.total}`);
ok('per-request: traditional blocks include enabled VIOLATIONS (2 of 3)', wcPR.perRequest.traditionalBlocks === 2 && wcPR.perRequest.traditionalAllows === 1, `tb=${wcPR.perRequest.traditionalBlocks}`);
ok('per-request: AI blocks 2 (req_risk attack), allows 1', wcPR.perRequest.aiBlocks === 2 && wcPR.perRequest.aiAllows === 1);
ok('per-request: violation-driven FP that AI auto-allows (engineActiveAiBenign=1)', wcPR.matrix.engineActiveAiBenign === 1 && wcPR.aiAdvantage.detectionsPreventingFp === 1);
ok('per-request: AutoSuppressed sig + AI attack → traditional allows, AI blocks', wcPR.matrix.aiSuppressedRiskAttack === 1 && wcPR.matrix.bothAttack === 1);

// The user's case: signature AutoSuppressed (why req_risk is "false positive") BUT an Enabled
// VIOLATION on the same request → traditional WOULD still block it (via the violation), AI allows it.
const wcMix = computeWafComparison([
  { signatures: [{ id: '7', name: 's', state: 'AutoSuppressed' }], violations: [{ name: 'VIOL_Y', state: 'Enabled' }], req_risk: 'false positive', rsp_code: '200' },
], 'monitoring');
ok('AutoSuppressed signature + Enabled VIOLATION → traditional blocks (via violation)', wcMix.perRequest.traditionalBlocks === 1, `tb=${wcMix.perRequest.traditionalBlocks}`);
ok('...counts as a false positive the AI auto-allows (Traditional BLOCKS, AI ALLOWS = 1)', wcMix.matrix.engineActiveAiBenign === 1 && wcMix.perRequest.aiAllows === 1);
ok('...and req_risk "false positive" is counted in the distribution', wcMix.riskCounts.falsePositive === 1, `fp=${wcMix.riskCounts.falsePositive}`);

// Bot detections are folded into the comparison for a 1-to-1 view: a malicious bot (Bot Signature)
// has no signature/violation, req_risk high → traditional blocks (bot defense) + AI blocks → both block.
const wcBot = computeWafComparison([
  { signatures: [], violations: [], bot_info: { classification: 'malicious', name: 'testssl', type: 'Vulnerability Scanner' }, req_risk: 'high', rsp_code: '404' },
  { signatures: [{ id: '1', name: 's', state: 'Enabled' }], violations: [], req_risk: 'high', rsp_code: '403' },
], 'monitoring');
ok('bot-only request is now included (total=2, 1 malicious bot)', wcBot.perRequest.total === 2 && wcBot.perRequest.maliciousBots === 1, `total=${wcBot.perRequest.total} bots=${wcBot.perRequest.maliciousBots}`);
ok('malicious bot → traditional blocks (bot signature) + AI blocks → both block', wcBot.matrix.bothAttack === 2 && wcBot.perRequest.traditionalBlocks === 2, `both=${wcBot.matrix.bothAttack} tb=${wcBot.perRequest.traditionalBlocks}`);
ok('a benign-bot / no-detection request is still skipped', computeWafComparison([{ signatures: [], violations: [], bot_info: { classification: 'human' }, req_risk: 'low' }], 'monitoring').perRequest.total === 0);

// Side-by-side approach comparison: Traditional-Enabled vs AI-High vs AI-High+Med + FP suppression.
const apEv = (id: string, state: string, risk: string) => ({ signatures: [{ id, name: 's' + id, state }], req_risk: risk, rsp_code: '200' });
const wcAp = computeWafComparison([
  ...Array.from({ length: 5 }, () => apEv('A', 'Enabled', 'high')),         // real attacks, both block
  ...Array.from({ length: 3 }, () => apEv('B', 'Enabled', 'false positive')), // FP traditional over-blocks
  ...Array.from({ length: 2 }, () => apEv('A', 'Enabled', 'medium')),       // attacks AI-High misses
  apEv('C', 'AutoSuppressed', 'false positive'),                            // FP traditional auto-suppressed
], 'monitoring');
const apRow = (k: string) => wcAp.approaches.rows.find(r => r.key === k)!;
ok('approaches: 7 attacks, 4 false positives total', wcAp.approaches.totalAttacks === 7 && wcAp.approaches.totalFalsePositives === 4, `att=${wcAp.approaches.totalAttacks} fp=${wcAp.approaches.totalFalsePositives}`);
ok('Traditional blocks most (10) but over-blocks 3 FPs, misses 0', apRow('traditional').blocked === 10 && apRow('traditional').fpBlocked === 3 && apRow('traditional').attacksMissed === 0, `b=${apRow('traditional').blocked} fp=${apRow('traditional').fpBlocked}`);
ok('AI-High blocks 5, 0 FP over-block, misses 2 medium attacks', apRow('ai_high').blocked === 5 && apRow('ai_high').fpBlocked === 0 && apRow('ai_high').attacksMissed === 2);
ok('AI-High+Med blocks all 7 attacks, 0 FP over-block, misses 0', apRow('ai_high_med').blocked === 7 && apRow('ai_high_med').fpBlocked === 0 && apRow('ai_high_med').attacksMissed === 0);
// FP suppression: AI column is specifically req_risk = "false positive" (not low/benign), plus a verdict.
const fpB = wcAp.fpSuppression.find(f => f.sigId === 'B')!;  // Enabled + req_risk false positive
const fpC = wcAp.fpSuppression.find(f => f.sigId === 'C')!;  // AutoSuppressed + req_risk false positive
ok('fpSuppression AI column = req_risk false positive (sig B: 3 FP, 0 autoSuppressed, 3 still-enabled)', fpB && fpB.aiFalsePositive === 3 && fpB.autoSuppressed === 0 && fpB.stillEnabled === 3, `B=${JSON.stringify(fpB)}`);
ok('fpSuppression verdict: AI catches it while traditional still blocks (sig B)', fpB.verdict === 'AI catches it — traditional still blocks', `verdict=${fpB?.verdict}`);
ok('fpSuppression verdict: both engines catch it (sig C: AutoSuppressed + req_risk FP)', fpC && fpC.autoSuppressed === 1 && fpC.aiFalsePositive === 1 && fpC.verdict === 'Both catch it', `C=${JSON.stringify(fpC)}`);
// A req_risk = "low" (benign but NOT false positive) must NOT count as an AI false positive.
const wcLow = computeWafComparison([{ signatures: [{ id: 'L', name: 'l', state: 'Enabled' }], req_risk: 'low', rsp_code: '200' }], 'monitoring');
ok('req_risk=low does NOT count as AI false positive (only "false positive" does)', wcLow.fpSuppression.length === 0, `len=${wcLow.fpSuppression.length}`);

// ── Ship-review fixes ──
// [2] clientBreadth: a MULTI-path finding must not use the single-path saturation ratio.
ok('[fix2] multi-path finding ignores single-path ratio (absolute fallback, not pinned to FP)', scoreClientBreadth(3, 3, 10, 5).score < 50, `score=${scoreClientBreadth(3, 3, 10, 5).score}`);
ok('[fix2] single-path finding still uses the saturation ratio', scoreClientBreadth(8, 8, 10, 1).score > 80);

// [3] A malicious bot the AI rates benign is a TRUE POSITIVE, not an FP the AI prevents.
const wcBotFp = computeWafComparison([
  { signatures: [], violations: [], bot_info: { classification: 'malicious', name: 'x' }, req_risk: 'false positive', rsp_code: '200' },
  { signatures: [{ id: 'S', name: 's', state: 'Enabled' }], req_risk: 'false positive', rsp_code: '200' },
], 'monitoring');
ok('[fix3] malicious bot rated AI-benign counts as attack, not false positive', wcBotFp.approaches.totalFalsePositives === 1 && wcBotFp.approaches.totalAttacks === 1, `fp=${wcBotFp.approaches.totalFalsePositives} att=${wcBotFp.approaches.totalAttacks}`);
ok('[fix3] AI advantage excludes the malicious bot (only the genuine signature FP)', wcBotFp.aiAdvantage.fpRequestsPrevented === 1, `prevented=${wcBotFp.aiAdvantage.fpRequestsPrevented}`);

// [12] fpSuppression verdict from PER-EVENT joins: the AutoSuppressed event is NOT the FP event,
// so the old marginal logic mislabeled this "Both catch it"; the join logic says "AI catches it".
const wcVerdict = computeWafComparison([
  { signatures: [{ id: 'M', name: 'm', state: 'Enabled' }], req_risk: 'false positive', rsp_code: '200' },
  { signatures: [{ id: 'M', name: 'm', state: 'AutoSuppressed' }], req_risk: 'high', rsp_code: '403' },
], 'monitoring');
ok('[fix12] fpSuppression verdict uses per-event joins (Enabled-FP + AutoSuppressed-attack → AI catches it)', wcVerdict.fpSuppression.find(f => f.sigId === 'M')?.verdict === 'AI catches it — traditional still blocks', `verdict=${wcVerdict.fpSuppression.find(f => f.sigId === 'M')?.verdict}`);

// dominantRiskLabel: a signature whose events are req_risk "false positive" must show "false positive",
// not the generic "low" level (the AI-Risk column must reflect the AI's explicit verdict).
const fpCounts = emptyAiRiskCounts(); ['false positive', 'false positive', 'false positive'].forEach(r => tallyReqRisk(fpCounts, r));
ok('[fixFP] dominantRiskLabel reports "false positive" (not "low") for FP-dominant events', dominantRiskLabel(fpCounts) === 'false positive', `label=${dominantRiskLabel(fpCounts)}`);
const lowCounts = emptyAiRiskCounts(); ['low', 'low', 'false positive'].forEach(r => tallyReqRisk(lowCounts, r));
ok('[fixFP] dominantRiskLabel stays "low" when plain-low events dominate the benign bucket', dominantRiskLabel(lowCounts) === 'low', `label=${dominantRiskLabel(lowCounts)}`);

console.log('\n10) Recommendations / Next Steps (action plan toward Blocking)');
const sig = (v: FPVerdict, score = 50, autoSuppressed = false): SignatureSummary => ({
  sigId: 's_' + v + (autoSuppressed ? '_auto' : ''), name: 'sig ' + v, accuracy: 'medium_accuracy', attackType: 'X', totalEvents: 1, uniqueUsers: 1,
  uniquePaths: 1, uniqueIPs: 1, topPaths: [], autoSuppressed, actions: { block: 0, report: 1 },
  quickVerdict: 'investigate', quickConfidence: 'low', fpScore: score, fpVerdict: v,
});
const recs = buildFpRecommendations({
  signatures: [sig('highly_likely_fp', 85), sig('likely_fp', 65), sig('ambiguous', 50), sig('confirmed_tp', 5), sig('likely_fp', 70, true)],
  violations: [], comparison: wc1, enforcementMode: 'monitoring',
});
ok('plan covers investigate → exclude → enable AI → go blocking',
  ['exclude', 'investigate', 'enable_ai', 'block'].every(k => recs.steps.some(s => s.kind === k)));
ok('exclude ONLY highly_likely_fp (non-autosuppressed)', recs.excludeList.length === 1 && recs.excludeList[0].id === 's_highly_likely_fp');
ok('likely_fp + ambiguous → investigate (not exclude)', recs.investigateList.some(i => i.id === 's_likely_fp') && recs.investigateList.some(i => i.id === 's_ambiguous'));
ok('AutoSuppressed → auto-handled, NOT excluded (F5 already handles it)', recs.autoHandledList.length === 1 && !recs.excludeList.some(e => e.id === 's_likely_fp_auto'));
ok('last step is move to Blocking (monitoring tenant)', recs.steps[recs.steps.length - 1].kind === 'block');
// Strong agreement + low FP noise → recommend High + Medium blocking
const recsHM = buildFpRecommendations({ signatures: [sig('confirmed_tp')], violations: [], comparison: wcMon, enforcementMode: 'monitoring' });
ok('strong agreement + low FP → High + Medium threshold', recsHM.aiBlockingThreshold === 'high_medium', `got ${recsHM.aiBlockingThreshold}`);

console.log('\n11) Bot classification analysis (aggregation-native: safe to block malicious bots?)');
const bkt = (pairs: [string, number][]): BotAggBucket[] => pairs.map(([key, count]) => ({ key, count }));
ok('classifyBot maps malicious/suspicious/good_bot→benign/clean→human/unknown',
  classifyBot('Malicious') === 'malicious' && classifyBot('suspicious') === 'suspicious' &&
  classifyBot('good_bot') === 'benign' && classifyBot('Good') === 'benign' &&
  classifyBot('clean') === 'human' && classifyBot('human') === 'human' &&
  classifyBot('') === 'unknown' && classifyBot('weird') === 'unknown');

const baseAgg = { classDistribution: bkt([['malicious', 100], ['suspicious', 30], ['good_bot', 20], ['clean', 500]]), byCountry: bkt([['CN', 80], ['US', 20]]), ipTopk: 500 };

// All scanner/unknown UAs in the malicious set → no FP risk → SAFE to block
const baSafe = computeBotAnalysisFromAggregates({ ...baseAgg, byIp: bkt([['9.9.9.9', 60], ['8.8.8.8', 40]]), byBotName: bkt([['UNKNOWN', 100]]), byUserAgent: bkt([['python-requests/2.31', 60], ['curl/8.1', 40]]) });
ok('counts from distribution (good_bot→benign, clean→human)', baSafe.classificationCounts.malicious === 100 && baSafe.classificationCounts.benign === 20 && baSafe.classificationCounts.human === 500);
ok('maliciousEvents + distinct IPs from buckets', baSafe.maliciousEvents === 100 && baSafe.maliciousIps === 2);
ok('all-scanner set → no FP-risk flags', baSafe.fpRiskFlags.length === 0);
ok('no risk → recommendation says SAFE', /SAFE/i.test(baSafe.recommendation));

// Googlebot present among malicious → known-good-bot FP risk → REVIEW
const baKnown = computeBotAnalysisFromAggregates({ ...baseAgg, byIp: bkt([['66.249.1.1', 50]]), byBotName: bkt([['Googlebot', 50]]), byUserAgent: bkt([['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 50]]) });
ok('known-good bot in malicious set → known_good_bot flag', baKnown.fpRiskFlags.some(f => f.kind === 'known_good_bot'));
ok('known-good present → recommendation says REVIEW', /REVIEW/i.test(baKnown.recommendation));

// Real-browser UA among malicious → real_browser FP risk → REVIEW
const baReal = computeBotAnalysisFromAggregates({ ...baseAgg, byIp: bkt([['5.5.5.5', 25]]), byBotName: bkt([['UNKNOWN', 25]]), byUserAgent: bkt([['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36', 25]]) });
ok('real-browser UA in malicious set → real_browser flag', baReal.fpRiskFlags.some(f => f.kind === 'real_browser'));

// ipsCapped when distinct IPs hit topk
const capped = computeBotAnalysisFromAggregates({ ...baseAgg, ipTopk: 2, byIp: bkt([['1.1.1.1', 5], ['2.2.2.2', 4]]), byBotName: [], byUserAgent: bkt([['curl/8', 9]]) });
ok('ipsCapped flagged when buckets reach topk', capped.ipsCapped === true);

// Enriched malicious-bot fields (bot_info.type, risk_score_info.source signature, as_org, req_risk) flow through.
const baRich = computeBotAnalysisFromAggregates({
  ...baseAgg,
  byIp: bkt([['1.2.3.4', 90]]), byBotName: bkt([['testssl', 90]]), byUserAgent: bkt([['TLS tester from https://testssl.sh/', 90]]),
  byBotType: bkt([['Vulnerability Scanner', 90]]),
  byDetection: bkt([['Bot Signature: testssl', 90]]),
  byAsOrg: bkt([['google llc', 90]]),
  byReqRisk: bkt([['high', 88], ['medium', 2]]),
});
ok('enriched bot: type (Vulnerability Scanner) surfaced', baRich.topBotTypes.some(b => b.key === 'Vulnerability Scanner'));
ok('enriched bot: detection source (Bot Signature) surfaced', baRich.topDetectionSources.some(b => /Bot Signature/i.test(b.key)));
ok('enriched bot: AS org + req_risk surfaced', baRich.topAsOrgs.some(b => b.key === 'google llc') && baRich.reqRiskDist.some(b => b.key === 'high'));

// Bot aggregates computed from RAW WAF events (the reliable path — replaces the failing agg API).
const botRawEvents = [
  ...Array.from({ length: 8 }, () => ({ sec_event_name: 'WAF', bot_info: { classification: 'malicious', name: 'testssl', type: 'Vulnerability Scanner' }, risk_score_info: { source: 'Bot Signature: testssl' }, action: 'allow', recommended_action: 'block', req_risk: 'high', src_ip: '1.2.3.4', user_agent: 'TLS tester from https://testssl.sh/', country: 'US', as_org: 'google llc' })),
  { sec_event_name: 'WAF', signatures: [{ id: '1', state: 'Enabled' }], req_risk: 'high' }, // non-bot WAF event — ignored
];
const botRawAgg = computeBotAggregatesFromEvents(botRawEvents)!;
ok('raw bot agg: 8 malicious events, testssl name + Vulnerability Scanner type', botRawAgg.byBotName[0].key === 'testssl' && botRawAgg.byBotName[0].count === 8 && botRawAgg.byBotType![0].key === 'Vulnerability Scanner', `name=${botRawAgg.byBotName[0]?.key}`);
ok('raw bot agg: action=allow, recommendation=block (the monitoring→blocking insight)', botRawAgg.byAction![0].key === 'allow' && botRawAgg.byRecommendation![0].key === 'block');
ok('raw bot agg: detection source = Bot Signature', /Bot Signature/i.test(botRawAgg.byDetection![0].key));
const baFromRaw = computeBotAnalysisFromAggregates(botRawAgg);
ok('raw bot agg → analysis: 8 malicious events, action/recommendation surfaced', baFromRaw.maliciousEvents === 8 && baFromRaw.actionDist[0].key === 'allow' && baFromRaw.recommendationDist[0].key === 'block', `mal=${baFromRaw.maliciousEvents}`);
// The aggregate is ALWAYS returned (section/tab always present); maliciousEvents=0 when none found.
const noMalAgg = computeBotAggregatesFromEvents([{ bot_info: { classification: 'human' } }, { signatures: [] }]);
ok('raw bot agg: no malicious bots → aggregate still returned, maliciousEvents=0', noMalAgg !== null && computeBotAnalysisFromAggregates(noMalAgg).maliciousEvents === 0, `mal=${computeBotAnalysisFromAggregates(noMalAgg).maliciousEvents}`);

// CRITICAL: F5's API returns bot_info in different shapes per tenant — nested object, flattened
// dotted key, or a stringified JSON blob. All three must classify as malicious (else the tab is empty).
const botShapes: Array<[string, Record<string, unknown>]> = [
  ['nested', { bot_info: { classification: 'malicious', name: 'testssl', type: 'Vulnerability Scanner' }, action: 'allow', recommended_action: 'block' }],
  ['flattened dotted keys', { 'bot_info.classification': 'malicious', 'bot_info.name': 'testssl', 'bot_info.type': 'Vulnerability Scanner', action: 'allow', recommended_action: 'block' }],
  ['stringified JSON', { bot_info: '{"classification":"malicious","name":"testssl","type":"Vulnerability Scanner"}', action: 'allow', recommended_action: 'block' }],
];
for (const [label, ev] of botShapes) {
  const agg = computeBotAggregatesFromEvents([ev]);
  ok(`robust bot_info shape (${label}) → malicious + name/type surfaced`, agg !== null && /malicious/i.test(agg.classDistribution[0]?.key ?? '') && agg.byBotName[0]?.key === 'testssl' && agg.byBotType?.[0]?.key === 'Vulnerability Scanner', `agg=${agg ? agg.classDistribution[0]?.key : 'null'}`);
}

// Bot classification still folds into the Client Behavior signal (non-malicious traffic)
ok('bot signal: benign-dominant raises client-behavior (FP-ward)', scoreClientBehavior([], { benign: 10 }).score > 50);
ok('bot signal: suspicious-dominant lowers client-behavior (TP-ward)', scoreClientBehavior([], { suspicious: 10 }).score < 50);
ok('bot signal: human/unknown ignored (stays neutral)', scoreClientBehavior([], { human: 5, unknown: 5 }).score === 50);

// Recommendation block_bots step, worded by safety
const recBots = buildFpRecommendations({ signatures: [sig('confirmed_tp')], violations: [], comparison: wc1, enforcementMode: 'monitoring', botAnalysis: baSafe });
ok('block_bots step present when malicious bots exist', recBots.steps.some(s => s.kind === 'block_bots'));
ok('no FP risk → block_bots step says safe', /safe/i.test(recBots.steps.find(s => s.kind === 'block_bots')!.title));
const recBotsReview = buildFpRecommendations({ signatures: [sig('confirmed_tp')], violations: [], comparison: wc1, enforcementMode: 'monitoring', botAnalysis: baKnown });
ok('FP risk → block_bots step says review', /review/i.test(recBotsReview.steps.find(s => s.kind === 'block_bots')!.title));

console.log('\n12) Blocking-mode (enforcement) comparison: legacy accuracy vs AI req_risk');
// Signatures: FP1 (medium-acc, Enabled FP), FP2 (high-acc, AutoSuppressed FP), TP1 (high-acc, real attack).
// Distinct paths so each FP signature maps to its own exclusion rule (no path merge).
const ecMeta = new Map<string, SignatureMeta>([
  ['FP1', { sigId: 'FP1', name: 'fp one', verdict: 'highly_likely_fp', attackType: 'XSS', contextType: 'CONTEXT_PARAMETER', contextName: 'q', path: '/a', methods: ['GET'] }],
  ['FP2', { sigId: 'FP2', name: 'fp two', verdict: 'likely_fp', attackType: 'SQLi', contextType: 'CONTEXT_PARAMETER', contextName: 'id', path: '/b', methods: ['GET'] }],
  ['TP1', { sigId: 'TP1', name: 'tp one', verdict: 'confirmed_tp', attackType: 'SQLi', contextType: 'CONTEXT_PARAMETER', contextName: 'id', path: '/c', methods: ['GET'] }],
]);
const evt = (risk: string, refs: Array<[string, string, string]>): ComparisonEvent =>
  ({ reqRisk: risk, signatures: refs.map(([id, accuracy, state]) => ({ id, accuracy, state })), violations: [] });
const ecEvents: ComparisonEvent[] = [
  evt('high', [['TP1', 'high_accuracy', 'Enabled']]),            // e1 TP, blocked by all
  evt('false positive', [['FP1', 'medium_accuracy', 'Enabled']]), // e2 FP, legacy-only block
  evt('low', [['FP2', 'high_accuracy', 'AutoSuppressed']]),       // e3 FP, legacy blocks AutoSuppressed sig
  evt('medium', [['FP1', 'medium_accuracy', 'Enabled']]),         // e4 FP, legacy + AI-high+med
  evt('medium', [['TP1', 'high_accuracy', 'Enabled']]),           // e5 TP, legacy + AI-high+med
];
const ec = computeEnforcementComparison(ecEvents, ecMeta);
const pol = (id: string) => ec.policies.find(p => p.policy === id)!;
ok('classes: 2 TP requests, 3 FP requests', ec.totalTpRequests === 2 && ec.totalFpRequests === 3, `tp=${ec.totalTpRequests} fp=${ec.totalFpRequests}`);
ok('legacy blocks all 5 (accuracy-driven, ignores AI suppression)', pol('legacy_accuracy').blockedRequests === 5, `blocked=${pol('legacy_accuracy').blockedRequests}`);
ok('legacy: AutoSuppressed high-acc sig still blocks (e3 counts as FP block)', pol('legacy_accuracy').fpBlocked === 3, `fp=${pol('legacy_accuracy').fpBlocked}`);
ok('legacy needs 2 exclusion rules (FP1 /a + FP2 /b)', pol('legacy_accuracy').exclusionRulesNeeded === 2, `rules=${pol('legacy_accuracy').exclusionRulesNeeded}`);
ok('AI-High blocks only req_risk=high (1 request), 0 FP rules', pol('ai_risk_high').blockedRequests === 1 && pol('ai_risk_high').exclusionRulesNeeded === 0, `blocked=${pol('ai_risk_high').blockedRequests} rules=${pol('ai_risk_high').exclusionRulesNeeded}`);
ok('AI-High misses 1 real attack (the medium-risk TP)', pol('ai_risk_high').attacksMissed === 1, `missed=${pol('ai_risk_high').attacksMissed}`);
ok('AI-High+Med blocks 3, full attack coverage, only 1 FP rule', pol('ai_risk_high_med').blockedRequests === 3 && pol('ai_risk_high_med').attacksMissed === 0 && pol('ai_risk_high_med').exclusionRulesNeeded === 1, `blocked=${pol('ai_risk_high_med').blockedRequests} missed=${pol('ai_risk_high_med').attacksMissed} rules=${pol('ai_risk_high_med').exclusionRulesNeeded}`);
ok('legacy-only blocks = 4 (FP/extra blocks AI-High avoids)', ec.legacyOnlyBlocked === 4, `legacyOnly=${ec.legacyOnlyBlocked}`);
ok('recommend AI-High+Med (full coverage, fewer rules than legacy)', ec.recommended === 'ai_risk_high_med', `rec=${ec.recommended}`);

// [fixBot] Malicious bots are now INCLUDED in the Blocking comparison: legacy (Bot Defense) blocks
// them, AI-High blocks them (req_risk high), and they count as true positives (no exclusion rules).
const ecBotEvents: ComparisonEvent[] = [
  { reqRisk: 'high', signatures: [{ id: 'TP1', accuracy: 'high_accuracy', state: 'Enabled' }], violations: [] },
  { reqRisk: 'high', signatures: [], violations: [], maliciousBot: true },
  { reqRisk: 'high', signatures: [], violations: [], maliciousBot: true },
];
const ecBot = computeEnforcementComparison(ecBotEvents, ecMeta);
const polBot = (id: string) => ecBot.policies.find(p => p.policy === id)!;
ok('[fixBot] enforcement includes malicious bots: 3 analyzed, all 3 true positives', ecBot.totalRequests === 3 && ecBot.totalTpRequests === 3, `total=${ecBot.totalRequests} tp=${ecBot.totalTpRequests}`);
ok('[fixBot] legacy blocks the 2 bots + the attack (3 blocked, 0 FP, 0 rules)', polBot('legacy_accuracy').blockedRequests === 3 && polBot('legacy_accuracy').tpBlocked === 3 && polBot('legacy_accuracy').exclusionRulesNeeded === 0);
ok('[fixBot] AI-High also blocks the bots (req_risk high) — 3 blocked, full coverage', polBot('ai_risk_high').blockedRequests === 3 && polBot('ai_risk_high').attacksMissed === 0);
ok('[fixBot] narrative is generated and mentions malicious bots', ecBot.narrative.length >= 4 && ecBot.narrative.some(s => /malicious bot/i.test(s)), `len=${ecBot.narrative.length}`);

console.log('\n13) Blocking-mode comparison — WAF violations folded in');
// Violations have no accuracy tier: legacy blocks any ENFORCED (non-staging) violation.
const ecvMeta = new Map<string, SignatureMeta>();
const ecvViol = new Map<string, ViolationMeta>([
  ['VIOL_FP', { name: 'VIOL_FP', verdict: 'highly_likely_fp', path: '/v', methods: [] }],
  ['VIOL_TP', { name: 'VIOL_TP', verdict: 'confirmed_tp', path: '/w', methods: [] }],
]);
const vevt = (risk: string, refs: Array<[string, string]>): ComparisonEvent =>
  ({ reqRisk: risk, signatures: [], violations: refs.map(([name, state]) => ({ name, state })) });
const ecvEvents: ComparisonEvent[] = [
  vevt('high', [['VIOL_TP', 'Enabled']]),            // ve1 TP, blocked by all
  vevt('false positive', [['VIOL_FP', 'Enabled']]),  // ve2 FP, legacy-only block
  vevt('low', [['VIOL_FP', 'Staging']]),             // ve3 FP but STAGING → legacy does not block
  vevt('medium', [['VIOL_FP', 'Enabled']]),          // ve4 FP, legacy + AI-high+med
];
const ecv = computeEnforcementComparison(ecvEvents, ecvMeta, ecvViol);
const vpol = (id: string) => ecv.policies.find(p => p.policy === id)!;
ok('violation-only requests are counted (4 considered)', ecv.totalRequests === 4, `total=${ecv.totalRequests}`);
ok('classes from violation verdicts: 1 TP, 3 FP', ecv.totalTpRequests === 1 && ecv.totalFpRequests === 3, `tp=${ecv.totalTpRequests} fp=${ecv.totalFpRequests}`);
ok('legacy blocks enforced violations but NOT staging (3 blocked, not 4)', vpol('legacy_accuracy').blockedRequests === 3, `blocked=${vpol('legacy_accuracy').blockedRequests}`);
ok('legacy FP-blocks the enforced FP violation twice → 1 violation exclusion rule', vpol('legacy_accuracy').fpBlocked === 2 && vpol('legacy_accuracy').exclusionRulesNeeded === 1, `fp=${vpol('legacy_accuracy').fpBlocked} rules=${vpol('legacy_accuracy').exclusionRulesNeeded}`);
ok('exclusion overhead detail tags the violation kind', vpol('legacy_accuracy').fpDetections.some(d => d.kind === 'violation' && d.id === 'VIOL_FP'));
ok('AI-High blocks only the real attack (1), zero exclusion rules', vpol('ai_risk_high').blockedRequests === 1 && vpol('ai_risk_high').exclusionRulesNeeded === 0, `blocked=${vpol('ai_risk_high').blockedRequests} rules=${vpol('ai_risk_high').exclusionRulesNeeded}`);
ok('recommend AI-High (full attack coverage, zero violation tuning overhead)', ecv.recommended === 'ai_risk_high', `rec=${ecv.recommended}`);

// ── [fixCollapse] WAF exclusion rule path collapsing ──
// Many same-subtree FP paths must fold into ONE prefix rule with an F5 XC RE2-valid path_regex,
// instead of one rule per path (the /php/examples/* scanner produced ~148 rules).
const manyPaths = ['includes', 'sites', 'admin/pages/page', '.env', '.git', 'wp-includes', 'uploads', 'admin', 'vendor', 'core', 'public', 'assets']
  .map(p => `/php/examples/${p}`);
const collapseUnit = {
  signatureId: '200000103', contextType: 'CONTEXT_URL', contextName: '',
  pathAnalyses: manyPaths.map(path => ({ path, verdict: 'likely_fp', methods: { GET: 1 } })),
} as unknown as Parameters<typeof generatePerPathExclusions>[0];
const collapsedRules = generatePerPathExclusions(collapseUnit);
ok('[fixCollapse] 12 same-prefix FP paths collapse to ONE exclusion rule', collapsedRules.length === 1, `rules=${collapsedRules.length}`);
ok('[fixCollapse] collapsed rule uses an F5 XC RE2-valid anchored path_regex for the subtree',
  collapsedRules[0]?.path_regex === '^/php/examples(/.*)?$', `regex=${collapsedRules[0]?.path_regex}`);
ok('[fixCollapse] collapsed regex is valid RE2 and matches the dir + sub-paths, not a sibling',
  (() => { const re = new RegExp(collapsedRules[0]!.path_regex!); return re.test('/php/examples') && re.test('/php/examples/.env') && re.test('/php/examples/a/b') && !re.test('/php/examplesX'); })());

const fewUnit = {
  signatureId: '200001', contextType: 'CONTEXT_URL', contextName: '',
  pathAnalyses: [{ path: '/a/login', verdict: 'likely_fp', methods: { GET: 1 } }, { path: '/b/search', verdict: 'likely_fp', methods: { GET: 1 } }],
} as unknown as Parameters<typeof generatePerPathExclusions>[0];
ok('[fixCollapse] few divergent FP paths stay per-path (no over-collapse)', generatePerPathExclusions(fewUnit).length === 2, `rules=${generatePerPathExclusions(fewUnit).length}`);

// ── [fixEngine] Scanner/recon TP recovery (attack-type awareness, code-0 origin, tightened FP floor) ──
console.log('\n8) Detection-engine accuracy: scanner enumeration → TP');

// 1) The anchor: 1 client enumerating 148 distinct paths under a recon attack type, all WAF-blocked
//    (rsp_code 0), AI rated low — must land TRUE POSITIVE via SCANNER_ENUMERATION.
const reconScan = computeFpSignals(base({
  distinctIPs: 1, distinctUsers: 1, pathCount: 148, totalAppPaths: 500, contextType: 'CONTEXT_URI',
  attackType: 'ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION', accuracy: 'medium_accuracy', sigState: 'Enabled',
  rspCodes: { '0': 148 }, sampleMatchingInfos: ['/php/examples/.env', '/php/examples/.git', '/php/examples/qwertyuiopxxx'],
  aiInput: { riskCounts: { high: 0, medium: 0, low: 148, unknown: 0, falsePositive: 0 }, reasonVerdict: parseRiskReasons(['low risk']), recommendedAction: 'report' },
}));
ok('[fixEngine] recon scanner (1 client, 148 paths, WAF-blocked) → TRUE POSITIVE', ['likely_tp', 'confirmed_tp'].includes(reconScan.verdict) && reconScan.override === 'SCANNER_ENUMERATION', `verdict=${reconScan.verdict} score=${reconScan.compositeScore} override=${reconScan.override}`);

// 2) A genuinely broad predictable-resource FP (150 clients, origin SERVES 95%) must NOT be flipped.
const broadPredictable = computeFpSignals(base({
  distinctIPs: 150, distinctUsers: 150, pathCount: 148, totalAppPaths: 500, contextType: 'CONTEXT_URI',
  attackType: 'ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION', accuracy: 'medium_accuracy', sigState: 'Enabled',
  rspCodes: { '200': 95, '404': 5 }, sampleMatchingInfos: ['search', 'hello', 'profile'],
  aiInput: { riskCounts: { high: 0, medium: 0, low: 148, unknown: 0, falsePositive: 0 }, reasonVerdict: parseRiskReasons(['low risk']), recommendedAction: 'allow' },
}));
ok('[fixEngine] broad multi-client predictable-resource (origin served) is NOT scanner-flipped', broadPredictable.override !== 'SCANNER_ENUMERATION', `override=${broadPredictable.override} verdict=${broadPredictable.verdict}`);

// 3) Recon gate: a non-recon attack type (XSS) with the same scanning shape must NOT arm the override.
const xssMany = computeFpSignals(base({
  distinctIPs: 1, distinctUsers: 1, pathCount: 148, totalAppPaths: 500, contextType: 'CONTEXT_URI',
  attackType: 'ATTACK_TYPE_CROSS_SITE_SCRIPTING', accuracy: 'medium_accuracy', sigState: 'Enabled',
  rspCodes: { '0': 148 }, sampleMatchingInfos: ['/x'],
  aiInput: { riskCounts: { high: 0, medium: 0, low: 148, unknown: 0, falsePositive: 0 }, reasonVerdict: parseRiskReasons(['low risk']) },
}));
ok('[fixEngine] non-recon attack type does NOT arm the scanner-enumeration override', xssMany.override !== 'SCANNER_ENUMERATION', `override=${xssMany.override}`);

// 4) Floor non-regression: AI-low (NOT explicit FP) + WAF-blocked (no origin verdict) must NOT floor to FP.
const aiLowBlocked = computeFpSignals(base({
  distinctIPs: 3, distinctUsers: 3, pathCount: 1, sigState: 'Enabled', accuracy: 'medium_accuracy',
  rspCodes: { '0': 10 }, sampleMatchingInfos: ['x'],
  aiInput: { riskCounts: { high: 0, medium: 0, low: 10, unknown: 0, falsePositive: 0 }, reasonVerdict: parseRiskReasons(['low risk']) },
}));
ok('[fixEngine] AI-low (not explicit FP) + WAF-blocked does NOT floor to F5_CONFIRMED_FP', aiLowBlocked.override !== 'F5_CONFIRMED_FP', `override=${aiLowBlocked.override}`);

// 5) Attack-type set contract: TP-bias and FP-prone disjoint; recon membership.
ok('[fixEngine] TP_BIAS ∩ FP_PRONE attack-type sets are disjoint', [...TP_BIAS_ATTACK_TYPES].every(t => !FP_PRONE_ATTACK_TYPES.has(t)));
ok('[fixEngine] PREDICTABLE_RESOURCE_LOCATION is classed as recon', RECON_ATTACK_TYPES.has('ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION'));

// 6) Code-0 (WAF-blocked) origin rebasing: 404 rate computed on SERVED requests, not total.
const or1 = scoreOriginResponse({ '0': 100, '404': 48 }, 50);
ok('[fixEngine] origin response ignores WAF-blocked code 0 — 404 rebased on served', Math.round(or1.notFoundPct * 100) === 100 && or1.okPct === 0, `nf=${or1.notFoundPct} ok=${or1.okPct} served=${or1.served}`);
const or2 = scoreOriginResponse({ '0': 100 }, 50);
ok('[fixEngine] all-WAF-blocked origin abstains at neutral 50 (no synthesized 404)', or2.signal.score === 50 && or2.okPct === 0 && or2.served === 0);

// 7) AI-low FP boost is discounted for inherently-malicious attack types (bounded to the boost only).
const aiLowInput = { riskCounts: { high: 0, medium: 0, low: 10, unknown: 0, falsePositive: 0 }, reasonVerdict: parseRiskReasons(['low risk']) };
const accWithout = scoreSignatureAccuracy('medium_accuracy', 'Enabled', false, [], aiLowInput).score;
const accWith = scoreSignatureAccuracy('medium_accuracy', 'Enabled', false, [], aiLowInput, 'ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION').score;
ok('[fixEngine] recon attack type discounts the AI low-risk FP boost (bounded to the boost)', accWith < accWithout && (accWithout - accWith) === Math.min(25, Math.max(0, accWithout - 50)), `without=${accWithout} with=${accWith}`);
const accFpProne = scoreSignatureAccuracy('medium_accuracy', 'Enabled', false, [], aiLowInput, 'ATTACK_TYPE_CROSS_SITE_SCRIPTING').score;
ok('[fixEngine] FP-prone attack type gets NO discount (scored as before)', accFpProne === accWithout, `fpProne=${accFpProne} without=${accWithout}`);

// ── [fixRpt] Enhancements from the 8 production-report review ──
console.log('\n9) Report-driven accuracy: sensitive-file recon, CVE-exploit FP gate, distributed scan');

// F2: sensitive-file / recon paths recognized as malicious (were read benign by the short-value heuristic)
for (const p of ['/composer.json', '/.git/config', '/.svn/text-base', '/WEB-INF/web.xml', '/tmp/auth.json',
  '/_vti_pvt/service.pwd', '/assets/app/services/AppModule.class', '/.htaccess', '/wp-config.php', '/phpinfo.php']) {
  ok(`[fixF2] sensitive recon path ${p} -> clearly_malicious`, classifyMatchingInfo(p).classification === 'clearly_malicious', `got ${classifyMatchingInfo(p).classification}`);
}
// F2b: encoded traversal + full-URL (SSRF) path
ok('[fixF2b] URL-encoded traversal ..%2f -> malicious', classifyMatchingInfo('..%2f..%2fetc%2fpasswd').classification === 'clearly_malicious');
ok('[fixF2b] double-encoded traversal %2e%2e -> malicious', classifyMatchingInfo('%2e%2e%2f%2e%2e%2fetc%2fpasswd').classification === 'clearly_malicious');
// SSRF: an INTERNAL/metadata host as the path is malicious; a legit EXTERNAL redirect URL must NOT be (it
// would otherwise + a 2xx wrongly trip the successful-exploit guard and cap a real FP to TP).
ok('[fixF2b] SSRF to cloud metadata (169.254.169.254) -> malicious', classifyMatchingInfo('/https://169.254.169.254/latest/meta-data/').classification === 'clearly_malicious');
ok('[fixF2b] protocol-relative SSRF to localhost -> malicious', classifyMatchingInfo('//localhost/admin').classification === 'clearly_malicious');
ok('[fixF2b] BOUND: legit external redirect URL stays NOT malicious', classifyMatchingInfo('https://mysite.example.com/return').classification !== 'clearly_malicious');
ok('[fixF2b] BOUND: external CDN URL path stays NOT malicious', classifyMatchingInfo('/https://d261.cloudfront.net/x').classification !== 'clearly_malicious');
// F2 BOUND: normal app paths/values must NOT become malicious
ok('[fixF2] normal app path stays non-malicious', classifyMatchingInfo('/api/v1/users/profile').classification !== 'clearly_malicious');
ok('[fixF2] static asset stays benign', classifyMatchingInfo('main.bundle.js').classification === 'clearly_benign');
ok('[fixF2] legitimate .well-known/security.txt is NOT flagged', classifyMatchingInfo('/.well-known/security.txt').classification !== 'clearly_malicious');

// F1: a TARGETED CVE exploit the F5 ML dismissed (AutoSuppressed, few clients) -> Ambiguous, NOT Likely FP
const cveExploit = computeFpSignals(base({
  distinctIPs: 1, distinctUsers: 1, pathCount: 1, attackType: 'ATTACK_TYPE_SERVER_SIDE_CODE_INJECTION',
  sigState: 'AutoSuppressed', rspCodes: { '200': 2 }, sampleMatchingInfos: ['preview'],
  aiInput: { riskCounts: { high: 0, medium: 0, low: 2, unknown: 0, falsePositive: 2 }, reasonVerdict: parseRiskReasons(['false positive']), recommendedAction: 'allow' },
}));
ok('[fixF1] targeted CVE exploit the ML dismissed -> Ambiguous (AI_DISMISSED_EXPLOIT), not Likely FP',
  cveExploit.override === 'AI_DISMISSED_EXPLOIT' && cveExploit.verdict === 'ambiguous', `override=${cveExploit.override} verdict=${cveExploit.verdict} sc=${cveExploit.compositeScore}`);

// F1 BOUND: a BROAD command-exec FP (18 clients, origin served, AI-FP) must STAY Likely FP (not un-floored)
const broadCmdFp = computeFpSignals(base({
  distinctIPs: 18, distinctUsers: 18, pathCount: 6, attackType: 'ATTACK_TYPE_COMMAND_EXECUTION',
  sigState: 'Enabled', rspCodes: { '200': 30 }, sampleMatchingInfos: ['sc'],
  aiInput: { riskCounts: { high: 0, medium: 0, low: 30, unknown: 0, falsePositive: 30 }, reasonVerdict: parseRiskReasons(['false positive']), recommendedAction: 'allow' },
}));
ok('[fixF1] broad cmd-exec FP (18 clients, served) STAYS Likely FP (not un-floored)',
  broadCmdFp.verdict === 'likely_fp' && broadCmdFp.override !== 'AI_DISMISSED_EXPLOIT', `override=${broadCmdFp.override} verdict=${broadCmdFp.verdict} sc=${broadCmdFp.compositeScore}`);

// F3: distributed scan (many clients enumerating many WAF-blocked paths, not 404 → NON_EXISTENT_PATH
// does not apply) -> TP via DISTRIBUTED_SCAN. (404-heavy distributed scans are already TP via NON_EXISTENT_PATH.)
const distScan = computeFpSignals(base({
  distinctIPs: 49, distinctUsers: 49, pathCount: 44, eventCount: 147, totalAppPaths: 500,
  attackType: 'ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION', sigState: 'Enabled',
  rspCodes: { '0': 147 }, sampleMatchingInfos: ['/.git/config'],
  aiInput: { riskCounts: { high: 100, medium: 0, low: 0, unknown: 0, falsePositive: 0 }, reasonVerdict: parseRiskReasons(['attack']) },
}));
ok('[fixF3] distributed /.git scan (49 IPs, 44 paths, WAF-blocked) -> TP (DISTRIBUTED_SCAN)',
  ['likely_tp', 'confirmed_tp'].includes(distScan.verdict) && distScan.override === 'DISTRIBUTED_SCAN', `override=${distScan.override} verdict=${distScan.verdict}`);

// F3 BOUND: a popular SERVED endpoint (high events-per-path, 200) must NOT be flipped
const popularEndpoint = computeFpSignals(base({
  distinctIPs: 49, distinctUsers: 49, pathCount: 25, eventCount: 5000, totalAppPaths: 500,
  attackType: 'ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION', sigState: 'Enabled',
  rspCodes: { '200': 5000 }, sampleMatchingInfos: ['search'],
  aiInput: { riskCounts: { high: 0, medium: 0, low: 5000, unknown: 0, falsePositive: 0 } },
}));
ok('[fixF3] popular SERVED endpoint (high events/path) is NOT flipped by distributed-scan',
  popularEndpoint.override !== 'DISTRIBUTED_SCAN', `override=${popularEndpoint.override}`);

// F3 BOUND (P0-A): COMMAND_EXECUTION is excluded from the distributed set — a broad cmd-exec FP that
// happens to hit many WAF-blocked paths must NOT be flipped to TP by distribution alone (real distributed
// cmd-exec is still caught by malicious matching-evidence / 404 override; a benign-content FP stays FP).
const broadCmdScan = computeFpSignals(base({
  distinctIPs: 30, distinctUsers: 30, pathCount: 40, eventCount: 60, totalAppPaths: 500,
  attackType: 'ATTACK_TYPE_COMMAND_EXECUTION', sigState: 'Enabled', rspCodes: { '0': 60 }, sampleMatchingInfos: ['sc'],
  aiInput: { riskCounts: { high: 0, medium: 0, low: 60, unknown: 0, falsePositive: 60 }, reasonVerdict: parseRiskReasons(['false positive']) },
}));
ok('[fixF3] COMMAND_EXECUTION is NOT flipped to TP by distributed-scan (excluded from the set)',
  broadCmdScan.override !== 'DISTRIBUTED_SCAN', `override=${broadCmdScan.override} verdict=${broadCmdScan.verdict}`);

console.log(`\n${'═'.repeat(40)}\nRESULT: ${pass} passed, ${fail} failed\n`);
process.exit(fail > 0 ? 1 : 0);
