/**
 * Behavioral tests for the redesigned FP Analyzer (single-mode, client-behavior).
 * Run: npm run test:fp   (npx tsx scripts/test-fp-accuracy.mts)
 */
import { parseReqRisk, parseRiskReasons, scoreAiRisk, estimateActualCountFromRate } from '../src/services/fp-analyzer/ai-signals.ts';
import {
  computeFpSignals, scoreClientBreadth, scoreMatchingEvidence, scoreOriginResponse,
  scoreClientBehavior, scoreViolationSeverity,
} from '../src/services/fp-analyzer/fp-signals-v2.ts';
import type { FpSignalsInput } from '../src/services/fp-analyzer/fp-signals-v2.ts';
import { buildSignatureExclusionsWithRollup } from '../src/services/fp-analyzer/exclusion-generator.ts';
import { scoreClientProfileQuick } from '../src/services/fp-analyzer/signal-calculator.ts';
import { computeWafComparison } from '../src/services/fp-analyzer/waf-comparison.ts';
import { buildFpRecommendations } from '../src/services/fp-analyzer/recommendations.ts';
import { computeBotAnalysisFromAggregates, classifyBot } from '../src/services/fp-analyzer/bot-analysis.ts';
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

console.log(`\n${'═'.repeat(40)}\nRESULT: ${pass} passed, ${fail} failed\n`);
process.exit(fail > 0 ? 1 : 0);
