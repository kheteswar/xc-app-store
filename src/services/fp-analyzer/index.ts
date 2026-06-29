export * from './types';
export { parseContext } from './context-parser';
export {
  scorePathBreadth, scoreContext, scoreSignatureAccuracy,
  computeQuickVerdict, getScoreConfidence,
  mapToRecord, mergeNormalTimestamps, mergeNormalCountries,
} from './signal-calculator';
// Redesigned single-mode scoring (2026)
export {
  computeFpSignals, scoreToVerdict, FP_WEIGHTS,
  scoreClientBreadth, scoreMatchingEvidence, scoreOriginResponse, scoreClientBehavior,
  scoreViolationSeverity, isAlwaysTpViolation, EXPLOIT_PATH_RE,
} from './fp-signals-v2';
export type { FpSignalsInput, OriginResponseResult } from './fp-signals-v2';
export { computeWafComparison } from './waf-comparison';
export type { WafComparisonResult, WafSignatureDivergence, WafRecommendation } from './waf-comparison';
export { buildFpRecommendations } from './recommendations';
export { computeBotAnalysisFromAggregates, classifyBot } from './bot-analysis';
export type { BotClass, BotAggregateInput } from './bot-analysis';
export {
  generateSignatureExclusion, generateViolationExclusion,
  groupExclusionRules, pathToRegex, generateExclusionsForSignatures,
  generatePerPathExclusions, generateViolationPerPathExclusions,
  buildWafExclusionPolicy, cleanPolicyForExport,
  generateAttackTypeExclusion, buildSignatureExclusionsWithRollup,
} from './exclusion-generator';
export type { SigExclusionIntent } from './exclusion-generator';
export * from './ai-signals';
export { exportAnalysisCSV, exportExclusionJSON } from './report-generator';
export { analysisLogger, AnalysisLogger, anonIP, anonUser, anonUA, anonDomain, sanitizePath } from './analysis-logger';
export type { LogEntry, LogLevel } from './analysis-logger';
export { classifyMatchingInfo } from './matching-info-analyzer';
export { generateFPAnalysisPDF } from './fp-report-pdf';
export type { FPReportOptions } from './fp-report-pdf';
export { generateFPAnalysisExcel } from './fp-report-excel';
export type { FPExcelReportOptions } from './fp-report-excel';
export type { MatchingInfoClassification, MatchingInfoResult } from './matching-info-analyzer';
export { AdaptiveConcurrencyController } from './adaptive-concurrency';
export type { AdaptiveConcurrencyConfig, RateLimitState } from './adaptive-concurrency';
export { runAdaptivePool } from './adaptive-worker-pool';
export type { AdaptivePoolResult } from './adaptive-worker-pool';
