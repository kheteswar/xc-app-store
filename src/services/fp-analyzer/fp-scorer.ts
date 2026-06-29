import type { SignalResult, FPVerdict, AnalysisMode } from './types';
import type { AiRiskCounts, RiskReasonVerdict, AiSignalInput } from './ai-signals';
import {
  scoreUserBreadth,
  scoreRequestBreadth,
  scorePathBreadth,
  scoreContext,
  scoreClientProfile,
  scoreTemporalPattern,
  scoreSignatureAccuracy,
  scoreUserBreadthQuick,
  scoreRequestBreadthQuick,
  scoreSignatureAccuracyEnhanced,
  scoreClientProfileQuick,
} from './signal-calculator';

// ═══════════════════════════════════════════════════════════════
// COMPUTE ALL 7 SIGNALS + COMPOSITE SCORE
// ═══════════════════════════════════════════════════════════════

export interface ComputeSignalsInput {
  flaggedUsers: number;
  flaggedIPs: number;
  eventCount: number;
  totalUsersOnPath: number;
  totalRequestsOnPath: number;
  pathCount: number;
  totalAppPaths: number;
  contextType: string;
  contextName: string;
  userAgents: Record<string, number>;
  botClassifications: Record<string, number>;
  trustScores: number[];
  countries: Record<string, number>;
  normalCountries: Record<string, number>;
  timestamps: string[];
  normalTimestamps: string[];
  accuracy: string;
  sigState: string;
  aiConfirmed: boolean;
  violationRatings: number[];
  // AI-WAF intelligence (optional — present when events carry req_risk* fields)
  aiRiskCounts?: AiRiskCounts;
  aiReasonVerdict?: RiskReasonVerdict;
  recommendedAction?: string;
  calculatedAction?: string;
}

const WEIGHTS = {
  userBreadth: 0.25,
  requestBreadth: 0.25,
  pathBreadth: 0.10,
  contextAnalysis: 0.10,
  clientProfile: 0.10,
  temporalPattern: 0.10,
  signatureAccuracy: 0.10,
};

export function computeAllSignals(input: ComputeSignalsInput): SignalResult {
  const userBreadth = scoreUserBreadth(input.flaggedUsers, input.totalUsersOnPath);
  const requestBreadth = scoreRequestBreadth(input.eventCount, input.totalRequestsOnPath);
  const pathBreadth = scorePathBreadth(input.pathCount, input.totalAppPaths);
  const contextAnalysis = scoreContext(input.contextType, input.contextName);
  const clientProfile = scoreClientProfile(
    input.userAgents,
    input.botClassifications,
    input.trustScores,
    input.countries,
    input.normalCountries,
  );
  const temporalPattern = scoreTemporalPattern(input.timestamps, input.normalTimestamps);
  const aiInput: AiSignalInput | undefined =
    input.aiRiskCounts || input.aiReasonVerdict || input.recommendedAction || input.calculatedAction
      ? {
          riskCounts: input.aiRiskCounts,
          reasonVerdict: input.aiReasonVerdict,
          recommendedAction: input.recommendedAction,
          calculatedAction: input.calculatedAction,
        }
      : undefined;
  const signatureAccuracy = scoreSignatureAccuracy(
    input.accuracy,
    input.sigState,
    input.aiConfirmed,
    input.violationRatings,
    aiInput,
  );

  const compositeScore = Math.round(
    userBreadth.score * WEIGHTS.userBreadth +
    requestBreadth.score * WEIGHTS.requestBreadth +
    pathBreadth.score * WEIGHTS.pathBreadth +
    contextAnalysis.score * WEIGHTS.contextAnalysis +
    clientProfile.score * WEIGHTS.clientProfile +
    temporalPattern.score * WEIGHTS.temporalPattern +
    signatureAccuracy.score * WEIGHTS.signatureAccuracy,
  );

  return {
    userBreadth,
    requestBreadth,
    pathBreadth,
    contextAnalysis,
    clientProfile,
    temporalPattern,
    signatureAccuracy,
    compositeScore,
    verdict: scoreToVerdict(compositeScore),
  };
}

// ═══════════════════════════════════════════════════════════════
// QUICK MODE: COMPUTE SIGNALS FROM SECURITY EVENTS ONLY
// ═══════════════════════════════════════════════════════════════

const QUICK_WEIGHTS = {
  userBreadth: 0.20,
  requestBreadth: 0.15,
  pathBreadth: 0.15,
  contextAnalysis: 0.15,
  clientProfile: 0.10,
  temporalPattern: 0.10,
  signatureAccuracy: 0.15,
};

export interface QuickModeSignalsInput {
  flaggedUsers: number;
  flaggedIPs: number;
  eventCount: number;
  pathCount: number;
  totalAppPaths: number;
  contextType: string;
  contextName: string;
  userAgents: Record<string, number>;
  botClassifications: Record<string, number>;
  trustScores: number[];
  countries: Record<string, number>;
  botAnomalies?: Record<string, number>;
  timestamps: string[];
  accuracy: string;
  sigState: string;
  aiConfirmed: boolean;
  violationRatings: number[];
  calculatedAction?: string;
  rspCode200Pct: number;
  // AI-WAF intelligence (optional — present when events carry req_risk* fields)
  aiRiskCounts?: AiRiskCounts;
  aiReasonVerdict?: RiskReasonVerdict;
  recommendedAction?: string;
}

export function computeQuickModeSignals(input: QuickModeSignalsInput): SignalResult {
  const userBreadth = scoreUserBreadthQuick(input.flaggedUsers);
  const requestBreadth = scoreRequestBreadthQuick(input.eventCount, input.rspCode200Pct);
  const pathBreadth = scorePathBreadth(input.pathCount, input.totalAppPaths);
  const contextAnalysis = scoreContext(input.contextType, input.contextName);
  const clientProfile = scoreClientProfileQuick(
    input.userAgents,
    input.botClassifications,
    input.trustScores,
    input.countries,
    input.botAnomalies,
  );
  const temporalPattern = scoreTemporalPattern(input.timestamps, []);
  const aiInput: AiSignalInput | undefined =
    input.aiRiskCounts || input.aiReasonVerdict || input.recommendedAction || input.calculatedAction
      ? {
          riskCounts: input.aiRiskCounts,
          reasonVerdict: input.aiReasonVerdict,
          recommendedAction: input.recommendedAction,
          calculatedAction: input.calculatedAction,
        }
      : undefined;
  const signatureAccuracy = scoreSignatureAccuracyEnhanced(
    input.accuracy,
    input.sigState,
    input.aiConfirmed,
    input.violationRatings,
    input.calculatedAction,
    input.rspCode200Pct,
    aiInput,
  );

  const compositeScore = Math.round(
    userBreadth.score * QUICK_WEIGHTS.userBreadth +
    requestBreadth.score * QUICK_WEIGHTS.requestBreadth +
    pathBreadth.score * QUICK_WEIGHTS.pathBreadth +
    contextAnalysis.score * QUICK_WEIGHTS.contextAnalysis +
    clientProfile.score * QUICK_WEIGHTS.clientProfile +
    temporalPattern.score * QUICK_WEIGHTS.temporalPattern +
    signatureAccuracy.score * QUICK_WEIGHTS.signatureAccuracy,
  );

  return {
    userBreadth,
    requestBreadth,
    pathBreadth,
    contextAnalysis,
    clientProfile,
    temporalPattern,
    signatureAccuracy,
    compositeScore,
    verdict: scoreToVerdict(compositeScore),
  };
}

// ═══════════════════════════════════════════════════════════════
// MODE-AWARE WEIGHTS GETTER
// ═══════════════════════════════════════════════════════════════

export function getWeightsForMode(mode: AnalysisMode): typeof WEIGHTS {
  return mode === 'hybrid' ? WEIGHTS : QUICK_WEIGHTS;
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO 2 OVERRIDE: PATH-SPECIFIC APP LOGIC FP
// ═══════════════════════════════════════════════════════════════

export function applyScenario2Override(
  signals: SignalResult,
  pathCount: number,
  requestRatio: number,
  userCountOnPath: number,
  rspCodes: Record<string, number>,
): SignalResult {
  // Trigger conditions: low path count, high request ratio, not mass-traffic
  if (pathCount > 3 || requestRatio <= 0.80 || userCountOnPath > 30) {
    return signals;
  }

  let fpBoost = 0;
  const reasons: string[] = [];

  // Origin 200 check
  const totalRsp = Object.values(rspCodes).reduce((a, b) => a + b, 0);
  const okCount = rspCodes['200'] || 0;
  if (totalRsp > 0 && (okCount / totalRsp) > 0.5) {
    fpBoost += 25;
    reasons.push(`Origin returned 200 OK for ${((okCount / totalRsp) * 100).toFixed(0)}% of flagged requests — app accepted this input`);
  }

  // Request ratio boost
  fpBoost += 20;
  reasons.push(`${(requestRatio * 100).toFixed(0)}% of ALL requests to this path trigger this signature — path's normal function`);

  const boostedScore = Math.min(100, signals.compositeScore + fpBoost);

  return {
    ...signals,
    compositeScore: boostedScore,
    verdict: scoreToVerdict(boostedScore),
    overrideApplied: 'SCENARIO_2_PATH_SPECIFIC_FP',
    overrideReason: reasons.join('; '),
  };
}

// ═══════════════════════════════════════════════════════════════
// VERDICT THRESHOLDS
// ═══════════════════════════════════════════════════════════════

function scoreToVerdict(score: number): FPVerdict {
  if (score > 75) return 'highly_likely_fp';
  if (score > 55) return 'likely_fp';
  if (score > 35) return 'ambiguous';
  if (score > 15) return 'likely_tp';
  return 'confirmed_tp';
}
