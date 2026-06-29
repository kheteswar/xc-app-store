import type { AccessLogEntry, SecurityEventEntry } from '../rate-limit-advisor/types';
import type { AiRiskCounts } from './ai-signals';
import type { WafComparisonResult } from './waf-comparison';

// Re-export for convenience
export type { AccessLogEntry, SecurityEventEntry };

// ═══════════════════════════════════════════════════════════════
// ANALYSIS SCOPE & VERDICTS
// ═══════════════════════════════════════════════════════════════

export type AnalysisScope = 'waf_signatures' | 'waf_violations' | 'threat_mesh' | 'service_policy' | 'bot_defense' | 'api_security';

export type AnalysisMode = 'quick' | 'hybrid';

export type QuickVerdict = 'likely_fp' | 'likely_tp' | 'investigate';
export type ConfidenceLevel = 'high' | 'medium' | 'low';

export type FPVerdict = 'highly_likely_fp' | 'likely_fp' | 'ambiguous' | 'likely_tp' | 'confirmed_tp';

// ═══════════════════════════════════════════════════════════════
// PARSED SECURITY EVENT TYPES
// ═══════════════════════════════════════════════════════════════

export interface WafSignature {
  id: string;
  name: string;
  attackType: string;
  accuracy: 'high_accuracy' | 'medium_accuracy' | 'low_accuracy';
  risk: string;
  context: string;
  contextType: string;
  contextName: string;
  matchingInfo: string;
  state: string;
}

export interface WafViolation {
  name: string;
  attackType: string;
  state: string;
}

export interface ThreatMeshDetails {
  description: string;
  attackTypes: string[];
  events: number;
  tenantCount: number;
  highAccuracySignatures: number;
  tlsCount: number;
  maliciousBotEvents: number;
}

export interface PolicyHitDetails {
  result: string;
  policy: string;
  policyRule: string;
  policyNamespace: string;
  ipThreatCategories: string;
  ipTrustScore: number;
  ipTrustWorthiness: string;
  ipRisk: string;
  rateLimiterAction: string;
}

// ═══════════════════════════════════════════════════════════════
// SIGNAL SCORING
// ═══════════════════════════════════════════════════════════════

export interface SignalScore {
  score: number;
  rawValue: number | string;
  reason: string;
}

export interface SignalResult {
  userBreadth: SignalScore;
  requestBreadth: SignalScore;
  pathBreadth: SignalScore;
  contextAnalysis: SignalScore;
  clientProfile: SignalScore;
  temporalPattern: SignalScore;
  signatureAccuracy: SignalScore;
  compositeScore: number;
  verdict: FPVerdict;
  overrideApplied?: string;
  overrideReason?: string;
}

// ═══════════════════════════════════════════════════════════════
// REDESIGN (2026): single-mode signals + per-IP behavioral profile
// ═══════════════════════════════════════════════════════════════

/** The 7 redesigned FP signals (see fp-signals-v2.ts). Higher = more FP. */
export interface FpSignals {
  clientBreadth: SignalScore;
  pathBreadth: SignalScore;
  context: SignalScore;
  matchingEvidence: SignalScore;
  originResponse: SignalScore;
  clientBehavior: SignalScore;
  detectionConfidence: SignalScore;
  compositeScore: number;
  verdict: FPVerdict;
  /** 2xx response on a malicious-looking payload — surfaced as a likely successful exploit. */
  possibleSuccessfulExploit?: boolean;
  override?: string;
  overrideReason?: string;
}

/** Behavioral profile of a single flagged client IP, from ITS OWN full access logs. */
export interface IPBehaviorProfile {
  ip: string;
  enriched: boolean;
  totalRequests: number;          // de-sampled
  rspCodes: Record<string, number>;
  successRatio: number;           // 2xx / total
  notFoundRatio: number;          // 404 / total
  clientErrorRatio: number;       // other 4xx / total
  serverErrorRatio: number;       // 5xx / total
  uniquePaths: number;
  exploitPathHits: number;
  reqPerHour: number;
  topUserAgent: string;
  country: string;
  asOrg: string;
  wafEventCount: number;          // this IP's requests that were WAF events
  wafEventRatio: number;          // wafEventCount / totalRequests
}

// ═══════════════════════════════════════════════════════════════
// PER-PATH FP/TP ANALYSIS
// ═══════════════════════════════════════════════════════════════

export interface PathAnalysis {
  path: string;
  eventCount: number;
  uniqueUsers: number;
  uniqueIPs: number;
  userAgents: Record<string, number>;
  countries: Record<string, number>;
  methods: Record<string, number>;
  rspCodes: Record<string, number>;
  sampleMatchingInfos: string[];
  fpScore: number;
  verdict: FPVerdict;
  reasons: string[];
}

// ═══════════════════════════════════════════════════════════════
// SIGNATURE ANALYSIS UNIT
// ═══════════════════════════════════════════════════════════════

export interface SignatureAnalysisUnit {
  signatureId: string;
  signatureName: string;
  attackType: string;
  accuracy: string;

  contextType: string;
  contextName: string;
  contextRaw: string;

  path: string;
  rawPaths: string[];
  pathCount: number;
  pathCounts: Record<string, number>;
  pathAnalyses?: PathAnalysis[];

  eventCount: number;
  flaggedUsers: number;
  flaggedIPs: number;
  ipCounts: Record<string, number>;
  ipDetails?: Record<string, { count: number; country: string; city: string; asOrg: string; userAgent: string }>;

  totalRequestsOnPath: number;
  totalUsersOnPath: number;

  userRatio: number;
  requestRatio: number;

  userAgents: Record<string, number>;
  countries: Record<string, number>;
  trustScores: number[];
  botClassifications: Record<string, number>;
  methods: Record<string, number>;

  sampleMatchingInfos: string[];
  sampleReqParams: string[];

  timestamps: string[];

  rspCodes: Record<string, number>;
  originAcceptedCount: number;

  violationRatings: number[];
  reqRiskReasons: string[];
  aiConfirmed: boolean;
  sigState: string;

  signals: FpSignals;
  /** Per-IP behavioral profiles for the flagged clients (redesign). */
  ipProfiles?: IPBehaviorProfile[];

  autoSuppressed?: boolean;
  staged?: boolean;
  /** AI-WAF: req_risk distribution across this signature's events. */
  aiRiskCounts?: AiRiskCounts;
  /** AI-WAF: dominant recommended_action (allow/report/block). */
  recommendedAction?: string;
  enriched?: boolean;
  suggestedExclusion?: WafExclusionRule;
}

// ═══════════════════════════════════════════════════════════════
// VIOLATION ANALYSIS UNIT
// ═══════════════════════════════════════════════════════════════

export interface ViolationAnalysisUnit {
  violationName: string;
  attackType: string;
  path: string;
  rawPaths: string[];
  pathCount: number;
  pathCounts: Record<string, number>;
  pathAnalyses?: PathAnalysis[];
  eventCount: number;
  flaggedUsers: number;
  flaggedIPs: number;
  ipCounts: Record<string, number>;
  ipDetails?: Record<string, { count: number; country: string; city: string; asOrg: string; userAgent: string }>;
  totalRequestsOnPath: number;
  totalUsersOnPath: number;
  userRatio: number;
  requestRatio: number;
  userAgents: Record<string, number>;
  countries: Record<string, number>;
  methods: Record<string, number>;
  botClassifications?: Record<string, number>;
  sampleMatchingInfos: string[];
  timestamps: string[];
  signals: FpSignals;
  ipProfiles?: IPBehaviorProfile[];
  suggestedExclusion?: WafExclusionRule;
}

// ═══════════════════════════════════════════════════════════════
// THREAT MESH ANALYSIS UNIT
// ═══════════════════════════════════════════════════════════════

export interface ThreatMeshAnalysisUnit {
  srcIp: string;
  user: string;

  threatDetails: ThreatMeshDetails;

  totalRequestsOnApp: number;
  pathsAccessed: Record<string, number>;
  userAgent: string;
  country: string;
  asOrg: string;
  rspCodes: Record<string, number>;

  wafEventsFromThisIP: number;

  fpScore: number;
  verdict: FPVerdict;
  reasons: string[];

  suggestedAction?: 'trusted_client' | 'no_action';
  suggestedConfig?: object;
}

// ═══════════════════════════════════════════════════════════════
// SERVICE POLICY ANALYSIS UNIT
// ═══════════════════════════════════════════════════════════════

export interface ServicePolicyAnalysisUnit {
  policyName: string;
  ruleName: string;

  totalBlocked: number;
  blockedIPs: Array<{
    ip: string;
    user: string;
    count: number;
    userAgent: string;
    trustScore: number;
    threatCategories: string;
    country: string;
    topPaths: string[];
    verdict: FPVerdict;
    reason: string;
  }>;

  realBrowserPct: number;
  avgTrustScore: number;

  fpScore: number;
  verdict: FPVerdict;
  reasons: string[];
}

// ═══════════════════════════════════════════════════════════════
// STREAMING AGGREGATION
// ═══════════════════════════════════════════════════════════════

export interface PathStats {
  totalRequests: number;
  totalUsers: number;
  flaggedRequests: number;
  flaggedUsers: number;
  userAgents: Map<string, number>;
  countries: Map<string, number>;
  rspCodes: Map<string, number>;
  methods: Map<string, number>;
  timestampSamples: string[];
}

export interface StreamingAggregation {
  pathStats: Map<string, PathStats>;
  totalAccessLogs: number;
  totalUniqueUsers: number;
  avgSampleRate: number;
}

// ═══════════════════════════════════════════════════════════════
// WAF EXCLUSION RULE
// ═══════════════════════════════════════════════════════════════

export interface WafExclusionRule {
  metadata: {
    name: string;
    disable: boolean;
    description?: string;
  };
  // Domain matching: one-of any_domain or exact_value
  any_domain?: Record<string, never>;
  exact_value?: string;
  // Path matching: one-of any_path, path_prefix, or path_regex
  any_path?: Record<string, never>;
  path_prefix?: string;
  path_regex?: string;
  methods: string[];
  app_firewall_detection_control: {
    exclude_signature_contexts: Array<{
      signature_id: number;
      context: string;
      context_name?: string;
    }>;
    exclude_violation_contexts: Array<{
      exclude_violation: string;
      context: string;
      context_name?: string;
    }>;
    exclude_attack_type_contexts: Array<{
      context: string;
      exclude_attack_type: string;
    }>;
    exclude_bot_name_contexts: Array<{
      bot_name: string;
    }>;
  };
}

// ═══════════════════════════════════════════════════════════════
// WAF EXCLUSION POLICY OBJECT (F5 XC first-class config)
// ═══════════════════════════════════════════════════════════════

export interface WafExclusionPolicyObject {
  metadata: {
    name: string;
    namespace?: string;
    labels?: Record<string, string>;
    description?: string;
  };
  spec: {
    waf_exclusion_rules: WafExclusionRule[];
  };
}

export interface WafExclusionPolicyCreateRequest {
  metadata: {
    name: string;
    namespace: string;
    labels?: Record<string, string>;
    description?: string;
  };
  spec: {
    waf_exclusion_rules: WafExclusionRule[];
  };
}

export interface WafExclusionPolicyRef {
  name: string;
  namespace?: string;
  tenant?: string;
}

// ═══════════════════════════════════════════════════════════════
// PROGRESSIVE FLOW — SUMMARY TYPES
// ═══════════════════════════════════════════════════════════════

export interface SignatureSummary {
  sigId: string;
  name: string;
  accuracy: string;
  attackType: string;
  totalEvents: number;
  uniqueUsers: number;
  uniquePaths: number;
  uniqueIPs: number;
  topPaths: Array<{ path: string; count: number }>;
  autoSuppressed: boolean;
  /** AI-WAF: dominant req_risk level across this signature's events (high/medium/low). */
  aiRisk?: 'high' | 'medium' | 'low' | 'unknown';
  /** AI-WAF: dominant recommended_action (allow/report/block). */
  recommendedAction?: string;
  /** Signature is in Staging (monitor-only, not actually blocking). */
  staged?: boolean;
  actions: { block: number; report: number };
  quickVerdict: QuickVerdict;
  quickConfidence: ConfidenceLevel;
  fpScore: number;
  fpVerdict: FPVerdict;
  /** Hybrid mode enrichment */
  enrichmentStatus?: 'pending' | 'complete';
  enrichedFpScore?: number;
  enrichedFpVerdict?: FPVerdict;
  /** User-assigned review status */
  reviewStatus?: 'confirmed_fp' | 'confirmed_tp' | 'skipped';
}

export interface ViolationSummary {
  violationName: string;
  attackType: string;
  totalEvents: number;
  uniqueUsers: number;
  uniquePaths: number;
  topPaths: Array<{ path: string; count: number }>;
  /** AI-WAF: dominant req_risk level across this violation's events. */
  aiRisk?: 'high' | 'medium' | 'low' | 'unknown';
  quickVerdict: QuickVerdict;
  quickConfidence: ConfidenceLevel;
  fpScore: number;
  fpVerdict: FPVerdict;
  /** Hybrid mode enrichment */
  enrichmentStatus?: 'pending' | 'complete';
  enrichedFpScore?: number;
  enrichedFpVerdict?: FPVerdict;
}

export interface ThreatMeshSummary {
  srcIp: string;
  eventCount: number;
  paths: number;
  description: string;
  action: string;
  userAgent: string;
  country: string;
  asOrg: string;
  attackTypes: string[];
  tenantCount: number;
  quickVerdict: QuickVerdict;
  quickConfidence: ConfidenceLevel;
  /** Populated after automatic access log enrichment */
  accessLogRequests?: number;
  successRate?: number;
  avgReqPerHour?: number;
  enrichedVerdict?: FPVerdict;
  enrichedScore?: number;
}

export interface PolicyRuleSummary {
  ruleName: string;
  policyName: string;
  totalBlocked: number;
  uniqueIPs: number;
}

export interface SummaryResult {
  signatures: SignatureSummary[];
  violations: ViolationSummary[];
  threatMeshIPs: ThreatMeshSummary[];
  policyRules: PolicyRuleSummary[];
  totalEvents: number;
  period: { start: string; end: string };
  /** LB WAF enforcement: BLOCKING means exclusions take effect; MONITORING is advisory. */
  enforcementMode?: 'blocking' | 'monitoring' | 'unknown';
  /** Average access-log sample_rate observed (hybrid). 1 = unsampled. */
  avgSampleRate?: number;
  /** True if event collection under-fetched vs server total_hits. */
  dataPartial?: boolean;
  /** Traditional signature engine vs AI-powered (req_risk) comparison. */
  wafComparison?: WafComparisonResult;
  /** Prescriptive action plan to move the customer to Blocking mode safely. */
  recommendations?: FpRecommendations;
  /** Bot classification (bot_info) analysis — is it safe to block Malicious bots? */
  botAnalysis?: BotAnalysisResult;
}

// ═══════════════════════════════════════════════════════════════
// BOT CLASSIFICATION ANALYSIS
// ═══════════════════════════════════════════════════════════════

/** A single terms-aggregation bucket (server-side count, no raw rows). */
export interface BotAggBucket { key: string; count: number; }

/**
 * A false-positive risk indicator found *inside* the Malicious-classified set:
 * a known-good bot name (Googlebot…) or a real-browser user-agent that — being
 * uncorrelated by aggregation — warrants a manual look before bot blocking.
 */
export interface BotFpRiskFlag {
  kind: 'known_good_bot' | 'real_browser';
  label: string;   // the bot name or user-agent string
  count: number;   // malicious events carrying it
}

/**
 * Bot classification, computed from SERVER-SIDE AGGREGATIONS (no raw malicious-bot
 * rows are downloaded). Answers: is it safe to block the Malicious bots, or would
 * that hit a known-good crawler / real user?
 */
export interface BotAnalysisResult {
  /** Event counts by bot classification (from a bot_class distribution aggregation over all WAF events). */
  classificationCounts: { malicious: number; suspicious: number; benign: number; human: number; unknown: number };
  maliciousEvents: number;          // total Malicious-classified WAF events
  maliciousIps: number;             // distinct Malicious src_ip (bucket count; capped at topk)
  ipsCapped: boolean;               // true if distinct IPs hit the topk cap (undercount)
  topMaliciousIps: BotAggBucket[];  // src_ip → events (for the table)
  topBotNames: BotAggBucket[];      // bot_name → events
  topUserAgents: BotAggBucket[];    // user_agent → events
  topCountries: BotAggBucket[];     // country → events
  /** Known-good bots / real-browser UAs detected among the Malicious set → review before blocking. */
  fpRiskFlags: BotFpRiskFlag[];
  recommendation: string;
  /** Marker: this result came from aggregation (no per-request enrichment). */
  aggregated: true;
}

// ═══════════════════════════════════════════════════════════════
// RECOMMENDATIONS / NEXT STEPS
// ═══════════════════════════════════════════════════════════════

export type RecoKind = 'exclude' | 'investigate' | 'enable_ai' | 'block' | 'block_bots' | 'done';

export interface RecoStep {
  num: number;
  kind: RecoKind;
  title: string;
  detail: string;
}

export interface FpRecommendations {
  enforcementMode: 'blocking' | 'monitoring' | 'unknown';
  fpCount: number;
  tpCount: number;
  ambiguousCount: number;
  /** Recommended AI-powered WAF blocking threshold. */
  aiBlockingThreshold: 'high' | 'high_medium';
  aiThresholdReason: string;
  steps: RecoStep[];
  /** High-confidence false positives NOT already auto-suppressed → candidates for a manual exclusion (confirm first). */
  excludeList: Array<{ kind: 'signature' | 'violation'; id: string; name: string; verdict: FPVerdict }>;
  /** Likely-FP / ambiguous findings → manual investigation & confirmation, NOT auto-exclusion. */
  investigateList: Array<{ kind: string; id: string; name: string; reason: string }>;
  /** Already auto-suppressed by F5's AI FP detection → no exclusion rule needed. */
  autoHandledList: Array<{ kind: string; id: string; name: string }>;
}

// ═══════════════════════════════════════════════════════════════
// PROGRESSIVE FLOW — JOB STATUS
// ═══════════════════════════════════════════════════════════════

export type ProgressiveJobStatus = 'collecting' | 'summary_ready' | 'enriching' | 'complete' | 'error' | 'cancelled';

export interface ProgressiveJobProgress {
  status: ProgressiveJobStatus;
  securityEventsCollected: number;
  /** Server-reported total_hits summed across chunks (expected event count). */
  securityEventsExpected?: number;
  /** True if any chunk under-fetched (scroll broke / error) vs total_hits. */
  dataPartial?: boolean;
  signaturesFound: number;
  violationsFound: number;
  totalChunks: number;
  chunksCompleted: number;
  currentPhaseLabel: string;
  elapsedMs: number;
  estimatedRemainingMs: number;
  adaptiveState?: string;
  adaptiveConcurrency?: number;
  error?: string;
  /** Per-IP behavioral enrichment progress (redesign). */
  ipEnrichTotal?: number;
  ipEnrichCompleted?: number;
}

export interface EnrichmentResult {
  enriched: boolean;
  pathStats: Record<string, { totalRequests: number; totalUsers: number; flaggedRequests: number; flaggedUsers: number }>;
  updatedSignals?: SignalResult;
  updatedComposite?: number;
  updatedVerdict?: FPVerdict;
}

export interface ThreatMeshEnrichmentResult {
  enriched: boolean;
  totalAccessLogRequests: number;
  successRate: number;
  rspCodeBreakdown: Record<string, number>;
  pathsAccessed: Record<string, number>;
  methodBreakdown: Record<string, number>;
  timeSpanHours: number;
  avgRequestsPerHour: number;
  updatedVerdict: FPVerdict;
  updatedScore: number;
  updatedReasons: string[];
}

// ═══════════════════════════════════════════════════════════════
// OVERALL ANALYSIS RESULTS
// ═══════════════════════════════════════════════════════════════

export interface FPAnalysisResults {
  lbName: string;
  namespace: string;
  domains: string[];
  analysisScopes: AnalysisScope[];
  mode?: AnalysisMode;
  wafPolicyName?: string;
  wafMode?: 'BLOCKING' | 'MONITORING';
  enforcementMode?: string;
  suggestedPolicy?: WafExclusionPolicyObject;
  existingPolicyRefs?: WafExclusionPolicyRef[];
  analysisStart: string;
  analysisEnd: string;
  generatedAt: string;

  totalSecurityEvents: number;
  totalAccessLogs: number;
  totalAccessLogsStreamed: number;
  avgSampleRate: number;

  signatureUnits?: SignatureAnalysisUnit[];
  violationUnits?: ViolationAnalysisUnit[];
  threatMeshUnits?: ThreatMeshAnalysisUnit[];
  servicePolicyUnits?: ServicePolicyAnalysisUnit[];

  summary: {
    totalAnalyzed: number;
    highlyLikelyFP: number;
    likelyFP: number;
    ambiguous: number;
    likelyTP: number;
    confirmedTP: number;
  };

  suggestedExclusions: WafExclusionRule[];
  existingExclusions: WafExclusionRule[];
}

// ═══════════════════════════════════════════════════════════════
// COLLECTION PROGRESS
// ═══════════════════════════════════════════════════════════════

export interface FPCollectionProgress {
  phase: 'idle' | 'fetching_security' | 'streaming_access' | 'analyzing' | 'complete' | 'error';
  message: string;
  progress: number;
  securityEventsCount: number;
  accessLogsStreamed: number;
  accessLogsEstimatedTotal: number;
  pathsAggregated: number;
  signaturesFound: number;
  violationsFound: number;
  error?: string;
}

// ═══════════════════════════════════════════════════════════════
// SECURITY EVENT INDEXER TYPES
// ═══════════════════════════════════════════════════════════════

export interface SignatureContextData {
  path: string;
  context: string;
  contextName: string;
  contextRaw: string;
  eventCount: number;
  uniqueUsers: Set<string>;
  uniqueIPs: Set<string>;
  userAgents: Map<string, number>;
  countries: Map<string, number>;
  trustScores: number[];
  botClassifications: Map<string, number>;
  methods: Map<string, number>;
  sampleMatchingInfo: string[];
  sampleReqParams: string[];
  timestamps: string[];
  rspCodes: Map<string, number>;
  violationRatings: number[];
  reqRiskReasons: string[];
  aiConfirmed: boolean;
  rawPaths: string[];
}

export interface SignatureIndexEntry {
  name: string;
  attackType: string;
  accuracy: string;
  risk: string;
  state: string;
  contexts: Map<string, SignatureContextData>;
}

export interface ViolationContextData {
  path: string;
  eventCount: number;
  uniqueUsers: Set<string>;
  userAgents: Map<string, number>;
  countries: Map<string, number>;
  methods: Map<string, number>;
  timestamps: string[];
  rawPaths: string[];
  sampleMatchingInfos: string[];
}

export interface ViolationIndexEntry {
  attackType: string;
  state: string;
  contexts: Map<string, ViolationContextData>;
}

export interface ThreatMeshIndexEntry {
  threatDetails: ThreatMeshDetails;
  user: string;
  eventCount: number;
  paths: Map<string, number>;
  userAgents: Map<string, number>;
  countries: Map<string, number>;
  timestamps: string[];
  asOrg: string;
}

export interface PolicyIndexEntry {
  policy: string;
  eventCount: number;
  blockedIPs: Map<string, {
    count: number;
    user: string;
    userAgent: string;
    trustScore: number;
    threatCategories: string;
    country: string;
    paths: Map<string, number>;
  }>;
}

export interface SecurityEventIndexes {
  signatureIndex: Map<string, SignatureIndexEntry>;
  violationIndex: Map<string, ViolationIndexEntry>;
  threatMeshIndex: Map<string, ThreatMeshIndexEntry>;
  policyIndex: Map<string, PolicyIndexEntry>;
  reqIdSet: Set<string>;
  stats: {
    totalEvents: number;
    wafEvents: number;
    threatMeshEvents: number;
    policyEvents: number;
    uniqueSignatures: number;
    uniqueViolations: number;
    uniqueThreatMeshIPs: number;
  };
}
