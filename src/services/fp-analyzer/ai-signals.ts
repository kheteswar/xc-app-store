/**
 * AI-WAF Signal Helpers
 *
 * F5 Distributed Cloud's AI-powered WAF attaches per-request intelligence to
 * every security event. This module parses those fields into structured signals
 * the FP scorer can consume. Single source of truth — used by both the live
 * server engine (server/progressive-job.ts) and the client-side indexer.
 *
 * Fields (see Log Analyzer field-definitions.ts + F5 Security Events Reference):
 *   - req_risk           string  AI risk verdict. High/Medium/Low (Likelihood × Impact)
 *                                or a numeric 0-100 score in some tenants.
 *   - req_risk_reasons   string[] Human-readable reasons feeding the risk verdict.
 *   - recommended_action string  AI recommendation: allow | report | block.
 *   - calculated_action  string  WAF computed action: allow | report | block.
 *   - enforcement_mode   string  BLOCKING | MONITORING (is the LB actually enforcing?)
 *   - signatures[].state string  Enabled | AutoSuppressed | Staging | ...
 *
 * Scoring convention (matches the rest of the FP engine):
 *   higher = more likely FALSE POSITIVE, lower = more likely TRUE POSITIVE.
 */

export type AiRiskLevel = 'high' | 'medium' | 'low' | 'unknown';

export interface AiRiskCounts {
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export function emptyAiRiskCounts(): AiRiskCounts {
  return { high: 0, medium: 0, low: 0, unknown: 0 };
}

/**
 * Normalize a single `req_risk` value into a level.
 * Accepts categorical ("High"/"Medium"/"Low") or numeric (0-100) forms.
 */
export function parseReqRisk(raw: unknown): AiRiskLevel {
  if (raw == null) return 'unknown';
  const s = String(raw).trim().toLowerCase();
  if (!s) return 'unknown';

  // Verdict-form req_risk (what F5 XC AI WAF actually emits, e.g. "false positive",
  // "legitimate", "malicious", "suspicious", "needs examination"). Map the verdict onto
  // the level that drives scoring: low = FP-ward, high = TP-ward. Checked first because
  // "false positive" contains none of the high/medium/low level tokens.
  if (/false[\s_-]*positive|legitimate|benign|no[\s_-]*risk|not[\s_-]*malicious/.test(s)) return 'low';
  if (/malicious|exploit|confirmed[\s_-]*attack/.test(s)) return 'high';
  if (/suspicious|need.*examin|need.*review/.test(s)) return 'medium';

  // Level-form (High / Medium / Low)
  if (s.includes('high') || s === 'h' || s === 'critical') return 'high';
  if (s.includes('medium') || s === 'm' || s === 'moderate') return 'medium';
  if (s.includes('low') || s === 'l' || s === 'minimal' || s === 'none') return 'low';

  // Numeric fallback (rare — the CVSS-like severity is risk_score_info.score, not req_risk).
  const n = Number(s);
  if (!isNaN(n)) {
    if (n >= 67) return 'high';
    if (n >= 34) return 'medium';
    return 'low';
  }
  return 'unknown';
}

export function tallyReqRisk(counts: AiRiskCounts, raw: unknown): void {
  counts[parseReqRisk(raw)]++;
}

/** The level with the most events (ignoring 'unknown'); 'unknown' if no signal. */
export function dominantRiskLevel(counts: AiRiskCounts): AiRiskLevel {
  const known = counts.high + counts.medium + counts.low;
  if (known === 0) return 'unknown';
  if (counts.high >= counts.medium && counts.high >= counts.low) return 'high';
  if (counts.low >= counts.medium && counts.low >= counts.high) return 'low';
  return 'medium';
}

// ───────────────────────────────────────────────────────────────
// req_risk_reasons parsing — replaces the fragile substring("100") hack
// ───────────────────────────────────────────────────────────────

export interface RiskReasonVerdict {
  /** F5's AI explicitly confirmed this is a real attack — strong TP. */
  aiConfirmedAttack: boolean;
  /** F5's AI/ML suggests benign / suppressed / false-positive — FP-ward. */
  aiSuggestsFp: boolean;
  /** Attack indicators present (SQLi signals, curated signature combos, etc.). */
  attackIndicators: boolean;
}

// "AI confirmed", "confirmed attack", "high confidence attack", "100% confidence/attack".
// Note: a BARE "100%" must NOT match (it appears in benign reasons like "100% cache hit") —
// the percentage only counts when explicitly tied to confidence/confirmation/attack.
const CONFIRM_RE = /\bai[\s_-]*confirmed\b|\bconfirmed\s+attack\b|\battack\s+confirmed\b|\bverified\s+attack\b|\bhigh[\s_-]*confidence\s+attack\b|\b100\s*%\s*(?:confidence|confirmed|attack)\b/i;
// ML/AI leaning benign / false positive / suppression
const FP_RE = /\b(false[\s_-]*positive|likely\s+benign|appears\s+benign|suppress(ed|ion)?|legitimate\s+(traffic|request)|low\s+risk\s+benign)\b/i;
// Attack indicators / curated combinations / signal families
const INDICATOR_RE = /\b(attack\s+indicator|sqli|xss\s+signal|curated|signature\s+combination|threat\s+campaign|exploit)\b/i;

export function parseRiskReasons(reasons: string[] | string | undefined | null): RiskReasonVerdict {
  const arr: string[] = Array.isArray(reasons)
    ? reasons.map(String)
    : reasons
    ? [String(reasons)]
    : [];
  const verdict: RiskReasonVerdict = { aiConfirmedAttack: false, aiSuggestsFp: false, attackIndicators: false };
  for (const r of arr) {
    if (CONFIRM_RE.test(r)) verdict.aiConfirmedAttack = true;
    if (FP_RE.test(r)) verdict.aiSuggestsFp = true;
    if (INDICATOR_RE.test(r)) verdict.attackIndicators = true;
  }
  return verdict;
}

// ───────────────────────────────────────────────────────────────
// Signature state
// ───────────────────────────────────────────────────────────────

/** Staged signatures are monitor-only — they never block, regardless of LB mode. */
export function isStagedState(state: string | undefined): boolean {
  return /stag/i.test(state || '');
}

export function isAutoSuppressedState(state: string | undefined): boolean {
  return /autosuppress|auto[\s_-]*suppress/i.test(state || '');
}

// ───────────────────────────────────────────────────────────────
// Enforcement awareness
// ───────────────────────────────────────────────────────────────

export type EnforcementMode = 'blocking' | 'monitoring' | 'unknown';

export function parseEnforcementMode(raw: unknown): EnforcementMode {
  const s = String(raw ?? '').toLowerCase();
  if (s.includes('block')) return 'blocking';
  if (s.includes('monitor')) return 'monitoring';
  return 'unknown';
}

// ───────────────────────────────────────────────────────────────
// Composite AI-risk → FP-signal contribution (delta, FP-positive)
// ───────────────────────────────────────────────────────────────

export interface AiSignalInput {
  riskCounts?: AiRiskCounts;
  reasonVerdict?: RiskReasonVerdict;
  recommendedAction?: string;
  calculatedAction?: string;
}

export interface AiSignalContribution {
  /** Score delta to apply (positive = FP-ward, negative = TP-ward). */
  delta: number;
  reasons: string[];
}

/**
 * Translate AI-WAF intelligence into a bounded score delta. F5's own AI verdict
 * is the strongest single signal we have for FP vs TP, so it is weighted heavily
 * but always bounded so it can't fully override the behavioural signals.
 */
export function scoreAiRisk(input: AiSignalInput): AiSignalContribution {
  let delta = 0;
  const reasons: string[] = [];

  // 1) req_risk distribution — F5 AI's per-request Likelihood × Impact verdict
  const c = input.riskCounts;
  if (c) {
    const known = c.high + c.medium + c.low;
    if (known > 0) {
      const lowPct = c.low / known;
      const highPct = c.high / known;
      if (highPct >= 0.5) {
        delta -= 35;
        reasons.push(`F5 AI rated ${(highPct * 100).toFixed(0)}% of requests HIGH risk — likely real attack`);
      } else if (highPct >= 0.2) {
        delta -= 15;
        reasons.push(`F5 AI rated ${(highPct * 100).toFixed(0)}% of requests HIGH risk`);
      } else if (lowPct >= 0.8) {
        delta += 30;
        reasons.push(`F5 AI rated ${(lowPct * 100).toFixed(0)}% of requests LOW risk — likely benign/FP`);
      } else if (lowPct >= 0.5) {
        delta += 15;
        reasons.push(`F5 AI rated ${(lowPct * 100).toFixed(0)}% of requests LOW risk`);
      }
    }
  }

  // 2) req_risk_reasons — explicit AI verdict text
  const v = input.reasonVerdict;
  if (v) {
    if (v.aiConfirmedAttack) {
      delta -= 40;
      reasons.push('F5 AI confirmed attack — very unlikely FP');
    }
    if (v.aiSuggestsFp) {
      delta += 20;
      reasons.push('F5 AI/ML reasons indicate benign/suppressed traffic');
    }
    if (v.attackIndicators && !v.aiConfirmedAttack) {
      delta -= 10;
      reasons.push('Attack indicators present (SQLi/curated combos/campaign)');
    }
  }

  // 3) AI recommendation (recommended_action / calculated_action)
  const rec = (input.recommendedAction || '').toLowerCase();
  if (rec === 'block') { delta -= 10; reasons.push('AI recommended_action=block'); }
  else if (rec === 'allow') { delta += 12; reasons.push('AI recommended_action=allow — AI would not block'); }
  else if (rec === 'report') { delta += 6; reasons.push('AI recommended_action=report — not confident enough to block'); }

  // Bound the total AI influence so behavioural breadth signals still matter.
  delta = Math.max(-55, Math.min(45, delta));
  return { delta, reasons };
}

// ───────────────────────────────────────────────────────────────
// Ratio clamp — sampled access-log denominators can yield ratio > 1
// ───────────────────────────────────────────────────────────────

/** Clamp a flagged/total ratio into [0,1]. Sampling can make flagged > total. */
export function clampRatio(flagged: number, total: number): number {
  if (total <= 0) return 0;
  return Math.min(1, flagged / total);
}

/**
 * Estimate the true (unsampled) volume from a sampled count.
 * F5 XC access logs are sampled (sample_rate ≥ 1; e.g. 10 = 1-in-10 logged),
 * so raw access-log counts undercount real request volume. Apply ONLY to
 * volume counts, never to unique cardinalities (users/IPs).
 */
export function estimateActualCountFromRate(sampledCount: number, avgSampleRate: number): number {
  if (sampledCount <= 0) return 0;
  return Math.round(sampledCount * Math.max(1, avgSampleRate));
}
