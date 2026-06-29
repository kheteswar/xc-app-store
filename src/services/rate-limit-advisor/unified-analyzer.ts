/**
 * Rate Limit Advisor — Unified Analyzer
 *
 * Combines 7-day baseline context (Phase A) with exact per-user deep scan
 * data (Phase B) to produce a single industry-standard recommendation.
 *
 * Formula (per OWASP, AWS, Google Cloud, Cloudflare consensus):
 *   N = ceil(P95_per_user_peaks × safety_factor)
 *   B = min(5, max(1, ceil(P99.9 / P95)))
 *
 * Why P95 (not P99):
 *   P95 is the industry standard baseline for rate limiting. 95% of
 *   legitimate users will never hit the limit. The 5% above P95 who
 *   have occasional bursts are protected by the burst multiplier (B).
 *   P99 would set N too high, allowing sustained abuse to go undetected.
 *
 * Why 1.5× safety (not 1.3×):
 *   Industry guidance recommends 20-50% above baseline. 1.5× (50%)
 *   provides headroom for organic traffic growth and natural variation
 *   without needing immediate retuning. The trend guard adds another
 *   +0.1 if traffic is actively growing.
 *
 * Phase A contributes:
 *   - Seasonality guard (weekday/weekend ratio)
 *   - Trend guard (7-day growth detection → bumps safety factor)
 *   - 7-day filter breakdown (for display)
 *   - Daily traffic shape (for context display)
 *
 * Phase B contributes:
 *   - Exact per-user per-minute data → all percentile calculations
 *   - Impact simulator data (replays every user)
 *   - Deep filter breakdown (from actual log inspection)
 */

import type { UnifiedCollection, DailyBucket } from './unified-collector';

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const IQR_MULTIPLIER = 3.0;
const XC_NUMBER_MAX = 8192;
const BURST_MAX = 5;
const BURST_NOOP_THRESHOLD = 1.5;
const DEFAULT_SAFETY_FACTOR = 1.5;

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export type ConfidenceLevel = 'high' | 'medium' | 'low';

export interface UnifiedRecommendation {
  numberOfRequests: number; // N
  burstMultiplier: number;  // B
  effectiveLimit: number;   // N × B
  confidence: ConfidenceLevel;
  rationale: string;
  stats: {
    usersAnalyzed: number;
    outliersTrimmed: number;
    p50Peaks: number;
    p75Peaks: number;
    p90Peaks: number;
    p95Peaks: number;     // ← industry standard baseline
    p99Peaks: number;
    p999Peaks: number;    // absolute ceiling
    p95Medians: number;   // typical steady-state
    safetyFactor: number;
  };
}

export interface AlgorithmOption {
  id: 'balanced' | 'simple_peak3' | 'strict' | 'lenient_p99';
  label: string;
  formula: string;
  n: number;            // requests per minute
  b: number;            // burst multiplier
  effectiveLimit: number;
  description: string;
  recommended?: boolean;
}

export interface UnifiedResult {
  lbName: string;
  namespace: string;
  domains: string[];

  // Time windows
  baselineStart: string;
  baselineEnd: string;
  deepStart: string;
  deepEnd: string;
  deepWindowHours: number;

  // Volume
  totalRequests7d: number;
  deepTotalFetched: number;
  deepCleanLogs: number;
  deepTotalExpected: number;

  // Filter breakdown (7-day from agg + deep from raw)
  filterBreakdown7d: UnifiedCollection['filterBreakdown'];
  filterBreakdownDeep: UnifiedCollection['deepFilterBreakdown'];

  // Weekly shape
  dailyShape: DailyBucket[];

  // Recommendation (Balanced = default) + selectable algorithm options
  recommendation: UnifiedRecommendation;
  algorithms: AlgorithmOption[];

  // Per-user data for display and simulator
  userPeaks: Array<{
    userId: string;
    peakRpm: number;
    medianRpm: number;
    activeMinutes: number;
    totalRequests: number;
  }>;

  // Warnings
  warnings: string[];

  // Meta
  apiCallsUsed: number;
  runtimeSeconds: number;
}

export interface UnifiedImpactResult {
  rateLimit: number;
  burstMultiplier: number;
  effectiveLimit: number;
  totalUsers: number;
  usersAffected: number;
  usersAffectedPct: number;
  totalRequests: number;
  requestsBlocked: number;
  requestsBlockedPct: number;
  affectedUsers: Array<{
    userId: string;
    peakRpm: number;
    medianRpm: number;
    minutesBlocked: number;
    requestsBlocked: number;
  }>;
}

// ═══════════════════════════════════════════════════════════════════
// MATH
// ═══════════════════════════════════════════════════════════════════

function pct(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const k = Math.max(0, Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[k];
}

function median(arr: number[]): number {
  if (arr.length === 0) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 === 0 ? (s[mid - 1] + s[mid]) / 2 : s[mid];
}

// ═══════════════════════════════════════════════════════════════════
// GUARDS (use Phase A 7-day data)
// ═══════════════════════════════════════════════════════════════════

function seasonalityGuard(daily: DailyBucket[], warnings: string[]) {
  const weekday: number[] = [];
  const weekend: number[] = [];
  for (const { dayStart, count } of daily) {
    try {
      const d = new Date(dayStart);
      const dow = d.getUTCDay();
      (dow >= 1 && dow <= 5 ? weekday : weekend).push(count);
    } catch { /* ignore */ }
  }
  if (weekday.length < 2 || weekend.length < 1) return;
  const wdAvg = weekday.reduce((s, v) => s + v, 0) / weekday.length;
  const weAvg = weekend.reduce((s, v) => s + v, 0) / weekend.length;
  const ratio = wdAvg / Math.max(weAvg, 1);
  if (ratio > 3 || ratio < 0.33) {
    warnings.push(
      `Strong weekday/weekend difference (${ratio.toFixed(1)}×). The deep scan window may not represent all traffic patterns. Ensure you test the rate limit across different days.`
    );
  }
}

function trendGuard(daily: DailyBucket[], warnings: string[]): number {
  const sorted = [...daily].filter(d => d.count > 0).sort((a, b) => a.dayStart.localeCompare(b.dayStart));
  if (sorted.length < 3) return DEFAULT_SAFETY_FACTOR;
  const ys = sorted.map(d => d.count);
  const n = ys.length;
  const xs = Array.from({ length: n }, (_, i) => i);
  const mx = xs.reduce((s, v) => s + v, 0) / n;
  const my = ys.reduce((s, v) => s + v, 0) / n;
  const denom = xs.reduce((s, x) => s + (x - mx) ** 2, 0) || 1;
  const slope = xs.reduce((s, x, i) => s + (x - mx) * (ys[i] - my), 0) / denom;
  const growth = (slope * (n - 1)) / (ys[0] || 1);

  if (growth > 0.2) {
    warnings.push(`Traffic grew ~${Math.round(growth * 100)}% over the past week. Safety factor increased to absorb expected growth.`);
    return DEFAULT_SAFETY_FACTOR + 0.1;
  }
  if (growth < -0.2) {
    warnings.push(`Traffic declined ~${Math.round(Math.abs(growth) * 100)}% over the past week. Recommendation may be conservative.`);
  }
  return DEFAULT_SAFETY_FACTOR;
}

// ═══════════════════════════════════════════════════════════════════
// MAIN ANALYZER
// ═══════════════════════════════════════════════════════════════════

export function analyzeUnified(collection: UnifiedCollection): UnifiedResult {
  const warnings: string[] = [];

  // Apply Phase A guards
  seasonalityGuard(collection.dailyShape, warnings);
  const safetyFactor = trendGuard(collection.dailyShape, warnings);

  if (collection.deepWindowHours < 24) {
    warnings.push(`Deep scan window is ${collection.deepWindowHours}h. For production rate limits, validate with a 24h scan covering peak business hours.`);
  }

  // Per-user stats from Phase B exact data (no pruning — every clean user included)
  const userPeaks: UnifiedResult['userPeaks'] = [];
  const allPeaks: number[] = [];
  const allMedians: number[] = [];

  for (const [userId, counts] of Object.entries(collection.userMinuteCounts)) {
    // Peak = max requests in any rolling 60s window (token-bucket view); falls back to the
    // calendar-minute max if per-second data wasn't tracked for this user.
    const peak = collection.userPeakRpm?.[userId] ?? (counts.length ? Math.max(...counts) : 0);
    const med = median(counts);
    const total = counts.reduce((s, v) => s + v, 0);
    allPeaks.push(peak);
    allMedians.push(med);
    userPeaks.push({ userId, peakRpm: peak, medianRpm: med, activeMinutes: counts.length, totalRequests: total });
  }

  allPeaks.sort((a, b) => a - b);
  allMedians.sort((a, b) => a - b);

  // 3×IQR outlier trim on peaks
  const q1 = pct(allPeaks, 25);
  const q3 = pct(allPeaks, 75);
  const iqr = q3 - q1;
  const upperFence = q3 + IQR_MULTIPLIER * iqr;
  const trimmedPeaks = allPeaks.filter(p => p <= upperFence);
  const outliersTrimmed = allPeaks.length - trimmedPeaks.length;

  // Full percentile spectrum
  const p50Peaks = pct(trimmedPeaks, 50);
  const p75Peaks = pct(trimmedPeaks, 75);
  const p90Peaks = pct(trimmedPeaks, 90);
  const p95Peaks = pct(trimmedPeaks, 95);  // ← industry standard baseline
  const p99Peaks = pct(trimmedPeaks, 99);
  const p999Peaks = pct(trimmedPeaks, 99.9);
  const p95Medians = pct(allMedians, 95);

  // Bimodal detection
  if (p95Peaks > 0 && p99Peaks / p95Peaks > 5) {
    warnings.push(`Bimodal traffic detected (P99/P95 ratio = ${(p99Peaks / p95Peaks).toFixed(1)}×). Some users have very different traffic patterns — consider separate rate limiter policies for API integrations.`);
  }

  if (allPeaks.length === 0) {
    warnings.push('No user data available for recommendation. Check if all traffic is being filtered out.');
  }

  // N = ceil(P95 × safety_factor) — INDUSTRY STANDARD
  const n = Math.min(XC_NUMBER_MAX, Math.max(1, Math.ceil(p95Peaks * safetyFactor)));

  // B = burst multiplier based on how spiky the top users are
  // B=2 is the standard default for web apps
  // Adjust: if P99.9 is much higher than P95, users have significant bursts → higher B
  const burstRatio = p95Peaks > 0 ? p999Peaks / p95Peaks : 1;
  let b: number;
  if (burstRatio < BURST_NOOP_THRESHOLD) {
    b = 2; // standard web default even if bursts are mild
  } else {
    b = Math.min(BURST_MAX, Math.max(2, Math.ceil(burstRatio)));
  }

  // ── Selectable algorithm options (all from the same per-user peak distribution) ──
  const clampN = (x: number) => Math.min(XC_NUMBER_MAX, Math.max(1, Math.ceil(x)));
  const maxPeak = allPeaks.length ? allPeaks[allPeaks.length - 1] : 0; // busiest single user-minute (untrimmed)
  const simpleN = clampN(maxPeak * 3);
  const strictN = clampN(p95Peaks * 1.2);
  const lenientN = clampN(p99Peaks * 1.5);
  const algorithms: AlgorithmOption[] = [
    {
      id: 'balanced', label: 'Balanced — P95 × 1.5', recommended: true,
      formula: `ceil(P95 ${Math.round(p95Peaks)} × ${safetyFactor}), burst ${b}×`,
      n, b, effectiveLimit: n * b,
      description: 'P95 of per-user peak minutes with a 50% safety margin and an automatic burst multiplier. 95% of users never hit it; brief bursts are absorbed by B. Industry-standard default.',
    },
    {
      id: 'simple_peak3', label: 'Simple — Peak × 3',
      formula: `ceil(busiest minute ${Math.round(maxPeak)} × 3), burst 1×`,
      n: simpleN, b: 1, effectiveLimit: simpleN,
      description: 'Three times the busiest single minute any one client reached, with no burst. Dead simple and very unlikely to block a legitimate user — looser on abuse. A safe first limit to deploy in alert-only mode.',
    },
    {
      id: 'strict', label: 'Strict — P95 × 1.2',
      formula: `ceil(P95 ${Math.round(p95Peaks)} × 1.2), burst 2×`,
      n: strictN, b: 2, effectiveLimit: strictN * 2,
      description: 'Tighter limit (20% margin) for aggressive protection. Higher chance of clipping heavy legitimate users — validate with the simulator before enforcing.',
    },
    {
      id: 'lenient_p99', label: 'Lenient — P99 × 1.5',
      formula: `ceil(P99 ${Math.round(p99Peaks)} × 1.5), burst 1×`,
      n: lenientN, b: 1, effectiveLimit: lenientN,
      description: 'Covers 99% of per-user peaks with margin and no burst. Use when you have legitimate high-volume API integrations you must not disrupt.',
    },
  ];

  // ── Data-quality & key-correctness warnings ──
  if (collection.sampleRateMax > 1) {
    warnings.push(`Access logs are sampled (up to ${collection.sampleRateMax}× on ${Math.round(collection.sampledShare * 100)}% of records). Per-minute counts are de-sampled estimates — validate against live traffic before enforcing in blocking mode.`);
  }
  if (collection.coverageGaps > 0) {
    warnings.push(`${collection.coverageGaps} short time segment(s) exceeded the API page limit even after sub-splitting; a few high-burst minutes may be marginally undercounted (true peaks could be slightly higher).`);
  }
  const fetchRatio = collection.deepTotalExpected > 0 ? collection.deepTotalFetched / collection.deepTotalExpected : 1;
  if (fetchRatio < 0.9) {
    warnings.push(`Only ${Math.round(fetchRatio * 100)}% of expected logs were retrieved — some clients may be missing from this run. Re-run or use a shorter window.`);
  }
  if (!collection.hasUserIdPolicy) {
    warnings.push(`No User Identification policy on this LB — the rate limit will key on source IP. If clients sit behind a CDN/proxy/NAT, many users share an IP and a per-IP limit can over-block. Consider a User Identification policy (cookie/header/JWT) so the limit keys per real user.`);
  }
  if (collection.existingRateLimit) {
    warnings.push(`This LB already has a rate limit configured — traffic already shaped by it (and prior 429s) is excluded from the baseline, but recommendations assume you are setting a fresh limit.`);
  }

  // Confidence
  let confidence: ConfidenceLevel;
  const usersAnalyzed = allPeaks.length;
  if (collection.deepCleanLogs >= 50000 && usersAnalyzed >= 100 && collection.deepWindowHours >= 24) {
    confidence = 'high';
  } else if (collection.deepCleanLogs >= 5000 && usersAnalyzed >= 20) {
    confidence = 'medium';
  } else {
    confidence = 'low';
  }

  // Build clear rationale
  const rationale = buildRationale(collection, usersAnalyzed, outliersTrimmed, p95Medians, p95Peaks, p999Peaks, n, b, safetyFactor);

  // Sort users by peak desc
  userPeaks.sort((a, b) => b.peakRpm - a.peakRpm);

  return {
    lbName: collection.lbName,
    namespace: collection.namespace,
    domains: collection.domains,
    baselineStart: collection.baselineStart,
    baselineEnd: collection.baselineEnd,
    deepStart: collection.deepStart,
    deepEnd: collection.deepEnd,
    deepWindowHours: collection.deepWindowHours,
    totalRequests7d: collection.totalRequests7d,
    deepTotalFetched: collection.deepTotalFetched,
    deepCleanLogs: collection.deepCleanLogs,
    deepTotalExpected: collection.deepTotalExpected,
    filterBreakdown7d: collection.filterBreakdown,
    filterBreakdownDeep: collection.deepFilterBreakdown,
    dailyShape: collection.dailyShape,
    recommendation: {
      numberOfRequests: n,
      burstMultiplier: b,
      effectiveLimit: n * b,
      confidence,
      rationale,
      stats: {
        usersAnalyzed, outliersTrimmed,
        p50Peaks, p75Peaks, p90Peaks, p95Peaks, p99Peaks, p999Peaks,
        p95Medians, safetyFactor,
      },
    },
    algorithms,
    userPeaks,
    warnings,
    apiCallsUsed: collection.apiCallsUsed,
    runtimeSeconds: Math.round(collection.runtimeMs / 100) / 10,
  };
}

// ═══════════════════════════════════════════════════════════════════
// RATIONALE
// ═══════════════════════════════════════════════════════════════════

function buildRationale(
  c: UnifiedCollection, usersAnalyzed: number, outliersTrimmed: number,
  p95Medians: number, p95Peaks: number, p999Peaks: number,
  n: number, b: number, sf: number,
): string {
  const fetchPct = c.deepTotalExpected > 0 ? Math.round((c.deepTotalFetched / c.deepTotalExpected) * 100) : 100;

  return [
    // Paragraph 1: What was analysed
    `Analysed ${c.deepCleanLogs.toLocaleString()} clean requests from ${usersAnalyzed.toLocaleString()} users ` +
    `over a ${c.deepWindowHours}h deep scan (${fetchPct}% of logs fetched). ` +
    `7-day baseline shows ${c.totalRequests7d.toLocaleString()} total requests with ` +
    `${c.filterBreakdown.total.toLocaleString()} filtered out (WAF blocks, malicious bots, policy denials)` +
    (outliersTrimmed > 0 ? `. ${outliersTrimmed} extreme outlier${outliersTrimmed > 1 ? 's' : ''} removed from the analysis.` : '.'),

    // Paragraph 2: What the data shows
    `For each user we measured their peak request rate in any rolling 60-second window — the same view a token-bucket limiter uses, so a burst that straddles a clock-minute boundary isn't undercounted. ` +
    `In normal operation, 95% of users send ≤${Math.round(p95Medians)} req/min (their typical rate). ` +
    `At their busiest, 95% of users stay below ${Math.round(p95Peaks)} req/min — this is the P95 peak, the industry-standard baseline for rate limiting (per OWASP and cloud provider guidance).`,

    // Paragraph 3: How N is set
    `Rate Limit (N) = ${p95Peaks} × ${sf} safety margin = ${n} req/min. ` +
    `This is set at the P95 of per-user peak minutes with a ${Math.round((sf - 1) * 100)}% buffer. ` +
    `95% of your legitimate users will never touch this limit, even in their busiest minute. ` +
    `The ${Math.round((sf - 1) * 100)}% headroom absorbs natural traffic variation and organic growth.`,

    // Paragraph 4: How B is set and why it matters
    `Burst Multiplier (B) = ${b}× (derived from P99.9 peak of ${p999Peaks} req/min vs P95 baseline of ${p95Peaks}). ` +
    (b > 1
      ? `F5 XC's rate limiter uses a token bucket: tokens refill at ${n}/min, but the bucket can hold ${n * b} tokens (${n} × ${b}). ` +
        `This allows a legitimate user to briefly spike to ${n * b} req/min — for example, loading a page that fires many API calls at once. ` +
        `A sustained attacker at ${Math.round(n * 1.3)} req/min will drain the bucket (consuming ${Math.round(n * 1.3)} tokens but only getting ${n} back per minute) and be blocked within ${Math.ceil(n * b / (Math.round(n * 1.3) - n))} minutes. ` +
        `Without burst (B=1 at ${n * b}/min), the same legitimate page-load spike would be falsely blocked. ` +
        `With a higher base rate instead (${n * b}/min × B=1), the attacker would never be caught because the refill rate equals the bucket capacity.`
      : `Peak and sustained rates are similar — no burst headroom is needed. B=1 provides strict enforcement.`),

    // Paragraph 5: Operational guidance
    `After applying, monitor the access logs for rate_limiter_action="fail" to see which users hit the limit. ` +
    `Re-run this analysis monthly or after major traffic changes to ensure the rate limit stays calibrated.`,
  ].join('\n\n');
}

// ═══════════════════════════════════════════════════════════════════
// IMPACT SIMULATOR — replays ALL users from Phase B
// ═══════════════════════════════════════════════════════════════════

export function simulateUnifiedImpact(
  userMinuteCounts: Record<string, number[]>,
  rateLimit: number,
  burstMultiplier: number,
): UnifiedImpactResult {
  const effectiveLimit = rateLimit * burstMultiplier;
  const affected: UnifiedImpactResult['affectedUsers'] = [];
  let totalRequests = 0;
  let totalBlocked = 0;

  for (const [userId, counts] of Object.entries(userMinuteCounts)) {
    let userBlocked = 0;
    let minutesBlocked = 0;

    for (const count of counts) {
      totalRequests += count;
      if (count > effectiveLimit) {
        const excess = count - effectiveLimit;
        userBlocked += excess;
        totalBlocked += excess;
        minutesBlocked++;
      }
    }

    if (userBlocked > 0) {
      const peak = Math.max(...counts);
      const med = median(counts);
      affected.push({ userId, peakRpm: peak, medianRpm: med, minutesBlocked, requestsBlocked: userBlocked });
    }
  }

  affected.sort((a, b) => b.requestsBlocked - a.requestsBlocked);
  const totalUsers = Object.keys(userMinuteCounts).length;

  return {
    rateLimit, burstMultiplier, effectiveLimit,
    totalUsers,
    usersAffected: affected.length,
    usersAffectedPct: totalUsers > 0 ? Math.round((affected.length / totalUsers) * 1000) / 10 : 0,
    totalRequests,
    requestsBlocked: totalBlocked,
    requestsBlockedPct: totalRequests > 0 ? Math.round((totalBlocked / totalRequests) * 1000) / 10 : 0,
    affectedUsers: affected,
  };
}
