import type { RateStats, AlgorithmResult, ImpactSimulation, TimeGranularity, UserMetadata } from './types';

const MAX_RATE_LIMIT = 8192;

/**
 * Algorithm A: Percentile-based recommendation.
 * Takes the PXX of per-user peak rates and multiplies by a safety margin.
 */
export function percentileRecommendation(
  stats: RateStats,
  granularity: TimeGranularity,
  percentile: number = 95,
  safetyMargin: number = 1.5
): AlgorithmResult {
  const pValue = percentile === 90 ? stats.p90 : percentile === 99 ? stats.p99 : stats.p95;
  const result = Math.min(Math.ceil(pValue * safetyMargin), MAX_RATE_LIMIT);

  return {
    type: 'percentile',
    label: `Percentile P${percentile} × ${safetyMargin}`,
    description: `${percentile}% of your users stay below ${pValue} req/${granularity}. With ${safetyMargin}x safety margin: ${result}.`,
    rateLimit: result,
    granularity,
    burstMultiplier: 2,
    formula: `P${percentile}=${pValue}, margin=${safetyMargin}x, result=${result}`,
    parameters: { percentile, safetyMargin },
  };
}

/**
 * Algorithm B: Mean + N standard deviations.
 */
export function meanStdDevRecommendation(
  stats: RateStats,
  granularity: TimeGranularity,
  nSigma: number = 3
): AlgorithmResult {
  const result = Math.min(Math.ceil(stats.mean + nSigma * stats.stdDev), MAX_RATE_LIMIT);

  return {
    type: 'mean_stddev',
    label: `Mean + ${nSigma}σ`,
    description: `Average=${stats.mean.toFixed(1)}, spread=${stats.stdDev.toFixed(1)}. ${nSigma} standard deviations above mean: ${result}.`,
    rateLimit: result,
    granularity,
    burstMultiplier: 3,
    formula: `μ=${stats.mean.toFixed(1)}, σ=${stats.stdDev.toFixed(1)}, ${nSigma}σ → ${result}`,
    parameters: { nSigma },
  };
}

/**
 * Algorithm C: Peak observed rate + buffer percentage.
 */
export function peakBufferRecommendation(
  stats: RateStats,
  granularity: TimeGranularity,
  bufferPercent: number = 0.5
): AlgorithmResult {
  const result = Math.min(Math.ceil(stats.max * (1 + bufferPercent)), MAX_RATE_LIMIT);

  return {
    type: 'peak_buffer',
    label: `Peak + ${(bufferPercent * 100).toFixed(0)}%`,
    description: `Your busiest user peaked at ${stats.max} req/${granularity}. With ${(bufferPercent * 100).toFixed(0)}% headroom: ${result}.`,
    rateLimit: result,
    granularity,
    burstMultiplier: 1,
    formula: `peak=${stats.max}, buffer=${(bufferPercent * 100).toFixed(0)}%, result=${result}`,
    parameters: { bufferPercent },
  };
}

/**
 * Algorithm D: P99-Burst — jointly computes base rate AND burst multiplier.
 * Sets base at P99 so 99% of users never touch the rate limiter.
 * Burst absorbs the top 1% peaks without blocking.
 * Best for right-skewed distributions (mean >> median).
 */
export function p99BurstRecommendation(
  stats: RateStats,
  granularity: TimeGranularity,
  safetyMargin: number = 1.1
): AlgorithmResult {
  const baseRate = Math.min(Math.ceil(stats.p99 * safetyMargin), MAX_RATE_LIMIT);
  const burstMultiplier = baseRate > 0 ? Math.max(Math.ceil(stats.max / baseRate) + 1, 2) : 2;
  const effectiveLimit = baseRate * burstMultiplier;

  return {
    type: 'p99_burst',
    label: `P99-Burst (${baseRate} × ${burstMultiplier})`,
    description: `99% of users stay below ${stats.p99}/${granularity}. Base set at ${baseRate} (+${Math.round((safetyMargin - 1) * 100)}% margin). Burst ${burstMultiplier}x absorbs peaks up to ${effectiveLimit}. Max observed: ${stats.max}.`,
    rateLimit: baseRate,
    granularity,
    burstMultiplier,
    formula: `P99=${stats.p99} × ${safetyMargin} = ${baseRate}, burst = ceil(${stats.max}/${baseRate})+1 = ${burstMultiplier}, effective = ${effectiveLimit}`,
    parameters: { percentile: 99, safetyMargin },
  };
}

/**
 * Impact simulator: replays traffic against a proposed rate limit.
 * Uses pre-grouped data + compact user metadata — no full log array needed.
 */
export function simulateImpact(
  preGrouped: Map<string, Map<string, number>>,
  userMeta: Map<string, UserMetadata>,
  rateLimit: number,
  granularity: TimeGranularity,
  burstMultiplier: number
): ImpactSimulation {
  const effectiveLimit = rateLimit * burstMultiplier;
  let usersAffected = 0;
  let totalRequestsBlocked = 0;
  let totalRequestsAnalyzed = 0;

  const affectedUsers: ImpactSimulation['affectedUsers'] = [];
  const blockTimelineBuckets = new Map<string, number>();
  const pathBlockCounts = new Map<string, number>();

  for (const [userId, windows] of preGrouped.entries()) {
    let timesBlocked = 0;
    let peakRate = 0;
    let totalRate = 0;
    let windowCount = 0;
    let blockedRequests = 0;

    for (const [windowKey, count] of windows.entries()) {
      const rate = Math.ceil(count);
      totalRequestsAnalyzed += rate;
      totalRate += rate;
      windowCount++;
      if (rate > peakRate) peakRate = rate;

      if (rate > effectiveLimit) {
        timesBlocked++;
        const excess = rate - effectiveLimit;
        blockedRequests += excess;
        totalRequestsBlocked += excess;
        blockTimelineBuckets.set(windowKey, (blockTimelineBuckets.get(windowKey) || 0) + excess);
      }
    }

    if (timesBlocked > 0) {
      usersAffected++;

      // Get top paths from compact metadata
      const meta = userMeta.get(userId);
      const topBlockedPaths: string[] = [];
      if (meta) {
        const sorted = [...meta.pathCounts.entries()].sort((a, b) => b[1] - a[1]);
        for (const [path, count] of sorted.slice(0, 3)) {
          topBlockedPaths.push(path);
          pathBlockCounts.set(path, (pathBlockCounts.get(path) || 0) + count);
        }
      }

      affectedUsers.push({
        identifier: userId,
        timesBlocked,
        peakRate,
        avgRate: windowCount > 0 ? Math.round(totalRate / windowCount) : 0,
        reputation: meta?.reputation || 'clean',
        topBlockedPaths,
      });
    }
  }

  affectedUsers.sort((a, b) => b.timesBlocked - a.timesBlocked);

  // Build timeline (keep top 50 entries)
  const blockTimeline = [...blockTimelineBuckets.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(0, 50)
    .map(([timestamp, blockedCount]) => ({ timestamp, blockedCount }));

  // Build path impact
  const totalBlocks = totalRequestsBlocked || 1;
  const pathImpact = [...pathBlockCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([path, blockedRequests]) => ({
      path,
      blockedRequests,
      percentOfBlocks: Math.round((blockedRequests / totalBlocks) * 100),
    }));

  const totalUsers = preGrouped.size;

  return {
    rateLimit,
    granularity,
    burstMultiplier,
    usersAffected,
    usersAffectedPercent: totalUsers > 0 ? Math.round((usersAffected / totalUsers) * 1000) / 10 : 0,
    totalUsersAnalyzed: totalUsers,
    requestsBlocked: totalRequestsBlocked,
    requestsBlockedPercent: totalRequestsAnalyzed > 0
      ? Math.round((totalRequestsBlocked / totalRequestsAnalyzed) * 1000) / 10
      : 0,
    totalRequestsAnalyzed,
    affectedUsers: affectedUsers.slice(0, 20),
    blockTimeline,
    pathImpact,
  };
}
