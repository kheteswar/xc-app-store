/**
 * Reliability tests for the Rate Limit Advisor peak measurement.
 * Run: npx tsx scripts/test-rate-limit.mts
 *
 * Focus: the rolling-60s peak (slidingMax60) — the input to the rate-limit recommendation —
 * must reflect what a token-bucket limiter sees, NOT a fixed clock-minute count.
 */
import { slidingMax60 } from '../src/services/rate-limit-advisor/unified-collector.ts';

let pass = 0, fail = 0;
function ok(name: string, cond: boolean, detail = '') {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name} ${detail}`); }
}

// Helper: build a per-second map from a list of [second, count] pairs.
const secMap = (pairs: Array<[number, number]>) => new Map<number, number>(pairs);
// Calendar-minute peak (the OLD method) for comparison.
function calendarPeak(pairs: Array<[number, number]>): number {
  const m = new Map<number, number>();
  for (const [s, c] of pairs) { const min = Math.floor(s / 60); m.set(min, (m.get(min) ?? 0) + c); }
  return Math.max(0, ...m.values());
}

console.log('\n1) Boundary-straddling burst (the core fix)');
// 60 requests, one per second, from sec 30..89 — a real 60s burst centred on the minute boundary.
const straddle: Array<[number, number]> = Array.from({ length: 60 }, (_, i) => [30 + i, 1]);
ok('calendar minute UNDERCOUNTS the straddling burst (~half)', calendarPeak(straddle) === 30, `got ${calendarPeak(straddle)}`);
ok('rolling-60s captures the full burst (60)', slidingMax60(secMap(straddle)) === 60, `got ${slidingMax60(secMap(straddle))}`);

console.log('\n2) Sustained traffic — rolling == calendar (no inflation)');
// Steady 1 req/sec for 5 minutes.
const steady: Array<[number, number]> = Array.from({ length: 300 }, (_, i) => [i, 1]);
ok('rolling-60s of steady 1/s = 60', slidingMax60(secMap(steady)) === 60, `got ${slidingMax60(secMap(steady))}`);
ok('rolling ≥ calendar for steady traffic', slidingMax60(secMap(steady)) >= calendarPeak(steady));

console.log('\n3) Two requests exactly 60s apart do NOT share a window');
ok('sec 0 and sec 60 → peak 1 (not 2)', slidingMax60(secMap([[0, 1], [60, 1]])) === 1);
ok('sec 0 and sec 59 → peak 2 (same 60s window)', slidingMax60(secMap([[0, 1], [59, 1]])) === 2);

console.log('\n4) De-sampled counts (weights) are summed, not record counts');
// One sampled record at sec 10 representing 10 real requests, another (×10) at sec 20.
ok('weighted seconds sum within window', slidingMax60(secMap([[10, 10], [20, 10]])) === 20);
ok('single dense second = its weight', slidingMax60(secMap([[100, 50]])) === 50);

console.log('\n5) Edge cases');
ok('empty map → 0', slidingMax60(secMap([])) === 0);
ok('rolling-60s never below calendar peak (random-ish set)',
  slidingMax60(secMap([[5, 3], [40, 4], [65, 5], [70, 6], [130, 2]])) >= calendarPeak([[5, 3], [40, 4], [65, 5], [70, 6], [130, 2]]));

console.log(`\n${'═'.repeat(40)}\nRESULT: ${pass} passed, ${fail} failed\n`);
process.exit(fail > 0 ? 1 : 0);
