// WAF Attack Simulator — public surface
export * from './types';
export { ATTACK_CATEGORIES, ATTACK_PAYLOADS, payloadsForCategories, getCategory } from './attack-library';
export { runAttacks, detectSourceIp, markerRunId } from './runner';
export { reconcile, liveOnly, buildReport } from './log-reconciler';
export { exportSimReportCSV } from './export';
