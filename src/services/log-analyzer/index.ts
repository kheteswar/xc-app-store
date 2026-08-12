export * from './types';
export { FIELD_DEFINITIONS, PRE_FETCH_FILTER_FIELDS, NUMERIC_FIELDS, STRING_FIELDS, BOOLEAN_FIELDS, FIELD_GROUP_LABELS, getFieldsForSource, getNumericFieldsForSource, getStringFieldsForSource, getBooleanFieldsForSource } from './field-definitions';
export { collectLogs, collectSecurityEvents, mergeSecurityIntoAccessLogs, buildQuery, probeLogs, collectWithAggregations, collectWithAggregationsMulti } from './log-collector';
export {
  computeNumericStats, computeStringStats, computeBooleanStats,
  computeBreakdown, resolveField,
  buildTimeSeries, computeSummary, applyClientFilters,
  computeErrorAnalysis, computePerformanceAnalysis,
  computeSecurityInsights, computeTopTalkers, buildStatusTimeSeries,
  // Aggregation-based analytics (fast path)
  buildStringStatsFromBuckets, buildSummaryFromAggregations,
  buildErrorAnalysisFromAgg, buildSecurityInsightsFromAgg,
  buildTopTalkersFromAgg, buildTimeSeriesFromHourlyBuckets,
  buildStatusTimeSeriesFromAgg,
  // On-demand full-dataset analytics
  buildNumericStatsFromAgg, buildBreakdownFromNestedAggs,
} from './analytics-engine';
export type { AggBucket, MultiFieldBucket, NumericAggResult, CardinalityResult, NestedBreakdownEntry } from './aggregation-client';
export {
  fetchFieldAggregation, fetchBatchAggregation,
  // On-demand full-dataset fetchers
  fetchMultiFieldAggregation, fetchNumericAggregations, fetchCardinality, fetchNestedBreakdown,
} from './aggregation-client';
export { exportAsJSON, exportAsCSV, exportBreakdownAsCSV, exportBreakdownAsExcel, exportBreakdownAsPDF } from './export-utils';
export { fetchMetrics, fetchMetricSummary, chooseStep, stepToMs } from './metrics-client';
export type { MetricType, MetricRequest, MetricResponse, MetricSummary, MetricSeries, MetricPoint, NodeMetrics, GroupByField } from './metrics-client';
