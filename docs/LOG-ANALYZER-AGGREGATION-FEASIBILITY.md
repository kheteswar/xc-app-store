# F5 XC Aggregation API — Log Analyzer Enhancement Feasibility

_Written: 2026-07-07. Source: F5 XC OpenAPI 2026-Q3 (`f5-product-docs/sources/f5-distributed-cloud-open-api/`), files `0021.public.ves.io.schema.app_security` and `0157.public.ves.io.schema.log`._

## Executive summary

| Enhancement phase | Feasibility | Verdict |
|-------------------|-------------|---------|
| **P1 — On-demand string/boolean field aggregation** (for fields not in the pre-fetched 22) | ✅ **Fully feasible** | Ship first. Uses existing `fetchFieldAggregation()` on-demand. |
| **P2 — Numeric stats via aggregation** (min / max / avg) | ⚠️ **Partially feasible** | Only `DURATION_WITH_DATA_TX_DELAY` and `TIMESTAMP` are aggregatable numeric fields. `min/max/avg` on full dataset — yes. **Percentiles on access logs — NOT supported.** For percentiles: bump sample (5-10K) or use `field_aggregation topk=1000` for value distribution and compute exact percentiles from bucket counts. |
| **P3 — Breakdown via aggregation** (cross-tab) | ✅ **Fully feasible via `multi_field_aggregation`** | Bucket keyed by combination of fields with count. Full dataset. |
| **BONUS — Native date_aggregation for time series** | ✅ **Supported** | Better than the current per-hour probe fan-out. Also supports `sub_aggs` (e.g. "top status codes per hour"). |
| **BONUS — Cardinality (approx distinct count)** | ✅ **Supported** | Fixes `buildSummaryFromAggregations`'s current hack of using `buckets.length` as unique count. |

## The aggregation endpoint (confirmed)

**`POST /api/data/namespaces/{namespace}/access_logs/aggregation`**
Request body:
```json
{
  "namespace": "<ns>",
  "query": "<VoltVQL string>",
  "start_time": "<ISO8601>",
  "end_time":   "<ISO8601>",
  "aggs": {
    "<user_defined_agg_name>": {
      "<one_of_agg_types>": { /* type-specific config */ }
    }
    /* multiple aggs allowed in one request */
  }
}
```

Response:
```json
{
  "total_hits": "<uint64 as string>",
  "aggs": {
    "<user_defined_agg_name>": { /* type-specific response data */ }
  }
}
```

## Supported aggregation types (access logs)

Per `logaccess_logAggregationRequest`:

| Aggregation type | Purpose | Response shape |
|------------------|---------|----------------|
| `field_aggregation` | Top-K buckets for one field, optional `sub_aggs` for nesting | `{buckets: [{key, count, sub_aggs?, trend_value?, order_by?}]}` |
| `date_aggregation` | Time-bucketed counts with `step` (e.g. `"5m"`, `"1h"`, `"1d"`) + optional `sub_aggs` | `{buckets: [{key, count, sub_aggs?}], step}` |
| `cardinality_aggregation` | Approximate distinct-value count | `{count, trend_value?}` |
| `min_aggregation` | Minimum numeric value | `{value}` |
| `max_aggregation` | Maximum numeric value | `{value}` |
| `avg_aggregation` | Average numeric value | `{value}` |
| `multi_field_aggregation` | Top-K buckets keyed by COMBINATION of multiple fields | `{buckets: [{keys: {F1: v1, F2: v2}, count}]}` |

**NOT supported for access logs:** `percentile_aggregation`, `metrics_aggregation` (both exist in the schema but are only slotted into `security_events` / `incidents` / `suspicious_user_logs` request schemas).

## Supported aggregation types (security events)

Per `schemaapp_securityAggregationRequest`:

| Aggregation type | Access logs | Security events | Incidents | Suspicious user logs |
|------------------|:-----------:|:---------------:|:---------:|:--------------------:|
| `field_aggregation` | ✅ | ✅ | ✅ | ✅ |
| `date_aggregation` | ✅ | ✅ | ✅ | ✅ |
| `cardinality_aggregation` | ✅ | ✅ | ✅ | ✅ |
| `multi_field_aggregation` | ✅ | ✅ | ✅ | ❌ |
| `min` / `max` / `avg` | ✅ | ❌ | ❌ | ✅ |
| **`metrics_aggregation` (percentile)** | ❌ | ✅ | ✅ | ✅ |

## Field restrictions (access logs)

The typed schema `logaccess_logKeyField` restricts string/keyword aggregations to an **enum**:

```
API_ENDPOINT, APP_TYPE, AUTHORITY, ASN, BROWSER_TYPE, CITY, COUNTRY, DEVICE_TYPE,
DST, DST_INSTANCE, DST_SITE, METHOD, SCHEME, REMOTE_LOCATION, REQ_PATH,
RSP_CODE, RSP_CODE_CLASS, RSP_CODE_DETAILS,
SRC, SRC_INSTANCE, SRC_IP, SRC_SITE,
TLS_CIPHER_SUITE, TLS_FINGERPRINT, TLS_VERSION,
USER, VH_NAME, VH_TYPE, VISITOR_ID, JA4_T… (truncated)
```

**Numeric key field enum** (`access_logNumKeyField`) is only **2 fields**:
```
DURATION_WITH_DATA_TX_DELAY  (default)
TIMESTAMP
```

## Cross-check with the current code

Existing `xc-app-store` code already calls `fetchBatchAggregation` with lowercase fields like `waf_action`, `bot_class`, `user_agent`, `dst_ip`, `as_org`, `protocol`, `tls_version`, etc. Some of these **are not in the documented enum** (e.g. `waf_action`, `bot_class`).

**Interpretation:** either (a) the enum is outdated in the OpenAPI export (F5 XC has expanded field support since) or (b) the API silently returns empty buckets for non-enum fields. The code has been in production and appears to work, so (a) is more likely — but the enhancement should still probe unknown fields once at runtime and cache the outcome to avoid repeat failures.

## Additional response-shape gotchas

- `count` is `uint64` returned as a **string** — always `Number(bucket.count ?? bucket.doc_count ?? 0)`.
- `key` may appear under either `key` (single-field) or `keys` (multi-field). Existing parser already handles both.
- `total_hits` on the top-level response is also a **string**.
- `field_aggregation` bucket has `trend_value` and `order_by` fields we don't currently use — could show change-over-time indicators.
- `date_aggregation` returns actual `step` in response (may be coarser than requested if data is heavily downsampled).

## Revised enhancement plan

### Phase 1 — On-demand field aggregation (P1, ~1 hour)

**Goal:** any string/boolean field selected by user gets its own aggregation call, giving full-dataset stats instead of 500-sample fallback.

**Change:**
- In `LogAnalyzer.tsx` field-analysis useEffect: if `aggData.accessAggs[selectedField]` is empty AND field type is string/boolean, `await fetchFieldAggregation()`, cache into `aggData.accessAggs`, then render.
- Show small spinner during the ~200-500ms fetch.
- For fields not in the enum: on empty response, fall back to sample-based stats with a small "sampled — field not aggregatable" badge.

**Files:**
- `src/pages/LogAnalyzer.tsx` (useEffect refactor + spinner state)
- `src/services/log-analyzer/log-collector.ts` (optional helper `ensureFieldAggregation`)

### Phase 2 — Numeric field stats via aggregation (P1, ~2 hours)

**Goal:** numeric fields get accurate min / max / mean on full dataset. Percentiles use the best available approach.

**Change:**
- For `DURATION_WITH_DATA_TX_DELAY` (map from `total_duration_seconds` or similar client-side key):
  - Fire 3 aggregations in one request: `min_aggregation`, `max_aggregation`, `avg_aggregation` on `DURATION_WITH_DATA_TX_DELAY`.
  - For percentiles: fire a `field_aggregation` with `topk=1000` on `DURATION_WITH_DATA_TX_DELAY` treated as a keyword — buckets give exact value distribution → compute exact percentiles from bucket counts + running totals.
- For fields NOT in `access_logNumKeyField` enum (bytes, per-segment timings, response codes as numeric): keep sample-based path but **bump sample to 5-10K** for numeric analysis. Add badge showing "5,000 sample" clearly.
- Add `buildNumericStatsFromAgg(aggData, buckets, totalHits)`.

**Files:**
- `src/services/log-analyzer/aggregation-client.ts` (add helpers)
- `src/services/log-analyzer/analytics-engine.ts` (add `buildNumericStatsFromAgg`)
- `src/services/log-analyzer/log-collector.ts` (bump sample size for numeric-fallback mode)
- `src/pages/LogAnalyzer.tsx` (route numeric fields through new path)

### Phase 3 — Breakdown via `multi_field_aggregation` (P1, ~2 hours)

**Goal:** breakdown (cross-tab) uses full dataset for all combinations of primary × breakdown fields.

**Change:**
- Add `fetchMultiFieldAggregation(namespace, endpoint, query, ts, te, fields[], topk)` — fields is an array like `["req_path", "rsp_code_class", "country"]`.
- Add `buildBreakdownFromMultiFieldAgg(buckets, primaryField, breakdownFields, totalHits): BreakdownResult`.
- LogAnalyzer breakdown useEffect prefers agg path when all fields in the combo are enum-supported; falls back to sample-based with clear labeling for non-supported fields.
- Response `keys: {"REQ_PATH": "/login", "RSP_CODE_CLASS": "5xx"}` maps directly to primary × breakdown structure.

**Files:**
- `src/services/log-analyzer/aggregation-client.ts` (new helper)
- `src/services/log-analyzer/analytics-engine.ts` (new builder)
- `src/pages/LogAnalyzer.tsx` (route breakdown through new path)

### BONUS enhancements (optional after P1-P3)

1. **Native date_aggregation for time series** (~1 hour) — replace the per-hour probe fan-out with a single `date_aggregation` call. Faster, fewer API calls.
2. **Cardinality aggregation for summary card** (~30 min) — replace `buildSummaryFromAggregations`'s bucket-length hack with true approx distinct counts for src_ip, req_path, domain.
3. **Status-code time series via date_aggregation + sub_aggs** (~1 hour) — one API call gives you per-hour status distribution instead of client-side reconstruction from raw sample.

## Risks & unknowns

| Risk | Mitigation |
|------|------------|
| Enum in OpenAPI may be outdated | Probe each field once at runtime; cache `supported | unsupported` decisions |
| `multi_field_aggregation` behavior on 3+ fields at scale | Test on a real tenant with high volume; start with 2 fields, add 3rd cautiously |
| Bucket cardinality explosion in multi-field aggs | Cap `topk` (e.g. 100), warn if `total_hits >> sum(bucket_counts)` |
| Field-name case mismatch (lowercase in code, UPPERCASE in enum) | Normalize both sides; probe both variants once |
| Response `count` as string vs number | Already handled in existing parser; verify for new helpers |
| Rate limits on burst of on-demand aggregation calls | Reuse `AdaptiveConcurrencyController` from `fp-analyzer/` |

## Effort

| Phase | Effort | Cumulative |
|-------|--------|------------|
| P1 (on-demand field agg) | ~1 hr | 1 hr |
| P2 (numeric aggregation) | ~2 hr | 3 hr |
| P3 (breakdown multi-field) | ~2 hr | 5 hr |
| BONUS (date agg + cardinality + status time series) | ~2.5 hr | 7.5 hr |

**Recommended sequence:** ship P1 → verify on tenant → ship P3 → verify → ship P2 (biggest scope of edge cases). BONUS as follow-up PR.

## Sources

- `f5-product-docs/sources/f5-distributed-cloud-open-api/docs-cloud-f5-com.0157.public.ves.io.schema.log.ves-swagger.json` — access log, audit log, firewall log, platform events, k8s events aggregation endpoints & schemas
- `f5-product-docs/sources/f5-distributed-cloud-open-api/docs-cloud-f5-com.0021.public.ves.io.schema.app_security.ves-swagger.json` — security events, incidents, suspicious user logs aggregation endpoints & schemas
- Existing implementation reference: `xc-app-store/src/services/log-analyzer/{aggregation-client,log-collector,analytics-engine}.ts` — current agg patterns, response parsing, adaptive concurrency
