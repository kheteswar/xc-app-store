// ============================================================
// API Discovery Report Dashboard – Type Definitions
// ============================================================

/** Stats for a namespace or individual load balancer */
export interface ApiEndpointStats {
  scope: string;                  // Display label — "Namespace: xyz" or "<ns>/<lb>" or just "<lb>"
  /** Namespace this row belongs to (set for per-LB rows; absent for namespace rollups) */
  namespace?: string;
  /** LB short name (set only for per-LB rows) */
  lbName?: string;
  total_endpoints: number;
  discovered: number;
  inventory: number;
  shadow: number;
  pii_detected: number;
  /** Optional richer counters surfaced by newer F5 XC API Discovery responses */
  zombie?: number;
  unauthenticated?: number;
  high_risk?: number;
  vulnerable?: number;
  /** Threat-level distribution — derived from per-endpoint security_risk field */
  threat_high?: number;
  threat_medium?: number;
  threat_low?: number;
  threat_info?: number;
  /** Risk score aggregates — derived from per-endpoint risk_score.score */
  risk_score_avg?: number;
  risk_score_max?: number;
}

/**
 * Column mapping for the detailed endpoint export.
 * Mirrors the latest F5 XC `/api_endpoints` response — when a key is missing
 * the formatter falls back to "—", so adding new columns is safe across
 * tenants on different XC versions.
 */
export const COLUMN_MAPPING: Record<string, string> = {
  'API Endpoint':           'collapsed_url',
  'Method':                 'method',
  'Domains':                'domains',
  'Hostnames':              'hostnames',
  'API Category':           'category',
  'API Groups':             'api_groups',
  'API Attributes':         'attributes',
  'Tags':                   'tags',
  'Discovery Source':       'engines',
  'Schema Status':          'schema_status',
  'Authentication State':   'authentication_state',
  'Authentication Type':    'authentication_types',
  'Sensitive Data':         'sensitive_data_types',
  'Sensitive Data Location': 'sensitive_data_location',
  'Sensitive Data Classes': 'sensitive_data_classes',
  'API Compliance':         'compliances',
  'Threat Level':           'security_risk',
  'Risk Score':             'risk_score.score',
  'Risk Factors':           'risk_score.factors',
  'Vulnerabilities':        'vulnerabilities',
  'Request Rate':           'req_rate',
  'Requests':               'requests_count',
  'Average Latency':        'avg_latency',
  'P95 Latency':            'latency_p95',
  'P99 Latency':            'latency_p99',
  'Errors':                 'err_rsp_count',
  '4xx Responses':          'rsp_4xx_count',
  '5xx Responses':          'rsp_5xx_count',
  'Status Codes':           'status_codes',
  'Last Updated':           'access_discovery_time',
  'Last Request':           'last_request_time',
  'Last Tested':            'last_tested',
};

export const COLUMN_KEYS = Object.keys(COLUMN_MAPPING);

/** A single parsed API endpoint row from the detail API */
export interface ApiEndpointRow {
  lb: string;        // display label — "<ns>/<lb>" or just "<lb>"
  namespace: string;
  lbName: string;
  [column: string]: string | number | undefined;
}

/** A single operation parsed from a swagger spec */
export interface SwaggerOperation {
  path: string;
  method: string;
  contentType: string;
  summary?: string;
  description?: string;
  tags?: string[];
  deprecated?: boolean;
  operationId?: string;
  parameters?: Array<{ name: string; in: string; required?: boolean; type?: string; description?: string }>;
  requestBody?: { contentTypes: string[]; required?: boolean; schemaSummary?: string };
  responses?: Array<{ code: string; description?: string; contentTypes?: string[] }>;
  security?: string[];
}

/** A single parsed swagger spec (one per FQDN per LB) */
export interface SwaggerSpec {
  lb: string;          // display label
  namespace: string;
  lbName: string;
  filename: string;
  fqdn: string;
  title?: string;
  version?: string;
  description?: string;
  openapi?: string;
  raw: unknown;
  endpoints: SwaggerOperation[];
}

/** Flattened swagger endpoint entry (kept for table/Excel export back-compat) */
export interface SwaggerEndpoint {
  lb: string;          // display label
  namespace: string;
  lbName: string;
  fqdn: string;
  path: string;
  method: string;
  contentType: string;
  summary?: string;
  tags?: string;
}

/** Progress callback for multi-LB operations */
export interface FetchProgress {
  phase: 'stats' | 'swagger' | 'endpoints';
  current: number;
  total: number;
  namespace?: string;
  lbName?: string;
  message: string;
}

/** A single (namespace, LB) selection — input to runFullReport */
export interface LBSelection {
  namespace: string;
  lbName: string;
}

/** Aggregated results from the full report run */
export interface ApiReportResults {
  /** Namespace-level rollup stats, one entry per namespace included */
  nsStats: ApiEndpointStats[];
  lbStats: ApiEndpointStats[];
  swaggerEndpoints: SwaggerEndpoint[];
  swaggerSpecs: SwaggerSpec[];
  endpointRows: ApiEndpointRow[];
  /** ISO timestamp when the report finished */
  generatedAt: string;
  /** Namespaces touched by this report */
  namespaces: string[];
  timeRangeDays: number;
}
