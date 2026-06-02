# F5 XC LIVE SOC MONITORING ROOM
## Definitive Implementation Specification — FINAL

**Tool Name:** Live SOC Monitoring Room
**Codename:** `soc-room`
**Routes:** `/soc-lobby` | `/soc-room/:roomId`
**Author:** Kheteshwar | F5 Networks Managed Services
**Date:** March 2026
**Status:** Final Implementation Specification — Implementation Ready
**Revision:** v3-FINAL — Consolidated from v1 vision + v1 review (4 critical + 6 high gaps) + v2 spec + v2 review (268 OpenAPI schema audit, 6 new API subsystems, aggregation-first architecture change) + depth restoration pass

**Source Artifacts:**
- v1 Vision (615 lines) → Initial concept, error diagnosis KB, 5 investigation workflows
- v1 Review (263 lines) → CDN gap, API security gap, config correlation gap, sample rate gap
- v2 Spec (1,120 lines) → 9 investigations, 15 detectors, 6 tabs, per-domain/per-origin, history buffer
- v2 Review (403 lines) → Access Log Aggregation discovery, Bot Defense 102 endpoints, InfraProtect, CSD, DNS, Synthetic
- This document: Final consolidation with full implementation depth

---

## TABLE OF CONTENTS

1. Executive Vision & Scope
2. Room Concept & Multi-Room Lobby
3. Complete F5 XC API Inventory (311 Monitoring Endpoints)
4. Aggregation-First Polling Architecture
5. Sample Rate Compensation
6. The rsp_code_details Intelligence Engine
7. Auto-Investigation Workflows (12 Workflows)
8. Investigation Chaining Architecture
9. Anomaly Detection Engine (23 Detectors)
10. Operator Questions Dashboard (8 Tabs)
11. Dashboard Panel Specification (21 Panels)
12. Feature-Specific Monitoring Subsystems
13. Cross-Launch Integration
14. State Management, Memory & History
15. UI/UX: Futuristic SOC Aesthetic
16. Phased Delivery Plan
17. File Structure
18. Differentiators vs F5 XC Console

---

## 1. EXECUTIVE VISION & SCOPE

The Live SOC Monitoring Room is a **real-time security operations center** built on top of 311 F5 XC monitoring API endpoints discovered across 268 OpenAPI schema files. It transforms the XC App Store from a collection of retrospective analysis tools into a **live operational command center** that monitors, detects, investigates, and recommends — continuously, across every security control F5 XC offers.

### 1.1 The 10 Capabilities

| # | Capability | What It Means |
|---|-----------|---------------|
| 1 | **Continuous Monitoring** | Polls F5 XC APIs every 2-5 minutes with a 4-track fetch strategy |
| 2 | **Full-Spectrum Coverage** | HTTP LBs, CDN Distributions, DNS Zones, Bot Defense, Client-Side Defense, Network DDoS, API Security, Synthetic Monitoring — every F5 XC security control in one view |
| 3 | **Aggregation-First Architecture** | Uses server-side aggregation APIs (access log + security event) instead of downloading raw logs for dashboard panels — more complete, more efficient, sample-rate immune |
| 4 | **23 Anomaly Detectors** | Compares live metrics against learned baselines across traffic, errors, security, CDN, DNS, bots, network DDoS, client-side scripts, and config changes |
| 5 | **12 Investigation Workflows** | When anomalies fire, auto-fetches additional data, correlates across sources, identifies root cause via K000146828 knowledge base, and recommends specific remediation |
| 6 | **Investigation Chaining** | Investigations can spawn child investigations when secondary issues are discovered |
| 7 | **F5 Rule Suggestion Integration** | Auto-fetches F5's own recommended WAF exclusions, block rules, trust rules, DDoS mitigations, and rate limits for one-click remediation |
| 8 | **Operator Q&A Dashboard** | 8 tabs, 50+ pre-built questions across Health, Security, Performance, CDN, API Security, Bot Defense, Infrastructure, and Operations |
| 9 | **Multi-Room Lobby** | Monitor 5-10 customers simultaneously from a command center overview with background heartbeat polling |
| 10 | **History & Shift Handover** | Ring buffer preserves 6+ hours of data, time scrubber for review, PDF shift summary export |

### 1.2 By the Numbers

| Metric | Count |
|--------|-------|
| F5 XC API families used | 18 |
| Total API endpoints leveraged | ~100 (of 311 available monitoring endpoints) |
| Dashboard panels | 21 |
| Anomaly detectors | 23 |
| Investigation workflows | 12 |
| Operator question tabs | 8 |
| Pre-built operator questions | 50+ |
| Estimated implementation | ~16,000-19,000 lines TypeScript across 4 phases |

---

## 2. ROOM CONCEPT & MULTI-ROOM LOBBY

### 2.1 Room Configuration

```typescript
interface SOCRoomConfig {
  id: string;
  name: string;                        // "OCBC Production", "SBI Internet Banking"
  namespace: string;

  // Monitored objects (multi-select)
  loadBalancers: string[];             // HTTP LB names
  cdnDistributions: string[];          // CDN distribution names
  dnsZones: string[];                  // DNS zone names (NEW in v3)
  dnsLoadBalancers: string[];          // DNS LB names (NEW in v3)

  // Feature detection flags (auto-detected from config, or manual override)
  features: {
    botDefenseEnabled: boolean;        // Enables Bot Defense Reporting panels
    clientSideDefenseEnabled: boolean; // Enables CSD panels
    infraProtectEnabled: boolean;      // Enables L3/L4 DDoS panels
    syntheticMonitorsEnabled: boolean; // Enables Synthetic Health
    apiSecurityEnabled: boolean;       // Enables API Security panels
  };

  // Polling settings
  pollingIntervalSec: 120 | 180 | 300;
  dataWindowMinutes: 5 | 10 | 15;
  fetchDepth: 'light' | 'standard' | 'deep';

  // Watch paths with custom thresholds
  watchPaths: Array<{
    path: string;
    label: string;
    errorThreshold?: number;
    latencyThresholdMs?: number;
  }>;

  // Display
  primaryDomain?: string;
  layout?: 'full' | 'compact';

  // Timestamps
  createdAt: string;
  lastOpenedAt: string;
}
```

### 2.2 Multi-Room Lobby (`/soc-lobby`)

```
┌──────────────────────────────────────────────────────────────────┐
│  SOC COMMAND CENTER                          [+ Create Room]     │
├────────────┬────────────┬────────────┬────────────┬──────────────┤
│ ● OCBC     │ ● SBI      │ ● EIB      │ ● QGas     │ ● Adani     │
│ NOMINAL    │ ELEVATED   │ HIGH ⚠     │ NOMINAL    │ NOMINAL      │
│ ~2.3K rps  │ ~340 rps   │ ~89 rps    │ ~45 rps    │ ~2.1K rps    │
│ 0.1% err   │ 0.3% err   │ 4.2% err   │ 0% err     │ 0.2% err     │
│ 0 incidents│ 1 incident │ 3 incidents│ 0 incidents│ 0 incidents  │
│ 12s ago    │ 8s ago     │ 5s ago     │ 30s ago    │ 15s ago      │
│  [ENTER]   │  [ENTER]   │  [ENTER]   │  [ENTER]   │  [ENTER]     │
└────────────┴────────────┴────────────┴────────────┴──────────────┘
```

- Room cards show: name, threat level, RPS (sample-corrected), error rate, incident count, last poll time
- Rooms with active anomalies sort to top, pulse border in threat color
- **Background heartbeat polling**: Track 1 only (2 API calls per room, every 60s)
- Click → enters full SOC view at `/soc-room/:roomId`
- Room CRUD: create, edit, duplicate, delete — all persisted to localStorage

### 2.3 Room Creation Wizard

**Step 1: Namespace** → select from connected tenant
**Step 2: Monitored Objects** → multi-select HTTP LBs, CDNs, DNS zones, DNS LBs
**Step 3: Feature Detection** → wizard auto-detects which F5 XC features are enabled by reading LB configs (bot defense, CSD, API discovery, etc.)
**Step 4: Polling Config** → interval, window, depth, watch paths
**Step 5: Confirm & Create** → room saved, enters SOC view immediately

---

## 3. COMPLETE F5 XC API INVENTORY

### 3.1 Data APIs — Logs & Telemetry (18 API families, ~100 endpoints)

#### 3.1.1 Access Logs (6 endpoints)

| Endpoint | Method | SOC Usage |
|----------|--------|-----------|
| `/api/data/namespaces/{ns}/access_logs` | POST | Track 1 probe (limit=1, total_hits) + Track 3 raw detail fetch |
| `/api/data/namespaces/{ns}/access_logs/aggregation` | POST | **Track 2 — primary dashboard data source** (v3 discovery) |
| `/api/data/namespaces/{ns}/access_logs/scroll` | GET/POST | Track 3 raw log pagination |

**Aggregation queries used (Track 2):**
```
Agg-A1: group by rsp_code              → Response code distribution panel
Agg-A2: group by rsp_code_details      → Error diagnosis panel
Agg-A3: group by country               → Geo distribution panel
Agg-A4: group by dst_ip                → Per-origin health grid
Agg-A5: group by req_path (top 30)     → Hot paths panel
Agg-A6: group by src_ip (top 30)       → Top talkers (non-security)
Agg-A7: group by domain/authority       → Per-domain breakdown
Agg-A8: group by waf_action            → WAF action distribution
```

#### 3.1.2 Security Events (11 endpoints)

| Endpoint | Method | SOC Usage |
|----------|--------|-----------|
| `/api/data/namespaces/{ns}/app_security/events` | POST | Track 1 probe + Track 3 detail |
| `/api/data/namespaces/{ns}/app_security/events/aggregation` | POST | **Track 2 — security dashboard counters** |
| `/api/data/namespaces/{ns}/app_security/events/scroll` | GET/POST | Track 3 pagination |
| `/api/data/namespaces/{ns}/app_security/metrics` | POST | Track 2 — pre-computed security metrics |
| `/api/data/namespaces/{ns}/app_security/incidents` | POST | Track 2 — F5 native incidents |
| `/api/data/namespaces/{ns}/app_security/incidents/aggregation` | POST | Track 2 — incident counters |
| `/api/data/namespaces/{ns}/app_security/suspicious_user_logs` | POST | Track 4 — behavioral threat data |
| `/api/data/namespaces/{ns}/app_security/suspicious_user_logs/aggregation` | POST | Track 2 — suspicious user counts |
| `/api/data/namespaces/system/app_security/all_ns_events` | POST | Lobby: cross-namespace view |
| `/api/data/namespaces/system/app_security/all_ns_events/aggregation` | POST | Lobby: cross-namespace counters |

**Security aggregation queries (Track 2):**
```
Agg-S1: group by sec_event_name        → Security breakdown donut (WAF/TM/Bot/Policy)
Agg-S2: group by signatures.id (top 20) → Top WAF signatures
Agg-S3: group by src_ip (top 20)       → Top attacking IPs
Agg-S4: group by country               → Security geo distribution
Agg-S5: group by violations.name       → Top violations
```

#### 3.1.3 Alerts (6 endpoints)

| Endpoint | Method | SOC Usage |
|----------|--------|-----------|
| `/api/data/namespaces/{ns}/alerts` | GET | Track 2 — active alert feed |
| `/api/data/namespaces/system/all_ns_alerts` | GET | Lobby — cross-namespace alerts |
| `/api/data/namespaces/{ns}/alerts/history` | GET | Investigation context |
| `/api/data/namespaces/{ns}/alerts/history/aggregation` | POST | Alert trend analysis |

**Alert types surfaced:**
- TSA alerts (request rate, error rate, latency, throughput anomalies) — minor/major/critical
- Configuration alerts (validation failures, resource issues)
- Security alerts (WAF, policy, anomaly detection)
- Infrastructure alerts (site down, connectivity lost, high resource utilization)

#### 3.1.4 Audit Logs (4 endpoints)

| Endpoint | Method | SOC Usage |
|----------|--------|-----------|
| `/api/data/namespaces/{ns}/audit_logs` | POST | Track 2 — config change detection |
| `/api/data/namespaces/{ns}/audit_logs/aggregation` | POST | Config change trend |

#### 3.1.5 Bot Defense Reporting (102 endpoints) — NEW in v3

| API Group | Key Endpoints | SOC Usage |
|-----------|--------------|-----------|
| **Traffic Overview** | `traffic/overview`, `traffic/overview/timeseries` | Human/Bot/Malicious split + time series |
| **Malicious Traffic** | `traffic/malicious/overview/metrics`, `/overview/actions`, `/overview/timeseries/actions` | Bot mitigation effectiveness |
| **Attack Intent** | `top/type/malicious/dimension/attackintent`, `traffic/malicious/dimension/attackintent/timeseries` | Credential stuffing, scraping, carding classification |
| **Top Attackers** | `top/type/malicious/dimension/ip`, `/ua`, `/asorg` | Top malicious by IP, user agent, ASN |
| **Top Endpoints** | `top/type/malicious/dimension/endpoints` (v5) | Which endpoints are under bot attack |
| **Credential Stuffing** | `insight/credential-stuffing-attack` | Dedicated credential stuffing detection |
| **Good Bots** | `top/type/good` | Legitimate bot identification |
| **Human Traffic** | `top/type/human/dimension/browser`, `/device`, `/geolocation` | Legitimate user profiling |
| **Peer Intelligence** | `reporting/peers/threat-types`, `/traffic/overview` | Comparison against F5 peer network |
| **Forensic Fields** | `v1/reporting/forensic/fields` | Available fields for deep analysis |

#### 3.1.6 InfraProtect L3/L4 DDoS (25 endpoints) — NEW in v3

| Endpoint | SOC Usage |
|----------|-----------|
| `infraprotect/alerts` | Network-layer DDoS alerts |
| `infraprotect/events`, `events_summary` | DDoS event timeline |
| `infraprotect/mitigations` | Active L3/L4 mitigations |
| `infraprotect/mitigation/{id}/ips` | IPs being mitigated |
| `infraprotect/networks` | Protected networks |
| `graph/l3l4/by_network/{id}` | L3/L4 traffic visualization |
| `graph/l3l4/top_talkers/{id}` | Volumetric attack source IPs |
| `graph/l3l4/event_count/{id}` | Event counters |

#### 3.1.7 Client-Side Defense (22 endpoints) — NEW in v3

| Endpoint | SOC Usage |
|----------|-----------|
| `csd/detected_domains` | Third-party domains injecting scripts |
| `csd/scripts`, `scripts/{id}/behaviors` | Script inventory + behavior analysis |
| `csd/scripts/{id}/formFields` | Which form fields scripts access |
| `csd/scripts/{id}/networkInteractions` | External domains scripts communicate with |
| `csd/{ns}/scripts/{id}/affectedUsers` | Users impacted by malicious scripts |
| `csd/summary`, `csd/status` | Overall CSD health |

#### 3.1.8 Synthetic Monitoring (19 endpoints) — NEW in v3

| Endpoint | SOC Usage |
|----------|-----------|
| `synthetic_monitor/health` | Overall synthetic health check status |
| `synthetic_monitor/http-monitors-health` | HTTP endpoint availability |
| `synthetic_monitor/dns-monitors-health` | DNS resolution availability |
| `synthetic_monitor/monitor-events` | Failure/recovery events |
| `synthetic_monitor/tls-report-summary` | TLS certificate status from external |
| `synthetic_monitor/certificate-summary` | Cert expiry from external probes |
| `synthetic_monitor/global-summary` | Global availability summary |

#### 3.1.9 DNS Monitoring (5 data endpoints) — NEW in v3

| Endpoint | SOC Usage |
|----------|-----------|
| `dns_zones/metrics` | DNS query volume, response codes |
| `dns_zones/request_logs` | DNS request-level logs |
| `dns_load_balancers/{name}/health_status` | DNS LB health |
| `dns_load_balancers/{name}/dns_lb_pools/{pool}/health_status` | Pool member health |
| `dns_load_balancers/{name}/dns_lb_pools/{pool}/health_status_change_events` | Health state changes |

#### 3.1.10 Additional Monitoring APIs

| API | Endpoints | SOC Usage |
|-----|-----------|-----------|
| **WAF Metrics** | `wafs/metrics/client/rule_hits`, `/security_events`, `server/...` | WAF analytics (client vs server) |
| **Firewall Logs** | `firewall_logs`, `/aggregation`, `/scroll` | Network firewall visibility |
| **Graph Connectivity** | `graph/connectivity`, `/node` (with healthscore) | Site health scores |
| **Graph Service** | `graph/service`, `/node`, `lb_cache_content` | Service mesh + CDN cacheability |
| **Virtual Host** | `api_endpoints`, `/stats`, `/vulnerabilities`, `swagger_spec` | API security deep data |
| **WAF Signatures Changelog** | `active_staged_signatures`, `released_signatures` | Signature update correlation |
| **Platform Events** | `platform_events`, `/aggregation` | Infrastructure events |
| **Flow Anomaly** | `flow_anomalys` | Network flow anomalies |

### 3.2 Rule Suggestion APIs (Auto-Remediation)

| Endpoint | Trigger Context |
|----------|----------------|
| `http_loadbalancers/{name}/waf_exclusion/suggestion` | WAF investigation → likely FP |
| `http_loadbalancers/{name}/block_client/suggestion` | WAF/DDoS investigation → confirmed attacker |
| `http_loadbalancers/{name}/trust_client/suggestion` | FP remediation → legitimate client |
| `http_loadbalancers/{name}/ddos_mitigation/suggestion` | DDoS investigation |
| `http_loadbalancers/{name}/rate_limit/suggestion` | Rate limit investigation |
| `http_loadbalancers/{name}/oas_validation/suggestion` | API security investigation |
| `http_loadbalancers/{name}/data_exposure/suggestion` | Sensitive data investigation |
| `http_loadbalancers/{name}/api_endpoint_protection/suggestion` | API endpoint protection |
| `cdn_loadbalancers/{name}/waf_exclusion/suggestion` | CDN WAF investigation |
| `cdn_loadbalancers/{name}/block_client/suggestion` | CDN attacker blocking |
| `cdn_loadbalancers/{name}/ddos_mitigation/suggestion` | CDN DDoS mitigation |

### 3.3 Intelligence APIs

| API | SOC Usage |
|-----|-----------|
| `GET /api/waf/threat_campaign/{id}` | Threat campaign context during WAF investigation |
| `GET app_setting.SuspiciousUserStatus` | Real-time suspicious/malicious user count |
| `POST virtual_host.vulnerabilities` | Known vulnerabilities for API endpoints |
| `GET virtual_host.api_endpoints/stats` | API endpoint statistics |
| `POST virtual_host.api_endpoints/summary/top_sensitive` | Sensitive data exposure |
| `POST AIAssistantQuery` | Natural language investigation (Phase 4) |

---

## 4. AGGREGATION-FIRST POLLING ARCHITECTURE

### 4.1 The Core Insight (v3 Architecture Change)

v2 downloaded raw logs (Track 3) to compute dashboard panels client-side. v3 uses **server-side aggregation APIs** for all countable/groupable metrics, keeping raw log download only for data that requires individual record access.

### 4.2 Four-Track Fetch Strategy

**Track 1 — Heartbeat (2 calls, every cycle)**
Purpose: Volume monitoring + spike detection
```
1. Access logs probe:  POST /access_logs {limit:1} → total_hits
2. Security events probe: POST /app_security/events {limit:1} → total_hits
```

**Track 2 — Aggregation (12-16 calls, every cycle)**
Purpose: All dashboard panels, alert feed, security counters
```
Access Log Aggregations (6-8 calls):
  Agg-A1: by rsp_code
  Agg-A2: by rsp_code_details
  Agg-A3: by country
  Agg-A4: by dst_ip
  Agg-A5: by req_path (top 30)
  Agg-A6: by domain/authority
  Agg-A7: by src_ip (top 30)
  Agg-A8: by waf_action

Security Event Aggregations (3-4 calls):
  Agg-S1: by sec_event_name
  Agg-S2: by signatures.id (top 20)
  Agg-S3: by src_ip (top 20)

Other Track 2 calls:
  - Active Alerts (GET /alerts)
  - Audit Logs (POST /audit_logs — last interval)
  - Security Incidents (POST /app_security/incidents)
  - Suspicious User Aggregation (POST /suspicious_user_logs/aggregation)

Feature-conditional Track 2:
  - Bot Defense: traffic/overview (1 call) — if botDefenseEnabled
  - WAF Metrics: wafs/metrics/client/security_events (1 call) — if WAF enabled
  - Synthetic Health: synthetic_monitor/health (1 call) — if syntheticMonitorsEnabled
  - DNS Health: dns_load_balancers/health_status (1 call) — if dnsLoadBalancers selected
```

**Track 3 — Detail Fetch (2-6 calls, configurable depth)**
Purpose: ONLY for data requiring individual records
```
  - Raw access logs (1-2 pages): live event feed, latency waterfall (5 timing fields), JA4 analysis
  - Raw security events (1-2 pages): live event feed, matching info details
  NOTE: Dashboard panels NO LONGER depend on Track 3
```

**Track 4 — Investigation (on-demand, when anomaly triggers)**
Purpose: Deep contextual data for auto-investigation
```
  - LB config, origin pool config, health check config
  - F5 Rule Suggestion APIs
  - Bot Defense detailed reports (attack intent, top malicious)
  - InfraProtect alerts/mitigations (if infraProtectEnabled)
  - CSD scripts/detected_domains (if clientSideDefenseEnabled)
  - DNS LB pool member health (if dnsLoadBalancers selected)
  - Threat campaign details
  - Additional targeted log queries
```

### 4.3 API Budget Per Cycle

| Interval | Track 1 | Track 2 (base) | Track 2 (features) | Track 3 | Total/Cycle | Total/Hour |
|----------|---------|----------------|--------------------|---------|---------|----|
| 5 min | 2 | 14 | 0-4 | 2-4 | 18-24 | 216-288 |
| 3 min | 2 | 14 | 0-4 | 2-3 | 18-23 | 360-460 |
| 2 min | 2 | 14 | 0-4 | 2 | 18-22 | 540-660 |

### 4.4 Why Aggregation-First Is Superior

| Metric | v2 (Raw Logs) | v3 (Aggregation) |
|--------|--------------|------------------|
| Response code distribution | Count 500-2500 downloaded entries | **Complete** distribution from all logs in window |
| Top paths | Limited to downloaded pages | Top 30 across ALL traffic |
| Per-origin health | Group downloaded entries by dst_ip | **Exact** per-origin counts |
| Geo distribution | Sample from downloaded entries | **Complete** country breakdown |
| Error diagnosis | Group downloaded entries by rsp_code_details | **Complete** error classification |
| Sample rate sensitivity | Volume metrics wrong without correction | Aggregation counts are **exact** (server counts all logs) |
| API calls needed | 4-12 (raw log pages) | 6-8 (aggregation queries) |

---

## 5. SAMPLE RATE COMPENSATION

F5 XC performs rate-adaptive sampling on access logs. `sample_rate` can be 1 (no sampling) to 100+ (heavy sampling).

### 5.1 Rules

**Aggregation queries (Track 2):** Aggregation counts ALL logs server-side before sampling display entries. The `total_hits` and aggregation counts represent the TRUE count. **No compensation needed for Track 2 aggregation results.**

**Track 1 probes:** `total_hits` from the probe represents the true count. **No compensation needed.**

**Track 3 raw logs:** Individual log entries represent sampled data. For volume estimates from raw logs: `estimated_count = sum(sample_rate)` across entries. For percentiles (latency): percentiles are statistically valid from sampled data. **Compensation needed only for raw volume counts.**

**Anomaly detection:** Baseline values from aggregation are already accurate. Comparisons are apples-to-apples. **No compensation needed for anomaly detection when using aggregation.**

### 5.2 Display

When `avg_sample_rate > 1` (detected from Track 3 raw logs), display "Sampled" indicator in status strip with the average rate. RPS gauge always uses Track 1 `total_hits / window_seconds` which is accurate.

### 5.3 Sample Rate Anomaly

If average `sample_rate` jumps >5x between cycles, F5 XC is seeing a massive traffic spike. This is anomaly detector #15, triggered before even computing RPS.

---

## 6. THE rsp_code_details INTELLIGENCE ENGINE

### 6.1 Error Diagnosis Knowledge Base (19 Patterns)

Sourced from K000146828, the complete `rsp_code_details` → root cause mapping. Each entry includes category, severity, root cause, whether the error is origin-generated vs F5-generated, auto-investigation actions, and remediation steps.

| Code | rsp_code_details Pattern | Category | Severity | Origin Error? | Root Cause Summary | Auto-Investigation Action | Remediation |
|------|------------------------|----------|----------|--------------|-------------------|--------------------------|----|
| 403 | `csrf_origin_mismatch` | config | medium | No | CSRF check — missing Origin/Referer header | Check if POST requests lack Origin header | Review CSRF policy; check SPA CORS config |
| 403 | `ext_authz_denied` | config | medium | No | Service Policy blocked request | Fetch active service policies, identify blocking rule | Review service policy rules; check audit log for changes |
| 404 | `route_not_found` | config | high | No | No matching route/domain; or all health checks failed | Check LB domains vs request authority; check all origin health | Verify domain config, route rules, health checks |
| 408 | `request_overall_timeout` | config | medium | No | Slow DDoS mitigation timeout | Check slow_ddos_mitigation.request_timeout in LB config | Increase timeout or adjust slow DDoS settings |
| 413 | `request_payload_too_large` | config | low | No | Buffer Policy limit exceeded | Check Buffer Policy config on LB/route | Increase Max Request Bytes (max 10485760) or disable Buffer Policy |
| 421 | `misdirected_request` | config | medium | No | HTTP/2 + wildcard cert TLS coalescing | Check if multiple LBs share same wildcard cert | Ensure consistent TLS config across LBs, use separate certs, or disable HTTP/2 |
| 503 | `cluster_not_found` | origin | critical | No | No upstream endpoint (k8s/DNS/cluster) | Check origin pool status, k8s service discovery, Quad-A DNS records | Set LB_Override, check Endpoint Selection, verify cluster status |
| 503 | `upstream_reset.*connection_failure` | origin | critical | No | Cannot TCP connect to origin | Check firewall rules for F5 XC egress IPs, verify origin accessibility | Whitelist F5 XC IPs (docs.cloud.f5.com/docs/reference/network-cloud-ref), increase timeout |
| 503 | `no_healthy_upstream` | origin | critical | No | All health checks failed | Fetch health check config, check origin server status | Fix origin server, adjust health check parameters |
| 503 | `via_upstream` | origin | high | **Yes** | Origin itself returned 503 | Origin is the source — check origin directly | This is NOT an F5 XC issue; investigate origin server health |
| 503 | `remote_reset` | origin | high | No | HTTP version incompatibility | Check HTTP protocol negotiation between XC and origin | Test HTTP/1.1 vs HTTP/2 against origin; adjust origin pool protocol |
| 503 | `upstream_reset.*TLS_error.*Connection_reset` | origin | high | No | TLS handshake failure | Check origin TLS config, certificate chain | Configure TLS verification in Origin Pool or skip verification (K000147459) |
| 503 | `upstream_reset.*WRONG_VERSION_NUMBER` | origin | high | No | TLS vs plaintext mismatch | Check if origin port expects TLS or plaintext | Verify "Use TLS" in origin pool matches origin port's actual protocol |
| 503 | `upstream_reset.*CERTIFICATE_VERIFY_FAILED` | origin | high | No | Origin cert validation failed | Check origin cert chain, CA trust store | Skip verification OR configure custom CA list in origin pool TLS config |
| 503 | `upstream_reset.*connection_termination` | origin | medium | No | Idle timeout mismatch (origin closing) | Check idle timeout alignment | Set XC origin-pool idle-timeout LOWER than origin server's timeout |
| 503 | `upstream_reset.*protocol_error` | origin | medium | Partial | HTTP response header parsing error | Check origin response headers for duplicates/malformed values | Fix origin response headers (often duplicate Content-Length) |
| 503 | `upstream_reset.*delayed_connect_error.*111` | origin | critical | No | TCP connection refused (no SYN-ACK) | No TCP connectivity; time_to_last_downstream_tx_byte shows timeout | Check network connectivity, firewall, origin server status |
| 503 | `upstream_reset.*remote_refused_stream_reset` | origin | medium | Partial | HTTP/2 max concurrent streams exceeded | Check SETTINGS_MAX_CONCURRENT_STREAMS on origin | Adjust HTTP/2 stream limit or reduce concurrent connections |
| 503 | `response_payload_too_large` | config | medium | No | DataGuard + HTTP/1.1 limit | Check DataGuard config and response size | Enable HTTP/2 on origin OR add Skip DataGuard rule for affected paths |
| 504 | `stream_idle_timeout` | origin | high | No | Origin exceeded idle timeout | Check idle timeout config on HTTP LB | Increase idle timeout on the HTTP LB |
| 504 | `upstream_response_timeout` | origin | high | No | Origin exceeded route timeout | Check route timeout vs origin processing time | Increase timeout in LB miscellaneous options |

### 6.2 Latency Waterfall (5 Timing Fields)

```
time_to_first_upstream_tx_byte   → XC starts sending to origin
time_to_first_upstream_rx_byte   → TTFB from origin
time_to_last_upstream_rx_byte    → Complete response from origin
time_to_first_downstream_tx_byte → XC starts sending to client
time_to_last_downstream_tx_byte  → Complete delivery to client
```

**Auto-diagnosis tree:**
1. `first_upstream_rx` high → **Origin slow** (server processing)
2. `last_upstream_rx - first_upstream_rx` high → **Large response body**
3. `first_downstream_tx - last_upstream_rx` high → **F5 XC processing** (WAF inspection)
4. `last_downstream_tx - first_downstream_tx` high → **Slow client**
5. `src_site ≠ dst_site` → **Cross-site routing** → check LocalEndpointsPreferred
6. `duration_with_data_tx_delay ≠ duration_with_no_data_tx_delay` → **Idle timeout issue**

### 6.3 Additional Diagnostic Signals

| Signal | Field(s) | Diagnostic Value |
|--------|---------|-----------------|
| Envoy response flags | `response_flags` | `UF`=upstream failure, `UO`=circuit breaker, `UT`=timeout |
| Circuit breaker | `UpstreamConnectionFailure + UpstreamOverflow` | Default circuit breaker limit hit |
| Cross-site routing | `src_site` vs `dst_site` | Latency from inter-site traffic |
| Per-origin attribution | `dst_ip`, `dst_port` | Which origin server failed |
| Rate limiter trigger | `policy_hits.rate_limiter_action` | Rate limit effectiveness |
| IP reputation | `policy_hits.ip_trustscore` | Trust score of requestor |
| JA4 fingerprint | `ja4_tls_fingerprint` | Client tool identification |
| TLS version | `tls_version` | Security compliance |

---

## 7. AUTO-INVESTIGATION WORKFLOWS (12)

Each investigation produces: evidence tree, root cause determination, remediation recommendations, child investigation triggers, and one-click cross-launch actions.

### 7.1 Investigation: Origin 5xx Surge

**Trigger:** 5xx error rate exceeds 2x baseline OR >10% of traffic (from Agg-A1)

| Step | Action | API / Data Source | Output |
|------|--------|-------------------|--------|
| 1 | **Classify errors** | Agg-A2 (by rsp_code_details) | Error type breakdown with KB root cause labels |
| 2 | **Separate F5-generated vs origin-generated** | KB `isOriginError` flag | "73% are upstream_reset (F5-generated), 27% are via_upstream (origin-generated)" |
| 3 | **Identify failing origins** | Agg-A4 (by dst_ip) with 5xx filter | Per-origin error rates: "10.0.1.7 returning 92% of 503s" |
| 4 | **Analyze timing waterfall** | Track 3 raw logs: 5 timing fields | P95 per field → pinpoint bottleneck (origin slow? network? XC processing?) |
| 5 | **Check cross-site routing** | Track 3: src_site vs dst_site | "38% of requests routing cross-site (pa2-par → ams9-ams)" |
| 6 | **Check circuit breaker** | Track 3: response_flags for UO/UF | "Circuit breaker triggered on 12 requests (UpstreamOverflow)" |
| 7 | **Check config changes** | Audit logs (last 30 min) | "Origin pool 'prod-pool' modified by user@f5.com at 14:12 UTC" |
| 8 | **Check health check config** | GET origin pool + health check config | Health check interval, threshold, endpoint |
| 9 | **Fetch remediation** | Rule Suggestion APIs (if attack-related) | Suggested block/DDoS mitigation rules |

**Presented as:** Investigation card with diagnosis tree showing: error classification → failing origin identification → root cause → remediation actions

### 7.2 Investigation: WAF Attack Surge

**Trigger:** WAF block count exceeds 3x baseline OR new signature IDs not in baseline (from Agg-S1/S2)

| Step | Action | API / Data Source | Output |
|------|--------|-------------------|--------|
| 1 | **Aggregate by signature** | Agg-S2 (by signatures.id, top 20) | Top firing signatures with hit counts |
| 2 | **Identify attack sources** | Agg-S3 (by src_ip) + security events by country/ASN | Top attacker IPs with geo and ASN org |
| 3 | **Check threat campaigns** | GET /api/waf/threat_campaign/{id} for each signature | "Signature 200010019 is part of Log4j campaign" |
| 4 | **Classify FP vs TP** | Reuse fp-scorer.ts 7-signal scoring on top signatures | FP confidence score per signature |
| 5 | **Cross-reference with access logs** | Match sec event src_ip+timestamp against access logs looking for origin 200 | "43% of blocked requests would have gotten 200 → likely FP" |
| 6 | **JA4 fingerprint clustering** | Track 3 raw logs: group JA4 for attack source IPs | "47 IPs but only 2 JA4 fingerprints → 2 attack tools" |
| 7 | **Check for WAF policy changes** | Audit logs: filter for app_firewall modifications | "WAF exclusion removed by admin at 13:45" |
| 8 | **Generate remediation** | GetSuggestedWAFExclusionRule (FP) / GetSuggestedBlockClientRule (TP) | One-click rule suggestions |

### 7.3 Investigation: DDoS Detection

**Trigger:** F5 TSA alert from Alerts API OR traffic volume >5x baseline (from Track 1)

| Step | Action | API / Data Source | Output |
|------|--------|-------------------|--------|
| 1 | **Fetch active TSA alerts** | GET /alerts (active) | Alert details: severity, metric, threshold |
| 2 | **Profile the spike** | Agg-A3 (country), Agg-A6 (src_ip), Track 3 (JA4, UA) | Geographic + fingerprint distribution |
| 3 | **Classify attack type** | Analysis of step 2 results | Volumetric (diverse IPs/JA4) vs App-layer (targeted paths, few IPs) |
| 4 | **Check existing mitigations** | GET LB config: l7_ddos_protection, rate_limiters, service_policies | Current protection posture |
| 5 | **Check sample_rate surge** | Track 3: compare current avg sample_rate vs baseline | "sample_rate jumped from 1 to 47 → F5 XC under heavy load" |
| 6 | **Check InfraProtect** | InfraProtect alerts (if enabled) | L3/L4 DDoS alerts alongside L7 |
| 7 | **Generate mitigation** | GetSuggestedDDoSMitigationRule | IP/ASN-based mitigation rule |
| 8 | **Recommend threshold** | DDoS Advisor Peak×3 algorithm | "Current peak: 12,400 RPS. Recommended threshold: 37,200 RPS" |

### 7.4 Investigation: Latency Spike

**Trigger:** P95 latency exceeds 3x baseline (from Track 3 timing fields)

| Step | Action | API / Data Source | Output |
|------|--------|-------------------|--------|
| 1 | **Analyze timing waterfall** | Track 3: compute P50/P95 of all 5 timing fields | Bottleneck identification via decision tree (Section 6.2) |
| 2 | **Per-origin breakdown** | Track 3: group timing by dst_ip | "10.0.1.7 P95 TTFB=3.2s vs 10.0.1.5 P95=230ms" |
| 3 | **Check site routing** | Track 3: src_site vs dst_site | "62% cross-site routing → recommend LocalEndpointsPreferred" |
| 4 | **Check HTTP protocol** | LB config: HTTP version negotiation | "Origin using HTTP/1.1 — recommend enabling HTTP/2 for connection reuse" |
| 5 | **Check idle timeout** | Track 3: duration_with_data_tx_delay; LB config: idle timeout | "Connection Idle Timeout may need adjustment" |
| 6 | **Path-specific analysis** | Agg-A5 (top paths) + Track 3 timing per path | "POST /api/report P95=4.1s vs all-paths P95=230ms → origin processing" |
| 7 | **Remediation** | Based on bottleneck location | Specific: increase timeout / enable HTTP/2 / set LocalEndpointsPreferred / fix origin |

### 7.5 Investigation: Bot Surge

**Trigger:** Bot traffic ratio > 2x baseline OR suspicious user count spike

| Step | Action | API / Data Source | Output |
|------|--------|-------------------|--------|
| 1 | **Fetch bot traffic overview** | Bot Defense: traffic/overview | Human/Bot/Malicious split with percentages |
| 2 | **Get attack intent** | Bot Defense: top/type/malicious/dimension/attackintent | "78% credential stuffing, 15% scraping, 7% carding" |
| 3 | **Identify top attackers** | Bot Defense: top/type/malicious/dimension/ip, /ua, /asorg | Top malicious by IP, UA, ASN org |
| 4 | **Identify target endpoints** | Bot Defense: top/type/malicious/dimension/endpoints | "/api/login (credential stuffing), /search (scraping)" |
| 5 | **JA4 clustering** | Track 3: group JA4 for bot-classified traffic | Tool identification |
| 6 | **Check bot defense config** | LB config: bot defense policy, protected endpoints | Is bot defense enabled? Which endpoints protected? |
| 7 | **Check mitigation effectiveness** | Bot Defense: traffic/malicious/overview/actions | "Block: 89%, Challenge: 8%, Allow: 3%" |
| 8 | **Generate response** | GetSuggestedBlockClientRule for top malicious IPs | One-click block rules |

### 7.6 Investigation: Service Policy Block Surge

**Trigger:** `ext_authz_denied` count spikes (from Agg-A2)

| Step | Action | API / Data Source | Output |
|------|--------|-------------------|--------|
| 1 | **Identify blocking policy** | Track 3: extract policy name/rule from policy_hits | "Policy 'geo-restrict-v2', rule 'block-cn-ru'" |
| 2 | **Fetch policy config** | GET service_policy config | Full rule set with match conditions |
| 3 | **Profile blocked traffic** | Agg-A3 (country), Agg-A6 (src_ip) filtered to 403 | Who is being blocked: IPs, countries, paths |
| 4 | **Check audit logs** | Audit logs filtered for service_policy changes | "Policy modified by admin at 14:05 — 10 min before spike" |
| 5 | **Cross-reference reputation** | Track 3: ip_trustscore for blocked IPs | "72% of blocked IPs have trustscore > 80 → likely false blocks" |
| 6 | **Calculate false-block rate** | Clean users blocked / total blocked | False-block percentage |
| 7 | **Remediation** | GetSuggestedTrustClientRule / policy adjustment | Trust rule for legitimate users / policy fix |

### 7.7 Investigation: Rate Limit Impact Assessment

**Trigger:** `rate_limiter_action` appearing in Track 3 policy_hits

| Step | Action | API / Data Source | Output |
|------|--------|-------------------|--------|
| 1 | **Count rate-limited requests** | Track 3: count policy_hits with rate_limiter_action | "342 requests rate-limited in last 5 min" |
| 2 | **Profile rate-limited users** | Track 3: group rate-limited by src_ip + ip_trustscore | Clean vs malicious user breakdown |
| 3 | **Identify affected paths** | Track 3: group rate-limited by req_path | "/api/search: 89%, /api/login: 11%" |
| 4 | **Compare to config** | GET rate_limiter config | "Limit: 100 req/min. Top user: 147 req/min" |
| 5 | **Calculate false-limit rate** | Clean users (trustscore > 70) being limited / total limited | "23% of rate-limited users are clean → limit may be too aggressive" |
| 6 | **Remediation** | If high false-limit: suggest higher threshold. If effective: show attack blocked. | GetSuggestedRateLimitRule |

### 7.8 Investigation: TLS/Certificate Error

**Trigger:** 503 errors with TLS_error patterns in rsp_code_details (from Agg-A2)

| Step | Action | API / Data Source | Output |
|------|--------|-------------------|--------|
| 1 | **Classify TLS error** | Agg-A2: match rsp_code_details against TLS pattern variants | Error variant identification |
| 2 | **Fetch origin pool TLS config** | GET origin pool config: TLS section | Use TLS on/off, verification mode, custom CA |
| 3 | **Map to KB remediation** | K000146828 mapping per variant | Specific fix per error: |
| | | • `Connection_reset_by_peer` | → Configure TLS in Origin Pool or skip verification (K000147459) |
| | | • `WRONG_VERSION_NUMBER` | → Verify "Use TLS" matches origin port protocol |
| | | • `CERTIFICATE_VERIFY_FAILED` | → Skip verification OR add custom CA list |
| | | • `connection_termination` | → Align idle timeout: XC < origin server timeout |

### 7.9 Investigation: Route Configuration Error

**Trigger:** 404 `route_not_found` spike (from Agg-A2)

| Step | Action | API / Data Source | Output |
|------|--------|-------------------|--------|
| 1 | **Extract request authorities** | Agg-A7 (by domain/authority) filtered to 404 | What clients are requesting |
| 2 | **Fetch LB config** | GET HTTP LB: domains, routes | Configured domains and route match conditions |
| 3 | **Compare** | Diff step 1 vs step 2 | "Requests for 'api-v2.example.com' but no matching domain configured" |
| 4 | **Check CNAME** | LB config: DNS info / CNAME value | Does request match CNAME? |
| 5 | **Check health checks** | GET origin pool health check status | "All health checks failed → HTTP returns 404, HTTPS returns 0" |
| 6 | **Check audit logs** | Audit logs for route/domain changes | Recent route modifications |
| 7 | **Remediation** | Add missing domain / fix route match / fix DNS | Specific config actions |

### 7.10 Investigation: Credential Stuffing Attack

**Trigger:** Bot Defense credential-stuffing-attack insight fires

| Step | Action | API / Data Source | Output |
|------|--------|-------------------|--------|
| 1 | **Fetch credential stuffing metrics** | Bot Defense: insight/credential-stuffing-attack | Attack volume, success rate, timeline |
| 2 | **Identify targeted endpoints** | Bot Defense: top/type/malicious/dimension/endpoints (filtered) | Login pages, auth APIs |
| 3 | **Profile sources by intent** | Bot Defense: top/type/malicious/dimension/ip/{attack_type} | Top IPs doing credential stuffing |
| 4 | **Check bot defense effectiveness** | Bot Defense: traffic/malicious/overview/actions | Block vs challenge vs allow for cred stuffing |
| 5 | **Check rate limiters on login** | Rate limiter config for login paths | Are login endpoints rate-limited? |
| 6 | **Generate remediation** | GetSuggestedBlockClientRule + GetSuggestedRateLimitRule | Block top sources + rate limit login |

### 7.11 Investigation: Client-Side Script Attack (Magecart)

**Trigger:** CSD detects new malicious script or suspicious domain

| Step | Action | API / Data Source | Output |
|------|--------|-------------------|--------|
| 1 | **Fetch detected scripts** | CSD: scripts + scripts/{id}/behaviors | Script inventory with behavior classification |
| 2 | **Identify affected form fields** | CSD: scripts/{id}/formFields | "Script accessing 'cc-number', 'cc-cvv' fields → CRITICAL" |
| 3 | **Check network interactions** | CSD: scripts/{id}/networkInteractions | "Script communicating with evil-exfil.com" |
| 4 | **Count affected users** | CSD: scripts/{id}/affectedUsers | Scale of impact |
| 5 | **Check mitigation status** | CSD: detected_domains + mitigated domains list | Is the domain already mitigated? |
| 6 | **Severity determination** | Based on targeted form fields | Payment fields = CRITICAL, login = HIGH, other = MEDIUM |
| 7 | **Remediation** | CSD: update_domains (add to mitigated list) | Block the malicious domain |

### 7.12 Investigation: DNS Failure

**Trigger:** DNS LB pool member health check failure

| Step | Action | API / Data Source | Output |
|------|--------|-------------------|--------|
| 1 | **Fetch DNS LB health** | dns_load_balancers/{name}/health_status | Overall DNS LB status |
| 2 | **Get pool member status** | dns_lb_pools/{pool}/health_status | Per-member health: which are down? |
| 3 | **Get health change events** | dns_lb_pools/{pool}/health_status_change_events | Timeline: when did failures start? |
| 4 | **Check failover** | DNS LB config: failover policy | Is traffic failing over to healthy members? |
| 5 | **Check DNS query metrics** | dns_zones/metrics | Is query volume abnormal? (possible DNS DDoS) |
| 6 | **Remediation** | DNS-specific: check origin records, HC config, pool weights | Fix underlying DNS resolution

---

## 8. INVESTIGATION CHAINING

### 8.1 Chain Trigger Paths

| Parent | Finding | Child |
|--------|---------|-------|
| Origin 5xx | TLS errors dominant | → TLS/Certificate Investigation |
| Origin 5xx | `via_upstream` dominant | → Terminal: "Origin is source — check origin" |
| Origin 5xx | Circuit breaker UO flag | → Capacity assessment |
| Origin 5xx | Recent config change | → Config Change Impact Analysis |
| DDoS | WAF signatures also spiking | → WAF Attack Investigation |
| DDoS | Rate limiters firing | → Rate Limit Impact Assessment |
| WAF Attack | Bot classifications dominant | → Bot Surge Investigation |
| WAF Attack | FP score > 70 for top sigs | → Quick FP Assessment |
| Latency Spike | Cross-site routing | → Route Optimization Recommendation |
| Route Config Error | Health checks all failed | → Origin Health Investigation |
| Bot Surge | Credential stuffing detected | → Credential Stuffing Investigation |

### 8.2 Display

Investigation Panel shows a **tree**: parent at root, child investigations branching below. Each node: status indicator (running/complete), finding summary, severity badge, remediation actions.

---

## 9. ANOMALY DETECTION ENGINE (23 DETECTORS)

### 9.1 Baseline (persisted to localStorage)

```typescript
interface Baseline {
  // Traffic (from Track 1 total_hits + Track 2 aggregation)
  avgRps: number; stdDevRps: number;
  avgSampleRate: number;
  
  // Errors (from Track 2 Agg-A1)
  avgErrorRate: number; avg5xxRate: number; avg4xxRate: number;
  
  // Security (from Track 2 Agg-S1)
  avgSecEvents: number; avgWafBlocks: number;
  avgThreatMeshHits: number; avgBotRatio: number;
  knownSignatureIds: Set<string>;
  
  // Performance (from Track 3 raw logs)
  avgLatencyP50: number; avgLatencyP95: number;
  avgOriginTTFB: number;
  
  // CDN (from Track 2 Agg-A8 or graph/lb_cache_content)
  avgCacheHitRatio: number;
  
  // Geo/Identity
  topCountries: Map<string, number>;
  topJA4: Set<string>;
  
  // Per-domain/path baselines
  perDomain: Map<string, DomainBaseline>;
  perWatchPath: Map<string, PathBaseline>;
  
  sampleCount: number; lastUpdated: string;
}
```

### 9.2 Complete Detector Table

| # | Detector | Source | Trigger | Severity | Investigation |
|---|---------|--------|---------|----------|---------------|
| 1 | RPS Spike | Track 1 | > avg + 3σ | HIGH/MEDIUM | DDoS (if sec events too) |
| 2 | RPS Drop | Track 1 | < avg - 3σ | HIGH | Origin Down |
| 3 | 5xx Error Spike | Agg-A1 | > 2x baseline | CRITICAL/HIGH | Origin 5xx |
| 4 | 4xx Error Spike | Agg-A1 | > 3x baseline | MEDIUM | Route Config (if 404) |
| 5 | WAF Surge | Agg-S1 | > 3x baseline | HIGH | WAF Attack |
| 6 | New Signature | Agg-S2 | ID not in baseline | MEDIUM | FP/TP Assessment |
| 7 | Latency Spike | Track 3 | P95 > 3x baseline | HIGH | Latency |
| 8 | Origin Down | Agg-A2 | no_healthy_upstream | CRITICAL | Origin Health |
| 9 | Geo Anomaly | Agg-A3 | New country >5% | MEDIUM | Geo Assessment |
| 10 | Bot Surge (access logs) | Agg-A8 | Bot ratio > 2x | HIGH | Bot |
| 11 | Rate Limit Fire | Track 3 | rate_limiter_action | MEDIUM | Rate Limit Impact |
| 12 | Threat Mesh New IP | Agg-S3 | tenant_count ≥5 | HIGH | Threat Mesh |
| 13 | CDN Cache Degradation | Agg-A8/graph | Hit ratio drop >15pt | HIGH | CDN Cache |
| 14 | Config Change | Audit Logs | New entry | INFO→escalates | Config Correlation |
| 15 | Sample Rate Surge | Track 3 | > 5x increase | MEDIUM | Traffic Surge |
| 16 | Bot Traffic Surge (BD) | Bot Defense | Malicious % > 2x | HIGH | Bot |
| 17 | Credential Stuffing | Bot Defense | Attack detected | CRITICAL | Credential Stuffing |
| 18 | Synthetic Monitor Fail | Synthetic | Monitor unhealthy | CRITICAL | External Availability |
| 19 | DNS Health Degradation | DNS LB | Pool member fail | CRITICAL | DNS Failure |
| 20 | Client-Side Script Alert | CSD | New malicious script | CRITICAL | Magecart |
| 21 | WAF Signature Update | WAF Changelog | New sigs staged | INFO | Sig Update Correlation |
| 22 | Network DDoS Alert | InfraProtect | L3/L4 alert | CRITICAL | Network DDoS |
| 23 | API Vulnerability | Virtual Host | New vulnerability | HIGH | API Security |
| — | F5 TSA Alert | Alerts API | Active TSA alert | Per F5 severity | Surface F5 detection |
| — | F5 Security Incident | Incidents API | Active incident | Per F5 severity | Surface F5 incident |

### 9.3 Threat Level

```
CRITICAL: Any CRITICAL anomaly OR origin down OR DNS down OR F5 critical alert OR Magecart
HIGH:     Any HIGH anomaly OR active DDoS (L7 or L3/L4) OR F5 major alert
ELEVATED: Any MEDIUM anomaly OR ≥2 concurrent anomalies OR F5 minor alert
NOMINAL:  No anomalies, all metrics within baseline
```

---

## 10. OPERATOR QUESTIONS DASHBOARD (8 TABS, 50+ QUESTIONS)

### Tab 1: Health

| Question | Data Source | Computed Answer |
|----------|------------|----------------|
| "Is the application up?" | Track 1 total_hits + Agg-A1 (2xx count) + Active alerts | Green/Red indicator: 2xx% + absence of critical alerts |
| "Are all origins healthy?" | Agg-A4 (by dst_ip with 5xx filter) + origin pool health check config | Per-origin health grid with status LED, P95 latency, error % |
| "What's the error rate?" | Agg-A1 (rsp_code: sum 4xx + 5xx / total) | Real-time percentage with trend arrow (▲/▼ vs last cycle) |
| "What's causing 5xx errors?" | Agg-A2 (by rsp_code_details) + K000146828 KB | Auto-classified table: error type, count, root cause label, severity |
| "Are there active alerts?" | GET /alerts (active) | Live feed with severity badges (critical/major/minor) |
| "Any config changes recently?" | Audit logs (last 6 hours) | Change log: time, user, object, operation |

### Tab 2: Security

| Question | Data Source | Computed Answer |
|----------|------------|----------------|
| "Are we under attack?" | Anomaly engine threat level + active incidents | Threat level gauge with summary of evidence |
| "Top WAF signatures?" | Agg-S2 (by signatures.id, top 20) | Top 10 with hit count + FP/TP confidence hint from fp-scorer |
| "Who is attacking?" | Agg-S3 (by src_ip, top 20) + Track 3 JA4 clustering | Attacker table: IP, country, ASN, events, JA4, type badge |
| "Any false positives?" | FP Analyzer 7-signal scoring on top firing signatures | Quick assessment with confidence % per signature |
| "Bot traffic normal?" | Bot Defense traffic/overview OR Agg-A8 waf_action | Bot vs human % with trend vs baseline |
| "Rate limits being hit?" | Track 3 policy_hits.rate_limiter_action | Count + affected paths + effectiveness (clean vs malicious blocked) |

### Tab 3: Performance

| Question | Data Source | Computed Answer |
|----------|------------|----------------|
| "How fast is the app?" | Track 3: 5 timing fields, compute P50/P95/P99 | Visual waterfall showing Client→XC→Origin→XC→Client with ms values |
| "Origin slow?" | Track 3: time_to_first_upstream_rx_byte P95 | Origin TTFB gauge vs baseline, per-origin breakdown |
| "Slowest paths?" | Agg-A5 (by req_path, top 30) + Track 3 timing per path | Top 10 paths sorted by P95 latency |
| "Traffic volume?" | Track 1 total_hits / window_seconds | RPS gauge with 12-cycle sparkline |
| "Traffic by country?" | Agg-A3 (by country) | Bar chart with anomaly flags on new/unexpected countries |
| "Cross-site routing?" | Track 3: count where src_site ≠ dst_site | Percentage + recommendation if > 10% |

### Tab 4: CDN

| Question | Data Source | Computed Answer |
|----------|------------|----------------|
| "Cache hit ratio?" | graph/lb_cache_content OR Track 3 x-cache-status | Hit ratio gauge with trend arrow and baseline comparison |
| "Why are requests missing cache?" | Track 3: classify MISS by reason | Breakdown: no cache-control, set-cookie, non-GET, non-cacheable status |
| "WAF set-cookie causing misses?" | Track 3: detect TS cookie in MISS responses | Yes/No with count. If Yes: "Known F5 issue — configure Ignore-Response-Cookie" |
| "Origin pull rate?" | MISS count / total from cache analysis | Pull rate % with trend (lower = better CDN performance) |
| "TTFB hit vs miss?" | Track 3: split time_to_first_downstream_tx_byte by cache status | Side-by-side: HIT P95=12ms vs MISS P95=340ms → "CDN saves 328ms" |

### Tab 5: API Security

| Question | Data Source | Computed Answer |
|----------|------------|----------------|
| "How many API endpoints?" | virtual_host.api_endpoints/stats | Total discovered + shadow + inventory counts |
| "New/unknown APIs?" | virtual_host.api_endpoints (compare vs last known) | New endpoint list with paths and methods |
| "Sensitive data exposed?" | virtual_host.api_endpoints/summary/top_sensitive | PII type, endpoint, risk level |
| "Authentication issues?" | API Discovery auth state monitoring | Unauthenticated endpoints requiring auth |
| "Known vulnerabilities?" | virtual_host.vulnerabilities | Vulnerability list with severity and affected endpoints |

### Tab 6: Bot Defense

| Question | Data Source | Computed Answer |
|----------|------------|----------------|
| "% of traffic that's bots?" | Bot Defense: traffic/overview | Human/Bot/Malicious donut with exact percentages |
| "Credential stuffing?" | Bot Defense: insight/credential-stuffing-attack | Detected/Not-detected + affected endpoints + volume |
| "What are bots doing?" | Bot Defense: top/type/malicious/dimension/attackintent | Intent breakdown: cred stuffing %, scraping %, carding % |
| "Bot defense effective?" | Bot Defense: traffic/malicious/overview/actions | Pie: Blocked %, Challenged %, Allowed % |
| "Top bot attackers?" | Bot Defense: top/type/malicious/dimension/ip, /ua, /asorg | Top 10 by IP, user agent, and ASN organization |

### Tab 7: Infrastructure

| Question | Data Source | Computed Answer |
|----------|------------|----------------|
| "L3/L4 DDoS attacks?" | InfraProtect: alerts, events_summary | Active DDoS alerts with severity and target network |
| "Network firewalls blocking?" | Firewall logs aggregation | Block count with trend arrow |
| "Site healthy?" | graph/connectivity/node with healthscore | Site health score gauge (0-100%) |
| "Synthetic monitors passing?" | synthetic_monitor/health | Pass/Fail per monitor with last check time |
| "DNS resolution working?" | DNS LB health status | Per-pool-member health grid |

### Tab 8: Operations

| Question | Data Source | Computed Answer |
|----------|------------|----------------|
| "WAF policy config?" | GET app_firewall config | Mode (blocking/monitoring), exclusion count, detection settings |
| "Certificates expiring?" | Certificate config + synthetic TLS report | Countdown per cert: "*.example.com expires in 23 days" |
| "DDoS threshold?" | LB config: l7_ddos_protection | Threshold value vs current observed peak |
| "Config changes today?" | Audit logs (last 24h) | Full change log: time, user, object type, operation |
| "Current LB config?" | GET HTTP LB config summary | Route count, origin count, security features enabled |

---

## 11. DASHBOARD PANEL SPECIFICATION (21 PANELS)

### 11.1 Layout

```
┌──────────────────────────────────────────────────────────────────────────┐
│ [THREAT ORB] [RPS] [ERR%] [SEC] [ORIGIN] [CDN%] [BOT%] [DNS●] [SYN●] [⏱]│
│  NOMINAL   ~2.3K  0.12%  14blk P95:230ms 94.2%  3.1%  OK     OK   43s  │
├──────────────────────[Domain: ALL ▼]──────────────────────────[HISTORY ◄►]│
├───────────────────────────────┬───────────────────────────────────────────┤
│ 1. TRAFFIC TIME SERIES        │ 2. SECURITY EVENT BREAKDOWN              │
│    RPS area + error line +    │    Donut: WAF/TM/Bot/Policy              │
│    sec event markers          │    + Top 5 signatures                    │
│    Baseline band + anomalies  │    + Top 5 violations                    │
├───────────────────────────────┼───────────────────────────────────────────┤
│ 3. RESPONSE CODE DIST.        │ 4. TOP ATTACKING IPs                     │
│    Stacked area 2xx/3xx/4xx/  │    IP|Country|ASN|Events|JA4|Type        │
│    5xx over cycles            │    Multi-vector + NEW badges             │
├──────────┬────────────────────┼───────────────────────────────────────────┤
│ 5. GEO   │ 6. LATENCY         │ 7. ERROR DIAGNOSIS                       │
│    DIST  │    WATERFALL        │    rsp_code_details grouped              │
│    Bars  │    5-field bars     │    count|trend|root cause|severity       │
│    +anom │    Per-origin tab   │    Click → investigation                 │
├──────────┴────────────────────┴───────────────────────────────────────────┤
│ 8. ORIGIN HEALTH GRID                                                     │
│    [10.0.1.5 ● OK 230ms 0.1%] [10.0.1.6 ● OK 210ms 0%] [10.0.1.7 ●FAIL]│
├───────────────────────────────────────────────────────────────────────────┤
│ 9. BOT INTELLIGENCE (if Bot Defense enabled)                              │
│    [Human 82%][Good Bot 15%][Bad Bot 3%] | Attack Intent | Top Malicious │
├───────────────────────────────────────────────────────────────────────────┤
│ 10-14. CONDITIONAL PANELS (if features enabled):                          │
│    CDN Cache Panel | CSD Scripts | DNS Health | InfraProtect | Synthetic  │
├───────────────────────────────────────────────────────────────────────────┤
│ 15. INCIDENT TIMELINE (auto-detected + F5 native + investigations)        │
├───────────────────────────────────────────────────────────────────────────┤
│ 16. INVESTIGATION PANEL (expandable — tree with parent/child)             │
├───────────────────────────────────────────────────────────────────────────┤
│ 17. OPERATOR QUESTIONS (8-tab Q&A dashboard)                              │
├───────────────────────────────────────────────────────────────────────────┤
│ 18. LIVE EVENT FEED (terminal, color-coded, filterable)                   │
│    [All] [Security] [Errors] [Watch Paths] [Bot] [DNS]                   │
└───────────────────────────────────────────────────────────────────────────┘
```

### 11.2 Status Strip Gauges

| Gauge | Data Source | When Shown |
|-------|-----------|-----------|
| Threat Level Orb | Anomaly engine | Always |
| RPS | Track 1 total_hits | Always |
| Error % | Agg-A1 | Always |
| Security Events | Agg-S1 | Always |
| Origin P95 | Track 3 timing | Always |
| CDN Hit % | CDN aggregation | If CDN selected |
| Bot % | Bot Defense overview | If Bot Defense enabled |
| DNS ● | DNS LB health | If DNS selected |
| Synthetic ● | Synthetic health | If Synthetic enabled |
| Countdown ⏱ | Internal timer | Always |
| Domain Selector | Config | If multi-domain |
| History Scrubber | Ring buffer | Always |

### 11.3 Conditional Feature Panels

These panels appear only when the corresponding feature is detected/enabled in the room config:

| Panel | Condition | Content |
|-------|-----------|---------|
| Bot Intelligence | `features.botDefenseEnabled` | Human/Bot/Malicious donut, attack intent, top malicious, credential stuffing indicator |
| CDN Cache | CDN distributions selected | Hit ratio, miss reasons, TS cookie check, origin pull rate |
| Client-Side Defense | `features.clientSideDefenseEnabled` | Detected scripts, suspicious domains, affected form fields |
| DNS Health | DNS zones/LBs selected | DNS query metrics, pool member health, health change events |
| InfraProtect DDoS | `features.infraProtectEnabled` | L3/L4 alerts, active mitigations, top talkers |
| Synthetic Health | `features.syntheticMonitorsEnabled` | Monitor pass/fail, TLS cert status, availability % |

---

## 12. FEATURE-SPECIFIC MONITORING SUBSYSTEMS

### 12.1 CDN Monitoring

| Metric | Source | Value |
|--------|--------|-------|
| Cache Hit Ratio | Agg by cache status or `graph/lb_cache_content` | Primary CDN health indicator |
| Miss Reasons | Access log analysis: no cache-control, set-cookie, non-GET | Why caching isn't working |
| WAF TS Cookie Conflict | Detect TS cookie in MISS responses | Known F5 XC issue: WAF set-cookie breaks CDN caching |
| Origin Pull Rate | MISS / total | How much bypasses cache |
| TTFB Hit vs Miss | Track 3 timing split by cache status | CDN value quantification |

### 12.2 Bot Defense Intelligence

| Data Point | API | Value |
|-----------|-----|-------|
| Traffic Split | `traffic/overview` | Human % / Bot % / Malicious % |
| Attack Intent | `top/type/malicious/dimension/attackintent` | Why bots are attacking (credential stuffing, scraping, carding) |
| Top Malicious | `top/type/malicious/dimension/ip`, `/ua`, `/asorg` | Who is attacking |
| Attacked Endpoints | `top/type/malicious/dimension/endpoints` | What is being attacked |
| Credential Stuffing | `insight/credential-stuffing-attack` | Dedicated login abuse detection |
| Mitigation Actions | `traffic/malicious/overview/actions` | Block vs challenge vs allow effectiveness |
| Peer Intelligence | `reporting/peers/threat-types` | How you compare to F5 network peers |

### 12.3 Client-Side Defense

| Data Point | API | Severity |
|-----------|-----|----------|
| New Malicious Script | `csd/scripts` + behavior analysis | CRITICAL if form fields targeted |
| Suspicious Domain | `csd/detected_domains` | HIGH |
| Form Field Exfiltration | `csd/scripts/{id}/formFields` | CRITICAL if payment/login fields |
| Affected Users | `csd/scripts/{id}/affectedUsers` | Scale indicator |

### 12.4 DNS Monitoring

| Data Point | API | Severity |
|-----------|-----|----------|
| DNS LB Health | `dns_load_balancers/health_status` | CRITICAL if all members down |
| Pool Member Failure | `dns_lb_pools/{pool}/health_status` | HIGH per member |
| Health Change Events | `health_status_change_events` | Timeline data |
| DNS Query Metrics | `dns_zones/metrics` | Volume + error rate |

### 12.5 InfraProtect (L3/L4 DDoS)

| Data Point | API | Severity |
|-----------|-----|----------|
| DDoS Alert | `infraprotect/alerts` | Per F5 severity |
| Active Mitigation | `infraprotect/mitigations` | Ongoing protection |
| Top Talkers | `graph/l3l4/top_talkers` | Attack source IDs |
| Event Summary | `infraprotect/events_summary` | Quick overview |

### 12.6 Synthetic Monitoring (External)

| Data Point | API | Severity |
|-----------|-----|----------|
| HTTP Monitor Health | `http-monitors-health` | CRITICAL if failing |
| DNS Monitor Health | `dns-monitors-health` | CRITICAL if failing |
| TLS Certificate | `tls-report-summary` | HIGH if near expiry |
| Global Availability | `global-summary` | Availability % |

---

## 13. CROSS-LAUNCH INTEGRATION

| Action in SOC Room | Target Tool | Context Passed |
|--------------------|-------------|----------------|
| Click WAF signature | FP Analyzer | LB, namespace, signature ID, time range |
| Click "DDoS" incident | DDoS Advisor | LB, namespace, time range |
| Click a hot path | Log Analyzer | Namespace, path filter, time range |
| Click attacking IP | IP Deep Dive (inline) | IP, events, geo, JA4, threat mesh |
| Click origin in health grid | Config Viewer | LB → origin pool inspection |
| Click "Run Audit" | Security Auditor | Namespace pre-selected |
| Click WAF exclusion suggestion | FP Analyzer | Pre-filled exclusion from API |
| Click rate limit suggestion | Rate Limit Advisor | Pre-filled config from API |
| Click DDoS suggestion | DDoS Advisor | Pre-filled threshold |
| Click CDN cache issue | (Future) CDN Ops Console | Distribution, cache rule context |
| Click DNS failure | Config Viewer | DNS zone/LB config |
| Click bot attacker | (Inline) Bot forensics | Bot Defense detailed report |

---

## 14. STATE MANAGEMENT, MEMORY & HISTORY

### 14.1 Ring Buffers

| Structure | Max Size | Eviction |
|-----------|----------|----------|
| Time series | 288 points (24h @ 5min) | Oldest first |
| Per-cycle snapshots | 72 (6h @ 5min) | Oldest first |
| Live event feed | 1,000 events | Oldest first |
| Incidents | 200 | Oldest resolved |
| Investigations | 50 | Oldest completed |
| Audit log entries | 100 | Oldest first |

### 14.2 Browser Tab Handling

- **Tab hidden:** Pause polling, show "PAUSED" on resume
- **Tab visible:** Catch-up fetch (Track 1+2+3), resume normal interval
- **Hidden >30min:** Clear stale baseline, rebuild over 3 cycles
- **Multi-tab:** `BroadcastChannel` warning → one tab polls, other receives

### 14.3 History Scrubber

Time slider in status strip: slide to review any past cycle snapshot. ALL panels update to historical data. "LIVE" button returns to real-time.

### 14.4 Shift Summary

One-click PDF export covering last N hours: peak metrics, all incidents, all investigations, all anomalies, all config changes, top attackers, threat summary.

---

## 15. UI/UX: FUTURISTIC SOC AESTHETIC

- **Base:** #0a0e1a with animated hexagonal grid background
- **Primary:** Cyan #00d4ff | **Healthy:** Neon green #00ff88 | **Warning:** Amber #ffbe0b | **Critical:** Neon red #ff0040
- **Typography:** JetBrains Mono (data) + Space Grotesk (labels)
- **Panels:** Glass effect (backdrop-filter: blur(12px), rgba(15,20,35,0.7)) with 1px glowing borders
- **Ambient:** Background hue shifts with threat level (cool blue → warm amber → deep red)
- **Threat Orb:** Pulsing sphere, speed: NOMINAL=3s, ELEVATED=1.5s, HIGH=0.8s, CRITICAL=0.4s
- **Data Pulse:** Updated panels flash border on new data
- **Event Feed:** Monospace, color-coded, CRT scanline overlay
- **Delta Badges:** ▲/▼ on every metric showing cycle-over-cycle change
- **Countdown Ring:** Circular progress for next-poll timer

---

## 16. PHASED DELIVERY PLAN

### Phase 1: Foundation (~5,000 lines)
- Room lobby + room creation wizard with feature auto-detection
- 4-track polling engine with aggregation-first architecture
- Track 1 + Track 2 (all 8 access log aggregations + 5 security aggregations + alerts + audit logs)
- Track 3 light (raw logs for event feed + latency waterfall)
- Sample rate handling
- Status strip with all gauges (threat, RPS, error, security, origin, countdown)
- Domain selector
- Traffic time series chart with baseline band
- Response code distribution (from Agg-A1)
- Error diagnosis panel (from Agg-A2 + K000146828 KB)
- Origin health grid (from Agg-A4)
- Live event feed (terminal style, filterable)
- Anomaly detectors #1-8 (core traffic/error/security)
- Basic incident timeline
- localStorage persistence (rooms + baselines)
- Futuristic SOC UI shell with ambient threat level

### Phase 2: Full Intelligence (~4,000 lines)
- All 23 anomaly detectors
- Full incident lifecycle (create, track, auto-resolve)
- Security event breakdown panel (donut + top sigs from Agg-S1/S2)
- Top attacking IPs (from Agg-S3 + JA4 from Track 3)
- Geo distribution (from Agg-A3 with anomaly flags)
- Latency waterfall with auto-diagnosis
- Hot paths panel (from Agg-A5)
- Bot Intelligence panel (from Bot Defense Reporting API)
- CDN monitoring panel (cache hit/miss, TS cookie detection)
- Conditional feature panels (CSD, DNS, InfraProtect, Synthetic)
- History ring buffer + time scrubber
- Per-domain baseline and anomaly detection
- Watch path monitoring with custom thresholds

### Phase 3: Auto-Investigation & Remediation (~4,000 lines)
- All 12 investigation workflows
- Investigation chaining architecture
- F5 Rule Suggestion API integration (all 11 suggestion endpoints)
- Root cause engine using complete rsp_code_details KB
- Remediation recommendation with one-click actions
- Operator Questions Dashboard (all 8 tabs, 50+ questions)
- Full cross-launch integration
- Shift summary PDF export
- Multi-tab coordination via BroadcastChannel

### Phase 4: Advanced (~3,000 lines)
- F5 AI Assistant integration (AIAssistantQuery)
- API Security deep integration (vulnerabilities, endpoints, sensitive data)
- Peer intelligence from Bot Defense
- WAF signature changelog correlation
- Comparison mode (now vs same time yesterday)
- Sound/notification system
- Configurable panel layout (drag-and-drop)
- Fullscreen focus mode
- Room sharing (export/import JSON)
- Server-side polling (Vite plugin)

---

## 17. FILE STRUCTURE

```
src/
  pages/
    SOCLobby.tsx                         # Multi-room lobby
    SOCRoom.tsx                          # Main SOC room (~4,500 lines)
  services/
    live-soc/
      types.ts                           # All type definitions (~800 lines)
      index.ts                           # Public exports
      polling-engine.ts                  # 4-track fetch orchestrator
      aggregation-builder.ts             # Builds aggregation query payloads
      metrics-calculator.ts              # Aggregation results → dashboard data
      raw-log-processor.ts               # Track 3 raw log → timing/JA4/events
      anomaly-detector.ts                # Baseline + 23 detectors
      incident-manager.ts                # Incident lifecycle
      investigation-engine.ts            # 12 workflows + chaining
      investigation-chains.ts            # Chain trigger definitions
      error-diagnosis.ts                 # K000146828 knowledge base
      cdn-monitor.ts                     # CDN cache analysis
      bot-defense-fetcher.ts             # Bot Defense Reporting API wrapper
      infraprotect-fetcher.ts            # InfraProtect DDoS API wrapper
      csd-fetcher.ts                     # Client-Side Defense API wrapper
      synthetic-fetcher.ts               # Synthetic Monitoring API wrapper
      dns-monitor.ts                     # DNS health monitoring
      api-security-monitor.ts            # Virtual host API security data
      config-change-tracker.ts           # Audit log correlation
      alert-fetcher.ts                   # Alerts API wrapper
      rule-suggestion.ts                 # 11 Rule Suggestion API wrappers
      room-storage.ts                    # localStorage CRUD
      sample-rate.ts                     # Sample rate utilities
      history-buffer.ts                  # Ring buffer + shift summary
  components/
    soc/
      ThreatLevelOrb.tsx                 # Pulsing threat sphere
      StatusStrip.tsx                    # Gauges + domain selector + countdown
      TrafficTimeSeries.tsx              # RPS chart with baseline band
      SecurityBreakdown.tsx              # Security donut + top sigs
      ResponseCodeDist.tsx               # Stacked 2xx/3xx/4xx/5xx
      ErrorDiagnosis.tsx                 # rsp_code_details tree + KB
      LatencyWaterfall.tsx               # 5-field timing auto-diagnosis
      OriginHealthGrid.tsx               # Per-dst_ip health
      BotIntelligence.tsx                # Bot Defense dashboard
      CDNMonitor.tsx                     # Cache hit/miss analysis
      CSDMonitor.tsx                     # Client-Side Defense panel
      DNSHealth.tsx                      # DNS monitoring panel
      InfraProtectPanel.tsx              # L3/L4 DDoS panel
      SyntheticHealth.tsx                # External availability
      InvestigationPanel.tsx             # Investigation tree
      LiveEventFeed.tsx                  # Terminal feed
      IncidentTimeline.tsx               # Horizontal timeline
      OperatorQuestions.tsx              # 8-tab Q&A
      AttackerTable.tsx                  # Top IPs + JA4
      GeoDistribution.tsx                # Country bars
      HistoryScrubber.tsx                # Time slider
      RoomCreator.tsx                    # Setup wizard
      RoomCard.tsx                       # Lobby card
      HotPaths.tsx                       # Top paths panel
      DeltaBadge.tsx                     # ▲/▼ indicator
server/
  soc-plugin.ts                          # (Phase 4) Server-side polling
```

**Total estimated: ~16,000 lines across Phase 1-3, ~19,000 with Phase 4**

---

## 18. DIFFERENTIATORS vs F5 XC CONSOLE

| Capability | F5 XC Console | SOC Room |
|-----------|--------------|----------|
| Multi-LB/CDN/DNS unified view | One object at a time | All in single room |
| Multi-customer | Switch namespaces | Room Lobby with health cards |
| Live polling | Manual refresh | Auto 2-5 min with countdown |
| Aggregation-first | Console renders pre-aggregated | Tool uses same aggregation APIs directly |
| Anomaly detection | TSA only (4 metrics) | 23 detectors + F5 TSA + F5 Incidents |
| Bot intelligence | Separate Bot Defense dashboard | Unified in SOC: traffic split, attack intent, credential stuffing |
| L3/L4 + L7 DDoS unified | Separate dashboards | Single panel with both layers |
| Client-side defense | Separate CSD dashboard | Unified in SOC with Magecart alerting |
| DNS health + app health | Separate views | Single room covering DNS→LB→Origin |
| Synthetic + internal | Separate dashboards | External + internal perspective together |
| Error root cause | Raw rsp_code_details | K000146828 KB mapping + investigation |
| Auto-investigation | None | 12 workflows with evidence trees + chaining |
| Rule suggestions in context | Manual navigation | Auto-fetched, one-click remediation |
| Config change correlation | Separate audit log | Auto-correlated with anomaly timestamps |
| JA4 fingerprint analysis | Not surfaced | Attack tool clustering |
| Cross-tool launch | No context passing | Full context to FP Analyzer, DDoS Advisor, etc. |
| Operator Q&A | Manual dashboard navigation | 50+ questions across 8 tabs with live answers |
| Shift handover | No built-in feature | History buffer + PDF summary export |
| API security + WAF + Bot unified | Three separate views | Single operational view |
| Futuristic aesthetic | Enterprise UI | Command center with ambient threat theming |

---

*This document is the definitive, implementation-ready specification for the Live SOC Monitoring Room. It consolidates all findings from 5 prior documents (v1 vision, v1 review, v2 spec, v2 review, v3 spec) with full implementation depth restored for investigation workflows, operator questions, and error diagnosis.*

*API inventory: 311 monitoring endpoints verified across 268 OpenAPI schema files. 18 API families leveraged. ~100 endpoints actively used.*
*Troubleshooting KB: K000146828 (21 error patterns with auto-investigation actions and remediation steps).*
*Feature coverage: HTTP LB, CDN, DNS, Bot Defense (102 reporting endpoints), Client-Side Defense (22 endpoints), InfraProtect L3/L4 DDoS (25 endpoints), Synthetic Monitoring (19 endpoints), API Security, WAF, Service Policies, Rate Limiters.*
*Architecture: Aggregation-first (server-side counting via access_logs/aggregation + security events/aggregation) — complete data, lower API cost, sample-rate immune.*
