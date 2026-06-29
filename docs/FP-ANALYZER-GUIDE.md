# WAF False-Positive Analyzer — Comprehensive Guide

> Authoritative current-state documentation for the **FP Analyzer** (2026 redesign).
> Covers what it is, how it works, the full inner engineering, how to use it, best practices, an FAQ, and an API reference.

> **What changed in the 2026 redesign (read this first):**
> - **One flow, no modes.** The old Quick/Hybrid toggle is gone.
> - **WAF Signatures + Violations only.** Threat Mesh, Service Policy, Bot Defense and API Security scopes were removed.
> - **Client-behavior centric.** Instead of downloading the whole load balancer's access logs, the tool pulls **only the access logs of the IPs that were flagged by WAF events**, and uses each client's *whole-traffic* behavior as a signal.
> - **Response-code aware.** `200` (origin accepted) leans **false positive**, `404`/`4xx` leans **true positive** — with a guard so a `200` on a malicious payload is surfaced as a **possible successful exploit**, not hidden.

---

## Table of contents

1. [What it is](#1-what-it-is)
2. [Background: the F5 XC concepts you need](#2-background-the-f5-xc-concepts-you-need)
3. [How it works (high level)](#3-how-it-works-high-level)
4. [Architecture & inner engineering](#4-architecture--inner-engineering)
5. [The scoring engine in detail](#5-the-scoring-engine-in-detail)
6. [AI-WAF intelligence](#6-ai-waf-intelligence)
7. [Sampling, completeness & accuracy](#7-sampling-completeness--accuracy)
8. [Exclusion generation](#8-exclusion-generation)
9. [How to use the tool](#9-how-to-use-the-tool)
10. [Best practices](#10-best-practices)
11. [FAQ](#11-faq)
12. [API reference](#12-api-reference)
13. [Limitations & known gaps](#13-limitations--known-gaps)
14. [Development, verification & extension](#14-development-verification--extension)
15. [Glossary](#15-glossary)

---

## 1. What it is

The **FP Analyzer** answers the question every WAF operator faces:

> *"Of all the requests my WAF flagged, which are **false positives** (legitimate traffic mistaken for an attack) versus **true positives** (real attacks)?"*

It connects to an **F5 Distributed Cloud (XC)** tenant, pulls the **WAF security events** for a chosen HTTP Load Balancer over a time window, then — for every flagged **signature** and **violation** — produces:

- a **0–100 FP score** and a **5-level verdict** (highly-likely-FP → confirmed-TP),
- the **evidence and reasoning** behind it, broken into 7 signals,
- and, for confirmed false positives, a **ready-to-apply WAF exclusion policy** (export JSON, or stage into the tenant).

The defining idea of the redesign: **it judges the clients, not just the path.** For every IP caught by a WAF event, the tool pulls that IP's *own* access logs and asks *"what does this client's whole traffic look like — a normal user, or a scanner?"* A signature triggered mostly by **legitimate-looking clients getting 200s** is a false positive; one triggered by **scanners getting 404s on exploit paths** is a true positive.

It is **read-first, analyst-in-the-loop**: it ranks and explains, the human confirms, and only then is an exclusion produced.

---

## 2. Background: the F5 XC concepts you need

| Concept | What it means | Why the analyzer cares |
|---|---|---|
| **Security event** | One record emitted whenever the WAF acts on a request. Always logged (not sampled, except extreme load). | The **flagged requests** — the thing being judged. |
| **Access log** | A **sampled** record of *all* requests (request/response context). | Pulled **per flagged IP** to profile that client's whole-traffic behavior. |
| **Signature** | A specific attack pattern (e.g. SQLi sig `200010019`). Has an **accuracy** (`high`/`medium`/`low`) and **state** (`Enabled`, `AutoSuppressed`, `Staging`). | A signature firing broadly across many legit clients is a classic FP shape. |
| **Violation** | A protocol/format finding (e.g. `VIOL_JSON_MALFORMED`, `VIOL_URL_LENGTH`). | Some violations are almost always FP (length/format); evasions are always TP. |
| **`rsp_code`** | The HTTP response the **origin** returned (200/404/403/5xx). | **200 → app accepted (FP-ward); 404 → probing (TP-ward).** A first-class signal now. |
| **AI-powered WAF** | F5's ML layer: a per-request risk score (`req_risk` High/Med/Low), explanation reasons, a recommended action, and **AutoSuppression** of likely FPs. | F5's own AI verdict is a strong FP/TP signal — folded into Detection Confidence. |
| **WAF exclusion** | A tuning rule telling the WAF to stop flagging a specific signature/violation/attack-type in a context on a path. | The **output** — the fix for a confirmed FP. |

---

## 3. How it works (high level)

A single, linear flow:

```
 1. COLLECT   WAF security events for the LB (2-hour chunks, scroll-paged, adaptive-concurrent),
              EXCLUDING malicious-bot rows server-side (bot_class!~"malicious")
                 │
 1b. BOT AGG  one server-side aggregation pass for the Malicious-bot slice (counts only, no raw)
                 │
 2. INDEX     group by signature_id / violation; collect the set of flagged client IPs
                 │
 3. ENRICH    for the top-500 flagged IPs (by event volume), pull EACH IP's own access logs
              → behavioral profile: success/404 ratio, path diversity, exploit probing,
                request rate, user-agent, WAF-event ratio        ◄── the key step
                 │
 4. SCORE     each signature & violation with the 7 signals → composite → verdict
                 │
 5. REVIEW    confirm FP/TP → generate / stage exclusion policy
```

There is no mode toggle and no separate "enrichment phase" you wait through after results — scoring happens **once**, after the per-IP behavior is collected, so the verdicts you see are final. Per-IP enrichment is light (only the flagged IPs, not the whole LB), so the whole run is fast.

---

## 4. Architecture & inner engineering

### 4.1 Where the code lives

```
src/pages/FPAnalyzer.tsx                 ← the UI (config, polling, tables, detail views, exports, staging)
src/services/fp-analyzer/                ← pure, testable analysis library (runs in browser AND node)
  types.ts                               ← all data contracts (FpSignals, IPBehaviorProfile, units, summaries)
  fp-signals-v2.ts                       ← the 7 redesigned signals + composite (computeFpSignals)
  signal-calculator.ts                   ← shared signal helpers (scoreContext, scorePathBreadth, scoreSignatureAccuracy)
  ai-signals.ts                          ← F5 AI-WAF field parsing + scoring (req_risk, reasons, recommended_action)
  matching-info-analyzer.ts              ← classify matching_info as malicious/benign/ambiguous
  exclusion-generator.ts                 ← build WAF exclusion rules + attack-type rollup
  context-parser.ts                      ← "parameter (q)" → CONTEXT_PARAMETER enum
  adaptive-concurrency.ts / adaptive-worker-pool.ts ← rate-limit-aware fetch pool
  analysis-logger.ts, report-generator.ts, fp-report-pdf.ts, fp-report-excel.ts

server/                                  ← Vite dev-server middleware (the actual backend)
  fp-analyzer-plugin.ts                  ← HTTP routes (/api/fp-analyzer/*)
  progressive-job.ts                     ← THE ENGINE (collect → index → per-IP enrich → score)
  node-api-caller.ts                     ← direct HTTPS to {tenant}.console.ves.volterra.io
```

> **Removed in the redesign:** `signature-analyzer.ts`, `violation-analyzer.ts`, `threat-mesh-analyzer.ts`, `service-policy-analyzer.ts`, `security-event-indexer.ts`, `streaming-aggregator.ts`, and the legacy `server/analysis-job.ts`. The engine now does its own lean indexing inline.

> **Deployment note:** like every tool in this suite, the FP Analyzer has **no production build** — all "backend" logic runs inside **Vite dev-server middleware**. `npm run dev` boots the app *and* the `/api/fp-analyzer/*` endpoints. Requests are made server-side from Node directly to the XC tenant (`Authorization: APIToken <token>`).

### 4.2 The engine lifecycle (`progressive-job.ts`)

`ProgressiveAnalysisJob.run()`:

```
endTime = now;  startTime = now - hoursBack
── collectWafEvents()          # query {vh_name=…, sec_event_name="WAF"}, chunked + scroll-paged
── indexEvents()               # group by sigId / violation; collect flaggedIpEventCount; count distinct paths
── detectWafConfig()           # read the LB's app_firewall name + enforcement mode
── collectFlaggedIpBehavior()  # top-500 flagged IPs, batched src_ip=~ regex queries → IPBehaviorProfile
── buildSummary()              # score every signature & violation with computeFpSignals → final result
── status: complete
```

Status flows `collecting → enriching → complete`. The summary is fully scored only at `complete` (single pass).

### 4.3 Data collection: chunking, scroll, concurrency, completeness

- The window is split into **2-hour chunks**. Each chunk is one scoped query, scrolled to exhaustion.
- Chunks run through an **adaptive-concurrency worker pool**: a `green/yellow/red` state machine that **halves concurrency and backs off on HTTP 429**, then ramps back up.
- A run is flagged **`dataPartial`** if any chunk fails to complete or a scroll breaks mid-pagination — surfaced as a **⚠ Partial data** banner rather than presenting incomplete data as "complete."

#### Malicious-bot rows are excluded from this pull

The WAF/violation query carries **`bot_class!~"malicious"`**, so requests F5 already classifies as a malicious bot are **never downloaded**. A request a malicious bot made is a true positive by definition — including it would both inflate the download (scanners can generate enormous volumes) and add TP noise to FP scoring. Two safeguards make this robust:

1. **Probe-verify** — before collecting, one tiny query confirms the tenant accepts the filter. If the field/operator is unsupported the probe errors and the engine falls back to fetching unfiltered.
2. **Always-on client-side drop** — after fetching, any Malicious-classified row is dropped regardless, so even if the server filter is silently ignored the malicious rows never reach FP scoring (the count dropped is logged).

The malicious bots themselves are handled by a separate **aggregation-only** track (§6.1) — counts, not raw rows.

### 4.4 Per-IP behavioral enrichment (the redesign's core)

`collectFlaggedIpBehavior()`:

- Takes the **top-500 flagged IPs** by WAF-event count (the long tail of one-off IPs is scored from events alone).
- Batches them **30 per query** as `src_ip=~"ip1|ip2|…"` and pulls each IP's full access logs over the window.
- Builds an **`IPBehaviorProfile`** per IP: total requests (de-sampled by `sample_rate`), response-code distribution, success/404/4xx/5xx ratios, unique-path diversity, exploit-path hits, request rate, dominant user-agent, and the **WAF-event ratio** (`wafEventCount / totalRequests` — what fraction of this client's traffic tripped the WAF).

This is far lighter than the old whole-LB access-log download and gives a *per-client* picture that path-level ratios can't.

---

## 5. The scoring engine in detail

Every signature is scored on **7 signals**, each 0–100 (higher = more FP), combined by a weighted sum into a 0–100 **composite**, then mapped to a verdict.

### 5.1 The 7 signals

| # | Signal | What it measures | FP-ward (high score) when… |
|---|---|---|---|
| 1 | **Client Breadth** | how many distinct client IPs trigger it | many distinct clients trigger it (a real attack is usually few sources) |
| 2 | **Path Breadth** | how many app paths it fires on | it fires across many/most paths (app-wide noise) |
| 3 | **Context** | *where* it matches | cookie / app-generated header / search param (app-controlled input) |
| 4 | **Matching Evidence** | *what* the flagged value is | the flagged values are clearly benign (legit input), not attack syntax |
| 5 | **Origin Response** | what the origin returned to flagged reqs | mostly **200** (app accepted) — *unless* the payload is malicious (then TP) |
| 6 | **Client Behavior** | the flagged IPs' *whole* traffic | clients look legitimate (high success, low 404, low WAF-ratio, real browsers) |
| 7 | **Detection Confidence** | F5's own confidence | low-accuracy sig, AutoSuppressed/Staging, **F5 AI rated low-risk** (violations: severity table) |

### 5.2 Weights (single table — no modes)

The composite is `Σ(signal × weight)`:

| Signal | Weight |
|---|---|
| Client Breadth | 0.15 |
| Path Breadth | 0.10 |
| Context | 0.10 |
| Matching Evidence | 0.15 |
| **Origin Response (200 vs 404)** | 0.15 |
| **Client Behavior (per-IP whole traffic)** | 0.20 |
| Detection Confidence (accuracy + AI) | 0.15 |

The two redesign signals — **Origin Response** and **Client Behavior** — carry **35%** of the weight, and response code (200 vs 404) drives both. Unlike the old design, response code is now a **first-class signal**, not a sub-input.

### 5.3 Verdict bands

```
composite > 75  → highly_likely_fp     (strong candidate to exclude)
composite > 55  → likely_fp
composite > 35  → ambiguous            (needs human investigation)
composite > 15  → likely_tp
composite ≤ 15  → confirmed_tp         (a real attack — never exclude)
```

### 5.4 How the new signals are computed

- **Client Breadth** — absolute distinct-IP thresholds (e.g. `>200 IPs → 95`, `>100 → 88`, …, `≤2 → 6`). We no longer need a whole-app denominator.
- **Matching Evidence** — classifies each sampled `matching_info` value (malicious / benign / ambiguous). Mostly-benign → high (FP); mostly-malicious → low (TP).
- **Origin Response** — counts 2xx / 404 / other-4xx / 5xx of the flagged requests. Mostly-2xx → FP-ward; mostly-404 → TP-ward. **Successful-exploit guard:** if ≥50% are 2xx **and** Matching Evidence says the payload is clearly malicious, it flags `possibleSuccessfulExploit` and the composite is **capped at 25 (TP)** — a 200 that served an attack is the worst kind of true positive, not a false positive.
- **Client Behavior** — aggregates the `IPBehaviorProfile`s of the flagged clients: average success ratio (high → FP), 404 ratio (high → TP), WAF-event ratio (≈100% → dedicated attacker TP; near-0 → mostly-legit FP), path diversity (high → scanning TP), exploit-path probing (→ TP), and real-browser vs scripting/scanner UAs. It also folds in **F5 Bot Defense classification** of the flagged clients: mostly-**Benign/Good** bots → FP-ward (+15, a legitimate bot being flagged), mostly-**Suspicious** → mildly TP-ward (−8). (Malicious would be −18, but those rows are excluded from the WAF/violation pull per §4.3, so in practice this slot sees the *non-malicious* mix.) Human/Unknown are ignored. This works even when per-IP enrichment is absent, because the classification comes from the security events themselves.
- **Detection Confidence** — signature accuracy + state (AutoSuppressed/Staging) + the AI delta (see §6). For **violations** this slot becomes a **severity table** (`VIOL_ATTACK_SIGNATURE`/evasions → always-TP cap; length/format violations → high FP severity).

### 5.5 Guardrails (overrides)

- **Possible successful exploit** — 2xx + malicious payload ⇒ capped to TP (≤25).
- **Always-TP violations** — evasion / raw attack-signature violations ⇒ capped to `confirmed_tp` (never excluded).

---

## 6. AI-WAF intelligence

F5's AI-powered WAF is folded into **Detection Confidence**. Parsing lives in `ai-signals.ts`.

| Field | Meaning | Effect |
|---|---|---|
| `req_risk` (High/Med/Low or 0–100) | AI per-request risk = Likelihood × Impact | **Low → FP-ward**, **High → TP-ward** |
| `req_risk_reasons` | AI rationale | "confirmed attack" → strong TP; "benign/suppressed" → FP |
| `recommended_action` (allow/report/block) | AI recommendation | `allow`/`report` → FP-ward; `block` → TP-ward |
| signature `state` (Enabled/AutoSuppressed/Staging) | F5 ML / staging state | AutoSuppressed → FP-ward; Staging → monitor-only flag |
| `enforcement_mode` | BLOCKING / MONITORING | context banner (not scoring) |

The combined AI influence is a **bounded delta `[-55, +45]`** so F5's AI informs but can't single-handedly override the behavioural signals. The `req_risk_reasons` parser requires a percentage to be tied to *confidence/confirmed/attack* (so a benign "100% cache hit" reason is not misread as a confirmation).

### 6.1 Bot classification (`bot-analysis.ts`)

F5 XC Bot Defense classifies each request's client as **Malicious / Suspicious / Benign(Good) / Human**. In practice only **Malicious** is blocked; Suspicious and Good/Benign are allowed or ignored. So before a customer turns on Malicious-bot blocking, the report answers one question: *are these Malicious classifications true positives, or would blocking them take out a real user or a known-good crawler?*

This track is **aggregation-only** — to avoid downloading the (potentially enormous) raw malicious-bot logs, it never reads raw rows. The engine issues server-side terms aggregations over the security events:

- One **`bot_class` distribution** over *all* WAF events → the classification counts (Malicious / Suspicious / Benign / Human; `good_bot` folds into Benign, `clean` into Human).
- Four **Malicious-only** aggregations (filtered by `bot_class=~"malicious"`): `src_ip` (top 500), `bot_name`, `user_agent`, `country`.

`computeBotAnalysisFromAggregates(buckets)` then:

1. Reports total Malicious events and distinct Malicious IPs (with an `ipsCapped` flag when the distinct count hits the top-500 bucket limit — an undercount marker).
2. Scans the Malicious set's **bot-name and user-agent** buckets for **false-positive indicators**: a **known-good bot** name/UA (Googlebot, Bingbot, AdsBot…) or a **real-browser** user-agent (a Mozilla/Chrome/Safari UA with no bot/scanner token). Each becomes a `BotFpRiskFlag`.
3. Produces a one-line **recommendation**: *SAFE to block* when there are **no** FP-risk flags (every Malicious client carries a scanner/unknown UA), otherwise *REVIEW* naming the known-good bots / real-browser UAs to verify first.

Because aggregations don't correlate fields per request, the report shows **distributions** (top Malicious IPs, top UAs with FP-risk ⚠ marks, top bot names, top countries) rather than a per-IP verdict table — which is exactly enough to answer "is it safe to block?" The result drives a **Bot Classification** report section, a dedicated **Bot Classification** Excel sheet, a PDF block, and a `block_bots` step in **Next Steps** ("Enable Malicious-bot blocking — safe" vs "Review the Malicious set first").

> **Note:** because Malicious-bot rows are excluded from the main WAF/violation pull (§4.3), a signature or violation that fires *only* on malicious bots will not appear in the Signatures/Violations tables (it has zero non-bot events) — it is represented here in the Bot track instead.

---

## 7. Sampling, completeness & accuracy

- **Access-log sampling** — F5 samples access logs (`sample_rate` ≥ 1). The per-IP enrichment records `sample_rate` and **de-samples each IP's request volume** (`estimateActualCountFromRate`) so the `wafEventRatio` and rate figures reflect real traffic. Ratios used in signals are clamped to sane bounds.
- **Completeness** — chunk-completion + scroll-break detection sets `dataPartial`; a partial run's verdicts are provisional (⚠ banner).
- **Security events are not sampled** (except extreme load), so the flagged-request counts are exact.

---

## 8. Exclusion generation

For confirmed false positives the tool emits a first-class **`waf_exclusion_policy`** object.

- **Rule shape** — scopes *where* (domain, `path_prefix`/`path_regex`, `methods`) and *what* (`exclude_signature_contexts` / `exclude_violation_contexts` / `exclude_attack_type_contexts`).
- **Grouping** — rules on the same domain+path+methods collapse into one.
- **Attack-type rollup** — when **≥3 distinct signatures of the same `attack_type`** are FP on the same path+methods, the tool emits **one `exclude_attack_type_contexts` rule** instead of N signature rules (F5 best practice). Smaller groups stay precise per-signature.
- **Output paths** — (1) **Generate / download** the policy JSON to apply yourself; (2) **Stage to Tenant** — creates the policy as a config object that is **NOT attached** to the LB, so it has **zero enforcement effect** until you review and attach it in the XC console (the F5 stage → review → enforce methodology). Staging writes to the tenant and is gated behind a confirmation.

---

## 9. How to use the tool

### 9.1 Prerequisites
- An F5 XC **API token** with read access to app-security events & access logs for the namespace (plus config-write if you'll use *Stage to Tenant*).
- The tenant, namespace, and HTTP Load Balancer to analyze.

### 9.2 Step by step
1. **Connect** — set tenant + API token.
2. **Open FP Analyzer** and configure: **Namespace**, **Load Balancer**, **Time range** (24h / 48h / 72h / 7d / 14d / 30d), and **Scope** (WAF Signatures and/or WAF Violations — that's all there is now).
3. **Start.** Watch the two phases: *Downloading WAF events* → *Analyzing client traffic (N/M IPs)*.
4. **Read the table.** Rows are ranked most-likely-FP first: events, clients, paths, accuracy, **AI Risk**, **FP score**, **verdict**, status.
5. **Drill in.** Each signature shows the **7-signal breakdown** (each with score + reason — including the client-behavior summary and origin-response shape), per-path analysis, top source IPs, and **sample matching values** (color-coded malicious/benign).
6. **Confirm.** Mark **Confirm FP** / **Confirm TP** (or "Mark all HIGH-confidence FP"). Watch for a **possible successful exploit** flag — never exclude those. Check the enforcement-mode banner.
7. **Produce the fix:** **Generate Exclusion Policy** (clipboard) / **WAF Policy** (download), or **Stage to Tenant** (unattached) and attach it in the console when ready.
8. **Export** a PDF or Excel report.

---

## 10. Best practices

1. **Read the evidence, never exclude on score alone.** Open the detail; check the **matching values** (is the flagged input actually benign?) and the **client behavior** (are these scanners or real users?).
2. **Trust the successful-exploit guard.** A `200` on a malicious payload is a *true positive*. The tool caps it to TP for a reason — don't override it into an exclusion.
3. **Respect the always-TP guardrails.** Evasion and raw attack-signature violations are capped at TP.
4. **Prefer narrow exclusions.** Per-signature/per-path/per-method/per-context is safer; let the attack-type rollup fire only when many signatures of one type are genuinely noisy on a path.
5. **Stage, then enforce.** Use *Stage to Tenant* (unattached) → review rule order in the XC console → attach. Rule order matters (first match wins); excluding an attack type cascades to all its signatures.
6. **Mind the enforcement mode.** In MONITORING, signatures aren't blocking yet — exclusions are pre-emptive tuning.
7. **Watch `Staging` / `AutoSuppressed`.** Staged = monitor-only (not blocking); AutoSuppressed = F5 ML already treats it as FP.
8. **Heed the Partial-data banner.** Narrow the window or re-run before trusting a partial run.
9. **Re-validate after tuning.** Re-run over the next window to confirm the FP is gone and no new TPs were masked.

---

## 11. FAQ

**Q: Why did you remove Quick/Hybrid modes?**
The old Hybrid mode downloaded the *whole LB's* access logs to compute path-level ratios — heavy and sampled. The redesign instead pulls only the *flagged IPs'* logs and judges client behavior, which is both lighter and a better FP/TP signal. One flow, no choice to make.

**Q: 200 vs 404 — what exactly do they mean here?**
A flagged request that the **origin** answered `200` was *processed successfully* by the app → leans **false positive**. A `404` means the client probed something that doesn't exist → leans **true positive** (recon/scanning). The catch: a `200` on a *malicious* payload is a **successful exploit** (the worst TP), so the tool surfaces that case explicitly instead of calling it FP.

**Q: What is the "Client Behavior" signal?**
For each IP caught by a WAF event, the tool pulls that IP's whole traffic and asks whether it looks like a normal user (mostly 200s, few paths, real browser, small fraction of traffic tripping WAF) or a scanner (lots of 404s, many paths, exploit-path probing, scripting UA, ~all traffic tripping WAF). It's the highest-weighted signal (20%).

**Q: It found a high FP score but the matching values look malicious / the IPs are scanners. Exclude it?**
No. The score is a prior, not a verdict. Malicious content + scanner behavior = true positive. Confirm TP.

**Q: How many IPs does it pull logs for?**
The top **500** flagged IPs by event volume (batched). The long tail of one-off IPs is scored from events alone — they contribute little behavioral signal anyway.

**Q: Does the tool change my WAF config?**
Only if you click **Stage to Tenant**, and even then it creates an **unattached** policy with no enforcement effect until *you* attach it. Generate/Download just produce JSON.

**Q: How does bot classification fit in — is it safe to block the Malicious bots?**
A **Bot Classification** section (computed from server-side aggregation, no raw bot logs) checks whether the Malicious set contains any false positives. It scans the user-agents and bot names of the Malicious clients for **known-good crawlers** (Googlebot, Bingbot…) or **real-browser UAs** — if none appear, Next Steps recommends enabling Malicious-bot blocking as safe; if any do, it flags them to verify first. Non-malicious bot classifications (Benign/Good → FP-ward, Suspicious → TP-ward) also feed the Client Behavior signal.

**Q: Why aren't the malicious-bot requests in my Signatures/Violations counts?**
By design — the WAF/violation pull excludes `bot_class="malicious"` server-side (§4.3) so huge scanner volumes aren't downloaded and don't add true-positive noise to FP scoring. Those requests live in the **Bot Classification** track instead. A signature that fires *only* on malicious bots therefore won't show in the Signatures table.

**Q: Can I analyze Threat Mesh / Service Policy here?**
No — the redesign is focused on WAF Signatures + Violations (with bot classification folded in). Use the SOC Room / other tools for Threat Mesh and Service Policy.

---

## 12. API reference

Served by the Vite middleware at `/api/fp-analyzer/*`.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/start` | Start a job. Body: `{ tenant, token, namespace, lbName, domains, scopes, hoursBack }` → `{ jobId }` |
| `GET` | `/progress/:id` | Poll progress (`status`, chunk counts, `ipEnrichTotal/Completed`, `dataPartial`) |
| `GET` | `/summary/:id` | Ranked summary (available at `complete`) |
| `GET` | `/detail/:id/signature/:sigId` | Signature detail (7 signals, per-path, IP profiles, matching values) |
| `GET` | `/detail/:id/violation/:name` | Violation detail |
| `POST` | `/exclusion/:id` | Build an exclusion policy from confirmed FPs (body: `{ sigIds }`) → policy JSON |
| `POST` | `/apply-exclusion/:id` | **Stage** the policy into the tenant (unattached). Body: `{ sigIds }` |
| `POST` | `/cancel/:id` | Cancel a running job |

(The old `/enrich/*` and `/detail/*/threat-mesh/*` routes were removed — enrichment is automatic.)

---

## 13. Limitations & known gaps

- **Per-IP enrichment is capped at 500 IPs** (by event volume). The long tail is scored from events alone; their Client Behavior signal is neutral.
- **Bot track is aggregation-only and capped at the top 500 Malicious IPs** (`ipsCapped` marks the undercount). Aggregations don't correlate fields per request, so the FP-risk check works on UA/bot-name *distributions*, not per-IP — it surfaces *that* a known-good bot or real-browser UA exists in the Malicious set, not which specific IP it maps to.
- **The malicious-exclude filter assumes `bot_class` is queryable on the events endpoint.** A probe verifies it per-tenant and an always-on client-side drop guarantees correctness, but on a tenant where the field is unsupported you lose only the bandwidth saving, not accuracy.
- **`Stage to Tenant` is not yet verified against a live tenant.** It follows the documented `waf_exclusion_policys` create API and is safe (unattached), but should be smoke-tested.
- **Origin Response keys on standard code ranges** (2xx/404/4xx/5xx); it does not yet reinterpret `403` as "WAF block page" vs "origin auth" based on enforcement mode.
- **Unique-user/IP counts from access logs are sampled** (volume is de-sampled; cardinalities can undercount).
- **`server/` is excluded from the app's default `tsc`** — use **`npm run typecheck`** (`tsconfig.all.json`) to type-check the engine too.

---

## 14. Development, verification & extension

```bash
npm run dev          # boots app + /api/fp-analyzer/* middleware (http://localhost:5173)
npm run typecheck    # full type-check INCLUDING server/ (tsconfig.all.json)
npm run test:fp      # behavioral tests for the scoring/AI/exclusion logic
```

`npm run test:fp` covers all 7 signals, the 200-vs-404 + successful-exploit guard, client-behavior legit-vs-scanner, violation severity, the AI parser, attack-type rollup, sample-rate de-sampling, the Traditional-vs-AI WAF comparison, the Next-Steps action plan, and bot classification (known-good vs scanner vs review).

**Extending the scoring:** edit `fp-signals-v2.ts` (signal functions + `FP_WEIGHTS`), keep the convention **higher = more FP**, add a case to `scripts/test-fp-accuracy.mts`, and run `npm run typecheck`.

---

## 15. Glossary

| Term | Definition |
|---|---|
| **FP / TP** | False Positive (legit traffic flagged) / True Positive (real attack). |
| **Composite score** | The 0–100 weighted sum of the 7 signals; higher = more FP. |
| **Verdict** | The 5-level band (`highly_likely_fp` … `confirmed_tp`). |
| **Client Behavior** | The flagged IP's whole-traffic fingerprint (success/404 ratio, path diversity, WAF-event ratio, UA). |
| **Origin Response** | What the origin returned to flagged requests (200 → FP, 404 → TP). |
| **Possible successful exploit** | A 200 served for a malicious payload — capped to TP, never excluded. |
| **WAF-event ratio** | Fraction of a client's total requests that tripped the WAF (≈1 → dedicated attacker; ≈0 → mostly-legit). |
| **`req_risk`** | F5 AI-WAF per-request risk verdict (Likelihood × Impact). |
| **AutoSuppressed / Staging** | Signature states: F5 ML treats as FP / monitor-only. |
| **Attack-type rollup** | Collapsing many same-attack-type FP signatures into one attack-type exclusion. |
| **Stage to Tenant** | Creating the exclusion policy in XC unattached (no enforcement until attached). |
| **`dataPartial`** | Flag indicating event collection under-fetched; verdicts are provisional. |

---

*Generated for the XC App Store FP Analyzer (2026 redesign). Source of truth: `src/services/fp-analyzer/fp-signals-v2.ts` (scoring) and `server/progressive-job.ts` (engine).*
