---
project: xc-app-store
type: internal-tooling
owner: KB
status: active-development
repo: https://github.com/kheteswar/xc-app-store
current_branch: fp-analyzer-redesign
last_touched: 2026-07-05
freshness_window_days: 14
---

# xc-app-store — F5 XC operator suite

## Snapshot
A React + TypeScript + Node internal suite for F5 XC practitioners. Ships as a locally-run Vite app (`npm run dev` → `http://localhost:5173`). Bundles several purpose-built XC operator tools plus time tracking.

## Modules (per commit history)
- **FP Analyzer** — WAF false-positive analysis with client-behavior model, bot classification, optimized collection. _In active redesign on branch `fp-analyzer-redesign` (WIP)._
- **Rate Limit Advisor** — rolling-60s peak analysis, de-sampling, complete capture.
- **WAF Attack Simulator** — attack replay / policy validation.
- **Security Auditor** — rules in `security-auditor-rules.{csv,xlsx}`.
- **Time tracking** — per README.
- **Reports** — client-side generation of HTTP LB PDFs (`http_loadbalancer_*.pdf`).

## Tech
- Frontend: React 18, Vite 5, Tailwind, react-router, recharts, lucide-react
- Data: exceljs, xlsx, jszip, js-yaml, lz-string
- PDF/canvas: jspdf, html2canvas
- Crypto: node-forge
- Server: Node/TS (`server/{fp-analyzer-plugin,node-api-caller,progressive-job}.ts`)
- Test: `npx tsx scripts/test-*.mts` (`test:fp`, `test:rl`)

## Active workstreams
- [ ] Complete FP Analyzer redesign on `fp-analyzer-redesign` → merge to main.
- [ ] Land Security Auditor v2 (see `scripts/test-auditor-v2.mts`).
- [ ] Document Rate Limit Advisor + WAF Attack Simulator in `docs/` (specs exist, guides do not).
- [ ] Wire `docs/log-analysis.csv` sample into a runnable test/demo.
- [ ] Ship a v1.1 release tag when FP Analyzer redesign lands.

## Next 3 actions
1. Finish FP Analyzer redesign work-in-progress on branch and rebase on main.
2. Publish a short changelog / release notes into `docs/`.
3. Add a short demo GIF or screenshots to `README.md` for quick pitch to customers.

## Key links
- Repo: https://github.com/kheteswar/xc-app-store
- Overview deck: `F5_XC_App_Store_OS.pptx`, `docs/XC-App-Store-Overview.pptx`
- Technical reference: `XC-App-Store-Technical-Reference-v1.docx`
- Build specs: `docs/FP-ANALYZER-BUILD-SPEC.md`, `docs/RATE-LIMIT-ADVISOR-BUILD-SPEC.md`, `docs/LIVE-SOC-ROOM-SPEC-v3-FINAL.md`
- Guides: `docs/FP-ANALYZER-GUIDE.md` + docx

## Customer applicability (candidates to demo / roll out)
| Customer | Fit | Note |
|----------|-----|------|
| FWD | FP Analyzer + Security Auditor | Live FP backlog (`waf-fp-assessment-30jun26/`) is a perfect input |
| OCBC | Rate Limit Advisor | Recent 503 upstream_reset investigation |
| SMBC | Security Auditor | RBAC + custom-policy governance overlap |
| Qatar Gas | Rate Limit Advisor | 503 surge investigation (2 Mar 2026) |
| Tata SB | WAF Attack Simulator | Bot migration validation |

## Career hook
- Publishable, differentiating deliverable — feed into `Career/promotion-case.md` "Evidence — Technical depth" and "Evidence — Influence".
- Track adoption metric (# customers using / # tools shipped) in `Career/wins-log.md`.

## History (rolling, newest first)
- 2026-07-05 — WIP: FP Analyzer redesign + Security Auditor updates (b0727e5).
- 2026-06-XX — Untracked node_modules, build artifacts, snapshots (6cbce08).
- Earlier — WAF Attack Simulator added; Rate Limit Advisor reliability improvements; FP Analyzer client-behavior redesign.
