/**
 * FP Analyzer Vite Plugin — Progressive Interactive Flow
 *
 * Endpoints:
 *   POST /api/fp-analyzer/start             → Start a new progressive analysis job
 *   GET  /api/fp-analyzer/progress/:id      → Poll job progress
 *   GET  /api/fp-analyzer/summary/:id       → Get summary table (after summary_ready)
 *   GET  /api/fp-analyzer/detail/:id/signature/:sigId     → Get signature detail (on-demand)
 *   GET  /api/fp-analyzer/detail/:id/violation/:name      → Get violation detail (on-demand)
 *   POST /api/fp-analyzer/exclusion/:id        → Generate exclusion policy for confirmed FPs
 *   POST /api/fp-analyzer/apply-exclusion/:id  → Stage exclusion policy into the tenant (unattached)
 *   POST /api/fp-analyzer/cancel/:id           → Cancel a running job
 */

import type { Plugin } from 'vite';
import type { IncomingMessage, ServerResponse } from 'http';
import { ProgressiveAnalysisJob } from './progressive-job';
import type { ProgressiveJobConfig } from './progressive-job';

function generateJobId(): string {
  return `fp-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function parseBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk: string) => { body += chunk; });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function sendJSON(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(JSON.stringify(data));
}

/**
 * Parse path segments after a prefix.
 * e.g. url="/fp-123/signature/200010019", prefix="" → ["fp-123", "signature", "200010019"]
 */
function getPathSegments(url: string): string[] {
  return url.replace(/^\//, '').replace(/\/$/, '').split('/').filter(Boolean);
}

export function fpAnalyzerPlugin(): Plugin {
  const jobs = new Map<string, ProgressiveAnalysisJob>();

  let cleanupInterval: ReturnType<typeof setInterval> | null = null;

  function cleanupExpired(): void {
    for (const [id, job] of jobs) {
      if (job.isExpired()) {
        jobs.delete(id);
        console.log(`[FPAnalyzer] Expired job ${id} removed`);
      }
    }
  }

  return {
    name: 'fp-analyzer',
    configureServer(server) {
      cleanupInterval = setInterval(cleanupExpired, 5 * 60 * 1000);

      // ── Start Analysis ──
      server.middlewares.use('/api/fp-analyzer/start', async (req: IncomingMessage, res: ServerResponse, next) => {
        if (req.method !== 'POST') return next();

        try {
          const body = await parseBody(req);
          const parsed = JSON.parse(body) as Partial<ProgressiveJobConfig>;

          if (!parsed.tenant || !parsed.token || !parsed.namespace || !parsed.lbName) {
            sendJSON(res, 400, { error: 'Missing required fields: tenant, token, namespace, lbName' });
            return;
          }

          const scopes = (parsed.scopes || ['waf_signatures', 'waf_violations'])
            .filter(s => s === 'waf_signatures' || s === 'waf_violations');
          const config: ProgressiveJobConfig = {
            tenant: parsed.tenant,
            token: parsed.token,
            namespace: parsed.namespace,
            lbName: parsed.lbName,
            domains: parsed.domains || [],
            scopes: scopes.length ? scopes : ['waf_signatures', 'waf_violations'],
            hoursBack: parsed.hoursBack || 168,
          };

          const jobId = generateJobId();
          const job = new ProgressiveAnalysisJob(jobId, config);
          jobs.set(jobId, job);

          job.run().catch(err => {
            console.error(`[FPAnalyzer] Job ${jobId} unhandled error:`, err);
          });

          console.log(`[FPAnalyzer] Job ${jobId} started`);
          sendJSON(res, 200, { jobId });
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          sendJSON(res, 400, { error: `Invalid request: ${msg}` });
        }
      });

      // ── Progress Polling ──
      server.middlewares.use('/api/fp-analyzer/progress/', (req: IncomingMessage, res: ServerResponse, next) => {
        if (req.method !== 'GET') return next();

        const segments = getPathSegments(req.url || '');
        const jobId = segments[0];
        if (!jobId) { sendJSON(res, 400, { error: 'Missing job ID' }); return; }

        const job = jobs.get(jobId);
        if (!job) { sendJSON(res, 404, { error: 'Job not found' }); return; }

        sendJSON(res, 200, job.getProgress());
      });

      // ── Get Summary ──
      server.middlewares.use('/api/fp-analyzer/summary/', (req: IncomingMessage, res: ServerResponse, next) => {
        if (req.method !== 'GET') return next();

        const segments = getPathSegments(req.url || '');
        const jobId = segments[0];
        if (!jobId) { sendJSON(res, 400, { error: 'Missing job ID' }); return; }

        const job = jobs.get(jobId);
        if (!job) { sendJSON(res, 404, { error: 'Job not found' }); return; }

        const status = job.getStatus();
        if (status !== 'summary_ready' && status !== 'enriching' && status !== 'complete') {
          sendJSON(res, 202, { message: 'Summary not yet available', progress: job.getProgress() });
          return;
        }

        const summary = job.getSummary();
        if (!summary) {
          sendJSON(res, 202, { message: 'Summary being computed' });
          return;
        }

        sendJSON(res, 200, summary);
      });

      // ── Get Signature Detail ──
      server.middlewares.use('/api/fp-analyzer/detail/', (req: IncomingMessage, res: ServerResponse, next) => {
        if (req.method !== 'GET') return next();

        // URL pattern: /{jobId}/signature/{sigId} or /{jobId}/violation/{violName}
        const segments = getPathSegments(req.url || '');
        if (segments.length < 3) { sendJSON(res, 400, { error: 'Invalid URL format' }); return; }

        const jobId = segments[0];
        const type = segments[1]; // "signature" or "violation"
        const id = decodeURIComponent(segments.slice(2).join('/'));

        const job = jobs.get(jobId);
        if (!job) { sendJSON(res, 404, { error: 'Job not found' }); return; }

        if (type === 'signature') {
          const detail = job.getSignatureDetail(id);
          if (!detail) { sendJSON(res, 404, { error: `Signature ${id} not found` }); return; }
          sendJSON(res, 200, detail);
        } else if (type === 'violation') {
          const detail = job.getViolationDetail(id);
          if (!detail) { sendJSON(res, 404, { error: `Violation ${id} not found` }); return; }
          sendJSON(res, 200, detail);
        } else {
          sendJSON(res, 400, { error: `Unknown detail type: ${type}` });
        }
      });

      // (On-demand enrichment removed — per-IP behavior is collected automatically before scoring.)

      // ── Generate Exclusion Policy ──
      server.middlewares.use('/api/fp-analyzer/exclusion/', async (req: IncomingMessage, res: ServerResponse, next) => {
        if (req.method !== 'POST') return next();

        try {
          const segments = getPathSegments(req.url || '');
          const jobId = segments[0];
          if (!jobId) { sendJSON(res, 400, { error: 'Missing job ID' }); return; }

          const job = jobs.get(jobId);
          if (!job) { sendJSON(res, 404, { error: 'Job not found' }); return; }

          const body = await parseBody(req);
          const parsed = JSON.parse(body) as { sigIds?: string[] };
          const sigIds = parsed.sigIds || [];

          if (sigIds.length === 0) {
            sendJSON(res, 400, { error: 'No signature IDs specified' });
            return;
          }

          const policy = job.generatePolicyForConfirmedFPs(sigIds);
          if (!policy) { sendJSON(res, 404, { error: 'Could not generate policy' }); return; }

          sendJSON(res, 200, policy);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          sendJSON(res, 500, { error: `Exclusion generation failed: ${msg}` });
        }
      });

      // ── Stage Exclusion Policy to Tenant (creates an UNATTACHED config object) ──
      server.middlewares.use('/api/fp-analyzer/apply-exclusion/', async (req: IncomingMessage, res: ServerResponse, next) => {
        if (req.method !== 'POST') return next();

        try {
          const segments = getPathSegments(req.url || '');
          const jobId = segments[0];
          if (!jobId) { sendJSON(res, 400, { error: 'Missing job ID' }); return; }

          const job = jobs.get(jobId);
          if (!job) { sendJSON(res, 404, { error: 'Job not found' }); return; }

          const body = await parseBody(req);
          const parsed = JSON.parse(body) as { sigIds?: string[] };
          const sigIds = parsed.sigIds || [];
          if (sigIds.length === 0) { sendJSON(res, 400, { error: 'No signature IDs specified' }); return; }

          const result = await job.applyExclusionPolicy(sigIds);
          sendJSON(res, result.created ? 200 : 502, result);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          sendJSON(res, 500, { error: `Apply failed: ${msg}` });
        }
      });

      // ── Cancel Job ──
      server.middlewares.use('/api/fp-analyzer/cancel/', (req: IncomingMessage, res: ServerResponse, next) => {
        if (req.method !== 'POST') return next();

        const segments = getPathSegments(req.url || '');
        const jobId = segments[0];
        if (!jobId) { sendJSON(res, 400, { error: 'Missing job ID' }); return; }

        const job = jobs.get(jobId);
        if (!job) { sendJSON(res, 404, { error: 'Job not found' }); return; }

        job.cancel();
        sendJSON(res, 200, { message: 'Job cancelled' });
      });

      console.log(' 🔍 FP Analyzer progressive endpoints enabled at /api/fp-analyzer/*');
    },

    buildEnd() {
      if (cleanupInterval) {
        clearInterval(cleanupInterval);
        cleanupInterval = null;
      }
    },
  };
}
