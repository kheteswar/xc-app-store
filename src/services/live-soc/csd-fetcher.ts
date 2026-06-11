// =============================================================================
// Live SOC Monitoring Room — CSD (Client-Side Defense) Fetcher
// Retrieves CSD data: scripts, detected domains, targeted form fields,
// and affected users. Returns empty summary if CSD is not enabled.
// =============================================================================

import { apiClient } from '../api';
import type { CSDSummary } from './types';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function safeStr(val: unknown, fallback = ''): string {
  return typeof val === 'string' ? val : fallback;
}

// ---------------------------------------------------------------------------
// Empty result — returned when CSD is not enabled or API fails
// ---------------------------------------------------------------------------

function emptyCSD(): CSDSummary {
  return {
    scripts: [],
    detectedDomains: [],
  };
}

// ---------------------------------------------------------------------------
// Sub-fetchers
// ---------------------------------------------------------------------------

interface RawScript {
  id?: string;
  script_id?: string;
  domain?: string;
  host?: string;
  classification?: string;
  status?: string;
  network_interactions?: string[];
  network_domains?: string[];
}

async function fetchScripts(namespace: string): Promise<RawScript[]> {
  try {
    const res = await apiClient.get<{
      items?: RawScript[];
      scripts?: RawScript[];
    }>(`/api/data/namespaces/${namespace}/csd/scripts`);

    return res.items ?? res.scripts ?? [];
  } catch {
    return [];
  }
}

interface RawDetectedDomain {
  domain?: string;
  host?: string;
  classification?: string;
  status?: string;
  mitigated?: boolean;
  is_mitigated?: boolean;
}

async function fetchDetectedDomains(namespace: string): Promise<RawDetectedDomain[]> {
  try {
    const res = await apiClient.get<{
      items?: RawDetectedDomain[];
      domains?: RawDetectedDomain[];
    }>(`/api/data/namespaces/${namespace}/csd/detected_domains`);

    return res.items ?? res.domains ?? [];
  } catch {
    return [];
  }
}

async function fetchFormFields(
  namespace: string,
  scriptId: string,
): Promise<string[]> {
  try {
    const res = await apiClient.get<{
      items?: Array<{ name?: string; field_name?: string; id?: string }>;
      form_fields?: Array<{ name?: string; field_name?: string; id?: string }>;
    }>(`/api/data/namespaces/${namespace}/csd/scripts/${scriptId}/formFields`);

    const items = res.items ?? res.form_fields ?? [];

    return items.map(
      (f) => safeStr(f.name ?? f.field_name ?? f.id, 'unknown'),
    );
  } catch {
    return [];
  }
}

async function fetchAffectedUsers(
  namespace: string,
  scriptId: string,
): Promise<number> {
  try {
    const res = await apiClient.get<{
      count?: number;
      total?: number;
      users?: unknown[];
      items?: unknown[];
    }>(`/api/data/namespaces/${namespace}/csd/scripts/${scriptId}/affectedUsers`);

    if (typeof res.count === 'number') return res.count;
    if (typeof res.total === 'number') return res.total;
    if (Array.isArray(res.users)) return res.users.length;
    if (Array.isArray(res.items)) return res.items.length;
    return 0;
  } catch {
    return 0;
  }
}

// ---------------------------------------------------------------------------
// fetchCSDSummary — main public function
// ---------------------------------------------------------------------------

/**
 * Fetch a comprehensive Client-Side Defense summary for a namespace.
 *
 * Retrieves the list of scripts and detected domains first, then enriches
 * suspicious/malicious scripts with form field and affected user data.
 *
 * Returns an empty CSDSummary if CSD is not enabled or all calls fail.
 */
export async function fetchCSDSummary(
  namespace: string,
): Promise<CSDSummary> {
  try {
    // Phase 1: Fetch scripts and domains concurrently
    const [rawScripts, rawDomains] = await Promise.all([
      fetchScripts(namespace),
      fetchDetectedDomains(namespace),
    ]);

    // If no scripts found at all, CSD is likely not enabled
    if (rawScripts.length === 0 && rawDomains.length === 0) {
      return emptyCSD();
    }

    // Phase 2: Enrich suspicious/malicious scripts with details
    const scripts = await Promise.all(
      rawScripts.map(async (raw) => {
        const id = safeStr(raw.id ?? raw.script_id, `csd-${Date.now()}`);
        const classification = safeStr(
          raw.classification ?? raw.status,
          'benign',
        ).toLowerCase() as 'benign' | 'suspicious' | 'malicious';

        // Only fetch details for non-benign scripts to limit API calls
        let targetedFormFields: string[] = [];
        let affectedUserCount = 0;

        if (classification !== 'benign') {
          const [fields, users] = await Promise.all([
            fetchFormFields(namespace, id),
            fetchAffectedUsers(namespace, id),
          ]);
          targetedFormFields = fields;
          affectedUserCount = users;
        }

        return {
          id,
          domain: safeStr(raw.domain ?? raw.host, 'unknown'),
          classification,
          targetedFormFields,
          affectedUserCount,
          networkInteractions: raw.network_interactions ?? raw.network_domains ?? [],
        };
      }),
    );

    // Map detected domains
    const detectedDomains = rawDomains.map((raw) => ({
      domain: safeStr(raw.domain ?? raw.host, 'unknown'),
      classification: safeStr(raw.classification ?? raw.status, 'unknown'),
      mitigated: raw.mitigated === true || raw.is_mitigated === true,
    }));

    return { scripts, detectedDomains };
  } catch (err) {
    console.warn(
      `[SOC] CSD fetch failed for "${namespace}":`,
      err instanceof Error ? err.message : err,
    );
    return emptyCSD();
  }
}
