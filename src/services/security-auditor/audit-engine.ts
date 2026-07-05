// ═══════════════════════════════════════════════════════════════════════════
// Security Audit Engine
// Core engine that fetches configs and runs security rules
// ═══════════════════════════════════════════════════════════════════════════

import { apiClient } from '../api';
import { allRules } from './rules';
import { severityToRisk } from './types';
import type {
  SecurityRule,
  AuditContext,
  AuditFinding,
  AuditReport,
  AuditProgress,
  AuditOptions,
  AuditSummary,
  ConfigSnapshot,
  ConfigObjectType,
  Severity,
  EntitlementSummary,
  NamespaceSummary,
  LoadBalancerSummary,
  ScopeSummary,
  FetchError,
} from './types';

// A partial object is a list-view stub left behind when its detail GET failed (spec absent). Rules must
// not run posture logic on it (false PASS/FAIL) — the scan loop emits a manual-verify finding instead.
const isPartialObject = (o: unknown): boolean =>
  !!(o && typeof o === 'object' && (o as Record<string, unknown>).__partial === true);

// Helper to safely get metadata from object
const getMetadata = (obj: unknown): Record<string, unknown> => {
  const o = obj as Record<string, unknown>;
  return (o?.metadata || {}) as Record<string, unknown>;
};

// Relative weight of each severity for the weighted security score.
const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0.5,
};

// Severity-weighted score: PASS earns full weight, WARN half, FAIL zero;
// SKIP/ERROR/INFO are excluded entirely (INFO = "review / confirm intent", not a pass or fail).
// Shared sub-objects (one WAF/pool/cert referenced by N LBs) are de-duped by objectKey|ruleId so they
// count once. Returns the 0-100 score AND scoredCount (how many checks actually contributed) — when
// scoredCount is 0 the score is meaningless and callers should render N/A rather than a red 0.
function weightedScore(items: AuditFinding[]): { score: number; scoredCount: number } {
  let num = 0;
  let den = 0;
  let scoredCount = 0;
  const seen = new Set<string>();
  for (const f of items) {
    if (f.status === 'SKIP' || f.status === 'ERROR' || f.status === 'INFO') continue;
    const key = `${f.objectKey}|${f.ruleId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const w = SEVERITY_WEIGHT[f.severity] ?? 1;
    den += w;
    scoredCount++;
    if (f.status === 'PASS') num += w;
    else if (f.status === 'WARN') num += w * 0.5;
  }
  return { score: den > 0 ? Math.round((num / den) * 100) : 0, scoredCount };
}

export class AuditEngine {
  private rules: SecurityRule[] = allRules;
  private onProgress?: (progress: AuditProgress) => void;
  private aborted = false;
  private fetchErrors: FetchError[] = [];

  constructor(onProgress?: (progress: AuditProgress) => void) {
    this.onProgress = onProgress;
  }

  abort() {
    this.aborted = true;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // MAIN ENTRY POINT
  // ─────────────────────────────────────────────────────────────────────────

  async runAudit(namespaces: string[], options?: AuditOptions): Promise<AuditReport> {
    this.aborted = false;
    const startTime = Date.now();
    const findings: AuditFinding[] = [];

    // PHASE 1: Fetch all configurations
    this.reportProgress({
      phase: 'fetching',
      message: 'Fetching configurations...',
      progress: 0,
    });

    const context = await this.fetchAllConfigs(namespaces);

    if (this.aborted) {
      throw new Error('Audit aborted');
    }

    // PHASE 2: Run all rules against all objects
    this.reportProgress({
      phase: 'scanning',
      message: 'Running security checks...',
      progress: 20,
    });

    // Filter rules based on options
    let rulesToRun = this.rules;

    // Granular per-rule selection takes precedence over category selection.
    if (options?.ruleIds && options.ruleIds.length > 0) {
      const allow = new Set(options.ruleIds);
      rulesToRun = rulesToRun.filter((r) => allow.has(r.id));
    } else if (options?.categories && options.categories.length > 0) {
      rulesToRun = rulesToRun.filter((r) => options.categories!.includes(r.category));
    }

    if (options?.minSeverity) {
      rulesToRun = rulesToRun.filter((r) => this.meetsMinSeverity(r.severity, options.minSeverity!));
    }

    const totalRules = rulesToRun.length;

    // Partition rules by the object type they evaluate so we can run them
    // load-balancer-by-load-balancer (LB + its resolved sub-objects).
    const tenantRules = rulesToRun.filter((r) => r.id.includes('TENANT'));
    const lbRules = rulesToRun.filter((r) => !r.id.includes('TENANT') && r.appliesTo.includes('http_loadbalancer'));
    const opRules = rulesToRun.filter((r) => r.appliesTo.includes('origin_pool'));
    const hcRules = rulesToRun.filter((r) => r.appliesTo.includes('healthcheck'));
    const wafObjRules = rulesToRun.filter((r) => r.appliesTo.includes('app_firewall'));
    const certRules = rulesToRun.filter((r) => r.appliesTo.includes('certificate'));
    const spRules = rulesToRun.filter((r) => r.appliesTo.includes('service_policy'));

    // Run a single rule against one object and record the finding, tagged with
    // the load balancer it belongs to.
    const addFinding = (
      rule: SecurityRule,
      object: unknown,
      namespace: string,
      objectType: ConfigObjectType,
      objectName: string,
      loadBalancer: string,
      objectKey?: string
    ) => {
      const base = {
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        risk: rule.risk ?? severityToRisk(rule.severity),
        entitlement: rule.entitlement ?? 'Base',
        category: rule.category,
        namespace,
        objectType,
        objectName,
        loadBalancer,
        objectKey: objectKey || `${namespace}/${objectType}/${objectName}`,
        verify: rule.verify ?? 'auto',
        verifyNote: rule.verifyNote,
        remediation: rule.remediation,
        referenceUrl: rule.referenceUrl,
      };
      // A partial object is the list-view stub left when its detail GET failed — its spec is absent, so
      // running posture rules on it yields false PASS/FAIL. Emit one manual-verify finding and skip it.
      if (isPartialObject(object)) {
        findings.push({ ...base, status: 'INFO', verify: 'manual',
          verifyNote: 'Object could not be fully retrieved (partial config) — verify this control manually.',
          message: `${objectType.replace(/_/g, ' ')} "${objectName}" could not be fully retrieved; this control was not evaluated.` });
        return;
      }
      try {
        const result = rule.check(object, context);
        findings.push({
          ...base,
          status: result.status,
          message: result.message || '',
          currentValue: result.currentValue,
          expectedValue: result.expectedValue,
          details: result.details,
        });
      } catch (error) {
        findings.push({ ...base, status: 'ERROR', message: `Error running check: ${(error as Error).message}` });
      }
    };

    // Track which sub-objects were attributed to a load balancer so we can
    // surface the remainder as "unattached".
    const usedPools = new Set<string>();
    const usedWaf = new Set<string>();
    const usedCert = new Set<string>();
    const usedSP = new Set<string>();

    // LB-level scope (Tier 1): when the user picked specific LBs, audit only those. Tenant/namespace
    // checks below still run at their true scope.
    const scopedLbs = options?.loadBalancers && options.loadBalancers.length > 0
      ? new Set(options.loadBalancers.map((l) => `${l.namespace}/${l.name}`))
      : null;

    const lbEntries = [...context.configs.httpLoadBalancers.entries()]
      .filter(([lbKey]) => !scopedLbs || scopedLbs.has(lbKey));
    const totalLb = Math.max(lbEntries.length, 1);
    let lbIndex = 0;

    for (const [lbKey, lbObj] of lbEntries) {
      if (this.aborted) throw new Error('Audit aborted');

      const lbNs = lbKey.split('/')[0];
      const lbName = (getMetadata(lbObj).name as string) || lbKey.split('/')[1] || lbKey;
      const spec = ((lbObj as Record<string, unknown>).spec ||
        (lbObj as Record<string, unknown>).get_spec ||
        lbObj) as Record<string, unknown>;

      // LB-level checks
      for (const rule of lbRules) addFinding(rule, lbObj, lbNs, 'http_loadbalancer', lbName, lbName, lbKey);

      // Origin pools referenced by this LB (+ their health checks)
      for (const ref of this.collectPoolRefs(spec)) {
        const resolved = this.resolveRef(context.configs.originPools, ref, lbNs);
        if (!resolved) continue;
        usedPools.add(resolved.key);
        const poolNs = resolved.key.split('/')[0] || lbNs;
        const name = (getMetadata(resolved.obj).name as string) || ref.name;
        for (const rule of opRules) addFinding(rule, resolved.obj, lbNs, 'origin_pool', name, lbName, resolved.key);

        // Health checks referenced by this origin pool
        if (hcRules.length > 0) {
          const poolSpec = ((resolved.obj as Record<string, unknown>).spec ||
            (resolved.obj as Record<string, unknown>).get_spec ||
            resolved.obj) as Record<string, unknown>;
          const hcRefs = Array.isArray(poolSpec.healthcheck) ? (poolSpec.healthcheck as unknown[]) : [];
          for (const hcRefRaw of hcRefs) {
            const hcRef = this.refFrom(hcRefRaw);
            if (!hcRef) continue;
            const hc = this.resolveRef(context.configs.healthChecks, hcRef, poolNs);
            if (!hc) continue;
            const hcName = (getMetadata(hc.obj).name as string) || hcRef.name;
            for (const rule of hcRules) addFinding(rule, hc.obj, lbNs, 'healthcheck', `${name} / ${hcName}`, lbName, hc.key);
          }
        }
      }

      // App firewall (WAF) referenced by this LB
      const wafRef = this.refFrom(spec.app_firewall);
      if (wafRef) {
        const resolved = this.resolveRef(context.configs.appFirewalls, wafRef, lbNs);
        if (resolved) {
          usedWaf.add(resolved.key);
          const name = (getMetadata(resolved.obj).name as string) || wafRef.name;
          for (const rule of wafObjRules) addFinding(rule, resolved.obj, lbNs, 'app_firewall', name, lbName, resolved.key);
        } else if (wafObjRules.length > 0) {
          // Dark-spot guard: the LB references a WAF policy we could not retrieve (often in a shared/system
          // namespace) — do NOT silently skip the most important checks; flag for manual verification.
          findings.push({
            ruleId: 'WAFP-REF', ruleName: 'WAF policy retrievable', severity: 'HIGH', risk: 'High',
            entitlement: 'Base', category: 'WAF', namespace: lbNs, objectType: 'app_firewall',
            objectName: wafRef.name, loadBalancer: lbName, objectKey: `${wafRef.namespace || lbNs}/app_firewall/${wafRef.name}`,
            verify: 'manual', verifyNote: 'WAF policy is attached but could not be retrieved (it may live in a shared/system namespace) — verify its mode and tuning manually.',
            status: 'WARN', message: `WAF policy "${wafRef.name}" is attached to this load balancer but could not be retrieved, so its configuration was not audited.`,
            remediation: 'Ensure the WAF policy namespace is included in the audit, or verify the policy (blocking mode, signatures, tuning) directly in the console.',
          });
        }
      }

      // Service policies referenced by this LB
      for (const ref of this.servicePolicyRefs(spec)) {
        const resolved = this.resolveRef(context.configs.servicePolicies, ref, lbNs);
        if (!resolved) continue;
        usedSP.add(resolved.key);
        const name = (getMetadata(resolved.obj).name as string) || ref.name;
        for (const rule of spRules) addFinding(rule, resolved.obj, lbNs, 'service_policy', name, lbName, resolved.key);
      }

      // Custom certificates referenced by this LB
      for (const ref of this.certRefs(spec)) {
        const resolved = this.resolveRef(context.configs.certificates, ref, lbNs);
        if (!resolved) continue;
        usedCert.add(resolved.key);
        const name = (getMetadata(resolved.obj).name as string) || ref.name;
        for (const rule of certRules) addFinding(rule, resolved.obj, lbNs, 'certificate', name, lbName, resolved.key);
      }

      lbIndex++;
      this.reportProgress({
        phase: 'scanning',
        message: `Auditing load balancer: ${lbName}`,
        progress: 20 + Math.round((lbIndex / totalLb) * 65),
        rulesChecked: lbIndex,
        totalRules,
        findingsCount: findings.filter((f) => f.status === 'FAIL').length,
      });
    }

    // Note: objects NOT referenced by any load balancer are intentionally not
    // reported — the audit covers each LB and its attached child objects only.

    // Tenant-wide checks (SIEM, alerting, IAM, DNS) — run once, not per LB
    for (const rule of tenantRules) {
      addFinding(rule, {}, 'tenant-wide', 'tenant', 'Tenant Configuration', '(tenant-wide)', `tenant/${rule.id}`);
    }

    // PHASE 3: Generate report
    this.reportProgress({
      phase: 'reporting',
      message: 'Generating report...',
      progress: 95,
    });

    const report = this.generateReport(findings, context, namespaces, startTime, options);

    this.reportProgress({
      phase: 'complete',
      message: 'Audit complete!',
      progress: 100,
    });

    return report;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // PHASE 1: FETCH ALL CONFIGURATIONS
  // ─────────────────────────────────────────────────────────────────────────

  private async fetchAllConfigs(namespaces: string[]): Promise<AuditContext> {
    this.fetchErrors = [];
    const configs: AuditContext['configs'] = {
      httpLoadBalancers: new Map(),
      originPools: new Map(),
      appFirewalls: new Map(),
      healthChecks: new Map(),
      servicePolicies: new Map(),
      certificates: new Map(),
      alertPolicies: new Map(),
      alertReceivers: new Map(),
      globalLogReceivers: new Map(),
      userIdentifications: new Map(),
      dnsZones: new Map(),
    };

    let totalFetched = 0;
    const totalNamespaces = namespaces.length;

    // Fetch from each namespace
    for (let i = 0; i < namespaces.length; i++) {
      const namespace = namespaces[i];

      if (this.aborted) break;

      this.reportProgress({
        phase: 'fetching',
        message: `Fetching from namespace: ${namespace}`,
        progress: Math.round(((i + 1) / totalNamespaces) * 20),
        currentNamespace: namespace,
      });

      // Fetch all object types in parallel for this namespace
      const results = await Promise.allSettled([
        this.fetchLoadBalancers(namespace),
        this.fetchOriginPools(namespace),
        this.fetchAppFirewalls(namespace),
        this.fetchHealthChecks(namespace),
        this.fetchServicePolicies(namespace),
        this.fetchAlertPolicies(namespace),
        this.fetchAlertReceivers(namespace),
        this.fetchUserIdentifications(namespace),
        this.fetchCertificates(namespace),
      ]);

      // Process results
      if (results[0].status === 'fulfilled') {
        for (const [key, value] of results[0].value) {
          configs.httpLoadBalancers.set(key, value);
          totalFetched++;
        }
      }

      if (results[1].status === 'fulfilled') {
        for (const [key, value] of results[1].value) {
          configs.originPools.set(key, value);
          totalFetched++;
        }
      }

      if (results[2].status === 'fulfilled') {
        for (const [key, value] of results[2].value) {
          configs.appFirewalls.set(key, value);
          totalFetched++;
        }
      }

      if (results[3].status === 'fulfilled') {
        for (const [key, value] of results[3].value) {
          configs.healthChecks.set(key, value);
          totalFetched++;
        }
      }

      if (results[4].status === 'fulfilled') {
        for (const [key, value] of results[4].value) {
          configs.servicePolicies.set(key, value);
          totalFetched++;
        }
      }

      if (results[5].status === 'fulfilled') {
        for (const [key, value] of results[5].value) {
          configs.alertPolicies.set(key, value);
          totalFetched++;
        }
      }

      if (results[6].status === 'fulfilled') {
        for (const [key, value] of results[6].value) {
          configs.alertReceivers.set(key, value);
          totalFetched++;
        }
      }

      if (results[7].status === 'fulfilled') {
        for (const [key, value] of results[7].value) {
          configs.userIdentifications.set(key, value);
          totalFetched++;
        }
      }

      if (results[8].status === 'fulfilled') {
        for (const [key, value] of results[8].value) {
          configs.certificates.set(key, value);
          totalFetched++;
        }
      }
    }

    // Dark-spot fix: LBs frequently reference WAF policies / certs / pools / service-policies that live
    // in the `shared` (and sometimes `system`) namespace. Fetch those SUPPORTING object types from
    // shared/system too (deduped into the same maps) so their rules actually run instead of silently
    // going dark. We do NOT audit load balancers there — only resolve referenced dependencies.
    for (const supportNs of ['shared', 'system']) {
      if (namespaces.includes(supportNs) || this.aborted) continue;
      const support = await Promise.allSettled([
        this.fetchAppFirewalls(supportNs),
        this.fetchOriginPools(supportNs),
        this.fetchCertificates(supportNs),
        this.fetchServicePolicies(supportNs),
        this.fetchHealthChecks(supportNs),
      ]);
      const merge = (r: PromiseSettledResult<Map<string, unknown>>, into: Map<string, unknown>) => {
        if (r.status === 'fulfilled') for (const [k, v] of r.value) if (!into.has(k)) { into.set(k, v); totalFetched++; }
      };
      merge(support[0], configs.appFirewalls);
      merge(support[1], configs.originPools);
      merge(support[2], configs.certificates);
      merge(support[3], configs.servicePolicies);
      merge(support[4], configs.healthChecks);
    }

    // Fetch global objects (shared namespace)
    try {
      const glrMap = await this.fetchGlobalLogReceivers();
      for (const [key, value] of glrMap) {
        configs.globalLogReceivers.set(key, value);
        totalFetched++;
      }
    } catch (e) {
      console.warn('Could not fetch global log receivers:', e);
    }

    // Fetch XC-hosted DNS zones (tenant-wide, for DNSSEC) — best effort.
    try {
      const zoneMap = await this.fetchDnsZones();
      for (const [key, value] of zoneMap) {
        configs.dnsZones.set(key, value);
        totalFetched++;
      }
    } catch (e) {
      console.warn('Could not fetch DNS zones:', e);
    }

    // Build context with helper methods
    const context: AuditContext = {
      tenant: apiClient.getTenant() || '',
      fetchErrors: this.fetchErrors,
      configs,
      getOriginPool: (ns, name) => configs.originPools.get(`${ns}/${name}`),
      getAppFirewall: (ns, name) => configs.appFirewalls.get(`${ns}/${name}`),
      getHealthCheck: (ns, name) => configs.healthChecks.get(`${ns}/${name}`),
      getCertificate: (ns, name) => configs.certificates.get(`${ns}/${name}`),
      getServicePolicy: (ns, name) => configs.servicePolicies.get(`${ns}/${name}`),
      getUserIdentification: (ns, name) => configs.userIdentifications.get(`${ns}/${name}`),
    };

    return context;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // FETCH METHODS FOR EACH OBJECT TYPE
  // ─────────────────────────────────────────────────────────────────────────

  private async fetchLoadBalancers(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.getLoadBalancers(namespace);
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.getLoadBalancer(namespace, name);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, { ...(item as Record<string, unknown>), __partial: true });
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch load balancers from ${namespace}:`, e);
      // FATAL: the namespace's LB list could not be read → nothing in it was audited. Record so the
      // report/UI shows this scope as incomplete instead of silently scoring it clean.
      this.fetchErrors.push({ namespace, objectType: 'namespace', message: (e as Error).message || String(e), fatal: true });
    }
    return result;
  }

  private async fetchOriginPools(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(
        `/api/config/namespaces/${namespace}/origin_pools`
      );
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.getOriginPool(namespace, name);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, { ...(item as Record<string, unknown>), __partial: true });
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch origin pools from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchAppFirewalls(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(
        `/api/config/namespaces/${namespace}/app_firewalls`
      );
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.get(`/api/config/namespaces/${namespace}/app_firewalls/${name}`);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, { ...(item as Record<string, unknown>), __partial: true });
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch app firewalls from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchHealthChecks(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(
        `/api/config/namespaces/${namespace}/healthchecks`
      );
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.get(`/api/config/namespaces/${namespace}/healthchecks/${name}`);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, { ...(item as Record<string, unknown>), __partial: true });
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch health checks from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchServicePolicies(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(
        `/api/config/namespaces/${namespace}/service_policys`
      );
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.getServicePolicy(namespace, name);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, { ...(item as Record<string, unknown>), __partial: true });
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch service policies from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchAlertPolicies(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.getAlertPolicies(namespace);
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.getAlertPolicy(namespace, name);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, { ...(item as Record<string, unknown>), __partial: true });
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch alert policies from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchAlertReceivers(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.getAlertReceivers(namespace);
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.getAlertReceiver(namespace, name);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, { ...(item as Record<string, unknown>), __partial: true });
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch alert receivers from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchUserIdentifications(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(
        `/api/config/namespaces/${namespace}/user_identifications`
      );
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.get(`/api/config/namespaces/${namespace}/user_identifications/${name}`);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, { ...(item as Record<string, unknown>), __partial: true });
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch user identifications from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchCertificates(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(
        `/api/config/namespaces/${namespace}/certificates`
      );
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.get(`/api/config/namespaces/${namespace}/certificates/${name}`);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, { ...(item as Record<string, unknown>), __partial: true });
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch certificates from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchGlobalLogReceivers(): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    // Global log receivers live in the system namespace (Multi-Cloud Network
    // Connect → Log Management) or the shared namespace (Shared Configuration).
    // Check both so a SIEM configured in either is detected.
    for (const ns of ['system', 'shared']) {
      try {
        const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(
          `/api/config/namespaces/${ns}/global_log_receivers`
        );
        for (const item of resp.items || []) {
          const name = item.metadata?.name || item.name;
          if (!name) continue;
          // Fetch the full object so log-type coverage (TENANT-LOG-02) is visible.
          try {
            const full = await apiClient.get(`/api/config/namespaces/${ns}/global_log_receivers/${name}`);
            result.set(`${ns}/${name}`, full);
          } catch {
            result.set(`${ns}/${name}`, item);
          }
        }
      } catch (e) {
        console.warn(`Failed to fetch global log receivers from ${ns}:`, e);
      }
    }
    return result;
  }

  private async fetchDnsZones(): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    // DNS zones are managed in the system namespace under the DNS config path.
    const paths = ['/api/config/dns/namespaces/system/dns_zones', '/api/config/namespaces/system/dns_zones'];
    for (const path of paths) {
      try {
        const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(path);
        for (const item of resp.items || []) {
          const name = item.metadata?.name || item.name;
          if (!name || result.has(`system/${name}`)) continue;
          try {
            const full = await apiClient.get(`${path}/${name}`);
            result.set(`system/${name}`, full);
          } catch {
            result.set(`system/${name}`, item);
          }
        }
        if (result.size > 0) break; // first working path wins
      } catch {
        // try the next path shape
      }
    }
    return result;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // REFERENCE RESOLUTION (LB → sub-objects)
  // ─────────────────────────────────────────────────────────────────────────

  /** Normalize an XC object reference into { name, namespace? }. */
  private refFrom(val: unknown): { name: string; namespace?: string } | null {
    if (!val) return null;
    if (typeof val === 'string') return val ? { name: val } : null;
    if (typeof val === 'object') {
      const o = val as Record<string, unknown>;
      if (typeof o.name === 'string' && o.name) {
        return { name: o.name, namespace: typeof o.namespace === 'string' ? o.namespace : undefined };
      }
    }
    return null;
  }

  /** Resolve a reference against a config map, trying ns-qualified keys then a name match. */
  private resolveRef(
    map: Map<string, unknown>,
    ref: { name: string; namespace?: string },
    lbNamespace: string
  ): { key: string; obj: unknown } | null {
    const candidates = [
      `${ref.namespace || lbNamespace}/${ref.name}`,
      `${lbNamespace}/${ref.name}`,
      `shared/${ref.name}`,
    ];
    for (const c of candidates) {
      if (map.has(c)) return { key: c, obj: map.get(c) };
    }
    for (const [k, v] of map) {
      if (k.endsWith(`/${ref.name}`)) return { key: k, obj: v };
    }
    return null;
  }

  /** All origin-pool references on an LB spec (default route + per-route actions). */
  private collectPoolRefs(spec: Record<string, unknown>): Array<{ name: string; namespace?: string }> {
    const refs: Array<{ name: string; namespace?: string }> = [];
    const seen = new Set<string>();
    const add = (poolHolder: unknown) => {
      const ref = this.refFrom((poolHolder as Record<string, unknown>)?.pool);
      if (ref && !seen.has(ref.name)) {
        seen.add(ref.name);
        refs.push(ref);
      }
    };

    for (const p of (spec.default_route_pools as unknown[]) || []) add(p);

    for (const route of (spec.routes as Array<Record<string, unknown>>) || []) {
      for (const p of (route.origin_pools as unknown[]) || []) add(p);
      const ra = route.route_action as Record<string, unknown> | undefined;
      if (ra) {
        if (ra.single_default_pool) add(ra.single_default_pool);
        const wp = (ra.weighted_pools as Record<string, unknown> | undefined)?.pools as unknown[] | undefined;
        for (const p of wp || []) add(p);
      }
      const simple = route.simple_route_action as Record<string, unknown> | undefined;
      for (const p of (simple?.origin_pools as unknown[]) || []) add(p);
    }
    return refs;
  }

  /** Service-policy references on an LB spec (active_service_policies). */
  private servicePolicyRefs(spec: Record<string, unknown>): Array<{ name: string; namespace?: string }> {
    const active = spec.active_service_policies as Record<string, unknown> | undefined;
    const policies = (active?.policies as unknown[]) || [];
    return policies.map((p) => this.refFrom(p)).filter((r): r is { name: string; namespace?: string } => !!r);
  }

  /** Custom-certificate object references on an LB's HTTPS spec. */
  private certRefs(spec: Record<string, unknown>): Array<{ name: string; namespace?: string }> {
    const https = (spec.https || spec.https_auto_cert) as Record<string, unknown> | undefined;
    if (!https) return [];
    const refs: Array<{ name: string; namespace?: string }> = [];
    const certParams = https.tls_cert_params as Record<string, unknown> | undefined;
    for (const c of (certParams?.certificates as unknown[]) || []) {
      const r = this.refFrom(c);
      if (r) refs.push(r);
    }
    // Some configs reference cert objects directly under tls_certificates
    for (const c of (https.tls_certificates as Array<Record<string, unknown>>) || []) {
      const r = this.refFrom(c.certificate || c);
      if (r) refs.push(r);
    }
    return refs;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // GENERATE FINAL REPORT
  // ─────────────────────────────────────────────────────────────────────────

  private generateReport(
    findings: AuditFinding[],
    context: AuditContext,
    namespaces: string[],
    startTime: number,
    _options?: AuditOptions
  ): AuditReport {
    // The report retains EVERY finding (PASS/FAIL/WARN/SKIP) so exports can
    // present a complete checklist ("checkbook"). The UI filters for display.
    const reportFindings = findings;

    // Calculate summary
    const summary: AuditSummary = {
      total: findings.length,
      critical: findings.filter((f) => f.status === 'FAIL' && f.severity === 'CRITICAL').length,
      high: findings.filter((f) => f.status === 'FAIL' && f.severity === 'HIGH').length,
      medium: findings.filter((f) => f.status === 'FAIL' && f.severity === 'MEDIUM').length,
      low: findings.filter((f) => f.status === 'FAIL' && f.severity === 'LOW').length,
      info: findings.filter((f) => f.status === 'FAIL' && f.severity === 'INFO').length,
      passed: findings.filter((f) => f.status === 'PASS').length,
      warnings: findings.filter((f) => f.status === 'WARN').length,
      errors: findings.filter((f) => f.status === 'ERROR').length,
      skipped: findings.filter((f) => f.status === 'SKIP').length,
      informational: findings.filter((f) => f.status === 'INFO').length,
    };

    // Severity-weighted security score (0-100). A failed CRITICAL check costs
    // far more than a low-severity warning; WARN gets half credit, FAIL zero.
    // SKIP/ERROR are excluded. Applied consistently to overall + every scope.
    const { score, scoredCount } = weightedScore(findings);

    // Entitlement breakdown of FAILED checks — tells the customer how many gaps
    // are config fixes vs. require a licensed add-on.
    const failed = findings.filter((f) => f.status === 'FAIL');
    const entitlementSummary: EntitlementSummary = {
      baseFails: failed.filter((f) => f.entitlement === 'Base').length,
      entitlementFails: failed.filter((f) => f.entitlement === 'Entitlement').length,
      configFails: failed.filter((f) => f.entitlement === 'Config').length,
    };

    // Per-scope rollups (namespace + load balancer)
    const blankScope = (): ScopeSummary => ({ total: 0, pass: 0, fail: 0, warn: 0, na: 0, score: 0 });
    const tally = (s: ScopeSummary, status: string) => {
      s.total++;
      if (status === 'PASS') s.pass++;
      else if (status === 'FAIL') s.fail++;
      else if (status === 'WARN') s.warn++;
      else s.na++;
    };

    const nsMap = new Map<string, NamespaceSummary>();
    const nsLbs = new Map<string, Set<string>>();
    const nsFindings = new Map<string, AuditFinding[]>();
    const lbMap = new Map<string, LoadBalancerSummary>();
    const lbFindingsByKey = new Map<string, AuditFinding[]>();

    for (const f of findings) {
      // namespace rollup
      let ns = nsMap.get(f.namespace);
      if (!ns) {
        ns = { namespace: f.namespace, loadBalancers: 0, ...blankScope() };
        nsMap.set(f.namespace, ns);
        nsLbs.set(f.namespace, new Set());
        nsFindings.set(f.namespace, []);
      }
      tally(ns, f.status);
      nsFindings.get(f.namespace)!.push(f);
      if (f.loadBalancer && f.loadBalancer !== '(tenant-wide)' && f.loadBalancer !== '(unattached)') {
        nsLbs.get(f.namespace)!.add(f.loadBalancer);
      }

      // load balancer rollup
      const lbKey = `${f.namespace}|${f.loadBalancer}`;
      let lb = lbMap.get(lbKey);
      if (!lb) {
        lb = { namespace: f.namespace, loadBalancer: f.loadBalancer, ...blankScope() };
        lbMap.set(lbKey, lb);
        lbFindingsByKey.set(lbKey, []);
      }
      tally(lb, f.status);
      lbFindingsByKey.get(lbKey)!.push(f);
    }
    for (const ns of nsMap.values()) {
      ns.loadBalancers = nsLbs.get(ns.namespace)?.size ?? 0;
      ns.score = weightedScore(nsFindings.get(ns.namespace) || []).score;
    }
    for (const lb of lbMap.values()) {
      lb.score = weightedScore(lbFindingsByKey.get(`${lb.namespace}|${lb.loadBalancer}`) || []).score;
    }

    const namespaceSummary = [...nsMap.values()].sort((a, b) => a.namespace.localeCompare(b.namespace));
    const loadBalancerSummary = [...lbMap.values()].sort(
      (a, b) => a.namespace.localeCompare(b.namespace) || a.loadBalancer.localeCompare(b.loadBalancer)
    );

    // Config snapshot
    const configSnapshot: ConfigSnapshot = {
      loadBalancers: context.configs.httpLoadBalancers.size,
      originPools: context.configs.originPools.size,
      wafPolicies: context.configs.appFirewalls.size,
      healthChecks: context.configs.healthChecks.size,
      servicePolicies: context.configs.servicePolicies.size,
      certificates: context.configs.certificates.size,
      alertPolicies: context.configs.alertPolicies.size,
      alertReceivers: context.configs.alertReceivers.size,
      globalLogReceivers: context.configs.globalLogReceivers.size,
      userIdentifications: context.configs.userIdentifications.size,
    };

    return {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      tenant: context.tenant,
      namespaces,
      durationMs: Date.now() - startTime,
      summary,
      score,
      scoredCount,
      fetchErrors: context.fetchErrors,
      findings: reportFindings.sort((a, b) => {
        // Sort by severity (CRITICAL first), then by status (FAIL first)
        const severityOrder: Record<Severity, number> = {
          CRITICAL: 0,
          HIGH: 1,
          MEDIUM: 2,
          LOW: 3,
          INFO: 4,
        };
        const statusOrder: Record<string, number> = {
          FAIL: 0,
          WARN: 1,
          INFO: 2,
          ERROR: 3,
          PASS: 4,
          SKIP: 5,
        };

        const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
        if (sevDiff !== 0) return sevDiff;

        return (statusOrder[a.status] || 5) - (statusOrder[b.status] || 5);
      }),
      configSnapshot,
      entitlementSummary,
      namespaceSummary,
      loadBalancerSummary,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // HELPER METHODS
  // ─────────────────────────────────────────────────────────────────────────

  private reportProgress(progress: AuditProgress) {
    if (this.onProgress) {
      this.onProgress(progress);
    }
  }

  private meetsMinSeverity(ruleSeverity: Severity, minSeverity: Severity): boolean {
    const order: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 2,
      LOW: 3,
      INFO: 4,
    };
    return order[ruleSeverity] <= order[minSeverity];
  }
}
