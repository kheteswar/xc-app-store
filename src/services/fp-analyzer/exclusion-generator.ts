import type {
  WafExclusionRule,
  WafExclusionPolicyObject,
  SignatureAnalysisUnit,
  ViolationAnalysisUnit,
} from './types';

// ═══════════════════════════════════════════════════════════════
// PATH HELPERS
// ═══════════════════════════════════════════════════════════════

export function pathToRegex(path: string): string {
  const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return `^${escaped}/?$`;
}

function buildDomainField(domain?: string): Pick<WafExclusionRule, 'any_domain' | 'exact_value'> {
  if (!domain) return { any_domain: {} };
  return { exact_value: domain };
}

function buildPathField(path: string): Pick<WafExclusionRule, 'any_path' | 'path_prefix' | 'path_regex'> {
  // Clean paths (no query params, no wildcards) → use path_prefix
  if (/^\/[a-zA-Z0-9/_.-]*$/.test(path) && path.length > 1) {
    return { path_prefix: path };
  }
  // Root path or special → use path_regex
  if (path === '/') return { any_path: {} };
  return { path_regex: pathToRegex(path) };
}

// ═══════════════════════════════════════════════════════════════
// PATH COLLAPSING — fold many same-subtree FP paths into ONE rule
// ═══════════════════════════════════════════════════════════════

// When a signature/violation is an FP across many distinct paths under one directory (e.g. a scanner
// hitting 148 paths under /php/examples), emitting one exclusion per path is impractical. Collapse them
// into a single directory-subtree rule. ≥ this many same-prefix FP paths triggers a collapse.
const COLLAPSE_PATH_THRESHOLD = 4;

/** Longest common directory prefix by path segment: ['/a/b/x','/a/b/y/z'] → '/a/b'. */
function longestCommonDirPrefix(paths: string[]): string {
  const segLists = paths.map(p => p.split('/').filter(Boolean));
  if (segLists.length === 0) return '';
  let common = segLists[0];
  for (let k = 1; k < segLists.length && common.length > 0; k++) {
    const segs = segLists[k];
    let i = 0;
    while (i < common.length && i < segs.length && common[i] === segs[i]) i++;
    common = common.slice(0, i);
  }
  return '/' + common.join('/');
}

type CollapsedPath = { kind: 'prefix'; prefix: string; paths: string[] } | { kind: 'exact'; path: string };

/** Group FP paths by first segment; any group of ≥ threshold collapses to its longest common directory
 *  prefix (one subtree rule). Smaller groups stay per-path (precise). */
function collapseFpPaths(paths: string[], threshold = COLLAPSE_PATH_THRESHOLD): CollapsedPath[] {
  const uniq = [...new Set(paths.filter(p => p && p !== '/'))];
  if (uniq.length < threshold) return uniq.map(path => ({ kind: 'exact', path }));
  const groups = new Map<string, string[]>();
  for (const p of uniq) {
    const key = '/' + (p.split('/').filter(Boolean)[0] || '');
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(p);
  }
  const out: CollapsedPath[] = [];
  for (const [firstSeg, members] of groups) {
    if (members.length >= threshold) {
      const lcp = longestCommonDirPrefix(members);
      out.push({ kind: 'prefix', prefix: lcp.length > 1 ? lcp : firstSeg, paths: members });
    } else {
      for (const path of members) out.push({ kind: 'exact', path });
    }
  }
  return out;
}

/**
 * F5 XC RE2 path_regex matching a directory AND everything beneath it:
 *   /php/examples → ^/php/examples(/.*)?$
 * Anchored full-match; regex metacharacters in the literal prefix are escaped. RE2-compatible (no
 * lookaround/backrefs), so it is accepted by the F5 XC Distributed Cloud HTTP WAF exclusion-rule
 * path_regex field. The (/.*)? group matches the bare directory and any sub-path without over-matching
 * a sibling like /php/examplesX.
 */
function prefixPathRegexField(prefix: string): Pick<WafExclusionRule, 'path_regex'> {
  const escaped = prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return { path_regex: `^${escaped}(/.*)?$` };
}

// ═══════════════════════════════════════════════════════════════
// GENERATE SIGNATURE EXCLUSION
// ═══════════════════════════════════════════════════════════════

function buildSignatureRule(
  sigId: string, context: string, contextName: string, domain: string,
  pathField: Pick<WafExclusionRule, 'any_path' | 'path_prefix' | 'path_regex'>, pathLabel: string, methods: string[],
): WafExclusionRule {
  const hash = sigId.slice(-6) + Math.random().toString(36).slice(2, 6);
  return {
    metadata: {
      name: `fp-sig${sigId}-${hash}`,
      disable: false,
      description: `FP Analyzer: Exclude signature ${sigId} for ${context} "${contextName}" on ${pathLabel}`,
    },
    ...buildDomainField(domain),
    ...pathField,
    methods: methods.length > 0 ? methods : [],
    app_firewall_detection_control: {
      exclude_signature_contexts: [{
        signature_id: parseInt(sigId, 10),
        context,
        ...(contextName ? { context_name: contextName } : {}),
      }],
      exclude_violation_contexts: [],
      exclude_attack_type_contexts: [],
      exclude_bot_name_contexts: [],
    },
  };
}

export function generateSignatureExclusion(
  sigId: string,
  context: string,
  contextName: string,
  domain: string,
  path: string,
  methods: string[],
): WafExclusionRule {
  return buildSignatureRule(sigId, context, contextName, domain, buildPathField(path), path, methods);
}

// ═══════════════════════════════════════════════════════════════
// GENERATE ATTACK-TYPE EXCLUSION + ROLLUP
// ═══════════════════════════════════════════════════════════════

/**
 * Exclude an entire attack type on a path. F5 cascades this to ALL signatures
 * of that type — broader than a per-signature exclusion, so only use it when many
 * distinct signatures of one attack type are all firing as FPs on the same path.
 */
export function generateAttackTypeExclusion(
  attackType: string,
  domain: string,
  path: string,
  methods: string[],
): WafExclusionRule {
  const slug = attackType.toLowerCase().replace(/[^a-z0-9]+/g, '').slice(0, 6);
  const hash = slug + Math.random().toString(36).slice(2, 6);
  return {
    metadata: {
      name: `fp-atk-${hash}`,
      disable: false,
      description: `FP Analyzer: Exclude attack type ${attackType} on ${path} (rolled up from multiple FP signatures)`,
    },
    ...buildDomainField(domain),
    ...buildPathField(path),
    methods: methods.length > 0 ? methods : [],
    app_firewall_detection_control: {
      exclude_signature_contexts: [],
      exclude_violation_contexts: [],
      exclude_attack_type_contexts: [{ context: 'CONTEXT_ANY', exclude_attack_type: attackType }],
      exclude_bot_name_contexts: [],
    },
  };
}

export interface SigExclusionIntent {
  signatureId: string;
  attackType: string;
  contextType: string;
  contextName: string;
  path: string;
  methods: string[];
}

/**
 * Build signature exclusions with attack-type rollup. When >= minSigsPerAttackType
 * DISTINCT signatures of the same attack_type are excluded on the same path+methods,
 * collapse them into one attack-type exclusion (fewer, broader rules — F5 best
 * practice). Smaller groups stay as precise per-signature exclusions.
 */
export function buildSignatureExclusionsWithRollup(
  intents: SigExclusionIntent[],
  domain = '',
  minSigsPerAttackType = 3,
): WafExclusionRule[] {
  const groups = new Map<string, SigExclusionIntent[]>();
  for (const it of intents) {
    const methodsKey = [...it.methods].sort().join(',');
    const key = `${it.path}|${methodsKey}|${it.attackType || ''}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(it);
  }

  const rules: WafExclusionRule[] = [];
  for (const group of groups.values()) {
    const distinctSigs = new Set(group.map(i => i.signatureId));
    const first = group[0];
    if (first.attackType && distinctSigs.size >= minSigsPerAttackType) {
      rules.push(generateAttackTypeExclusion(first.attackType, domain, first.path, first.methods));
    } else {
      for (const it of group) {
        rules.push(generateSignatureExclusion(it.signatureId, it.contextType, it.contextName, domain, it.path, it.methods));
      }
    }
  }
  return groupExclusionRules(rules);
}

// ═══════════════════════════════════════════════════════════════
// GENERATE VIOLATION EXCLUSION
// ═══════════════════════════════════════════════════════════════

function buildViolationRule(
  violationName: string, context: string, contextName: string, domain: string,
  pathField: Pick<WafExclusionRule, 'any_path' | 'path_prefix' | 'path_regex'>, pathLabel: string, methods: string[],
): WafExclusionRule {
  const hash = Math.random().toString(36).slice(2, 8);
  return {
    metadata: {
      name: `fp-viol-${hash}`,
      disable: false,
      description: `FP Analyzer: Exclude ${violationName} on ${pathLabel}`,
    },
    ...buildDomainField(domain),
    ...pathField,
    methods: methods.length > 0 ? methods : [],
    app_firewall_detection_control: {
      exclude_signature_contexts: [],
      exclude_violation_contexts: [{
        exclude_violation: violationName,
        context,
        ...(contextName ? { context_name: contextName } : {}),
      }],
      exclude_attack_type_contexts: [],
      exclude_bot_name_contexts: [],
    },
  };
}

export function generateViolationExclusion(
  violationName: string,
  context: string,
  contextName: string,
  domain: string,
  path: string,
  methods: string[],
): WafExclusionRule {
  return buildViolationRule(violationName, context, contextName, domain, buildPathField(path), path, methods);
}

// ═══════════════════════════════════════════════════════════════
// GROUP EXCLUSION RULES (merge by domain + path + methods)
// ═══════════════════════════════════════════════════════════════

export function groupExclusionRules(rules: WafExclusionRule[]): WafExclusionRule[] {
  const groups = new Map<string, WafExclusionRule>();

  for (const rule of rules) {
    const domainKey = rule.exact_value || (rule.any_domain ? 'any' : '');
    const pathKey = rule.path_regex || rule.path_prefix || (rule.any_path ? 'any' : '');
    const key = `${domainKey}|${pathKey}|${rule.methods.sort().join(',')}`;
    if (!groups.has(key)) {
      groups.set(key, {
        ...rule,
        app_firewall_detection_control: {
          exclude_signature_contexts: [...rule.app_firewall_detection_control.exclude_signature_contexts],
          exclude_violation_contexts: [...rule.app_firewall_detection_control.exclude_violation_contexts],
          exclude_attack_type_contexts: [...rule.app_firewall_detection_control.exclude_attack_type_contexts],
          exclude_bot_name_contexts: [...rule.app_firewall_detection_control.exclude_bot_name_contexts],
        },
      });
    } else {
      const existing = groups.get(key)!;
      existing.app_firewall_detection_control.exclude_signature_contexts.push(
        ...rule.app_firewall_detection_control.exclude_signature_contexts,
      );
      existing.app_firewall_detection_control.exclude_violation_contexts.push(
        ...rule.app_firewall_detection_control.exclude_violation_contexts,
      );
      existing.app_firewall_detection_control.exclude_attack_type_contexts.push(
        ...rule.app_firewall_detection_control.exclude_attack_type_contexts,
      );
      existing.metadata.description += ` + ${rule.metadata.description}`;
    }
  }

  return [...groups.values()];
}

// ═══════════════════════════════════════════════════════════════
// PER-PATH EXCLUSIONS FOR SIGNATURES
// ═══════════════════════════════════════════════════════════════

export function generatePerPathExclusions(
  unit: SignatureAnalysisUnit,
  domain?: string,
): WafExclusionRule[] {
  const rules: WafExclusionRule[] = [];
  if (!unit.pathAnalyses) return rules;

  const fpPas = unit.pathAnalyses.filter(pa => pa.verdict === 'highly_likely_fp' || pa.verdict === 'likely_fp');
  if (fpPas.length === 0) return rules;
  const paByPath = new Map(fpPas.map(pa => [pa.path, pa]));

  for (const c of collapseFpPaths([...paByPath.keys()])) {
    if (c.kind === 'prefix') {
      const methods = [...new Set(c.paths.flatMap(p => Object.keys(paByPath.get(p)?.methods ?? {})))];
      rules.push(buildSignatureRule(
        unit.signatureId, unit.contextType, unit.contextName, domain || '',
        prefixPathRegexField(c.prefix),
        `${c.prefix}/* (${c.paths.length} FP paths collapsed — review: a subtree exclusion whitelists the whole directory)`,
        methods,
      ));
    } else {
      const pa = paByPath.get(c.path)!;
      rules.push(generateSignatureExclusion(unit.signatureId, unit.contextType, unit.contextName, domain || '', c.path, Object.keys(pa.methods)));
    }
  }

  return groupExclusionRules(rules);
}

// ═══════════════════════════════════════════════════════════════
// PER-PATH EXCLUSIONS FOR VIOLATIONS
// ═══════════════════════════════════════════════════════════════

export function generateViolationPerPathExclusions(
  unit: ViolationAnalysisUnit,
  domain?: string,
): WafExclusionRule[] {
  const rules: WafExclusionRule[] = [];
  if (!unit.pathAnalyses) return rules;

  const fpPas = unit.pathAnalyses.filter(pa => pa.verdict === 'highly_likely_fp' || pa.verdict === 'likely_fp');
  if (fpPas.length === 0) return rules;
  const paByPath = new Map(fpPas.map(pa => [pa.path, pa]));

  for (const c of collapseFpPaths([...paByPath.keys()])) {
    if (c.kind === 'prefix') {
      const methods = [...new Set(c.paths.flatMap(p => Object.keys(paByPath.get(p)?.methods ?? {})))];
      rules.push(buildViolationRule(
        unit.violationName, 'CONTEXT_ANY', '', domain || '',
        prefixPathRegexField(c.prefix),
        `${c.prefix}/* (${c.paths.length} FP paths collapsed — review: a subtree exclusion whitelists the whole directory)`,
        methods,
      ));
    } else {
      const pa = paByPath.get(c.path)!;
      rules.push(generateViolationExclusion(unit.violationName, 'CONTEXT_ANY', '', domain || '', c.path, Object.keys(pa.methods)));
    }
  }

  return groupExclusionRules(rules);
}

// ═══════════════════════════════════════════════════════════════
// GENERATE ALL EXCLUSIONS FOR SIGNATURE UNITS (aggregate level)
// ═══════════════════════════════════════════════════════════════

export function generateExclusionsForSignatures(
  units: SignatureAnalysisUnit[],
  domain = '',
): WafExclusionRule[] {
  const rules: WafExclusionRule[] = [];

  for (const unit of units) {
    // Prefer per-path exclusions when available
    if (unit.pathAnalyses && unit.pathAnalyses.length > 0) {
      rules.push(...generatePerPathExclusions(unit, domain));
    } else if (unit.signals.verdict === 'highly_likely_fp' || unit.signals.verdict === 'likely_fp') {
      rules.push(generateSignatureExclusion(
        unit.signatureId,
        unit.contextType,
        unit.contextName,
        domain,
        unit.path,
        Object.keys(unit.methods),
      ));
    }
  }

  return groupExclusionRules(rules);
}

// ═══════════════════════════════════════════════════════════════
// BUILD WAF EXCLUSION POLICY OBJECT
// ═══════════════════════════════════════════════════════════════

/**
 * Build a standalone WAF Exclusion Policy object from exclusion rules.
 * This creates a first-class F5 XC config object that can be POSTed
 * to /api/config/namespaces/{ns}/waf_exclusion_policys.
 */
export function buildWafExclusionPolicy(
  lbName: string,
  namespace: string,
  rules: WafExclusionRule[],
): WafExclusionPolicyObject {
  const sanitizedLbName = lbName.replace(/[^a-z0-9-]/gi, '-').toLowerCase();
  const dateStr = new Date().toISOString().slice(0, 10);
  const name = `fp-${sanitizedLbName}-${dateStr}`;

  // Group rules for dedup before building the policy
  const grouped = groupExclusionRules(rules);

  return {
    metadata: {
      name,
      namespace,
      labels: {
        'app.f5.com/generated-by': 'fp-analyzer',
      },
      description: `FP Analyzer auto-generated exclusion policy for ${lbName} on ${dateStr}`,
    },
    spec: {
      waf_exclusion_rules: grouped,
    },
  };
}

// ═══════════════════════════════════════════════════════════════
// CLEAN POLICY FOR DOWNLOAD (remove undefined fields)
// ═══════════════════════════════════════════════════════════════

export function cleanPolicyForExport(policy: WafExclusionPolicyObject): Record<string, unknown> {
  return JSON.parse(JSON.stringify(policy, (_key, value) => {
    if (value === undefined) return undefined;
    return value;
  }));
}
