import yaml from 'js-yaml';
import type { SemanticChange, SemanticFormat } from './types';
import { myersDiff } from './diff-engine';

const MAX_DEPTH = 50;

export function jsonDiff(leftStr: string, rightStr: string): SemanticChange[] {
  const left = JSON.parse(leftStr);
  const right = JSON.parse(rightStr);
  return diffValues(left, right, '$', 0);
}

export function yamlDiff(leftStr: string, rightStr: string): SemanticChange[] {
  const left = yaml.load(leftStr);
  const right = yaml.load(rightStr);
  return diffValues(left, right, '$', 0);
}

export function xmlDiff(leftStr: string, rightStr: string): SemanticChange[] {
  if (typeof DOMParser === 'undefined') {
    throw new Error('DOMParser not available in this environment');
  }
  const parser = new DOMParser();
  const leftDoc = parser.parseFromString(leftStr, 'application/xml');
  const rightDoc = parser.parseFromString(rightStr, 'application/xml');
  const leftErr = leftDoc.querySelector('parsererror');
  const rightErr = rightDoc.querySelector('parsererror');
  if (leftErr) throw new Error(`Left XML parse error: ${leftErr.textContent}`);
  if (rightErr) throw new Error(`Right XML parse error: ${rightErr.textContent}`);
  const changes: SemanticChange[] = [];
  diffXmlNodes(leftDoc.documentElement, rightDoc.documentElement, '$', changes);
  return changes;
}

export function runSemanticDiff(
  format: SemanticFormat,
  left: string,
  right: string,
): { changes: SemanticChange[]; error?: string } {
  try {
    if (format === 'json') return { changes: jsonDiff(left, right) };
    if (format === 'yaml') return { changes: yamlDiff(left, right) };
    if (format === 'xml') return { changes: xmlDiff(left, right) };
  } catch (e) {
    return { changes: [], error: e instanceof Error ? e.message : String(e) };
  }
  return { changes: [] };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function diffValues(left: unknown, right: unknown, path: string, depth: number): SemanticChange[] {
  if (depth > MAX_DEPTH) return [];
  const changes: SemanticChange[] = [];

  if (left === right) return changes;
  if (left === null || right === null || left === undefined || right === undefined) {
    if (left !== right) changes.push({ path, type: 'changed', oldValue: left, newValue: right });
    return changes;
  }
  if (typeof left !== typeof right) {
    changes.push({ path, type: 'changed', oldValue: left, newValue: right });
    return changes;
  }

  if (Array.isArray(left) && Array.isArray(right)) {
    changes.push(...diffArrays(left, right, path, depth));
    return changes;
  }

  if (isPlainObject(left) && isPlainObject(right)) {
    const allKeys = new Set<string>([...Object.keys(left), ...Object.keys(right)]);
    const sortedKeys = [...allKeys].sort();
    for (const key of sortedKeys) {
      const childPath = renderKey(path, key);
      const inLeft = key in left;
      const inRight = key in right;
      if (!inLeft) {
        changes.push({ path: childPath, type: 'added', newValue: right[key] });
      } else if (!inRight) {
        changes.push({ path: childPath, type: 'removed', oldValue: left[key] });
      } else {
        changes.push(...diffValues(left[key], right[key], childPath, depth + 1));
      }
    }
    return changes;
  }

  if (left !== right) {
    changes.push({ path, type: 'changed', oldValue: left, newValue: right });
  }
  return changes;
}

function diffArrays(left: unknown[], right: unknown[], path: string, depth: number): SemanticChange[] {
  const changes: SemanticChange[] = [];
  const leftKeys = left.map(stableKey);
  const rightKeys = right.map(stableKey);
  const ops = myersDiff(leftKeys, rightKeys);

  let i = 0;
  while (i < ops.length) {
    const op = ops[i];
    if (op.type === 'equal') {
      i++;
      continue;
    }
    const deletes: number[] = [];
    while (i < ops.length && ops[i].type === 'delete') {
      deletes.push((ops[i] as { leftIdx: number }).leftIdx);
      i++;
    }
    const inserts: number[] = [];
    while (i < ops.length && ops[i].type === 'insert') {
      inserts.push((ops[i] as { rightIdx: number }).rightIdx);
      i++;
    }
    const pairCount = Math.min(deletes.length, inserts.length);
    for (let p = 0; p < pairCount; p++) {
      const childPath = `${path}[${deletes[p]}]`;
      changes.push(...diffValues(left[deletes[p]], right[inserts[p]], childPath, depth + 1));
    }
    for (let p = pairCount; p < deletes.length; p++) {
      changes.push({ path: `${path}[${deletes[p]}]`, type: 'removed', oldValue: left[deletes[p]] });
    }
    for (let p = pairCount; p < inserts.length; p++) {
      changes.push({ path: `${path}[${inserts[p]}]`, type: 'added', newValue: right[inserts[p]] });
    }
  }
  return changes;
}

function stableKey(v: unknown): string {
  if (v === null) return 'null';
  if (typeof v !== 'object') return typeof v + ':' + String(v);
  try {
    return JSON.stringify(v, Object.keys(v as Record<string, unknown>).sort());
  } catch {
    return Object.prototype.toString.call(v);
  }
}

function renderKey(parent: string, key: string): string {
  if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key)) return `${parent}.${key}`;
  return `${parent}["${key.replace(/"/g, '\\"')}"]`;
}

function diffXmlNodes(left: Element | null, right: Element | null, path: string, changes: SemanticChange[]) {
  if (!left && !right) return;
  if (!left && right) {
    changes.push({ path, type: 'added', newValue: right.outerHTML });
    return;
  }
  if (left && !right) {
    changes.push({ path, type: 'removed', oldValue: left.outerHTML });
    return;
  }
  const a = left!;
  const b = right!;
  if (a.tagName !== b.tagName) {
    changes.push({ path, type: 'changed', oldValue: a.tagName, newValue: b.tagName });
    return;
  }
  const aAttrs: Record<string, string> = {};
  const bAttrs: Record<string, string> = {};
  for (const at of Array.from(a.attributes)) aAttrs[at.name] = at.value;
  for (const at of Array.from(b.attributes)) bAttrs[at.name] = at.value;
  const allAttrs = new Set([...Object.keys(aAttrs), ...Object.keys(bAttrs)]);
  for (const name of [...allAttrs].sort()) {
    const ap = `${path}@${name}`;
    if (!(name in aAttrs)) changes.push({ path: ap, type: 'added', newValue: bAttrs[name] });
    else if (!(name in bAttrs)) changes.push({ path: ap, type: 'removed', oldValue: aAttrs[name] });
    else if (aAttrs[name] !== bAttrs[name]) {
      changes.push({ path: ap, type: 'changed', oldValue: aAttrs[name], newValue: bAttrs[name] });
    }
  }

  const aChildren = elementChildren(a);
  const bChildren = elementChildren(b);
  const max = Math.max(aChildren.length, bChildren.length);
  const tagCounts: Record<string, number> = {};
  for (let i = 0; i < max; i++) {
    const ac = aChildren[i] ?? null;
    const bc = bChildren[i] ?? null;
    const tag = (ac?.tagName ?? bc?.tagName ?? 'node').toLowerCase();
    const idx = tagCounts[tag] ?? 0;
    tagCounts[tag] = idx + 1;
    const childPath = `${path}/${tag}[${idx}]`;
    diffXmlNodes(ac, bc, childPath, changes);
  }

  const aText = directText(a);
  const bText = directText(b);
  if (aText !== bText) {
    changes.push({ path: `${path}/text()`, type: 'changed', oldValue: aText, newValue: bText });
  }
}

function elementChildren(n: Element): Element[] {
  const out: Element[] = [];
  for (const c of Array.from(n.childNodes)) {
    if (c.nodeType === 1) out.push(c as Element);
  }
  return out;
}

function directText(n: Element): string {
  let s = '';
  for (const c of Array.from(n.childNodes)) {
    if (c.nodeType === 3) s += c.nodeValue ?? '';
  }
  return s.trim();
}

export function summarizeSemantic(changes: SemanticChange[]) {
  let added = 0;
  let removed = 0;
  let changed = 0;
  for (const c of changes) {
    if (c.type === 'added') added++;
    else if (c.type === 'removed') removed++;
    else if (c.type === 'changed') changed++;
  }
  return { added, removed, changed, total: changes.length };
}
