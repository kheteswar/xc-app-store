import { useMemo, useState } from 'react';
import { ChevronRight, Plus, Minus, Edit3, AlertTriangle } from 'lucide-react';
import type { SemanticChange } from '../../services/diff-checker/types';
import { summarizeSemantic } from '../../services/diff-checker/semantic-diff';

interface Props {
  changes: SemanticChange[];
  error?: string;
  formatLabel: string;
}

interface TreeNode {
  key: string;
  fullPath: string;
  children: Map<string, TreeNode>;
  change?: SemanticChange;
}

function buildTree(changes: SemanticChange[]): TreeNode {
  const root: TreeNode = { key: '$', fullPath: '$', children: new Map() };
  for (const change of changes) {
    const segments = tokenizePath(change.path);
    let node = root;
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i];
      let child = node.children.get(seg.display);
      if (!child) {
        child = { key: seg.display, fullPath: segments.slice(0, i + 1).map(s => s.display).join(''), children: new Map() };
        node.children.set(seg.display, child);
      }
      node = child;
    }
    node.change = change;
  }
  return root;
}

function tokenizePath(path: string): { display: string }[] {
  const segments: { display: string }[] = [];
  let i = 0;
  if (path.startsWith('$')) i = 1;
  let buffer = '$';
  while (i < path.length) {
    const ch = path[i];
    if (ch === '.') {
      if (buffer !== '$') segments.push({ display: buffer });
      buffer = '.';
      i++;
      while (i < path.length && /[A-Za-z0-9_$-]/.test(path[i])) {
        buffer += path[i];
        i++;
      }
    } else if (ch === '[') {
      if (buffer !== '$') segments.push({ display: buffer });
      buffer = '';
      const end = path.indexOf(']', i);
      if (end < 0) break;
      buffer = path.slice(i, end + 1);
      segments.push({ display: buffer });
      buffer = '';
      i = end + 1;
    } else if (ch === '/') {
      if (buffer !== '$') segments.push({ display: buffer });
      buffer = '/';
      i++;
      while (i < path.length && path[i] !== '/' && path[i] !== '[' && path[i] !== '@') {
        buffer += path[i];
        i++;
      }
    } else if (ch === '@') {
      if (buffer !== '$' && buffer !== '') segments.push({ display: buffer });
      buffer = '@';
      i++;
      while (i < path.length && /[A-Za-z0-9_:-]/.test(path[i])) {
        buffer += path[i];
        i++;
      }
    } else {
      buffer += ch;
      i++;
    }
  }
  if (buffer && buffer !== '$') segments.push({ display: buffer });
  return segments;
}

export function SemanticView({ changes, error, formatLabel }: Props) {
  const summary = useMemo(() => summarizeSemantic(changes), [changes]);
  const tree = useMemo(() => buildTree(changes), [changes]);

  if (error) {
    return (
      <div className="p-6 bg-amber-500/10 border border-amber-500/30 rounded-lg flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
        <div>
          <div className="text-amber-300 font-semibold mb-1">Could not parse as {formatLabel}</div>
          <div className="text-sm text-amber-200/80 font-mono">{error}</div>
          <div className="text-xs text-slate-400 mt-2">Showing text diff instead.</div>
        </div>
      </div>
    );
  }

  if (changes.length === 0) {
    return (
      <div className="p-6 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-center">
        <div className="text-emerald-300 font-semibold">No semantic differences</div>
        <div className="text-xs text-slate-400 mt-1">
          Both sides are structurally identical in {formatLabel} — reordered keys are not changes.
        </div>
      </div>
    );
  }

  return (
    <div className="p-3">
      <div className="flex items-center gap-4 mb-3 text-sm">
        <span className="text-slate-300 font-semibold">Semantic diff — {formatLabel}</span>
        <span className="text-rose-400 font-mono">{summary.removed} removed</span>
        <span className="text-emerald-400 font-mono">{summary.added} added</span>
        <span className="text-amber-300 font-mono">{summary.changed} changed</span>
      </div>
      <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-2 font-mono text-[12px]">
        <TreeView node={tree} depth={0} />
      </div>
    </div>
  );
}

function TreeView({ node, depth }: { node: TreeNode; depth: number }) {
  const [open, setOpen] = useState(depth < 3);
  const hasChildren = node.children.size > 0;
  const indent = { paddingLeft: `${depth * 14}px` } as const;

  if (node.change && !hasChildren) {
    return <LeafChange node={node} indent={indent} />;
  }

  return (
    <div>
      {depth > 0 && (
        <div style={indent} className="flex items-center gap-1 py-0.5 text-slate-300 cursor-pointer hover:bg-slate-800/50 rounded" onClick={() => setOpen(o => !o)}>
          <ChevronRight className={`w-3.5 h-3.5 transition-transform ${open ? 'rotate-90' : ''}`} />
          <span className="text-slate-400">{node.key}</span>
          {node.change && <span className="text-slate-500 text-[10px]">[{node.change.type}]</span>}
        </div>
      )}
      {open && (
        <div>
          {[...node.children.values()].map(child => (
            <TreeView key={child.fullPath} node={child} depth={depth + 1} />
          ))}
          {node.change && hasChildren && <LeafChange node={node} indent={{ paddingLeft: `${(depth + 1) * 14}px` }} />}
        </div>
      )}
    </div>
  );
}

function LeafChange({ node, indent }: { node: TreeNode; indent: React.CSSProperties }) {
  const change = node.change!;
  const Icon = change.type === 'added' ? Plus : change.type === 'removed' ? Minus : Edit3;
  const color = change.type === 'added' ? 'text-emerald-400' : change.type === 'removed' ? 'text-rose-400' : 'text-amber-300';
  return (
    <div style={indent} className="flex items-start gap-2 py-0.5">
      <Icon className={`w-3.5 h-3.5 mt-0.5 flex-shrink-0 ${color}`} />
      <div className="flex-1 min-w-0">
        <div className="text-slate-300">{node.key}</div>
        {change.type === 'changed' && (
          <div className="text-slate-400 text-[11px] pl-2">
            <span className="text-rose-400 line-through mr-1">{formatValue(change.oldValue)}</span>
            →
            <span className="text-emerald-400 ml-1">{formatValue(change.newValue)}</span>
          </div>
        )}
        {change.type === 'added' && (
          <div className="text-emerald-400 text-[11px] pl-2">{formatValue(change.newValue)}</div>
        )}
        {change.type === 'removed' && (
          <div className="text-rose-400 line-through text-[11px] pl-2">{formatValue(change.oldValue)}</div>
        )}
      </div>
    </div>
  );
}

function formatValue(v: unknown): string {
  if (v === undefined) return 'undefined';
  if (v === null) return 'null';
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'object') {
    try {
      const json = JSON.stringify(v);
      return json.length > 80 ? json.slice(0, 80) + '…' : json;
    } catch {
      return String(v);
    }
  }
  return String(v);
}
