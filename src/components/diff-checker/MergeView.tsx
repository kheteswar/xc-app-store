import { useMemo, useState } from 'react';
import { Copy, Download, CheckCircle, AlertTriangle, ChevronsLeft, ChevronsRight, FileText } from 'lucide-react';
import type { MergeConflict, ThreeWayInput } from '../../services/diff-checker/types';
import { renderResolved, threeWayMerge } from '../../services/diff-checker/three-way-merge';
import { InputPanel } from './InputPanel';

interface Props {
  input: ThreeWayInput;
  onInputChange: (next: ThreeWayInput) => void;
}

export function MergeView({ input, onInputChange }: Props) {
  const baseResult = useMemo(() => threeWayMerge(input), [input]);
  const [conflictState, setConflictState] = useState<Record<string, MergeConflict>>({});

  const conflicts = baseResult.conflicts.map(c => conflictState[c.id] ? { ...c, ...conflictState[c.id] } : c);
  const merged = useMemo(() => renderResolved(baseResult.segments, conflicts).join('\n'), [baseResult.segments, conflicts]);

  const remaining = conflicts.filter(c => !c.resolution || (c.resolution === 'manual' && !c.manualContent)).length;

  const resolve = (id: string, resolution: MergeConflict['resolution'], manualContent?: string) => {
    setConflictState(s => ({
      ...s,
      [id]: { ...(s[id] ?? baseResult.conflicts.find(c => c.id === id)!), resolution, manualContent },
    }));
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <InputPanel label="Base (ancestor)" value={input.base} onChange={(v) => onInputChange({ ...input, base: v })} onClear={() => onInputChange({ ...input, base: '' })} compact showUrlFetch={false} />
        <InputPanel label="Left (your changes)" value={input.left} onChange={(v) => onInputChange({ ...input, left: v })} onClear={() => onInputChange({ ...input, left: '' })} compact showUrlFetch={false} />
        <InputPanel label="Right (their changes)" value={input.right} onChange={(v) => onInputChange({ ...input, right: v })} onClear={() => onInputChange({ ...input, right: '' })} compact showUrlFetch={false} />
      </div>

      <div className="px-3 py-2 bg-slate-800/40 border border-slate-700 rounded text-xs flex items-center gap-4">
        <span className="flex items-center gap-1 text-emerald-400">
          <CheckCircle className="w-3.5 h-3.5" /> {baseResult.autoResolved} auto-resolved
        </span>
        <span className="flex items-center gap-1 text-amber-300">
          <AlertTriangle className="w-3.5 h-3.5" /> {remaining} of {baseResult.conflictCount} conflicts remaining
        </span>
      </div>

      {conflicts.length === 0 && (input.base || input.left || input.right) && (
        <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-center text-emerald-300 text-sm">
          Clean merge — no conflicts.
        </div>
      )}

      {conflicts.map((conflict, idx) => (
        <ConflictBlock
          key={conflict.id}
          conflict={conflict}
          idx={idx + 1}
          total={conflicts.length}
          onResolve={resolve}
        />
      ))}

      <ResolvedOutput merged={merged} remaining={remaining} />
    </div>
  );
}

function ConflictBlock({ conflict, idx, total, onResolve }: { conflict: MergeConflict; idx: number; total: number; onResolve: (id: string, resolution: MergeConflict['resolution'], manualContent?: string) => void }) {
  const [manualOpen, setManualOpen] = useState(false);
  const [manualText, setManualText] = useState(conflict.manualContent ?? conflict.leftLines.join('\n'));

  const isResolved = !!conflict.resolution && !(conflict.resolution === 'manual' && !conflict.manualContent);

  return (
    <div className={`border rounded-lg overflow-hidden ${isResolved ? 'border-emerald-500/30 bg-emerald-500/[0.03]' : 'border-amber-500/40 bg-amber-500/[0.03]'}`}>
      <div className="flex items-center justify-between px-3 py-1.5 bg-slate-800/60 border-b border-slate-700 text-xs">
        <div className="font-mono text-slate-300">
          Conflict {idx} of {total} {isResolved && <span className="text-emerald-400 ml-2">✓ resolved as {conflict.resolution}</span>}
        </div>
        <div className="flex items-center gap-1">
          <ResolveBtn label="Left" active={conflict.resolution === 'left'} onClick={() => onResolve(conflict.id, 'left')}>
            <ChevronsLeft className="w-3 h-3" />
          </ResolveBtn>
          <ResolveBtn label="Right" active={conflict.resolution === 'right'} onClick={() => onResolve(conflict.id, 'right')}>
            <ChevronsRight className="w-3 h-3" />
          </ResolveBtn>
          <ResolveBtn label="Base" active={conflict.resolution === 'base'} onClick={() => onResolve(conflict.id, 'base')}>
            <FileText className="w-3 h-3" />
          </ResolveBtn>
          <button
            type="button"
            onClick={() => setManualOpen(o => !o)}
            className={`px-1.5 py-0.5 text-[10px] rounded transition-colors ${manualOpen || conflict.resolution === 'manual' ? 'bg-blue-500/30 text-blue-200' : 'text-slate-400 hover:text-slate-100 hover:bg-slate-700'}`}
          >
            Edit ✎
          </button>
        </div>
      </div>
      <div className="grid grid-cols-3 font-mono text-[11px] leading-5 border-b border-slate-700">
        <Side title="LEFT" lines={conflict.leftLines} accent="emerald" />
        <Side title="BASE" lines={conflict.baseLines} accent="slate" />
        <Side title="RIGHT" lines={conflict.rightLines} accent="rose" />
      </div>
      {manualOpen && (
        <div className="p-2 bg-slate-900/50">
          <textarea
            value={manualText}
            onChange={e => setManualText(e.target.value)}
            className="w-full min-h-[80px] p-2 bg-slate-900 border border-slate-700 text-slate-200 font-mono text-[11px] rounded outline-none"
          />
          <div className="flex justify-end mt-1 gap-2">
            <button type="button" onClick={() => setManualOpen(false)} className="px-2 py-0.5 text-[11px] text-slate-400 hover:text-slate-100">Cancel</button>
            <button type="button" onClick={() => { onResolve(conflict.id, 'manual', manualText); setManualOpen(false); }} className="px-2 py-0.5 text-[11px] bg-blue-500/15 border border-blue-500/30 text-blue-300 rounded">Apply manual</button>
          </div>
        </div>
      )}
    </div>
  );
}

function Side({ title, lines, accent }: { title: string; lines: string[]; accent: 'emerald' | 'rose' | 'slate' }) {
  const accentColor = accent === 'emerald' ? 'text-emerald-400' : accent === 'rose' ? 'text-rose-400' : 'text-slate-400';
  const bg = accent === 'emerald' ? 'bg-emerald-500/[0.04]' : accent === 'rose' ? 'bg-rose-500/[0.04]' : 'bg-slate-800/30';
  return (
    <div className={`${bg} border-r border-slate-700 last:border-r-0`}>
      <div className={`px-2 py-1 text-[10px] uppercase tracking-wider ${accentColor} border-b border-slate-700`}>{title}</div>
      <div className="p-2 whitespace-pre overflow-x-auto text-slate-300">
        {lines.length === 0 ? <span className="text-slate-600 italic">(empty)</span> : lines.join('\n')}
      </div>
    </div>
  );
}

function ResolveBtn({ label, active, onClick, children }: { label: string; active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded transition-colors ${active ? 'bg-blue-500/30 text-blue-200' : 'text-slate-400 hover:text-slate-100 hover:bg-slate-700'}`}
    >
      {children}{label}
    </button>
  );
}

function ResolvedOutput({ merged, remaining }: { merged: string; remaining: number }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(merged);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* ignore */ }
  };
  const download = () => {
    const blob = new Blob([merged], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `merged-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  return (
    <div className="border border-slate-700 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 bg-slate-800/60 border-b border-slate-700">
        <div className="text-sm text-slate-200 font-semibold">
          Resolved output {remaining > 0 && <span className="text-amber-300 text-xs ml-2">({remaining} conflict marker{remaining === 1 ? '' : 's'} remain)</span>}
        </div>
        <div className="flex items-center gap-1">
          <button type="button" onClick={copy} className="flex items-center gap-1 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700 rounded">
            <Copy className="w-3.5 h-3.5" /> {copied ? 'Copied' : 'Copy'}
          </button>
          <button type="button" onClick={download} className="flex items-center gap-1 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700 rounded">
            <Download className="w-3.5 h-3.5" /> Download
          </button>
        </div>
      </div>
      <pre className="p-3 max-h-[400px] overflow-auto bg-slate-900/50 text-[12px] font-mono text-slate-200 whitespace-pre">{merged}</pre>
    </div>
  );
}
