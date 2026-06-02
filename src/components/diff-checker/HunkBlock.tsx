import { useMemo } from 'react';
import { ChevronsLeft, ChevronsRight, MergeIcon, X } from 'lucide-react';
import type { DiffHunk, DiffLine, ViewMode, CharChange } from '../../services/diff-checker/types';
import hljs from 'highlight.js/lib/common';

interface HunkBlockProps {
  hunk: DiffHunk;
  viewMode: ViewMode;
  language: string;
  wrap: boolean;
  onDecision: (id: string, decision: DiffHunk['mergeDecision']) => void;
  active?: boolean;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function highlightLine(text: string, language: string): string {
  if (!text) return '';
  if (language === 'plaintext' || language === 'auto') return escapeHtml(text);
  try {
    if (hljs.getLanguage(language)) {
      return hljs.highlight(text, { language, ignoreIllegals: true }).value;
    }
    return escapeHtml(text);
  } catch {
    return escapeHtml(text);
  }
}

function renderWithCharChanges(text: string, changes: CharChange[] | undefined, side: 'add' | 'del'): string {
  if (!changes || changes.length === 0) return escapeHtml(text);
  const chars = Array.from(text);
  const out: string[] = [];
  const cls = side === 'add' ? 'diff-char-add' : 'diff-char-del';
  let cursor = 0;
  const sorted = [...changes].sort((a, b) => a.start - b.start);
  for (const c of sorted) {
    while (cursor < c.start && cursor < chars.length) {
      out.push(escapeHtml(chars[cursor]));
      cursor++;
    }
    out.push(`<span class="${cls}">`);
    while (cursor < c.end && cursor < chars.length) {
      out.push(escapeHtml(chars[cursor]));
      cursor++;
    }
    out.push('</span>');
  }
  while (cursor < chars.length) {
    out.push(escapeHtml(chars[cursor]));
    cursor++;
  }
  return out.join('');
}

function renderContent(line: DiffLine, side: 'left' | 'right', language: string): string {
  if (line.type === 'replace') {
    if (side === 'left') {
      return renderWithCharChanges(line.leftContent ?? '', line.leftCharChanges, 'del');
    }
    return renderWithCharChanges(line.rightContent ?? '', line.rightCharChanges, 'add');
  }
  if (line.type === 'equal') {
    return highlightLine(side === 'left' ? line.leftContent ?? '' : line.rightContent ?? '', language);
  }
  if (line.type === 'insert' && side === 'right') {
    return highlightLine(line.rightContent ?? '', language);
  }
  if (line.type === 'delete' && side === 'left') {
    return highlightLine(line.leftContent ?? '', language);
  }
  return '';
}

const bgFor = (line: DiffLine, side: 'left' | 'right'): string => {
  if (line.isNoise) return 'bg-slate-800/30';
  if (line.type === 'equal') return '';
  if (line.type === 'replace') return side === 'left' ? 'bg-rose-500/10' : 'bg-emerald-500/10';
  if (line.type === 'insert') return side === 'right' ? 'bg-emerald-500/15' : '';
  if (line.type === 'delete') return side === 'left' ? 'bg-rose-500/15' : '';
  return '';
};

const gutterFor = (line: DiffLine, side: 'left' | 'right'): string => {
  if (line.isNoise) return 'text-slate-600';
  if (line.type === 'equal' || line.type === 'replace') return 'text-slate-500';
  if (line.type === 'insert' && side === 'right') return 'text-emerald-400';
  if (line.type === 'delete' && side === 'left') return 'text-rose-400';
  return 'text-slate-700';
};

const markFor = (line: DiffLine, side: 'left' | 'right'): string => {
  if (line.isNoise) return ' ';
  if (line.type === 'equal') return ' ';
  if (line.type === 'replace') return side === 'left' ? '−' : '+';
  if (line.type === 'insert') return side === 'right' ? '+' : ' ';
  if (line.type === 'delete') return side === 'left' ? '−' : ' ';
  return ' ';
};

export function HunkBlock({ hunk, viewMode, language, wrap, onDecision, active }: HunkBlockProps) {
  const decision = hunk.mergeDecision;
  const wrapCls = wrap ? 'whitespace-pre-wrap break-all' : 'whitespace-pre overflow-x-auto';

  const rows = useMemo(() => hunk.lines, [hunk.lines]);

  const header = (
    <div className={`flex items-center justify-between px-3 py-1.5 text-[11px] font-mono ${active ? 'bg-blue-500/15 text-blue-300' : 'bg-slate-800/60 text-blue-300/60'} border-y border-slate-700`}>
      <span>
        @@ −{hunk.leftStart || 0}{hunk.leftEnd > hunk.leftStart ? `,${hunk.leftEnd - hunk.leftStart + 1}` : ''} +{hunk.rightStart || 0}{hunk.rightEnd > hunk.rightStart ? `,${hunk.rightEnd - hunk.rightStart + 1}` : ''} @@
      </span>
      <div className="flex items-center gap-1">
        <MergeButton label="← Left" active={decision === 'left'} onClick={() => onDecision(hunk.id, decision === 'left' ? undefined : 'left')} title="Keep left side">
          <ChevronsLeft className="w-3 h-3" />
        </MergeButton>
        <MergeButton label="Right →" active={decision === 'right'} onClick={() => onDecision(hunk.id, decision === 'right' ? undefined : 'right')} title="Keep right side">
          <ChevronsRight className="w-3 h-3" />
        </MergeButton>
        <MergeButton label="Both" active={decision === 'both'} onClick={() => onDecision(hunk.id, decision === 'both' ? undefined : 'both')} title="Keep both">
          <MergeIcon className="w-3 h-3" />
        </MergeButton>
        <MergeButton label="Skip" active={decision === 'skip'} onClick={() => onDecision(hunk.id, decision === 'skip' ? undefined : 'skip')} title="Skip — keep base">
          <X className="w-3 h-3" />
        </MergeButton>
      </div>
    </div>
  );

  if (viewMode === 'split') {
    return (
      <div data-hunk-id={hunk.id} className="border-x border-slate-700">
        {header}
        <div className="grid grid-cols-2 font-mono text-[12px] leading-5">
          {rows.map((line, idx) => (
            <SplitRow key={idx} line={line} language={language} wrapCls={wrapCls} />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div data-hunk-id={hunk.id} className="border-x border-slate-700">
      {header}
      <div className="font-mono text-[12px] leading-5">
        {rows.map((line, idx) => (
          <UnifiedRow key={idx} line={line} language={language} wrapCls={wrapCls} />
        ))}
      </div>
    </div>
  );
}

function SplitRow({ line, language, wrapCls }: { line: DiffLine; language: string; wrapCls: string }) {
  return (
    <>
      <div className={`flex ${bgFor(line, 'left')}`}>
        <div className={`flex-none w-12 text-right pr-2 select-none border-r border-slate-800 ${gutterFor(line, 'left')}`}>
          {line.lineNumLeft ?? ''}
        </div>
        <div className="flex-none w-4 text-center select-none text-slate-500">{markFor(line, 'left')}</div>
        <div className={`flex-1 pl-1 pr-2 ${wrapCls}`}>
          <span dangerouslySetInnerHTML={{ __html: renderContent(line, 'left', language) }} />
        </div>
      </div>
      <div className={`flex ${bgFor(line, 'right')} border-l border-slate-800`}>
        <div className={`flex-none w-12 text-right pr-2 select-none border-r border-slate-800 ${gutterFor(line, 'right')}`}>
          {line.lineNumRight ?? ''}
        </div>
        <div className="flex-none w-4 text-center select-none text-slate-500">{markFor(line, 'right')}</div>
        <div className={`flex-1 pl-1 pr-2 ${wrapCls}`}>
          <span dangerouslySetInnerHTML={{ __html: renderContent(line, 'right', language) }} />
        </div>
      </div>
    </>
  );
}

function UnifiedRow({ line, language, wrapCls }: { line: DiffLine; language: string; wrapCls: string }) {
  if (line.type === 'replace') {
    return (
      <>
        <UnifiedRowSingle line={{ ...line, type: 'delete', lineNumRight: undefined }} side="left" language={language} wrapCls={wrapCls} />
        <UnifiedRowSingle line={{ ...line, type: 'insert', lineNumLeft: undefined }} side="right" language={language} wrapCls={wrapCls} />
      </>
    );
  }
  const side: 'left' | 'right' = line.type === 'insert' ? 'right' : 'left';
  return <UnifiedRowSingle line={line} side={side} language={language} wrapCls={wrapCls} />;
}

function UnifiedRowSingle({ line, side, language, wrapCls }: { line: DiffLine; side: 'left' | 'right'; language: string; wrapCls: string }) {
  const bg = bgFor(line, side);
  return (
    <div className={`flex ${bg}`}>
      <div className={`flex-none w-12 text-right pr-2 select-none border-r border-slate-800 ${gutterFor(line, 'left')}`}>
        {line.lineNumLeft ?? ''}
      </div>
      <div className={`flex-none w-12 text-right pr-2 select-none border-r border-slate-800 ${gutterFor(line, 'right')}`}>
        {line.lineNumRight ?? ''}
      </div>
      <div className="flex-none w-4 text-center select-none text-slate-500">{markFor(line, side)}</div>
      <div className={`flex-1 pl-1 pr-2 ${wrapCls}`}>
        <span dangerouslySetInnerHTML={{ __html: renderContent(line, side, language) }} />
      </div>
    </div>
  );
}

function MergeButton({ label, active, onClick, title, children }: { label: string; active: boolean; onClick: () => void; title: string; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      className={`flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded transition-colors ${active ? 'bg-blue-500/30 text-blue-200' : 'text-slate-400 hover:text-slate-100 hover:bg-slate-700'}`}
    >
      {children}{label}
    </button>
  );
}
