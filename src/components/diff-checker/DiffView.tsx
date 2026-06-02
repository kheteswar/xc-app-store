import { useEffect, useRef } from 'react';
import type { DiffResult, DiffHunk, DiffOptions, ViewMode } from '../../services/diff-checker/types';
import { HunkBlock } from './HunkBlock';

interface Props {
  result: DiffResult;
  options: DiffOptions;
  language: string;
  onHunkDecision: (id: string, decision: DiffHunk['mergeDecision']) => void;
  activeHunkId?: string;
}

export function DiffView({ result, options, language, onHunkDecision, activeHunkId }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!activeHunkId) return;
    const el = containerRef.current?.querySelector(`[data-hunk-id="${activeHunkId}"]`);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }, [activeHunkId]);

  const mode: ViewMode = options.viewMode;

  const empty = result.hunks.length === 0;

  return (
    <div ref={containerRef} className="bg-slate-900/40 border border-slate-700 rounded-lg overflow-hidden">
      {empty ? (
        <div className="p-6 text-center text-sm text-slate-400">
          {result.stats.totalLines === 0 ? 'Paste content into both panels to see a diff.' : 'No differences — 100% identical.'}
        </div>
      ) : (
        <div>
          {result.hunks.map(hunk => (
            <HunkBlock
              key={hunk.id}
              hunk={hunk}
              viewMode={mode}
              language={language}
              wrap={options.wrapLines}
              onDecision={onHunkDecision}
              active={hunk.id === activeHunkId}
            />
          ))}
        </div>
      )}
    </div>
  );
}
