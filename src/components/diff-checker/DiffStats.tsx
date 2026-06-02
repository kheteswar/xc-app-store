import { Plus, Minus, ChevronUp, ChevronDown, Activity, EyeOff } from 'lucide-react';
import type { DiffStats } from '../../services/diff-checker/types';

interface Props {
  stats: DiffStats;
  onPrev: () => void;
  onNext: () => void;
  currentHunk?: number;
  totalHunks: number;
}

export function DiffStatsBar({ stats, onPrev, onNext, currentHunk, totalHunks }: Props) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2 bg-slate-800/40 border-b border-slate-700 text-xs">
      <span className="flex items-center gap-1 text-emerald-400 font-mono">
        <Plus className="w-3.5 h-3.5" /> {stats.additions} additions
      </span>
      <span className="flex items-center gap-1 text-rose-400 font-mono">
        <Minus className="w-3.5 h-3.5" /> {stats.deletions} deletions
      </span>
      <span className="flex items-center gap-1 text-slate-400">
        <Activity className="w-3.5 h-3.5" /> {stats.hunkCount} hunk{stats.hunkCount === 1 ? '' : 's'}
      </span>
      <span className="text-slate-400">{stats.similarityPercent}% similar</span>
      {stats.noiseLines > 0 && (
        <span className="flex items-center gap-1 text-amber-300/80">
          <EyeOff className="w-3.5 h-3.5" /> {stats.noiseLines} noise line{stats.noiseLines === 1 ? '' : 's'} hidden
        </span>
      )}

      <div className="flex-1" />

      {totalHunks > 0 && (
        <div className="flex items-center gap-1">
          {currentHunk !== undefined && (
            <span className="text-slate-500">Hunk {currentHunk + 1} / {totalHunks}</span>
          )}
          <button
            type="button"
            onClick={onPrev}
            disabled={totalHunks === 0}
            className="px-2 py-0.5 text-slate-400 hover:text-slate-100 hover:bg-slate-700 rounded disabled:opacity-40 transition-colors"
            title="Previous hunk ( [ )"
          >
            <ChevronUp className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={onNext}
            disabled={totalHunks === 0}
            className="px-2 py-0.5 text-slate-400 hover:text-slate-100 hover:bg-slate-700 rounded disabled:opacity-40 transition-colors"
            title="Next hunk ( ] )"
          >
            <ChevronDown className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}
