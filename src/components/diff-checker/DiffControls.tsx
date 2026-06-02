import { ArrowLeftRight, Columns, Rows, Share2, Save, Sliders, Code2, FileJson } from 'lucide-react';
import type { DiffOptions, SemanticFormat } from '../../services/diff-checker/types';

interface DiffControlsProps {
  options: DiffOptions;
  onChange: (next: Partial<DiffOptions>) => void;
  semanticFormat: SemanticFormat;
  onSemanticFormatChange: (f: SemanticFormat) => void;
  onShare: () => void;
  onSave: () => void;
  onSwap: () => void;
  onOpenPatterns: () => void;
  patternsActiveCount: number;
}

export function DiffControls({
  options, onChange, semanticFormat, onSemanticFormatChange,
  onShare, onSave, onSwap, onOpenPatterns, patternsActiveCount,
}: DiffControlsProps) {
  return (
    <div className="sticky top-0 z-20 flex flex-wrap items-center gap-2 px-3 py-2 bg-slate-900/95 backdrop-blur border-b border-slate-700">
      <div className="flex items-center gap-1 bg-slate-800 border border-slate-700 rounded p-0.5">
        <button
          type="button"
          onClick={() => onChange({ viewMode: 'split' })}
          className={`flex items-center gap-1 px-2 py-1 text-xs rounded ${options.viewMode === 'split' ? 'bg-blue-500/20 text-blue-300' : 'text-slate-400 hover:text-slate-200'}`}
        >
          <Columns className="w-3.5 h-3.5" /> Split
        </button>
        <button
          type="button"
          onClick={() => onChange({ viewMode: 'unified' })}
          className={`flex items-center gap-1 px-2 py-1 text-xs rounded ${options.viewMode === 'unified' ? 'bg-blue-500/20 text-blue-300' : 'text-slate-400 hover:text-slate-200'}`}
        >
          <Rows className="w-3.5 h-3.5" /> Unified
        </button>
      </div>

      <div className="flex items-center gap-2 text-xs text-slate-400">
        <span className="text-slate-500">Ignore:</span>
        <Toggle label="Whitespace" checked={options.ignoreWhitespace} onChange={v => onChange({ ignoreWhitespace: v })} />
        <Toggle label="Case" checked={options.ignoreCase} onChange={v => onChange({ ignoreCase: v })} />
        <Toggle label="Blank lines" checked={options.ignoreBlankLines} onChange={v => onChange({ ignoreBlankLines: v })} />
      </div>

      <div className="flex items-center gap-2 text-xs text-slate-400">
        <Toggle label="Wrap" checked={options.wrapLines} onChange={v => onChange({ wrapLines: v })} />
        <label className="flex items-center gap-1">
          Context:
          <select
            value={options.contextLines}
            onChange={e => onChange({ contextLines: Number(e.target.value) })}
            className="bg-slate-800 border border-slate-700 rounded px-1.5 py-0.5 text-slate-200 outline-none"
          >
            {[0, 1, 2, 3, 5, 8, 999].map(n => (
              <option key={n} value={n}>{n === 999 ? 'All' : n}</option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-1">
          <Code2 className="w-3.5 h-3.5 text-slate-500" />
          <select
            value={options.language}
            onChange={e => onChange({ language: e.target.value })}
            className="bg-slate-800 border border-slate-700 rounded px-1.5 py-0.5 text-slate-200 outline-none"
            title="Syntax highlighting"
          >
            <option value="auto">auto</option>
            {['plaintext', 'javascript', 'typescript', 'python', 'json', 'yaml', 'xml', 'css', 'sql', 'bash', 'go', 'rust', 'java', 'markdown', 'dockerfile', 'ini', 'hcl', 'nginx'].map(l => (
              <option key={l} value={l}>{l}</option>
            ))}
          </select>
        </label>
      </div>

      <div className="flex items-center gap-2 text-xs">
        <div className="flex items-center gap-1 bg-slate-800 border border-slate-700 rounded p-0.5">
          {(['none', 'json', 'yaml', 'xml'] as SemanticFormat[]).map(f => (
            <button
              key={f}
              type="button"
              onClick={() => onSemanticFormatChange(f)}
              className={`px-1.5 py-0.5 rounded text-[11px] ${semanticFormat === f ? 'bg-violet-500/20 text-violet-300' : 'text-slate-400 hover:text-slate-200'}`}
              title={f === 'none' ? 'Text-only diff' : `Semantic ${f.toUpperCase()} diff`}
            >
              <FileJson className="w-3 h-3 inline mr-0.5" />
              {f === 'none' ? 'Text' : f.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1" />

      <button
        type="button"
        onClick={onSwap}
        className="flex items-center gap-1 px-2 py-1 text-xs bg-slate-800 border border-slate-700 hover:border-slate-600 text-slate-300 rounded transition-colors"
        title="Swap left and right"
      >
        <ArrowLeftRight className="w-3.5 h-3.5" /> Swap
      </button>
      <button
        type="button"
        onClick={onOpenPatterns}
        className={`flex items-center gap-1 px-2 py-1 text-xs border rounded transition-colors ${patternsActiveCount > 0 ? 'bg-amber-500/15 text-amber-300 border-amber-500/30' : 'bg-slate-800 text-slate-300 border-slate-700 hover:border-slate-600'}`}
        title="Ignore patterns (regex noise filter)"
      >
        <Sliders className="w-3.5 h-3.5" /> Patterns {patternsActiveCount > 0 && `(${patternsActiveCount})`}
      </button>
      <button
        type="button"
        onClick={onSave}
        className="flex items-center gap-1 px-2 py-1 text-xs bg-slate-800 border border-slate-700 hover:border-slate-600 text-slate-300 rounded transition-colors"
        title="Save to history"
      >
        <Save className="w-3.5 h-3.5" /> Save
      </button>
      <button
        type="button"
        onClick={onShare}
        className="flex items-center gap-1 px-2 py-1 text-xs bg-blue-500/15 border border-blue-500/30 text-blue-300 hover:bg-blue-500/25 rounded transition-colors"
        title="Share via URL (no server upload)"
      >
        <Share2 className="w-3.5 h-3.5" /> Share
      </button>
    </div>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-1 cursor-pointer select-none">
      <input
        type="checkbox"
        checked={checked}
        onChange={e => onChange(e.target.checked)}
        className="accent-blue-500 w-3 h-3"
      />
      <span className="text-slate-300">{label}</span>
    </label>
  );
}
