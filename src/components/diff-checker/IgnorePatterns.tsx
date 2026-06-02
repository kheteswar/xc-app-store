import { useState } from 'react';
import { Plus, X, Check, AlertTriangle } from 'lucide-react';
import type { IgnorePattern } from '../../services/diff-checker/types';
import { PRESET_PATTERNS, savePatterns, testPattern, validatePattern } from '../../services/diff-checker/ignore-patterns';

interface Props {
  patterns: IgnorePattern[];
  onChange: (next: IgnorePattern[]) => void;
  sampleText?: string;
  onClose: () => void;
}

export function IgnorePatternsEditor({ patterns, onChange, sampleText, onClose }: Props) {
  const [newName, setNewName] = useState('');
  const [newPattern, setNewPattern] = useState('');
  const [error, setError] = useState<string | null>(null);

  const togglePattern = (id: string) => {
    const next = patterns.map(p => p.id === id ? { ...p, enabled: !p.enabled } : p);
    onChange(next);
    savePatterns(next);
  };

  const removePattern = (id: string) => {
    const next = patterns.filter(p => p.id !== id);
    onChange(next);
    savePatterns(next);
  };

  const addPattern = () => {
    setError(null);
    if (!newPattern.trim()) {
      setError('Pattern is empty');
      return;
    }
    const v = validatePattern(newPattern);
    if (!v.ok) {
      setError(v.error);
      return;
    }
    const next: IgnorePattern[] = [
      ...patterns,
      {
        id: `user-${Date.now()}`,
        name: newName.trim() || 'Custom pattern',
        pattern: newPattern.trim(),
        enabled: true,
        preset: false,
      },
    ];
    onChange(next);
    savePatterns(next);
    setNewName('');
    setNewPattern('');
  };

  const resetToDefaults = () => {
    const next = [...PRESET_PATTERNS];
    onChange(next);
    savePatterns(next);
  };

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-sm">
      <div className="w-full max-w-3xl max-h-[85vh] flex flex-col bg-slate-900 border border-slate-700 rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
          <div>
            <h3 className="text-base font-semibold text-slate-100">Ignore Patterns</h3>
            <p className="text-xs text-slate-400">Mark matching content as noise — lines that differ only by these patterns are greyed-out and excluded from stats.</p>
          </div>
          <button type="button" onClick={onClose} className="p-1 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 overflow-auto p-4 space-y-3">
          <div className="text-xs text-slate-400 uppercase tracking-wider">Presets</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {patterns.filter(p => p.preset).map(p => (
              <PatternRow key={p.id} p={p} onToggle={() => togglePattern(p.id)} onRemove={undefined} sampleText={sampleText} />
            ))}
          </div>

          <div className="text-xs text-slate-400 uppercase tracking-wider mt-4">Custom</div>
          <div className="space-y-2">
            {patterns.filter(p => !p.preset).map(p => (
              <PatternRow key={p.id} p={p} onToggle={() => togglePattern(p.id)} onRemove={() => removePattern(p.id)} sampleText={sampleText} />
            ))}
            {patterns.filter(p => !p.preset).length === 0 && (
              <div className="text-xs text-slate-500 italic">No custom patterns yet.</div>
            )}
          </div>

          <div className="pt-3 mt-3 border-t border-slate-700">
            <div className="text-xs text-slate-400 mb-1">Add pattern</div>
            <div className="grid grid-cols-1 sm:grid-cols-[1fr_2fr_auto] gap-2">
              <input
                type="text"
                value={newName}
                onChange={e => setNewName(e.target.value)}
                placeholder="Name (e.g. Request IDs)"
                className="px-2 py-1.5 bg-slate-800 border border-slate-700 rounded text-xs text-slate-200 outline-none focus:border-blue-500"
              />
              <input
                type="text"
                value={newPattern}
                onChange={e => setNewPattern(e.target.value)}
                placeholder="/regex/flags  or  raw regex"
                className="px-2 py-1.5 bg-slate-800 border border-slate-700 rounded text-xs text-slate-200 font-mono outline-none focus:border-blue-500"
              />
              <button
                type="button"
                onClick={addPattern}
                className="flex items-center gap-1 px-3 py-1.5 text-xs bg-blue-500/15 border border-blue-500/30 text-blue-300 rounded hover:bg-blue-500/25"
              >
                <Plus className="w-3.5 h-3.5" /> Add
              </button>
            </div>
            {error && (
              <div className="mt-1 flex items-center gap-1 text-xs text-rose-400">
                <AlertTriangle className="w-3.5 h-3.5" /> {error}
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center justify-between px-4 py-3 border-t border-slate-700">
          <button type="button" onClick={resetToDefaults} className="text-xs text-slate-400 hover:text-slate-200">Reset to defaults</button>
          <button type="button" onClick={onClose} className="px-3 py-1.5 text-xs bg-blue-500/15 border border-blue-500/30 text-blue-300 rounded hover:bg-blue-500/25">Done</button>
        </div>
      </div>
    </div>
  );
}

function PatternRow({ p, onToggle, onRemove, sampleText }: { p: IgnorePattern; onToggle: () => void; onRemove?: () => void; sampleText?: string }) {
  const [showMatches, setShowMatches] = useState(false);
  const matches = showMatches && sampleText ? testPattern(p.pattern, sampleText).slice(0, 5) : [];

  return (
    <div className={`p-2 rounded border ${p.enabled ? 'border-amber-500/30 bg-amber-500/[0.04]' : 'border-slate-700 bg-slate-800/40'}`}>
      <div className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={p.enabled}
          onChange={onToggle}
          className="accent-amber-500 w-3.5 h-3.5"
        />
        <div className="flex-1 min-w-0">
          <div className="text-xs text-slate-200 truncate">{p.name}</div>
          <code className="text-[10px] text-slate-500 font-mono truncate block">{p.pattern}</code>
        </div>
        {sampleText && (
          <button type="button" onClick={() => setShowMatches(s => !s)} className="text-[10px] text-slate-400 hover:text-slate-100">
            {showMatches ? 'hide' : 'test'}
          </button>
        )}
        {onRemove && (
          <button type="button" onClick={onRemove} className="p-0.5 text-slate-500 hover:text-rose-400">
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
      {showMatches && (
        <div className="mt-1 pl-6 text-[10px] font-mono">
          {matches.length === 0 ? (
            <span className="text-slate-500 italic">no matches in sample</span>
          ) : (
            matches.map((m, i) => (
              <div key={i} className="flex items-center gap-1 text-amber-300/80">
                <Check className="w-2.5 h-2.5" /> <span className="truncate">{m}</span>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
