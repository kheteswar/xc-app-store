import { useCallback, useRef, useState } from 'react';
import { Trash2, Upload, Globe, Github, FileText, X } from 'lucide-react';

interface InputPanelProps {
  label: string;
  value: string;
  onChange: (value: string, filename?: string) => void;
  filename?: string;
  language?: string;
  onClear?: () => void;
  showUrlFetch?: boolean;
  showGitHub?: boolean;
  onGitHubImport?: (url: string) => void;
  compact?: boolean;
}

export function InputPanel({
  label,
  value,
  onChange,
  filename,
  language,
  onClear,
  showUrlFetch = true,
  showGitHub = false,
  onGitHubImport,
  compact = false,
}: InputPanelProps) {
  const [dragOver, setDragOver] = useState(false);
  const [urlInput, setUrlInput] = useState('');
  const [ghInput, setGhInput] = useState('');
  const [fetching, setFetching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      setError('File larger than 5 MB — diff performance may suffer');
    }
    const reader = new FileReader();
    reader.onload = () => onChange(String(reader.result ?? ''), file.name);
    reader.readAsText(file);
  }, [onChange]);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => onChange(String(reader.result ?? ''), file.name);
    reader.readAsText(file);
    e.target.value = '';
  }, [onChange]);

  const handleUrlFetch = useCallback(async () => {
    if (!urlInput.trim()) return;
    setFetching(true);
    setError(null);
    try {
      const res = await fetch(urlInput.trim());
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      const pathSegment = urlInput.split('/').pop() ?? 'fetched';
      onChange(text, pathSegment);
      setUrlInput('');
    } catch (e) {
      setError(e instanceof Error ? `Fetch failed: ${e.message} (CORS may be blocking the request)` : 'Fetch failed');
    } finally {
      setFetching(false);
    }
  }, [urlInput, onChange]);

  const lineCount = value ? value.split('\n').length : 0;
  const byteSize = value ? new Blob([value]).size : 0;

  return (
    <div className="flex flex-col">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-slate-200">{label}</h3>
          {filename && (
            <span className="text-xs text-slate-500 flex items-center gap-1">
              <FileText className="w-3 h-3" /> {filename}
            </span>
          )}
          {language && language !== 'plaintext' && (
            <span className="px-2 py-0.5 text-[10px] uppercase tracking-wider bg-blue-500/15 text-blue-300 rounded">
              {language}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center gap-1 px-2 py-1 text-xs text-slate-400 hover:text-slate-100 hover:bg-slate-700 rounded transition-colors"
            title="Upload a file"
          >
            <Upload className="w-3.5 h-3.5" /> Upload
          </button>
          {onClear && value && (
            <button
              type="button"
              onClick={onClear}
              className="flex items-center gap-1 px-2 py-1 text-xs text-slate-400 hover:text-red-400 hover:bg-slate-700 rounded transition-colors"
              title="Clear"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        className={`relative rounded-lg border ${dragOver ? 'border-blue-500 bg-blue-500/5' : 'border-slate-700 bg-slate-900/50'} transition-colors`}
      >
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value, filename)}
          placeholder={`Paste ${label.toLowerCase()} here, drop a file, or fetch from URL…`}
          spellCheck={false}
          className={`w-full ${compact ? 'min-h-[120px] max-h-[200px]' : 'min-h-[180px] max-h-[400px]'} p-3 bg-transparent text-slate-200 font-mono text-[12px] leading-5 resize-y outline-none placeholder:text-slate-600`}
        />
        {dragOver && (
          <div className="absolute inset-0 pointer-events-none flex items-center justify-center text-blue-300 font-semibold text-sm">
            Drop file to load
          </div>
        )}
      </div>

      <div className="flex items-center justify-between mt-1 text-[11px] text-slate-500">
        <span>{lineCount.toLocaleString()} lines · {formatBytes(byteSize)}</span>
        {error && (
          <span className="flex items-center gap-1 text-red-400">
            {error}
            <button type="button" onClick={() => setError(null)}><X className="w-3 h-3" /></button>
          </span>
        )}
      </div>

      <input ref={fileInputRef} type="file" hidden onChange={handleFileSelect} />

      {showUrlFetch && (
        <div className="mt-2 flex gap-2">
          <div className="flex-1 flex items-center gap-2 px-2 py-1.5 bg-slate-900/50 border border-slate-700 rounded text-xs">
            <Globe className="w-3.5 h-3.5 text-slate-500" />
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="https://…  (fetch raw text/JSON)"
              className="flex-1 bg-transparent outline-none text-slate-200"
            />
          </div>
          <button
            type="button"
            onClick={handleUrlFetch}
            disabled={!urlInput.trim() || fetching}
            className="px-3 py-1.5 text-xs bg-blue-500/15 text-blue-300 border border-blue-500/30 rounded hover:bg-blue-500/25 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {fetching ? 'Fetching…' : 'Fetch'}
          </button>
        </div>
      )}

      {showGitHub && onGitHubImport && (
        <div className="mt-2 flex gap-2">
          <div className="flex-1 flex items-center gap-2 px-2 py-1.5 bg-slate-900/50 border border-slate-700 rounded text-xs">
            <Github className="w-3.5 h-3.5 text-slate-500" />
            <input
              type="text"
              value={ghInput}
              onChange={(e) => setGhInput(e.target.value)}
              placeholder="https://github.com/owner/repo/pull/123  or  /commit/abc123"
              className="flex-1 bg-transparent outline-none text-slate-200"
            />
          </div>
          <button
            type="button"
            onClick={() => { onGitHubImport(ghInput); setGhInput(''); }}
            disabled={!ghInput.trim()}
            className="px-3 py-1.5 text-xs bg-violet-500/15 text-violet-300 border border-violet-500/30 rounded hover:bg-violet-500/25 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Import
          </button>
        </div>
      )}
    </div>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
