import { useState } from 'react';
import { Clock, Trash2, Edit2, Download, Upload, X } from 'lucide-react';
import type { DiffSnapshot } from '../../services/diff-checker/types';
import { deleteSnapshot, exportHistory, importHistory, loadHistory, renameSnapshot } from '../../services/diff-checker/history';

interface Props {
  open: boolean;
  onClose: () => void;
  onRestore: (snapshot: DiffSnapshot) => void;
}

export function HistoryPanel({ open, onClose, onRestore }: Props) {
  const [history, setHistory] = useState<DiffSnapshot[]>(() => loadHistory());
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');

  if (!open) return null;

  const refresh = () => setHistory(loadHistory());

  const handleRename = (id: string) => {
    renameSnapshot(id, editValue.trim() || 'Untitled');
    setEditingId(null);
    refresh();
  };

  const handleDelete = (id: string) => {
    deleteSnapshot(id);
    refresh();
  };

  const handleExport = () => {
    const blob = new Blob([exportHistory()], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `diff-history-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const handleImport = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      importHistory(String(reader.result ?? ''));
      refresh();
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-sm">
      <div className="w-full max-w-2xl max-h-[85vh] flex flex-col bg-slate-900 border border-slate-700 rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
          <div>
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2"><Clock className="w-4 h-4" /> Diff History</h3>
            <p className="text-xs text-slate-400">Stored in browser localStorage. Max 20 snapshots.</p>
          </div>
          <div className="flex items-center gap-1">
            <button type="button" onClick={handleExport} className="flex items-center gap-1 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800 rounded">
              <Download className="w-3.5 h-3.5" /> Export
            </button>
            <label className="flex items-center gap-1 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800 rounded cursor-pointer">
              <Upload className="w-3.5 h-3.5" /> Import
              <input type="file" hidden accept="application/json" onChange={handleImport} />
            </label>
            <button type="button" onClick={onClose} className="p-1 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-auto p-2 space-y-1">
          {history.length === 0 && (
            <div className="text-sm text-slate-500 italic p-6 text-center">No saved diffs yet. Use the Save button to capture the current diff.</div>
          )}
          {history.map(snap => (
            <div key={snap.id} className="flex items-center gap-2 p-2 rounded border border-slate-700 bg-slate-800/40 hover:border-slate-600">
              <div className="flex-1 min-w-0">
                {editingId === snap.id ? (
                  <div className="flex items-center gap-1">
                    <input
                      value={editValue}
                      onChange={e => setEditValue(e.target.value)}
                      autoFocus
                      onBlur={() => handleRename(snap.id)}
                      onKeyDown={e => { if (e.key === 'Enter') handleRename(snap.id); if (e.key === 'Escape') setEditingId(null); }}
                      className="flex-1 px-1 py-0.5 text-xs bg-slate-900 border border-slate-700 rounded text-slate-200"
                    />
                  </div>
                ) : (
                  <div className="text-xs text-slate-200 truncate">{snap.name}</div>
                )}
                <div className="text-[10px] text-slate-500">{new Date(snap.createdAt).toLocaleString()} · {snap.format !== 'none' ? snap.format.toUpperCase() : 'text'}</div>
              </div>
              <button type="button" onClick={() => onRestore(snap)} className="px-2 py-1 text-xs bg-blue-500/15 border border-blue-500/30 text-blue-300 rounded hover:bg-blue-500/25">Restore</button>
              <button type="button" onClick={() => { setEditingId(snap.id); setEditValue(snap.name); }} className="p-1 text-slate-400 hover:text-slate-100">
                <Edit2 className="w-3.5 h-3.5" />
              </button>
              <button type="button" onClick={() => handleDelete(snap.id)} className="p-1 text-slate-500 hover:text-rose-400">
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
