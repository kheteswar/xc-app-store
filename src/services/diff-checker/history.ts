import type { DiffSnapshot, DiffOptions, SemanticFormat } from './types';

const STORAGE_KEY = 'xc-app-store:diff-checker:history';
const MAX_SNAPSHOTS = 20;

export function loadHistory(): DiffSnapshot[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as DiffSnapshot[];
  } catch {
    return [];
  }
}

function persist(snapshots: DiffSnapshot[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(snapshots));
  } catch {
    // quota exceeded — drop oldest until it fits
    let trimmed = [...snapshots];
    while (trimmed.length > 0) {
      trimmed.pop();
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
        return;
      } catch {
        continue;
      }
    }
  }
}

export function saveSnapshot(
  left: string,
  right: string,
  options: DiffOptions,
  format: SemanticFormat,
  base?: string,
  name?: string,
): DiffSnapshot {
  const history = loadHistory();
  const firstLine = left.split('\n').find(l => l.trim()) ?? right.split('\n').find(l => l.trim()) ?? 'Untitled';
  const snippet = firstLine.slice(0, 40);
  const snapshot: DiffSnapshot = {
    id: `snap-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name: name ?? `${snippet} · ${new Date().toLocaleString()}`,
    createdAt: Date.now(),
    leftContent: left,
    rightContent: right,
    baseContent: base,
    options,
    format,
  };
  history.unshift(snapshot);
  while (history.length > MAX_SNAPSHOTS) history.pop();
  persist(history);
  return snapshot;
}

export function deleteSnapshot(id: string) {
  const history = loadHistory().filter(s => s.id !== id);
  persist(history);
}

export function renameSnapshot(id: string, name: string) {
  const history = loadHistory();
  const idx = history.findIndex(s => s.id === id);
  if (idx >= 0) {
    history[idx].name = name;
    persist(history);
  }
}

export function exportHistory(): string {
  return JSON.stringify(loadHistory(), null, 2);
}

export function importHistory(json: string): number {
  try {
    const imported = JSON.parse(json) as DiffSnapshot[];
    if (!Array.isArray(imported)) return 0;
    const current = loadHistory();
    const existingIds = new Set(current.map(s => s.id));
    let added = 0;
    for (const snap of imported) {
      if (snap && typeof snap.id === 'string' && !existingIds.has(snap.id)) {
        current.unshift(snap);
        added++;
      }
    }
    while (current.length > MAX_SNAPSHOTS) current.pop();
    persist(current);
    return added;
  } catch {
    return 0;
  }
}
