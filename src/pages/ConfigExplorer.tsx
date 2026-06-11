import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  GitBranch, Search, Loader2, AlertCircle, ArrowLeft,
  Package, ChevronRight, ChevronDown, XCircle,
  Table2, Network, TreePine, Grid3X3, Download, HelpCircle,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { apiClient } from '../services/api';
import {
  OBJECT_TYPES, OBJECT_CATEGORIES,
  listObjects, fetchObjectWithChildren,
  buildRelationshipGraph, clearCache, getTypeColor,
} from '../services/config-dump';
import type { ObjectTypeDefinition, FetchedObject, DumpProgress, RelationshipGraphData, GraphNode, GraphEdge } from '../services/config-dump';
import { RelationshipGraph } from '../components/config-dump/RelationshipGraph';

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function objKey(namespace: string, name: string): string {
  return `${namespace}/${name}`;
}

function parseObjKey(key: string): { namespace: string; name: string } {
  const idx = key.indexOf('/');
  return { namespace: key.slice(0, idx), name: key.slice(idx + 1) };
}

// ═══════════════════════════════════════════════════════════════════════════
// VIEW: DEPENDENCY TABLE
// ═══════════════════════════════════════════════════════════════════════════

function DependencyTable({ data }: { data: RelationshipGraphData }) {
  const [search, setSearch] = useState('');
  const [sortCol, setSortCol] = useState<'parent' | 'child' | 'label'>('parent');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  const nodeMap = useMemo(() => {
    const m = new Map<string, GraphNode>();
    data.nodes.forEach(n => m.set(n.id, n));
    return m;
  }, [data.nodes]);

  const rows = useMemo(() => {
    let items = data.edges.map(e => ({
      parentNode: nodeMap.get(e.source),
      childNode: nodeMap.get(e.target),
      label: e.label,
    })).filter(r => r.parentNode && r.childNode);

    if (search) {
      const q = search.toLowerCase();
      items = items.filter(r =>
        r.parentNode!.name.toLowerCase().includes(q) ||
        r.childNode!.name.toLowerCase().includes(q) ||
        r.label.toLowerCase().includes(q) ||
        r.parentNode!.type.toLowerCase().includes(q) ||
        r.childNode!.type.toLowerCase().includes(q)
      );
    }

    items.sort((a, b) => {
      let cmp = 0;
      if (sortCol === 'parent') cmp = a.parentNode!.name.localeCompare(b.parentNode!.name);
      else if (sortCol === 'child') cmp = a.childNode!.name.localeCompare(b.childNode!.name);
      else cmp = a.label.localeCompare(b.label);
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return items;
  }, [data.edges, nodeMap, search, sortCol, sortDir]);

  const toggleSort = (col: typeof sortCol) => {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('asc'); }
  };

  const exportCsv = () => {
    const header = 'Parent,Parent Type,Parent Namespace,Child,Child Type,Child Namespace,Relationship';
    const csvRows = rows.map(r =>
      `"${r.parentNode!.name}","${r.parentNode!.type}","${r.parentNode!.namespace}","${r.childNode!.name}","${r.childNode!.type}","${r.childNode!.namespace}","${r.label}"`
    );
    const csv = [header, ...csvRows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'dependencies.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  const SortIcon = ({ col }: { col: typeof sortCol }) => (
    <span className="text-slate-600 ml-1">
      {sortCol === col ? (sortDir === 'asc' ? '▲' : '▼') : '⇅'}
    </span>
  );

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter by name, type, or relationship..."
            className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-blue-500 placeholder:text-slate-500"
          />
        </div>
        <span className="text-xs text-slate-500">{rows.length} relationship{rows.length !== 1 ? 's' : ''}</span>
        <button onClick={exportCsv} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-emerald-400 hover:bg-emerald-500/10 border border-emerald-500/30 rounded-lg transition-colors">
          <Download className="w-3.5 h-3.5" /> CSV
        </button>
      </div>

      <div className="overflow-x-auto border border-slate-700 rounded-xl">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-slate-800/80 border-b border-slate-700">
              <th className="text-left px-4 py-3 cursor-pointer select-none text-slate-300 font-medium" onClick={() => toggleSort('parent')}>
                Parent <SortIcon col="parent" />
              </th>
              <th className="text-left px-4 py-3 text-slate-500 font-medium">Type</th>
              <th className="text-center px-2 py-3 text-slate-600">→</th>
              <th className="text-left px-4 py-3 cursor-pointer select-none text-slate-300 font-medium" onClick={() => toggleSort('child')}>
                Child <SortIcon col="child" />
              </th>
              <th className="text-left px-4 py-3 text-slate-500 font-medium">Type</th>
              <th className="text-left px-4 py-3 cursor-pointer select-none text-slate-300 font-medium" onClick={() => toggleSort('label')}>
                Relationship <SortIcon col="label" />
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/50">
            {rows.map((r, i) => (
              <tr key={i} className="hover:bg-slate-800/40 transition-colors">
                <td className="px-4 py-2.5">
                  <span className="font-medium text-slate-200">{r.parentNode!.name}</span>
                  <span className="text-xs text-slate-600 ml-1">({r.parentNode!.namespace})</span>
                </td>
                <td className="px-4 py-2.5">
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs" style={{ backgroundColor: getTypeColor(r.parentNode!.type) + '20', color: getTypeColor(r.parentNode!.type) }}>
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: getTypeColor(r.parentNode!.type) }} />
                    {r.parentNode!.type.replace(/_/g, ' ')}
                  </span>
                </td>
                <td className="text-center px-2 py-2.5 text-slate-600">→</td>
                <td className="px-4 py-2.5">
                  <span className="font-medium text-slate-200">{r.childNode!.name}</span>
                  <span className="text-xs text-slate-600 ml-1">({r.childNode!.namespace})</span>
                </td>
                <td className="px-4 py-2.5">
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs" style={{ backgroundColor: getTypeColor(r.childNode!.type) + '20', color: getTypeColor(r.childNode!.type) }}>
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: getTypeColor(r.childNode!.type) }} />
                    {r.childNode!.type.replace(/_/g, ' ')}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-slate-400">{r.label}</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="text-center py-8 text-slate-500">No dependencies found</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// VIEW: HIERARCHY TREE
// ═══════════════════════════════════════════════════════════════════════════

function HierarchyTree({ results }: { results: FetchedObject[] }) {
  const [expandAll, setExpandAll] = useState(false);
  const [key, setKey] = useState(0);

  const toggleAll = (expand: boolean) => {
    setExpandAll(expand);
    setKey(k => k + 1); // Force re-render
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <button onClick={() => toggleAll(true)} className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors">
          Expand All
        </button>
        <button onClick={() => toggleAll(false)} className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors">
          Collapse All
        </button>
        <span className="text-xs text-slate-500 ml-auto">{results.length} root object{results.length !== 1 ? 's' : ''}</span>
      </div>

      <div key={key} className="bg-slate-800/30 border border-slate-700 rounded-xl p-3 max-h-[600px] overflow-y-auto">
        {results.map((obj, i) => (
          <HierarchyTreeNodeControlled key={i} obj={obj} depth={0} defaultExpanded={expandAll} />
        ))}
      </div>
    </div>
  );
}

function HierarchyTreeNodeControlled({ obj, depth, defaultExpanded }: { obj: FetchedObject; depth: number; defaultExpanded: boolean }) {
  const [expanded, setExpanded] = useState(defaultExpanded || depth < 2);
  const hasChildren = obj.children.some(cg => cg.objects.length > 0);

  return (
    <div style={{ marginLeft: depth > 0 ? 20 : 0 }}>
      <div
        className="flex items-center gap-2 py-1.5 px-2 hover:bg-slate-700/30 rounded-lg cursor-pointer group transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        {hasChildren ? (
          expanded ? <ChevronDown className="w-3.5 h-3.5 text-slate-500" /> : <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
        ) : (
          <div className="w-3.5 h-3.5" />
        )}
        <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: getTypeColor(obj.type) }} />
        <span className="text-sm font-medium text-slate-200">{obj.name}</span>
        <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium" style={{ backgroundColor: getTypeColor(obj.type) + '20', color: getTypeColor(obj.type) }}>
          {obj.type.replace(/_/g, ' ')}
        </span>
        {obj.namespace && <span className="text-[10px] text-slate-600">{obj.namespace}</span>}
        {hasChildren && (
          <span className="text-[10px] text-slate-600 ml-auto">
            {obj.children.reduce((sum, cg) => sum + cg.objects.length, 0)} child{obj.children.reduce((sum, cg) => sum + cg.objects.length, 0) !== 1 ? 'ren' : ''}
          </span>
        )}
      </div>

      {expanded && hasChildren && (
        <div className="border-l border-slate-700/50 ml-[17px]">
          {obj.children.map((cg, i) => {
            if (cg.objects.length === 0) return null;
            return (
              <div key={i}>
                <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider px-3 py-1 mt-1">
                  {cg.label} ({cg.objects.length})
                </div>
                {cg.objects.map((child, j) => (
                  <HierarchyTreeNodeControlled key={j} obj={child} depth={depth + 1} defaultExpanded={defaultExpanded} />
                ))}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// VIEW: DEPENDENCY MATRIX
// ═══════════════════════════════════════════════════════════════════════════

function DependencyMatrix({ data }: { data: RelationshipGraphData }) {
  const [selectedCell, setSelectedCell] = useState<{ src: string; tgt: string } | null>(null);

  const nodeMap = useMemo(() => {
    const m = new Map<string, GraphNode>();
    data.nodes.forEach(n => m.set(n.id, n));
    return m;
  }, [data.nodes]);

  // Get unique types that appear in the graph
  const activeTypes = useMemo(() => {
    const types = new Set<string>();
    data.nodes.forEach(n => types.add(n.type));
    return Array.from(types).sort();
  }, [data.nodes]);

  // Build matrix: sourceType -> targetType -> edges
  const matrix = useMemo(() => {
    const m = new Map<string, Map<string, GraphEdge[]>>();
    for (const edge of data.edges) {
      const src = nodeMap.get(edge.source);
      const tgt = nodeMap.get(edge.target);
      if (!src || !tgt) continue;
      if (!m.has(src.type)) m.set(src.type, new Map());
      const row = m.get(src.type)!;
      if (!row.has(tgt.type)) row.set(tgt.type, []);
      row.get(tgt.type)!.push(edge);
    }
    return m;
  }, [data.edges, nodeMap]);

  // Max count for color scaling
  const maxCount = useMemo(() => {
    let max = 0;
    for (const row of matrix.values()) {
      for (const edges of row.values()) {
        max = Math.max(max, edges.length);
      }
    }
    return max;
  }, [matrix]);

  const getCellColor = (count: number): string => {
    if (count === 0) return 'transparent';
    const intensity = Math.min(1, count / Math.max(maxCount, 1));
    const alpha = 0.15 + intensity * 0.65;
    return `rgba(59, 130, 246, ${alpha})`;
  };

  // Selected cell detail
  const cellEdges = useMemo(() => {
    if (!selectedCell) return [];
    return matrix.get(selectedCell.src)?.get(selectedCell.tgt) || [];
  }, [selectedCell, matrix]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <span className="text-xs text-slate-500">{activeTypes.length} object types, {data.edges.length} relationships</span>
        <div className="ml-auto flex items-center gap-2">
          <span className="text-[10px] text-slate-600">Low</span>
          <div className="flex gap-0.5">
            {[0.2, 0.4, 0.6, 0.8].map(a => (
              <div key={a} className="w-4 h-3 rounded-sm" style={{ backgroundColor: `rgba(59, 130, 246, ${a})` }} />
            ))}
          </div>
          <span className="text-[10px] text-slate-600">High</span>
        </div>
      </div>

      <div className="overflow-x-auto border border-slate-700 rounded-xl">
        <table className="text-xs">
          <thead>
            <tr>
              <th className="sticky left-0 z-10 bg-slate-800 px-3 py-2 text-left text-slate-500 font-medium border-b border-r border-slate-700 min-w-[140px]">
                Source ↓ / Target →
              </th>
              {activeTypes.map(type => (
                <th key={type} className="px-2 py-2 text-center border-b border-slate-700 min-w-[40px]" title={type.replace(/_/g, ' ')}>
                  <div className="flex flex-col items-center gap-1">
                    <span className="w-3 h-3 rounded-full" style={{ backgroundColor: getTypeColor(type) }} />
                    <span className="text-[9px] text-slate-500 max-w-[60px] truncate writing-vertical" style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)', maxHeight: 70 }}>
                      {type.replace(/_/g, ' ')}
                    </span>
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {activeTypes.map(srcType => (
              <tr key={srcType}>
                <td className="sticky left-0 z-10 bg-slate-800 px-3 py-2 border-r border-slate-700">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: getTypeColor(srcType) }} />
                    <span className="text-slate-300 truncate max-w-[120px]">{srcType.replace(/_/g, ' ')}</span>
                  </div>
                </td>
                {activeTypes.map(tgtType => {
                  const edges = matrix.get(srcType)?.get(tgtType) || [];
                  const count = edges.length;
                  const isSelected = selectedCell?.src === srcType && selectedCell?.tgt === tgtType;
                  return (
                    <td
                      key={tgtType}
                      className={`text-center px-2 py-2 cursor-pointer transition-all ${
                        isSelected ? 'ring-2 ring-blue-500 ring-inset' : ''
                      } ${count > 0 ? 'hover:ring-1 hover:ring-slate-500 hover:ring-inset' : ''}`}
                      style={{ backgroundColor: getCellColor(count) }}
                      onClick={() => count > 0 && setSelectedCell(isSelected ? null : { src: srcType, tgt: tgtType })}
                      title={count > 0 ? `${srcType} → ${tgtType}: ${count}` : ''}
                    >
                      {count > 0 && <span className="text-slate-200 font-semibold">{count}</span>}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Cell detail */}
      {selectedCell && cellEdges.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <span className="w-3 h-3 rounded-full" style={{ backgroundColor: getTypeColor(selectedCell.src) }} />
            <span className="text-sm font-medium text-slate-200">{selectedCell.src.replace(/_/g, ' ')}</span>
            <span className="text-slate-600">→</span>
            <span className="w-3 h-3 rounded-full" style={{ backgroundColor: getTypeColor(selectedCell.tgt) }} />
            <span className="text-sm font-medium text-slate-200">{selectedCell.tgt.replace(/_/g, ' ')}</span>
            <span className="text-xs text-slate-500 ml-2">({cellEdges.length} relationship{cellEdges.length !== 1 ? 's' : ''})</span>
          </div>
          <div className="space-y-1 max-h-[200px] overflow-y-auto">
            {cellEdges.map((e, i) => {
              const src = nodeMap.get(e.source);
              const tgt = nodeMap.get(e.target);
              return (
                <div key={i} className="flex items-center gap-2 text-xs py-1 px-2 hover:bg-slate-700/30 rounded">
                  <span className="text-slate-300 font-medium">{src?.name}</span>
                  <span className="text-slate-600">→</span>
                  <span className="text-slate-300 font-medium">{tgt?.name}</span>
                  <span className="text-slate-500 ml-auto">{e.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN PAGE
// ═══════════════════════════════════════════════════════════════════════════

type ViewMode = 'graph' | 'table' | 'tree' | 'matrix';

export function ConfigExplorer() {
  const { isConnected } = useApp();
  const toast = useToast();

  // Step management
  const [step, setStep] = useState<'select-type' | 'select-objects' | 'results'>('select-type');

  // Type selection
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedType, setSelectedType] = useState<ObjectTypeDefinition | null>(null);
  const [typeSearch, setTypeSearch] = useState('');

  // Namespace & object selection
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [selectedNamespaces, setSelectedNamespaces] = useState<Set<string>>(new Set());
  const [isLoadingNs, setIsLoadingNs] = useState(false);
  const [nsSearch, setNsSearch] = useState('');
  const [showNsDropdown, setShowNsDropdown] = useState(false);
  const nsDropdownRef = useRef<HTMLDivElement>(null);

  // Object list
  const [objectList, setObjectList] = useState<{ name: string; namespace: string; labels?: Record<string, string> }[]>([]);
  const [isLoadingList, setIsLoadingList] = useState(false);
  const [selectedObjects, setSelectedObjects] = useState<Set<string>>(new Set());
  const [objectSearch, setObjectSearch] = useState('');

  // Fetch & results
  const [isFetching, setIsFetching] = useState(false);
  const [progress, setProgress] = useState<DumpProgress | null>(null);
  const [results, setResults] = useState<FetchedObject[]>([]);
  const [graphData, setGraphData] = useState<RelationshipGraphData | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  // View mode
  const [viewMode, setViewMode] = useState<ViewMode>('graph');

  // Close namespace dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (nsDropdownRef.current && !nsDropdownRef.current.contains(e.target as Node)) {
        setShowNsDropdown(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  // Fetch namespaces
  useEffect(() => {
    if (!isConnected) return;
    setIsLoadingNs(true);
    apiClient.getNamespaces()
      .then(res => {
        const ns = (res.items || []).map((n: any) => n.name || n).sort();
        setNamespaces(ns);
        if (ns.length > 0 && selectedNamespaces.size === 0) {
          setSelectedNamespaces(new Set([ns[0]]));
        }
      })
      .catch(() => toast.error('Failed to load namespaces'))
      .finally(() => setIsLoadingNs(false));
  }, [isConnected]);

  // Fetch objects when type/namespace changes
  useEffect(() => {
    if (!selectedType || selectedNamespaces.size === 0) return;
    setIsLoadingList(true);
    setObjectList([]);
    setSelectedObjects(new Set());

    const nsArray = Array.from(selectedNamespaces);
    Promise.all(
      nsArray.map(ns =>
        listObjects(selectedType, ns).then(items =>
          items.map(item => ({ ...item, namespace: ns }))
        )
      )
    )
      .then(results => {
        const merged = results.flat();
        merged.sort((a, b) => a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name));
        setObjectList(merged);
      })
      .catch(() => toast.error('Failed to list objects'))
      .finally(() => setIsLoadingList(false));
  }, [selectedType, selectedNamespaces]);

  // Filtered types
  const filteredTypes = useMemo(() => {
    let types = OBJECT_TYPES.filter(t => t.childRefs.length > 0); // Only types with relationships
    if (selectedCategory) types = types.filter(t => t.category === selectedCategory);
    if (typeSearch) {
      const q = typeSearch.toLowerCase();
      types = types.filter(t => t.label.toLowerCase().includes(q) || t.id.toLowerCase().includes(q));
    }
    return types;
  }, [selectedCategory, typeSearch]);

  // Filtered namespaces
  const filteredNamespaces = useMemo(() => {
    if (!nsSearch) return namespaces;
    const q = nsSearch.toLowerCase();
    return namespaces.filter(ns => ns.toLowerCase().includes(q));
  }, [namespaces, nsSearch]);

  // Filtered objects
  const filteredObjects = useMemo(() => {
    if (!objectSearch) return objectList;
    const q = objectSearch.toLowerCase();
    return objectList.filter(o => o.name.toLowerCase().includes(q));
  }, [objectList, objectSearch]);

  // Toggle helpers
  const toggleNamespace = (ns: string) => {
    setSelectedNamespaces(prev => {
      const next = new Set(prev);
      if (next.has(ns)) next.delete(ns); else next.add(ns);
      return next;
    });
  };

  const toggleObject = (namespace: string, name: string) => {
    const key = objKey(namespace, name);
    setSelectedObjects(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };

  const selectAll = () => setSelectedObjects(new Set(filteredObjects.map(o => objKey(o.namespace, o.name))));
  const selectNone = () => setSelectedObjects(new Set());

  // Cancel fetch
  const cancelFetch = useCallback(() => {
    abortControllerRef.current?.abort();
    setIsFetching(false);
    setProgress(prev => prev ? { ...prev, phase: 'cancelled', message: 'Cancelled by user' } : null);
    toast.warning('Fetch cancelled');
  }, [toast]);

  // Fetch selected objects
  const fetchConfigs = useCallback(async () => {
    if (!selectedType || selectedObjects.size === 0) return;

    clearCache();

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setIsFetching(true);
    setResults([]);
    setGraphData(null);
    setStep('results');

    const entries = Array.from(selectedObjects).map(parseObjKey);
    const fetched: FetchedObject[] = [];

    for (let i = 0; i < entries.length; i++) {
      if (controller.signal.aborted) break;

      const { namespace, name } = entries[i];
      setProgress({
        phase: 'fetching',
        message: `Fetching ${name} (${namespace}) — ${i + 1}/${entries.length}`,
        current: i,
        total: entries.length,
      });

      try {
        const obj = await fetchObjectWithChildren(
          selectedType,
          namespace,
          name,
          { signal: controller.signal },
        );
        if (obj) fetched.push(obj);
      } catch (e: any) {
        if (e.name === 'AbortError') break;
        toast.error(`Failed to fetch ${namespace}/${name}: ${e.message}`);
      }
    }

    if (!controller.signal.aborted) {
      setResults(fetched);
      const graph = buildRelationshipGraph(fetched);
      setGraphData(graph);
      setProgress({ phase: 'done', message: 'Complete', current: entries.length, total: entries.length });
      toast.success(`Loaded ${fetched.length} object(s) — ${graph.nodes.length} nodes, ${graph.edges.length} relationships`);
    }

    setIsFetching(false);
  }, [selectedType, selectedObjects, toast]);

  // Namespace summary
  const namespaceSummary = useMemo(() => {
    const arr = Array.from(selectedNamespaces);
    if (arr.length === 0) return 'none';
    if (arr.length === 1) return arr[0];
    if (arr.length <= 3) return arr.join(', ');
    return `${arr.slice(0, 2).join(', ')} +${arr.length - 2} more`;
  }, [selectedNamespaces]);

  // ── Not connected ───────────────────────────────────────────────
  if (!isConnected) {
    return (
      <main className="max-w-7xl mx-auto px-6 py-12">
        <div className="text-center py-20">
          <GitBranch className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-slate-300">Connect to F5 XC first</h2>
          <p className="text-slate-500 mt-2">Go to the home page and connect with your tenant credentials.</p>
        </div>
      </main>
    );
  }

  // ═══════════════════════════════════════════════════════════════
  // STEP 1: SELECT OBJECT TYPE
  // ═══════════════════════════════════════════════════════════════
  if (step === 'select-type') {
    return (
      <main className="max-w-7xl mx-auto px-6 py-8">
        <div className="flex items-center gap-4 mb-8">
          <div className="w-12 h-12 bg-blue-500/15 rounded-xl flex items-center justify-center text-blue-400">
            <GitBranch className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Dependency Map</h1>
            <p className="text-sm text-slate-400">Explore relationships between config objects with interactive visualizations</p>
          </div>
          <Link to="/explainer/dependency-map" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
            <HelpCircle className="w-3.5 h-3.5" /> How does this work?
          </Link>
        </div>

        {/* Search */}
        <div className="relative mb-6">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
          <input
            type="text"
            value={typeSearch}
            onChange={e => setTypeSearch(e.target.value)}
            placeholder="Search object types..."
            className="w-full pl-10 pr-4 py-3 bg-slate-800 border border-slate-700 rounded-xl text-slate-200 text-sm focus:outline-none focus:border-blue-500 placeholder:text-slate-500"
          />
        </div>

        {/* Category filter */}
        <div className="flex flex-wrap gap-2 mb-6">
          <button
            onClick={() => setSelectedCategory(null)}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
              !selectedCategory ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
            }`}
          >
            All
          </button>
          {OBJECT_CATEGORIES.map(cat => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(selectedCategory === cat ? null : cat)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                selectedCategory === cat ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        <p className="text-xs text-slate-500 mb-4">Showing object types that have child references (relationships to explore)</p>

        {/* Object type grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {filteredTypes.map(typeDef => (
            <button
              key={typeDef.id}
              onClick={() => { setSelectedType(typeDef); setStep('select-objects'); }}
              className="flex items-start gap-3 p-4 bg-slate-800/50 border border-slate-700 rounded-xl hover:border-blue-500/50 hover:bg-slate-800 text-left transition-all group"
            >
              <Package className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-slate-200 group-hover:text-white">{typeDef.label}</p>
                <p className="text-xs text-slate-500 font-mono mt-0.5">{typeDef.apiResource}</p>
                <p className="text-xs text-slate-600 mt-1">{typeDef.category}</p>
                <div className="flex flex-wrap gap-1 mt-2">
                  {typeDef.childRefs.map((cr, i) => (
                    <span key={i} className="px-1.5 py-0.5 text-[10px] bg-blue-500/10 text-blue-400 rounded">
                      {cr.label}
                    </span>
                  ))}
                </div>
              </div>
              <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-blue-400 mt-0.5" />
            </button>
          ))}
        </div>
      </main>
    );
  }

  // ═══════════════════════════════════════════════════════════════
  // STEP 2: SELECT NAMESPACE(S) & OBJECTS
  // ═══════════════════════════════════════════════════════════════
  if (step === 'select-objects' && selectedType) {
    return (
      <main className="max-w-7xl mx-auto px-6 py-8">
        <div className="flex items-center gap-4 mb-6">
          <button onClick={() => { setStep('select-type'); setSelectedType(null); }} className="p-2 hover:bg-slate-700 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-slate-400" />
          </button>
          <div className="w-10 h-10 bg-blue-500/15 rounded-xl flex items-center justify-center text-blue-400">
            <GitBranch className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100">{selectedType.label}</h1>
            <p className="text-xs text-slate-500 font-mono">{selectedType.apiResource}</p>
          </div>
        </div>

        {/* Namespace selector */}
        <div className="mb-4 bg-slate-800/50 p-4 rounded-xl border border-slate-700">
          <div className="flex items-center gap-2 mb-2">
            <label className="text-sm font-medium text-slate-300 whitespace-nowrap">Namespaces:</label>
            <span className="text-xs text-slate-500">{selectedNamespaces.size} selected</span>
          </div>
          <div ref={nsDropdownRef} className="relative">
            <button
              onClick={() => setShowNsDropdown(!showNsDropdown)}
              className="w-full flex items-center justify-between px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-slate-200 hover:border-slate-600 transition-colors"
            >
              <span className="truncate">{isLoadingNs ? 'Loading...' : namespaceSummary}</span>
              <ChevronDown className="w-4 h-4 text-slate-500 flex-shrink-0" />
            </button>
            {showNsDropdown && (
              <div className="absolute z-20 mt-1 w-full bg-slate-800 border border-slate-700 rounded-lg shadow-xl max-h-64 overflow-y-auto">
                <div className="sticky top-0 bg-slate-800 p-2 border-b border-slate-700">
                  <input
                    type="text"
                    value={nsSearch}
                    onChange={e => setNsSearch(e.target.value)}
                    placeholder="Search namespaces..."
                    className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-sm text-slate-200 focus:outline-none focus:border-blue-500 placeholder:text-slate-500"
                  />
                  <div className="flex gap-2 mt-2">
                    <button onClick={() => setSelectedNamespaces(new Set(filteredNamespaces))} className="text-xs text-blue-400 hover:text-blue-300">Select All</button>
                    <button onClick={() => setSelectedNamespaces(new Set())} className="text-xs text-slate-400 hover:text-slate-300">Clear</button>
                  </div>
                </div>
                {filteredNamespaces.map(ns => (
                  <label key={ns} className="flex items-center gap-2 px-3 py-1.5 hover:bg-slate-700/50 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedNamespaces.has(ns)}
                      onChange={() => toggleNamespace(ns)}
                      className="rounded border-slate-600 bg-slate-900 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-sm text-slate-200">{ns}</span>
                  </label>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Object list */}
        <div className="bg-slate-800/50 p-4 rounded-xl border border-slate-700">
          <div className="flex items-center gap-3 mb-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                value={objectSearch}
                onChange={e => setObjectSearch(e.target.value)}
                placeholder="Search objects..."
                className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-blue-500 placeholder:text-slate-500"
              />
            </div>
            <button onClick={selectAll} className="text-xs text-blue-400 hover:text-blue-300 whitespace-nowrap">Select All</button>
            <button onClick={selectNone} className="text-xs text-slate-400 hover:text-slate-300 whitespace-nowrap">Clear</button>
          </div>

          {isLoadingList ? (
            <div className="flex items-center gap-2 justify-center py-8 text-slate-500">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading objects...
            </div>
          ) : filteredObjects.length === 0 ? (
            <p className="text-center py-8 text-slate-500 text-sm">No objects found</p>
          ) : (
            <div className="max-h-[400px] overflow-y-auto space-y-0.5">
              {filteredObjects.map(obj => {
                const key = objKey(obj.namespace, obj.name);
                return (
                  <label key={key} className="flex items-center gap-3 px-3 py-2 hover:bg-slate-700/30 rounded-lg cursor-pointer transition-colors">
                    <input
                      type="checkbox"
                      checked={selectedObjects.has(key)}
                      onChange={() => toggleObject(obj.namespace, obj.name)}
                      className="rounded border-slate-600 bg-slate-900 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-sm text-slate-200 font-medium">{obj.name}</span>
                    <span className="text-xs text-slate-600">{obj.namespace}</span>
                  </label>
                );
              })}
            </div>
          )}
        </div>

        {/* Fetch button */}
        <div className="mt-6 flex items-center justify-between">
          <span className="text-xs text-slate-500">{selectedObjects.size} object{selectedObjects.size !== 1 ? 's' : ''} selected</span>
          <button
            onClick={fetchConfigs}
            disabled={selectedObjects.size === 0}
            className="px-6 py-3 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors flex items-center gap-2"
          >
            <GitBranch className="w-5 h-5" />
            Build Map
          </button>
        </div>
      </main>
    );
  }

  // ═══════════════════════════════════════════════════════════════
  // STEP 3: RESULTS — MULTI-VIEW
  // ═══════════════════════════════════════════════════════════════
  const viewModes: { key: ViewMode; label: string; icon: typeof Network }[] = [
    { key: 'graph', label: 'Interactive Graph', icon: Network },
    { key: 'table', label: 'Dependency Table', icon: Table2 },
    { key: 'tree', label: 'Hierarchy Tree', icon: TreePine },
    { key: 'matrix', label: 'Dependency Matrix', icon: Grid3X3 },
  ];

  return (
    <main className="max-w-7xl mx-auto px-6 py-8">
      {/* Header */}
      <div className="flex items-center gap-4 mb-6">
        <button onClick={() => { setStep('select-objects'); }} className="p-2 hover:bg-slate-700 rounded-lg transition-colors">
          <ArrowLeft className="w-5 h-5 text-slate-400" />
        </button>
        <div className="w-10 h-10 bg-blue-500/15 rounded-xl flex items-center justify-center text-blue-400">
          <GitBranch className="w-5 h-5" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-slate-100">Dependency Map</h1>
          <p className="text-xs text-slate-400">
            {selectedType?.label} — {namespaceSummary}
            {graphData && ` — ${graphData.nodes.length} objects, ${graphData.edges.length} relationships`}
          </p>
        </div>
        <button
          onClick={() => { setStep('select-type'); setSelectedType(null); setResults([]); setGraphData(null); }}
          className="ml-auto px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors"
        >
          New Map
        </button>
      </div>

      {/* Progress */}
      {isFetching && progress && (
        <div className="mb-6 bg-slate-800/50 p-4 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
              <span className="text-sm text-slate-300">{progress.message}</span>
            </div>
            <button
              onClick={cancelFetch}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-400 hover:bg-red-500/10 border border-red-500/30 rounded-lg transition-colors"
            >
              <XCircle className="w-3.5 h-3.5" /> Cancel
            </button>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className="bg-blue-500 h-2 rounded-full transition-all"
              style={{ width: `${progress.total > 0 ? (progress.current / progress.total) * 100 : 0}%` }}
            />
          </div>
        </div>
      )}

      {/* View mode tabs */}
      {!isFetching && graphData && (
        <>
          <div className="flex items-center gap-1 mb-6 bg-slate-800/50 rounded-xl p-1 border border-slate-700 w-fit">
            {viewModes.map(mode => (
              <button
                key={mode.key}
                onClick={() => setViewMode(mode.key)}
                className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                  viewMode === mode.key ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-700'
                }`}
              >
                <mode.icon className="w-4 h-4" /> {mode.label}
              </button>
            ))}
          </div>

          {/* Graph view */}
          {viewMode === 'graph' && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden" style={{ height: 700 }}>
              <RelationshipGraph
                data={graphData}
                results={results}
              />
            </div>
          )}

          {/* Table view */}
          {viewMode === 'table' && (
            <DependencyTable data={graphData} />
          )}

          {/* Tree view */}
          {viewMode === 'tree' && (
            <HierarchyTree results={results} />
          )}

          {/* Matrix view */}
          {viewMode === 'matrix' && (
            <DependencyMatrix data={graphData} />
          )}
        </>
      )}

      {/* Empty state */}
      {!isFetching && graphData && graphData.edges.length === 0 && (
        <div className="text-center py-16 mt-4">
          <AlertCircle className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <p className="text-slate-400">No relationships found for the selected objects.</p>
          <p className="text-xs text-slate-500 mt-1">Try selecting objects with child references.</p>
        </div>
      )}
    </main>
  );
}
