/**
 * Shared logic + reusable panels for Work Manager v1/v2/v3.
 * The three variants differ ONLY in shell/layout/visual language — the data
 * hooks, pin store, product-config editor and customer-details form live here
 * so functionality stays identical across designs.
 */
import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { Star, Save, ChevronDown, ChevronRight, Plus, Check } from 'lucide-react';
import {
  workmgrApi, type AccountSummary, type AccountDetail, type AccountConfig,
  type TimelineItem, type SummaryResponse, type TasksResponse,
} from '../../services/work-mgr';
import {
  PRODUCTS, PRODUCTS_BY_KEY, resolveProductKey, CUSTOMER_TEMPLATE,
  type ConfigField, type ProductDef,
} from '../../services/work-mgr/catalog';

// ===========================================================================
// Pin store — localStorage, shared across every variant + browser tab
// ===========================================================================
const PINS_KEY = 'workmgr:pins:v1';
const listeners = new Set<() => void>();
function readPins(): string[] { try { return JSON.parse(localStorage.getItem(PINS_KEY) || '[]'); } catch { return []; } }
let pinsCache = readPins();
function emitPins() { pinsCache = readPins(); listeners.forEach(l => l()); }
if (typeof window !== 'undefined') window.addEventListener('storage', emitPins);

export function usePins() {
  const pins = useSyncExternalStore(
    (cb) => { listeners.add(cb); return () => listeners.delete(cb); },
    () => pinsCache,
    () => pinsCache,
  );
  const toggle = useCallback((name: string) => {
    const cur = readPins();
    const next = cur.includes(name) ? cur.filter(p => p !== name) : [...cur, name];
    localStorage.setItem(PINS_KEY, JSON.stringify(next));
    emitPins();
  }, []);
  const isPinned = useCallback((name: string) => pinsCache.includes(name), [pins]);
  return { pins, toggle, isPinned };
}

/** Sort accounts so pinned ones float to the top, keeping given order within groups. */
export function withPinnedFirst<T extends { name: string }>(list: T[], pins: string[]): T[] {
  const p = new Set(pins);
  return [...list].sort((a, b) => {
    const ap = p.has(a.name) ? 0 : 1, bp = p.has(b.name) ? 0 : 1;
    return ap - bp;
  });
}

// ===========================================================================
// Async hook
// ===========================================================================
export function useAsync<T>(fn: () => Promise<T>, deps: any[]): { data: T | null; loading: boolean; error: string | null; reload: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const fnRef = useRef(fn); fnRef.current = fn;
  const reload = useCallback(() => {
    setLoading(true); setError(null);
    fnRef.current().then(setData).catch(e => setError(String(e.message || e))).finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { reload(); }, [reload]);
  return { data, loading, error, reload };
}

export const useSummary = () => useAsync<SummaryResponse>(() => workmgrApi.summary(), []);
export const useAccounts = () => useAsync<AccountSummary[]>(() => workmgrApi.listAccounts(), []);
export const useTasks = () => useAsync<TasksResponse>(() => workmgrApi.listTasks(), []);
export const useGlobalTimeline = () => useAsync<TimelineItem[]>(() => workmgrApi.getGlobalTimeline(), []);

// ===========================================================================
// Formatting helpers
// ===========================================================================
export function groupByDate<T extends { date: string }>(items: T[]): [string, T[]][] {
  const map = new Map<string, T[]>();
  for (const it of items) { if (!map.has(it.date)) map.set(it.date, []); map.get(it.date)!.push(it); }
  return [...map.entries()].sort((a, b) => b[0].localeCompare(a[0]));
}

export function daysAgo(dateStr?: string): number | null {
  if (!dateStr) return null;
  const d = new Date(dateStr + 'T00:00:00'); if (isNaN(d.getTime())) return null;
  return Math.floor((Date.now() - d.getTime()) / 86400000);
}
export function fmtRel(dateStr?: string): string {
  const d = daysAgo(dateStr); if (d === null) return '';
  if (d === 0) return 'today'; if (d === 1) return 'yesterday';
  if (d < 0) return `in ${-d}d`; if (d < 30) return `${d}d ago`;
  if (d < 365) return `${Math.round(d / 30)}mo ago`; return `${Math.round(d / 365)}y ago`;
}

export const TIMELINE_STYLE: Record<string, { label: string; color: string; dot: string }> = {
  'task-created':   { label: 'Created',   color: '#3b82f6', dot: '➕' },
  'task-completed': { label: 'Completed', color: '#22c55e', dot: '✅' },
  'task-due':       { label: 'Due',       color: '#f59e0b', dot: '📅' },
  'history':        { label: 'Update',    color: '#a855f7', dot: '📝' },
  'win':            { label: 'Win',       color: '#10b981', dot: '🏆' },
  'update':         { label: 'Update',    color: '#14b8a6', dot: '🗒️' },
  'task-log':       { label: 'Task',      color: '#6366f1', dot: '💬' },
  'file':           { label: 'File',      color: '#64748b', dot: '📎' },
};

/** General (non-account) buckets available when logging a quick update. */
export const UPDATE_BUCKETS = ['F5 Internal', 'Career', 'Personal', 'Team', 'Product / Feature', 'Learning'];

/** Resolve the product defs an account uses, from its config + overview products. */
export function accountProductDefs(cfg: AccountConfig | null, overviewProducts?: string[]): ProductDef[] {
  const keys = new Set<string>();
  (cfg?.products || []).forEach(k => {
    const rk = PRODUCTS_BY_KEY[k] ? k : resolveProductKey(k);
    if (rk) keys.add(rk);
  });
  (overviewProducts || []).forEach(t => { const rk = resolveProductKey(t); if (rk) keys.add(rk); });
  return [...keys].map(k => PRODUCTS_BY_KEY[k]).filter(Boolean);
}

// ===========================================================================
// Theming tokens (variants pass tone='dark'|'light')
// ===========================================================================
export type Tone = 'dark' | 'light';
export const TONES: Record<Tone, {
  panel: string; input: string; label: string; sub: string; heading: string;
  chipOn: string; chipOff: string; btn: string; btnGhost: string; divider: string;
}> = {
  dark: {
    panel: 'bg-slate-800/40 border border-slate-700/60',
    input: 'bg-slate-900 border border-slate-700 text-slate-100 placeholder-slate-600 focus:border-blue-500',
    label: 'text-slate-400', sub: 'text-slate-500', heading: 'text-slate-100',
    chipOn: 'bg-blue-500/20 border-blue-500/50 text-blue-200',
    chipOff: 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500',
    btn: 'bg-blue-500/20 border border-blue-500/50 text-blue-200 hover:bg-blue-500/30',
    btnGhost: 'text-slate-400 hover:text-slate-100', divider: 'border-slate-700/60',
  },
  light: {
    panel: 'bg-white border border-slate-200 shadow-sm',
    input: 'bg-white border border-slate-300 text-slate-800 placeholder-slate-400 focus:border-indigo-500',
    label: 'text-slate-500', sub: 'text-slate-400', heading: 'text-slate-900',
    chipOn: 'bg-indigo-50 border-indigo-300 text-indigo-700',
    chipOff: 'bg-slate-50 border-slate-200 text-slate-500 hover:border-slate-400',
    btn: 'bg-indigo-600 border border-indigo-600 text-white hover:bg-indigo-700',
    btnGhost: 'text-slate-500 hover:text-slate-900', divider: 'border-slate-200',
  },
};

// ===========================================================================
// Pin star button
// ===========================================================================
export function PinStar({ name, size = 16 }: { name: string; size?: number }) {
  const { isPinned, toggle } = usePins();
  const on = isPinned(name);
  return (
    <button
      onClick={(e) => { e.stopPropagation(); toggle(name); }}
      title={on ? 'Unpin' : 'Pin to top'}
      className="flex-shrink-0 transition-transform hover:scale-110"
    >
      <Star width={size} height={size} className={on ? 'fill-amber-400 text-amber-400' : 'text-slate-500 hover:text-amber-400'} />
    </button>
  );
}

// ===========================================================================
// Field input (drives config + customer-details forms)
// ===========================================================================
function FieldInput({ field, value, onChange, tone }: { field: ConfigField; value: any; onChange: (v: any) => void; tone: Tone }) {
  const t = TONES[tone];
  const base = `w-full px-2.5 py-1.5 text-sm rounded-md focus:outline-none ${t.input}`;
  switch (field.type) {
    case 'boolean':
      return (
        <button onClick={() => onChange(!value)} className={`px-3 py-1.5 text-sm rounded-md border ${value ? t.chipOn : t.chipOff}`}>
          {value ? '✓ Yes' : 'No'}
        </button>
      );
    case 'select':
      return (
        <select value={value ?? ''} onChange={e => onChange(e.target.value)} className={base}>
          <option value="">—</option>
          {field.options?.map(o => <option key={o} value={o}>{o}</option>)}
        </select>
      );
    case 'multiselect': {
      const arr: string[] = Array.isArray(value) ? value : [];
      return (
        <div className="flex flex-wrap gap-1.5">
          {field.options?.map(o => {
            const on = arr.includes(o);
            return (
              <button key={o} onClick={() => onChange(on ? arr.filter(x => x !== o) : [...arr, o])}
                className={`px-2 py-1 text-xs rounded-full border ${on ? t.chipOn : t.chipOff}`}>
                {on && <Check className="inline w-3 h-3 mr-0.5" />}{o}
              </button>
            );
          })}
        </div>
      );
    }
    case 'textarea':
      return <textarea value={value ?? ''} onChange={e => onChange(e.target.value)} placeholder={field.placeholder} rows={3} className={`${base} font-mono text-xs`} />;
    case 'number':
      return <input type="number" value={value ?? ''} onChange={e => onChange(e.target.value)} placeholder={field.placeholder} className={base} />;
    case 'date':
      return <input type="date" value={value ?? ''} onChange={e => onChange(e.target.value)} className={base} />;
    default:
      return <input type={field.type === 'url' ? 'url' : 'text'} value={value ?? ''} onChange={e => onChange(e.target.value)} placeholder={field.placeholder} className={base} />;
  }
}

function groupFields(fields: ConfigField[]): [string, ConfigField[]][] {
  const map = new Map<string, ConfigField[]>();
  for (const f of fields) { const g = f.group || 'General'; if (!map.has(g)) map.set(g, []); map.get(g)!.push(f); }
  return [...map.entries()];
}

// ===========================================================================
// Product & config editor  (products the user asked for: WAAP, Bot Std/Adv, MCN…)
// ===========================================================================
export function ProductConfigPanel({ name, tone = 'dark', onSaved }: { name: string; tone?: Tone; onSaved?: () => void }) {
  const t = TONES[tone];
  const { data: cfg, loading, reload } = useAsync<AccountConfig>(() => workmgrApi.getAccountConfig(name), [name]);
  const [selected, setSelected] = useState<string[]>([]);
  const [config, setConfig] = useState<Record<string, Record<string, any>>>({});
  const [expanded, setExpanded] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (!cfg) return;
    const keys = new Set<string>();
    cfg.products.forEach(k => { const rk = PRODUCTS_BY_KEY[k] ? k : resolveProductKey(k); if (rk) keys.add(rk); });
    setSelected([...keys]); setConfig(cfg.config || {}); setDirty(false);
  }, [cfg]);

  const toggleProduct = (key: string) => {
    setSelected(prev => prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]);
    setExpanded(key); setDirty(true);
  };
  const setField = (pk: string, fk: string, v: any) => {
    setConfig(prev => ({ ...prev, [pk]: { ...(prev[pk] || {}), [fk]: v } })); setDirty(true);
  };
  const save = async () => {
    setSaving(true);
    try { await workmgrApi.saveAccountConfig(name, { products: selected, config }); setDirty(false); reload(); onSaved?.(); }
    finally { setSaving(false); }
  };

  if (loading) return <div className={t.sub}>Loading products…</div>;

  const byCategory = PRODUCTS.reduce<Record<string, ProductDef[]>>((acc, p) => { (acc[p.category] = acc[p.category] || []).push(p); return acc; }, {});

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className={`text-sm font-semibold ${t.heading}`}>F5 XC Products & Config</h3>
        <button onClick={save} disabled={!dirty || saving} className={`flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-md disabled:opacity-40 ${t.btn}`}>
          <Save className="w-4 h-4" /> {saving ? 'Saving…' : dirty ? 'Save changes' : 'Saved'}
        </button>
      </div>

      {/* Product picker grouped by category */}
      <div className={`p-3 rounded-lg ${t.panel}`}>
        <div className={`text-xs uppercase tracking-wider mb-2 ${t.sub}`}>Products in use — tap to toggle</div>
        <div className="space-y-2">
          {Object.entries(byCategory).map(([cat, prods]) => (
            <div key={cat} className="flex flex-wrap items-center gap-1.5">
              <span className={`text-[10px] w-16 ${t.sub}`}>{cat}</span>
              {prods.map(p => {
                const on = selected.includes(p.key);
                return (
                  <button key={p.key} onClick={() => toggleProduct(p.key)}
                    className={`px-2.5 py-1 text-xs rounded-full border transition-colors ${on ? t.chipOn : t.chipOff}`}
                    title={p.blurb} style={on ? { borderColor: p.color, color: p.color } : {}}>
                    <span className="w-2 h-2 rounded-full inline-block mr-1.5 align-middle" style={{ background: p.color }} />
                    {p.short}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Per-product config cards */}
      {selected.length === 0 && <p className={`text-sm italic ${t.sub}`}>No products selected. Tap products above to capture their config.</p>}
      {selected.map(pk => {
        const p = PRODUCTS_BY_KEY[pk]; if (!p) return null;
        const open = expanded === pk;
        const filled = Object.values(config[pk] || {}).filter(v => v !== '' && v != null && !(Array.isArray(v) && v.length === 0)).length;
        return (
          <div key={pk} className={`rounded-lg ${t.panel}`}>
            <button onClick={() => setExpanded(open ? null : pk)} className="w-full flex items-center gap-2 px-3 py-2.5">
              {open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
              <span className="w-2.5 h-2.5 rounded-full" style={{ background: p.color }} />
              <span className={`text-sm font-medium ${t.heading}`}>{p.name}</span>
              <span className={`ml-auto text-xs ${t.sub}`}>{filled}/{p.fields.length} fields</span>
            </button>
            {open && (
              <div className={`px-3 pb-3 pt-1 border-t ${t.divider} space-y-4`}>
                <p className={`text-xs ${t.sub}`}>{p.blurb}</p>
                {groupFields(p.fields).map(([grp, fields]) => (
                  <div key={grp}>
                    <div className={`text-[10px] uppercase tracking-wider mb-1.5 ${t.sub}`}>{grp}</div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {fields.map(f => (
                        <div key={f.key} className={f.type === 'textarea' || f.type === 'multiselect' ? 'md:col-span-2' : ''}>
                          <label className={`block text-xs mb-1 ${t.label}`}>{f.label}</label>
                          <FieldInput field={f} value={config[pk]?.[f.key]} onChange={v => setField(pk, f.key, v)} tone={tone} />
                          {f.help && <p className={`text-[10px] mt-0.5 ${t.sub}`}>{f.help}</p>}
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ===========================================================================
// Customer-details form (the full template)
// ===========================================================================
export function CustomerDetailsPanel({ name, tone = 'dark', onSaved }: { name: string; tone?: Tone; onSaved?: () => void }) {
  const t = TONES[tone];
  const { data: cfg, loading, reload } = useAsync<AccountConfig>(() => workmgrApi.getAccountConfig(name), [name]);
  const [details, setDetails] = useState<Record<string, any>>({});
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);

  useEffect(() => { if (cfg) { setDetails(cfg.details || {}); setDirty(false); } }, [cfg]);
  const set = (k: string, v: any) => { setDetails(prev => ({ ...prev, [k]: v })); setDirty(true); };
  const save = async () => { setSaving(true); try { await workmgrApi.saveAccountConfig(name, { details }); setDirty(false); reload(); onSaved?.(); } finally { setSaving(false); } };

  if (loading) return <div className={t.sub}>Loading details…</div>;
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className={`text-sm font-semibold ${t.heading}`}>Customer details</h3>
        <button onClick={save} disabled={!dirty || saving} className={`flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-md disabled:opacity-40 ${t.btn}`}>
          <Save className="w-4 h-4" /> {saving ? 'Saving…' : dirty ? 'Save' : 'Saved'}
        </button>
      </div>
      {CUSTOMER_TEMPLATE.map(sec => (
        <div key={sec.title} className={`p-3 rounded-lg ${t.panel}`}>
          <div className={`text-xs uppercase tracking-wider mb-2 ${t.sub}`}>{sec.title}</div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {sec.fields.map(f => (
              <div key={f.key} className={f.type === 'textarea' || f.type === 'multiselect' ? 'md:col-span-2' : ''}>
                <label className={`block text-xs mb-1 ${t.label}`}>{f.label}</label>
                <FieldInput field={f} value={details[f.key]} onChange={v => set(f.key, v)} tone={tone} />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ===========================================================================
// Product chips (read-only) for cards/lists
// ===========================================================================
export function ProductChips({ defs, max = 6 }: { defs: ProductDef[]; max?: number }) {
  return (
    <div className="flex flex-wrap gap-1">
      {defs.slice(0, max).map(p => (
        <span key={p.key} className="px-1.5 py-0.5 text-[10px] rounded-full border" style={{ borderColor: p.color + '66', color: p.color }}>
          {p.short}
        </span>
      ))}
      {defs.length > max && <span className="px-1.5 py-0.5 text-[10px] text-slate-500">+{defs.length - max}</span>}
    </div>
  );
}

// Re-export commonly used bits
export { PRODUCTS, PRODUCTS_BY_KEY, CUSTOMER_TEMPLATE };
export type { AccountSummary, AccountDetail, AccountConfig, TimelineItem, ProductDef };
