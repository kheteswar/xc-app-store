/**
 * Global cross-account timeline — new in the redesign. Aggregates task events,
 * account history, and career wins across the whole portfolio, with filters.
 * Shared by all variants; `tone` skins it.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { Filter, Search, Plus, Save } from 'lucide-react';
import { useGlobalTimeline, useAccounts, UPDATE_BUCKETS, TONES, type Tone, TIMELINE_STYLE, fmtRel, groupByDate } from './shared';
import { workmgrApi, type AccountSummary } from '../../services/work-mgr';

const KINDS: { key: string; label: string }[] = [
  { key: 'task-created', label: '➕ Created' },
  { key: 'task-completed', label: '✅ Completed' },
  { key: 'task-due', label: '📅 Due' },
  { key: 'history', label: '📝 History' },
  { key: 'task-log', label: '💬 Task activity' },
  { key: 'update', label: '🗒️ Updates' },
  { key: 'win', label: '🏆 Wins' },
];

export function GlobalTimeline({ tone = 'dark', onOpenAccount, compact }: {
  tone?: Tone;
  onOpenAccount?: (name: string) => void;
  compact?: boolean;
}) {
  const t = TONES[tone];
  const { data, loading, reload } = useGlobalTimeline();
  const { data: accounts } = useAccounts();
  const [kinds, setKinds] = useState<Set<string>>(new Set());
  const [customer, setCustomer] = useState('');
  const [q, setQ] = useState('');
  const [showAdd, setShowAdd] = useState(false);

  const customers = useMemo(() => [...new Set((data || []).map(i => i.customer).filter(Boolean) as string[])].sort(), [data]);
  const filtered = useMemo(() => (data || []).filter(i => {
    if (kinds.size && !kinds.has(i.kind)) return false;
    if (customer && i.customer !== customer) return false;
    if (q && !`${i.label} ${i.customer} ${i.detail || ''}`.toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  }), [data, kinds, customer, q]);
  const grouped = groupByDate(filtered);

  // Land on today's group (or nearest past date if none today)
  const todayRef = useRef<HTMLDivElement>(null);
  const scrolledRef = useRef(false);
  const targetDate = useMemo(() => {
    const keys = grouped.map(g => g[0]);
    return keys.find(k => k <= todayStr()) ?? keys[keys.length - 1];
  }, [grouped]);
  useEffect(() => {
    if (compact || scrolledRef.current || loading || !grouped.length) return;
    if (todayRef.current) {
      scrolledRef.current = true;
      requestAnimationFrame(() => todayRef.current?.scrollIntoView({ block: 'start' }));
    }
  }, [loading, grouped, compact, targetDate]);

  const toggleKind = (k: string) => setKinds(prev => { const n = new Set(prev); n.has(k) ? n.delete(k) : n.add(k); return n; });

  return (
    <div className="space-y-4">
      {/* Add update */}
      {!compact && (
        <div>
          {!showAdd ? (
            <button onClick={() => setShowAdd(true)} className={`flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-md ${t.btn}`}>
              <Plus className="w-4 h-4" /> Add update
            </button>
          ) : (
            <AddUpdateForm tone={tone} accounts={accounts || []} onClose={() => setShowAdd(false)} onSaved={reload} />
          )}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md ${t.panel}`}>
          <Search className={`w-4 h-4 ${t.sub}`} />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search timeline…"
            className={`bg-transparent text-sm focus:outline-none ${tone === 'light' ? 'text-slate-800' : 'text-slate-100'}`} />
        </div>
        <select value={customer} onChange={e => setCustomer(e.target.value)} className={`px-2.5 py-1.5 text-sm rounded-md focus:outline-none ${t.input}`}>
          <option value="">All customers</option>
          {customers.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <span className={`flex items-center gap-1 text-xs ${t.sub}`}><Filter className="w-3.5 h-3.5" /></span>
        {KINDS.map(k => (
          <button key={k.key} onClick={() => toggleKind(k.key)}
            className={`px-2 py-1 text-xs rounded-full border ${kinds.has(k.key) || kinds.size === 0 ? t.chipOn : t.chipOff}`}>
            {k.label}
          </button>
        ))}
        <span className={`text-xs ml-auto ${t.sub}`}>{filtered.length} events</span>
      </div>

      {loading && <div className={t.sub}>Loading timeline…</div>}

      {/* Stream */}
      <div className="relative pl-4">
        <div className={`absolute left-1.5 top-1 bottom-1 w-px ${tone === 'light' ? 'bg-slate-200' : 'bg-slate-700'}`} />
        {grouped.map(([date, list]) => (
          <div key={date} ref={date === targetDate ? todayRef : undefined} className="mb-5 scroll-mt-24">
            <div className={`sticky top-0 z-10 py-1 text-sm font-semibold ${t.heading} ${tone === 'light' ? 'bg-slate-50' : 'bg-slate-900'} ${date === targetDate ? 'flex items-center gap-2' : ''}`}>
              {date} <span className={`font-normal ${t.sub}`}>· {fmtRel(date)} · {list.length}</span>
              {date === targetDate && <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/40">Today</span>}
            </div>
            <div className="space-y-1.5 mt-1.5">
              {list.map((it, i) => {
                const s = TIMELINE_STYLE[it.kind] || TIMELINE_STYLE.file;
                return (
                  <div key={i} className={`relative px-3 py-2 rounded-lg ${t.panel}`}>
                    <span className="absolute -left-[13px] top-3.5 w-2.5 h-2.5 rounded-full ring-2" style={{ background: s.color, ...(tone === 'light' ? { boxShadow: '0 0 0 2px #f8fafc' } : { boxShadow: '0 0 0 2px #0f172a' }) }} />
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs" style={{ color: s.color }}>{s.dot} {s.label}</span>
                      {it.time && <span className={`text-[10px] font-mono ${t.sub}`}>{it.time}</span>}
                      {it.customer && it.customer !== 'career' && (
                        <button onClick={() => onOpenAccount?.(it.customer!)}
                          className={`text-[10px] px-1.5 py-0.5 rounded-full border ${t.chipOff}`}>{it.customer}</button>
                      )}
                      {it.customer === 'career' && <span className="text-[10px] px-1.5 py-0.5 rounded-full border border-emerald-500/40 text-emerald-400">career</span>}
                    </div>
                    {!compact && <div className={`text-sm mt-0.5 ${t.heading}`}>{it.label}</div>}
                    {compact && <div className={`text-sm mt-0.5 truncate ${t.heading}`}>{it.label}</div>}
                    {it.detail && !compact && <div className={`text-xs ${t.sub}`}>{it.detail}</div>}
                    {it.body && !compact && <div className={`text-xs mt-1.5 whitespace-pre-wrap leading-relaxed border-l-2 pl-2.5 ${tone === 'light' ? 'text-slate-600 border-slate-200' : 'text-slate-300 border-slate-700'}`}>{it.body}</div>}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function todayStr() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function AddUpdateForm({ tone, accounts, onSaved, onClose }: { tone: Tone; accounts: AccountSummary[]; onSaved: () => void; onClose: () => void }) {
  const t = TONES[tone];
  const [bucket, setBucket] = useState('');
  const [text, setText] = useState('');
  const [date, setDate] = useState(todayStr());
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');

  const save = async () => {
    if (!bucket || !text.trim()) return;
    setSaving(true); setMsg('');
    try {
      const r = await workmgrApi.addUpdate({ customer: bucket, text: text.trim(), date });
      setMsg(`Saved to ${r.target}`);
      setText('');
      onSaved();
      setTimeout(onClose, 700);
    } catch (e: any) {
      setMsg(`Failed: ${e.message}`);
    } finally { setSaving(false); }
  };

  const inputCls = `px-2.5 py-1.5 text-sm rounded-md focus:outline-none ${t.input}`;
  return (
    <div className={`p-3 rounded-lg ${t.panel} space-y-2`}>
      <div className="flex items-center gap-2">
        <span className="text-base">🗒️</span>
        <span className={`text-sm font-semibold ${t.heading}`}>Log a quick update</span>
      </div>
      <div className="flex flex-wrap gap-2">
        <select value={bucket} onChange={e => setBucket(e.target.value)} className={inputCls} autoFocus>
          <option value="">Select account / bucket…</option>
          <optgroup label="Accounts">
            {accounts.map(a => <option key={a.name} value={a.name}>{a.overview?.customer || a.name}</option>)}
          </optgroup>
          <optgroup label="General">
            {UPDATE_BUCKETS.map(b => <option key={b} value={b}>{b}</option>)}
          </optgroup>
        </select>
        <input type="date" value={date} onChange={e => setDate(e.target.value)} className={inputCls} />
      </div>
      <input
        value={text}
        onChange={e => setText(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter') save(); }}
        placeholder="What did you work on? e.g. Reviewed RBAC matrix with Antony"
        className={`w-full ${inputCls}`}
      />
      <div className="flex items-center gap-2">
        {msg && <span className={`text-xs ${msg.startsWith('Failed') ? 'text-red-400' : t.sub}`}>{msg}</span>}
        <span className="ml-auto" />
        <button onClick={onClose} className={`text-sm px-2.5 py-1.5 rounded-md ${t.btnGhost}`}>Cancel</button>
        <button onClick={save} disabled={saving || !bucket || !text.trim()} className={`flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-md disabled:opacity-40 ${t.btn}`}>
          <Save className="w-4 h-4" /> {saving ? 'Saving…' : 'Save update'}
        </button>
      </div>
      <p className={`text-[11px] ${t.sub}`}>Real accounts → appended to their <code>00-overview.md</code> history. Other buckets → <code>updates-log.md</code>. Both reflect here and in the account timeline.</p>
    </div>
  );
}
