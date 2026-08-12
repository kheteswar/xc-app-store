/**
 * Work Patterns — capture reusable "trigger → action" playbooks used during
 * work, for later reference and analysis. Trigger, action, category, tools and
 * tags all offer past values as a dropdown while allowing custom text. Each
 * pattern tracks a usage counter to power the analysis panel.
 */
import { useMemo, useState, useEffect } from 'react';
import {
  Workflow, Plus, Search, X, Save, Trash2, ArrowRight, Pencil, TrendingUp,
  BarChart3, Wrench, Zap, Repeat,
} from 'lucide-react';
import { workmgrApi, type WorkPattern, type WorkPatternFm } from '../../services/work-mgr';
import { useAsync } from './shared';

const CATEGORIES: { key: string; color: string }[] = [
  { key: 'Troubleshooting', color: '#ef4444' },
  { key: 'Research', color: '#3b82f6' },
  { key: 'Escalation', color: '#f59e0b' },
  { key: 'Communication', color: '#8b5cf6' },
  { key: 'Automation', color: '#22c55e' },
  { key: 'Config Change', color: '#14b8a6' },
  { key: 'Validation / Testing', color: '#06b6d4' },
  { key: 'Documentation', color: '#eab308' },
  { key: 'Planning', color: '#ec4899' },
  { key: 'Learning', color: '#0ea5e9' },
  { key: 'General', color: '#94a3b8' },
];
const CAT_COLOR = (c?: string) => CATEGORIES.find(x => x.key === c)?.color || '#94a3b8';
const TOOLS = ['AI Assistant', 'Slack', 'Teams', 'Jira', 'Salesforce', 'XC Console', 'Confluence / KB', 'Email', 'Runbook', 'CLI / Script', 'Colleague / SME', 'Grafana / Logs', 'Docs'];
const EFFECTIVENESS = ['', 'low', 'medium', 'high'];
const today = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
const field = 'w-full px-2.5 py-1.5 text-sm bg-slate-900 border border-slate-700 rounded-md text-slate-100 placeholder-slate-600 focus:border-blue-500 focus:outline-none';

export function WorkPatternsTab({ toast }: { toast: any }) {
  const { data, loading, reload } = useAsync<WorkPattern[]>(() => workmgrApi.listWorkPatterns(), []);
  const [category, setCategory] = useState('');
  const [tool, setTool] = useState('');
  const [q, setQ] = useState('');
  const [editing, setEditing] = useState<{ filename?: string } | null>(null);

  const patterns = data || [];
  // suggestion pools (past values)
  const pastTriggers = useMemo(() => [...new Set(patterns.map(p => p.frontmatter.trigger).filter(Boolean) as string[])].sort(), [patterns]);
  const pastActions = useMemo(() => [...new Set(patterns.map(p => p.frontmatter.action).filter(Boolean) as string[])].sort(), [patterns]);
  const pastCategories = useMemo(() => [...new Set([...CATEGORIES.map(c => c.key), ...patterns.map(p => p.frontmatter.category).filter(Boolean) as string[]])], [patterns]);
  const pastTools = useMemo(() => [...new Set([...TOOLS, ...patterns.flatMap(p => p.frontmatter.tools || [])])], [patterns]);
  const pastTags = useMemo(() => [...new Set(patterns.flatMap(p => p.frontmatter.tags || []))].sort(), [patterns]);

  const filtered = patterns.filter(p => {
    const fm = p.frontmatter;
    if (category && fm.category !== category) return false;
    if (tool && !(fm.tools || []).includes(tool)) return false;
    if (q && !`${fm.trigger} ${fm.action} ${fm.category} ${(fm.tags || []).join(' ')} ${(fm.tools || []).join(' ')} ${p.body}`.toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  });

  const bump = async (p: WorkPattern) => {
    try {
      await workmgrApi.patchWorkPattern(p.filename, { frontmatter: { uses: (Number(p.frontmatter.uses) || 0) + 1, last_used: today() } });
      reload();
    } catch (e: any) { toast.error(`Failed: ${e.message}`); }
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold text-slate-100"><Workflow className="w-5 h-5 text-blue-400" /> Work Patterns</h1>
          <p className="text-xs text-slate-500 mt-0.5">Capture the "when this → I do that" moves you repeat, then spot what you rely on most.</p>
        </div>
        <button onClick={() => setEditing({})} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30">
          <Plus className="w-4 h-4" /> New pattern
        </button>
      </div>

      <AnalysisPanel patterns={patterns} />

      {/* category filter chips */}
      <div className="flex flex-wrap gap-1.5">
        <button onClick={() => setCategory('')} className={`px-2.5 py-1 text-xs rounded-full border ${!category ? 'bg-slate-700 border-slate-500 text-slate-100' : 'border-slate-700 text-slate-400 hover:border-slate-500'}`}>All ({patterns.length})</button>
        {CATEGORIES.filter(c => patterns.some(p => p.frontmatter.category === c.key)).map(c => {
          const n = patterns.filter(p => p.frontmatter.category === c.key).length;
          return (
            <button key={c.key} onClick={() => setCategory(category === c.key ? '' : c.key)} className="px-2.5 py-1 text-xs rounded-full border"
              style={category === c.key ? { borderColor: c.color, color: c.color, background: c.color + '22' } : { borderColor: '#33415580', color: '#94a3b8' }}>
              {c.key} ({n})
            </button>
          );
        })}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-slate-800/40 border border-slate-700/60">
          <Search className="w-4 h-4 text-slate-500" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search patterns…" className="bg-transparent text-sm text-slate-100 focus:outline-none" />
        </div>
        <select value={tool} onChange={e => setTool(e.target.value)} className={`${field} w-auto`}>
          <option value="">All tools</option>
          {pastTools.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <span className="text-xs text-slate-500 ml-auto">{filtered.length} patterns</span>
      </div>

      {loading && <div className="text-slate-400">Loading…</div>}
      {!loading && filtered.length === 0 && <p className="text-sm text-slate-500 italic">No patterns yet. Capture your first with “New pattern” — e.g. <em>Troubleshooting XC error → Research error with AI tools</em>.</p>}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {filtered.map(p => <PatternCard key={p.filename} pattern={p} onOpen={() => setEditing({ filename: p.filename })} onBump={() => bump(p)} />)}
      </div>

      {editing && (
        <PatternEditor
          filename={editing.filename}
          toast={toast}
          suggestions={{ triggers: pastTriggers, actions: pastActions, categories: pastCategories, tools: pastTools, tags: pastTags }}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); reload(); }}
        />
      )}
    </div>
  );
}

function PatternCard({ pattern, onOpen, onBump }: { pattern: WorkPattern; onOpen: () => void; onBump: () => void }) {
  const fm = pattern.frontmatter;
  const color = CAT_COLOR(fm.category);
  const uses = Number(fm.uses) || 0;
  return (
    <div className="flex rounded-lg bg-slate-800/40 border border-slate-700/60 hover:border-slate-600 transition-colors overflow-hidden">
      <div className="w-1 flex-shrink-0" style={{ background: color }} />
      <div className="flex-1 min-w-0 p-4">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="px-2 py-0.5 text-[11px] rounded-full border font-medium" style={{ borderColor: color + '66', color, background: color + '14' }}>{fm.category || 'General'}</span>
          {fm.effectiveness && <span className={`text-[10px] px-1.5 py-0.5 rounded-full border ${fm.effectiveness === 'high' ? 'border-emerald-500/40 text-emerald-300' : fm.effectiveness === 'medium' ? 'border-amber-500/40 text-amber-300' : 'border-slate-600 text-slate-400'}`}>{fm.effectiveness}</span>}
          <div className="ml-auto flex items-center gap-1">
            <button onClick={onBump} title="Used it again (+1)" className="flex items-center gap-1 px-2 py-0.5 text-xs rounded-md bg-blue-500/15 border border-blue-500/30 text-blue-300 hover:bg-blue-500/25"><Repeat className="w-3 h-3" /> {uses}</button>
            <button onClick={onOpen} title="Edit" className="p-1 rounded text-slate-500 hover:text-slate-100 hover:bg-slate-700/60"><Pencil className="w-3.5 h-3.5" /></button>
          </div>
        </div>
        {/* trigger → action */}
        <div className="flex items-start gap-2 mt-3">
          <div className="flex-1 px-2.5 py-1.5 rounded-md bg-slate-900/60 border border-slate-700/60 text-sm text-slate-200"><span className="text-[10px] uppercase tracking-wider text-slate-500 block">When</span>{fm.trigger}</div>
          <ArrowRight className="w-4 h-4 text-slate-500 mt-5 flex-shrink-0" />
          <div className="flex-1 px-2.5 py-1.5 rounded-md bg-slate-900/60 border border-slate-700/60 text-sm text-slate-200"><span className="text-[10px] uppercase tracking-wider text-slate-500 block">I do</span>{fm.action || '—'}</div>
        </div>
        {pattern.body && <p className="text-sm text-slate-400 mt-2 whitespace-pre-wrap">{pattern.body}</p>}
        <div className="flex flex-wrap gap-1.5 mt-2.5">
          {(fm.tools || []).map(t => <span key={t} className="px-1.5 py-0.5 text-[10px] rounded-full bg-slate-700/40 border border-slate-600 text-slate-300"><Wrench className="inline w-2.5 h-2.5 mr-0.5 -mt-0.5" />{t}</span>)}
          {(fm.tags || []).map(t => <span key={t} className="px-1.5 py-0.5 text-[10px] rounded-full border border-slate-700 text-slate-400">#{t}</span>)}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- analysis
function AnalysisPanel({ patterns }: { patterns: WorkPattern[] }) {
  const stats = useMemo(() => {
    const totalUses = patterns.reduce((s, p) => s + (Number(p.frontmatter.uses) || 0), 0);
    const byCat: Record<string, number> = {};
    const triggers: Record<string, number> = {};
    const actions: Record<string, number> = {};
    const tools: Record<string, number> = {};
    for (const p of patterns) {
      const fm = p.frontmatter;
      byCat[fm.category || 'General'] = (byCat[fm.category || 'General'] || 0) + 1;
      if (fm.trigger) triggers[fm.trigger] = (triggers[fm.trigger] || 0) + 1;
      if (fm.action) actions[fm.action] = (actions[fm.action] || 0) + 1;
      (fm.tools || []).forEach(t => { tools[t] = (tools[t] || 0) + 1; });
    }
    const top = (o: Record<string, number>, n = 5) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, n);
    const mostUsed = [...patterns].sort((a, b) => (Number(b.frontmatter.uses) || 0) - (Number(a.frontmatter.uses) || 0)).slice(0, 5).filter(p => (Number(p.frontmatter.uses) || 0) > 0);
    return { totalUses, byCat: top(byCat, 8), triggers: top(triggers), actions: top(actions), tools: top(tools), mostUsed };
  }, [patterns]);

  if (patterns.length === 0) return null;
  const maxCat = Math.max(1, ...stats.byCat.map(c => c[1]));

  return (
    <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50 space-y-4">
      <h3 className="flex items-center gap-1.5 text-sm font-semibold text-slate-200"><BarChart3 className="w-4 h-4" /> Analysis</h3>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat icon={Workflow} label="Patterns" value={patterns.length} color="text-blue-400" />
        <Stat icon={Repeat} label="Total uses" value={stats.totalUses} color="text-emerald-400" />
        <Stat icon={Zap} label="Categories" value={stats.byCat.length} color="text-purple-400" />
        <Stat icon={TrendingUp} label="Avg uses" value={patterns.length ? (stats.totalUses / patterns.length).toFixed(1) : 0} color="text-amber-400" />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <div className="text-xs font-semibold text-slate-400 mb-1.5">By category</div>
          <div className="space-y-1">
            {stats.byCat.map(([c, n]) => (
              <div key={c} className="flex items-center gap-2 text-xs">
                <span className="w-32 truncate text-slate-300">{c}</span>
                <div className="flex-1 h-3 bg-slate-800 rounded overflow-hidden"><div className="h-full" style={{ width: `${(n / maxCat) * 100}%`, background: CAT_COLOR(c) }} /></div>
                <span className="w-5 text-right text-slate-400">{n}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="space-y-3">
          <TopList title="Most-used patterns" items={stats.mostUsed.map(p => [`${p.frontmatter.trigger} → ${p.frontmatter.action || ''}`, Number(p.frontmatter.uses) || 0] as [string, number])} empty="Hit “+1” on a pattern when you use it." />
          <div>
            <div className="text-xs font-semibold text-slate-400 mb-1.5">Top tools</div>
            <div className="flex flex-wrap gap-1.5">
              {stats.tools.length === 0 && <span className="text-xs text-slate-500 italic">—</span>}
              {stats.tools.map(([t, n]) => <span key={t} className="px-2 py-0.5 text-[11px] rounded-full bg-slate-700/40 border border-slate-600 text-slate-300">{t} · {n}</span>)}
            </div>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <TopList title="Common triggers" items={stats.triggers} empty="—" />
        <TopList title="Common actions" items={stats.actions} empty="—" />
      </div>
    </div>
  );
}

function Stat({ icon: Icon, label, value, color }: any) {
  return (
    <div className="p-3 rounded-lg bg-slate-800/40 border border-slate-700/50">
      <div className="flex items-center justify-between"><span className="text-[10px] uppercase tracking-wider text-slate-500">{label}</span><Icon className={`w-4 h-4 ${color}`} /></div>
      <div className="text-2xl font-bold text-slate-100 mt-1">{value}</div>
    </div>
  );
}
function TopList({ title, items, empty }: { title: string; items: [string, number][]; empty: string }) {
  return (
    <div>
      <div className="text-xs font-semibold text-slate-400 mb-1.5">{title}</div>
      {items.length === 0 ? <span className="text-xs text-slate-500 italic">{empty}</span> : (
        <div className="space-y-1">
          {items.map(([label, n], i) => (
            <div key={i} className="flex items-center gap-2 text-xs">
              <span className="flex-1 truncate text-slate-300" title={label}>{label}</span>
              <span className="px-1.5 py-0.5 rounded bg-slate-700/50 text-slate-400">{n}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- editor
function ChipMulti({ value, suggestions, onChange, placeholder, listId }: { value: string[]; suggestions: string[]; onChange: (v: string[]) => void; placeholder: string; listId: string }) {
  const [draft, setDraft] = useState('');
  const add = (v: string) => { const t = v.trim(); if (t && !value.includes(t)) onChange([...value, t]); setDraft(''); };
  return (
    <div>
      <div className="flex flex-wrap gap-1 mb-1">
        {value.map((v, i) => <span key={i} className="px-2 py-0.5 text-xs rounded-full border border-slate-600 text-slate-300 flex items-center gap-1">{v}<button onClick={() => onChange(value.filter((_, j) => j !== i))}><X className="w-3 h-3" /></button></span>)}
      </div>
      <input value={draft} onChange={e => setDraft(e.target.value)} list={listId} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); add(draft); } }} className={field} placeholder={placeholder} />
      <datalist id={listId}>{suggestions.filter(s => !value.includes(s)).map(s => <option key={s} value={s} />)}</datalist>
    </div>
  );
}

function PatternEditor({ filename, toast, suggestions, onClose, onSaved }: {
  filename?: string; toast: any;
  suggestions: { triggers: string[]; actions: string[]; categories: string[]; tools: string[]; tags: string[] };
  onClose: () => void; onSaved: () => void;
}) {
  const isEdit = !!filename;
  const [category, setCategory] = useState('Troubleshooting');
  const [trigger, setTrigger] = useState('');
  const [action, setAction] = useState('');
  const [tools, setTools] = useState<string[]>([]);
  const [tags, setTags] = useState<string[]>([]);
  const [effectiveness, setEffectiveness] = useState('');
  const [uses, setUses] = useState(0);
  const [body, setBody] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!filename) return;
    workmgrApi.getWorkPattern(filename).then(p => {
      const fm = p.frontmatter;
      setCategory(fm.category || 'Troubleshooting'); setTrigger(fm.trigger || ''); setAction(fm.action || '');
      setTools(Array.isArray(fm.tools) ? fm.tools : []); setTags(Array.isArray(fm.tags) ? fm.tags : []);
      setEffectiveness(String(fm.effectiveness || '')); setUses(Number(fm.uses) || 0); setBody(p.body || '');
    }).catch(e => toast.error(`Load failed: ${e.message}`));
  }, [filename, toast]);

  const save = async () => {
    if (!trigger.trim()) { toast.error('A trigger / situation is required'); return; }
    setSaving(true);
    const fm: WorkPatternFm = { category, trigger: trigger.trim(), action: action.trim(), tools, tags, effectiveness: effectiveness || undefined, uses };
    try {
      if (isEdit) { await workmgrApi.patchWorkPattern(filename!, { frontmatter: fm, body }); toast.success('Pattern saved'); }
      else { await workmgrApi.createWorkPattern({ frontmatter: fm, body }); toast.success('Pattern captured'); }
      onSaved();
    } catch (e: any) { toast.error(`Save failed: ${e.message}`); } finally { setSaving(false); }
  };
  const remove = async () => {
    if (!filename || !confirm('Delete this pattern?')) return;
    try { await workmgrApi.deleteWorkPattern(filename); toast.success('Deleted'); onSaved(); } catch (e: any) { toast.error(`Delete failed: ${e.message}`); }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/70 flex items-start justify-center p-4 overflow-y-auto">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-lg shadow-2xl my-6">
        <div className="flex items-center justify-between p-4 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-slate-100">{isEdit ? 'Edit pattern' : 'New work pattern'}</h2>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Category</label>
              <input value={category} onChange={e => setCategory(e.target.value)} list="pat-categories" className={field} placeholder="pick or type" />
              <datalist id="pat-categories">{suggestions.categories.map(c => <option key={c} value={c} />)}</datalist>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Effectiveness</label>
              <select value={effectiveness} onChange={e => setEffectiveness(e.target.value)} className={field}>
                {EFFECTIVENESS.map(x => <option key={x} value={x}>{x || '—'}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">When / trigger <span className="text-slate-600">(situation)</span></label>
            <input autoFocus value={trigger} onChange={e => setTrigger(e.target.value)} list="pat-triggers" className={field} placeholder="e.g. Troubleshooting XC error · Found a bug · Blocked on access" />
            <datalist id="pat-triggers">{suggestions.triggers.map(s => <option key={s} value={s} />)}</datalist>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">I do / action <span className="text-slate-600">(response)</span></label>
            <input value={action} onChange={e => setAction(e.target.value)} list="pat-actions" className={field} placeholder="e.g. Research error with AI tools · Search Slack history · Raise ticket with X team" />
            <datalist id="pat-actions">{suggestions.actions.map(s => <option key={s} value={s} />)}</datalist>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Tools used</label>
            <ChipMulti value={tools} suggestions={suggestions.tools} onChange={setTools} placeholder="pick a tool or type + Enter" listId="pat-tools" />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Tags</label>
            <ChipMulti value={tags} suggestions={suggestions.tags} onChange={setTags} placeholder="pick a tag or type + Enter" listId="pat-tags" />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Notes / example <span className="text-slate-600">(optional)</span></label>
            <textarea value={body} onChange={e => setBody(e.target.value)} className={`${field} h-28 font-mono text-xs`} placeholder="Any detail, a concrete example, when it works best…" spellCheck={false} />
          </div>
          <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
            {isEdit && <><button onClick={remove} className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-red-400 hover:bg-red-500/10 rounded-md"><Trash2 className="w-4 h-4" /> Delete</button><span className="text-xs text-slate-500">used {uses}×</span></>}
            <div className="flex-1" />
            <button onClick={onClose} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
            <button onClick={save} disabled={saving || !trigger.trim()} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30 disabled:opacity-50">
              <Save className="w-4 h-4" /> {saving ? 'Saving…' : isEdit ? 'Save' : 'Capture pattern'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
