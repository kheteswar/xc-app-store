/**
 * Thought Journal — an intimate space to capture ideas, thoughts, reflections
 * and feelings as you work. This is deliberately separate from Updates (account
 * activity), Learnings (reusable knowledge) and Work Patterns (reusable methods):
 * the Journal is for your own mind — half-formed ideas, questions you're sitting
 * with, how the work is landing on you — to help structure your understanding
 * and mindspace over time.
 *
 * Each entry is tagged by Kind (Idea / Reflection / Insight / Question / …),
 * Mood (the mental/emotional state you were in) and a free-text Theme, plus
 * tags. Kind, Mood and Theme offer previously-used values while still allowing
 * any new custom value. Stored as markdown files in mywork/journal/.
 */
import { useMemo, useState, useEffect } from 'react';
import {
  BookHeart, Plus, Search, X, Save, Trash2, Pencil, Sparkles, HelpCircle,
  Heart, Lightbulb, Compass, Flag, Tag, Calendar, BarChart3,
  Filter, Smile, Feather, ScrollText,
} from 'lucide-react';
import { workmgrApi, type JournalEntry, type JournalFm } from '../../services/work-mgr';
import { useAsync, fmtRel } from './shared';

// The nature of an entry — what kind of thought it is. Colour-coded so the feed
// reads at a glance.
const KINDS: { key: string; color: string; icon: any }[] = [
  { key: 'Idea', color: '#6366f1', icon: Lightbulb },
  { key: 'Reflection', color: '#8b5cf6', icon: Feather },
  { key: 'Insight', color: '#22c55e', icon: Sparkles },
  { key: 'Question', color: '#06b6d4', icon: HelpCircle },
  { key: 'Feeling', color: '#ec4899', icon: Heart },
  { key: 'Intention', color: '#f59e0b', icon: Flag },
  { key: 'Decision', color: '#14b8a6', icon: Compass },
  { key: 'Doubt', color: '#ef4444', icon: HelpCircle },
  { key: 'Gratitude', color: '#eab308', icon: Heart },
  { key: 'Observation', color: '#94a3b8', icon: ScrollText },
];
const KIND_COLOR = (c?: string) => KINDS.find(x => x.key === c)?.color || '#94a3b8';
const KIND_ICON = (c?: string) => KINDS.find(x => x.key === c)?.icon || ScrollText;

// Seed suggestions — merged with previously-used values, all editable as custom text.
const MOOD_SEED = ['Energized', 'Focused', 'Curious', 'Calm', 'Inspired', 'Content', 'Neutral', 'Restless', 'Tired', 'Frustrated', 'Anxious', 'Overwhelmed'];

const today = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
const nowTime = () => { const d = new Date(); return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`; };
const field = 'w-full px-2.5 py-1.5 text-sm bg-slate-900 border border-slate-700 rounded-md text-slate-100 placeholder-slate-600 focus:border-blue-500 focus:outline-none';
const uniq = (arr: (string | undefined)[]) => [...new Set(arr.filter(Boolean) as string[])];

export function JournalTab({ toast }: { toast: any }) {
  const { data, loading, reload } = useAsync<JournalEntry[]>(() => workmgrApi.listJournal(), []);
  const [kind, setKind] = useState('');
  const [mood, setMood] = useState('');
  const [theme, setTheme] = useState('');
  const [q, setQ] = useState('');
  const [editing, setEditing] = useState<{ filename?: string } | null>(null);

  const items = data || [];

  // suggestion pools = seeds ∪ past values
  const sugg = useMemo(() => ({
    kinds: uniq([...KINDS.map(k => k.key), ...items.map(i => i.frontmatter.kind)]),
    moods: uniq([...MOOD_SEED, ...items.map(i => i.frontmatter.mood)]),
    themes: uniq(items.map(i => i.frontmatter.theme)).sort(),
    tags: uniq(items.flatMap(i => i.frontmatter.tags || [])).sort(),
  }), [items]);

  const filtered = items.filter(i => {
    const fm = i.frontmatter;
    if (kind && fm.kind !== kind) return false;
    if (mood && fm.mood !== mood) return false;
    if (theme && fm.theme !== theme) return false;
    if (q) {
      const hay = `${fm.title} ${fm.kind} ${fm.mood} ${fm.theme} ${(fm.tags || []).join(' ')} ${i.body}`.toLowerCase();
      if (!hay.includes(q.toLowerCase())) return false;
    }
    return true;
  });

  const anyFilter = kind || mood || theme || q;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold text-slate-100"><BookHeart className="w-5 h-5 text-blue-400" /> Thought Journal</h1>
          <p className="text-xs text-slate-500 mt-0.5">A private space for the ideas and thoughts you have as you work — reflections, questions, how it's landing on you. Your mindspace, structured over time.</p>
        </div>
        <button onClick={() => setEditing({})} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30">
          <Plus className="w-4 h-4" /> New thought
        </button>
      </div>

      <AnalysisPanel items={items} />

      {/* kind chips */}
      <div className="flex flex-wrap gap-1.5">
        <button onClick={() => setKind('')} className={`px-2.5 py-1 text-xs rounded-full border ${!kind ? 'bg-slate-700 border-slate-500 text-slate-100' : 'border-slate-700 text-slate-400 hover:border-slate-500'}`}>All ({items.length})</button>
        {KINDS.filter(k => items.some(i => i.frontmatter.kind === k.key)).map(k => {
          const n = items.filter(i => i.frontmatter.kind === k.key).length;
          return (
            <button key={k.key} onClick={() => setKind(kind === k.key ? '' : k.key)} className="px-2.5 py-1 text-xs rounded-full border"
              style={kind === k.key ? { borderColor: k.color, color: k.color, background: k.color + '22' } : { borderColor: '#33415580', color: '#94a3b8' }}>
              {k.key} ({n})
            </button>
          );
        })}
      </div>

      {/* filter row */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-slate-800/40 border border-slate-700/60">
          <Search className="w-4 h-4 text-slate-500" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search your thoughts…" className="bg-transparent text-sm text-slate-100 focus:outline-none" />
        </div>
        <FilterSelect icon={Smile} value={mood} onChange={setMood} options={sugg.moods} allLabel="Any mood" />
        <FilterSelect icon={Compass} value={theme} onChange={setTheme} options={sugg.themes} allLabel="Any theme" />
        {anyFilter && <button onClick={() => { setKind(''); setMood(''); setTheme(''); setQ(''); }} className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200"><Filter className="w-3.5 h-3.5" /> Clear</button>}
        <span className="text-xs text-slate-500 ml-auto">{filtered.length} thoughts</span>
      </div>

      {loading && <div className="text-slate-400">Loading…</div>}
      {!loading && filtered.length === 0 && (
        <p className="text-sm text-slate-500 italic">
          {items.length === 0
            ? 'Nothing here yet. Capture your first thought with “New thought” — an idea worth keeping, a question you’re sitting with, or just how the work feels right now.'
            : 'No thoughts match these filters.'}
        </p>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {filtered.map(i => <JournalCard key={i.filename} item={i} onOpen={() => setEditing({ filename: i.filename })} />)}
      </div>

      {editing && (
        <JournalEditor
          filename={editing.filename}
          toast={toast}
          suggestions={sugg}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); reload(); }}
        />
      )}
    </div>
  );
}

function FilterSelect({ icon: Icon, value, onChange, options, allLabel }: { icon: any; value: string; onChange: (v: string) => void; options: string[]; allLabel: string }) {
  return (
    <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-md bg-slate-800/40 border border-slate-700/60">
      <Icon className="w-4 h-4 text-slate-500" />
      <select value={value} onChange={e => onChange(e.target.value)} className="bg-transparent text-sm text-slate-200 focus:outline-none max-w-[10rem]">
        <option value="" className="bg-slate-800">{allLabel}</option>
        {options.map(o => <option key={o} value={o} className="bg-slate-800">{o}</option>)}
      </select>
    </div>
  );
}

function MetaChip({ icon: Icon, value }: { icon: any; value?: string }) {
  if (!value) return null;
  return <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded-full bg-slate-700/40 border border-slate-600 text-slate-300"><Icon className="w-2.5 h-2.5" />{value}</span>;
}

function JournalCard({ item, onOpen }: { item: JournalEntry; onOpen: () => void }) {
  const fm = item.frontmatter;
  const color = KIND_COLOR(fm.kind);
  const KindIcon = KIND_ICON(fm.kind);
  return (
    <div className="flex rounded-lg bg-slate-800/40 border border-slate-700/60 hover:border-slate-600 transition-colors overflow-hidden">
      <div className="w-1 flex-shrink-0" style={{ background: color }} />
      <div className="flex-1 min-w-0 p-4">
        <div className="flex items-start gap-2">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] rounded-full border font-medium" style={{ borderColor: color + '66', color, background: color + '14' }}><KindIcon className="w-2.5 h-2.5" />{fm.kind || 'Thought'}</span>
              <span className="flex items-center gap-1 text-[11px] text-slate-500"><Calendar className="w-3 h-3" />{fm.date}{fm.time ? ` ${fm.time}` : ''} · {fmtRel(String(fm.date))}</span>
            </div>
            <h3 className="text-sm font-semibold text-slate-100 leading-snug">{fm.title}</h3>
          </div>
          <button onClick={onOpen} title="Edit" className="flex-shrink-0 p-1 rounded text-slate-500 hover:text-slate-100 hover:bg-slate-700/60"><Pencil className="w-3.5 h-3.5" /></button>
        </div>

        {item.body && <p className="text-sm text-slate-400 mt-2 whitespace-pre-wrap line-clamp-5">{item.body}</p>}

        <div className="flex flex-wrap items-center gap-1.5 mt-2.5">
          <MetaChip icon={Smile} value={fm.mood} />
          <MetaChip icon={Compass} value={fm.theme} />
          {(fm.tags || []).map(t => <span key={t} className="px-1.5 py-0.5 text-[10px] rounded-full border border-slate-700 text-slate-400">#{t}</span>)}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- analysis
function AnalysisPanel({ items }: { items: JournalEntry[] }) {
  const stats = useMemo(() => {
    const tally = (get: (i: JournalEntry) => string | undefined) => {
      const o: Record<string, number> = {};
      for (const i of items) { const v = get(i); if (v) o[v] = (o[v] || 0) + 1; }
      return Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 6);
    };
    // entries within the last 7 days, by captured date
    const cutoff = new Date(); cutoff.setDate(cutoff.getDate() - 7);
    const thisWeek = items.filter(i => { const d = new Date(String(i.frontmatter.date || '') + 'T00:00:00'); return !isNaN(d.getTime()) && d >= cutoff; }).length;
    return {
      byKind: tally(i => i.frontmatter.kind),
      byMood: tally(i => i.frontmatter.mood),
      byTheme: tally(i => i.frontmatter.theme),
      thisWeek,
    };
  }, [items]);
  if (items.length === 0) return null;
  return (
    <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50 space-y-3">
      <h3 className="flex items-center gap-1.5 text-sm font-semibold text-slate-200"><BarChart3 className="w-4 h-4" /> Your mindspace</h3>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <TopList title="By kind" items={stats.byKind} />
        <TopList title="By mood" items={stats.byMood} />
        <TopList title="By theme" items={stats.byTheme} />
        <div>
          <div className="text-xs font-semibold text-slate-400 mb-1.5">Momentum</div>
          <div className="text-2xl font-bold text-slate-100">{stats.thisWeek}</div>
          <div className="text-xs text-slate-500">thoughts in the last 7 days</div>
          <div className="text-xs text-slate-600 mt-1">{items.length} total</div>
        </div>
      </div>
    </div>
  );
}
function TopList({ title, items }: { title: string; items: [string, number][] }) {
  return (
    <div>
      <div className="text-xs font-semibold text-slate-400 mb-1.5">{title}</div>
      {items.length === 0 ? <span className="text-xs text-slate-500 italic">—</span> : (
        <div className="space-y-1">
          {items.map(([label, n]) => (
            <div key={label} className="flex items-center gap-2 text-xs">
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
function ComboField({ label, value, onChange, suggestions, placeholder, listId, autoFocus }: {
  label: string; value: string; onChange: (v: string) => void; suggestions: string[]; placeholder?: string; listId: string; autoFocus?: boolean;
}) {
  return (
    <div>
      <label className="block text-xs text-slate-400 mb-1">{label}</label>
      <input autoFocus={autoFocus} value={value} onChange={e => onChange(e.target.value)} list={listId} className={field} placeholder={placeholder} />
      <datalist id={listId}>{suggestions.map(s => <option key={s} value={s} />)}</datalist>
    </div>
  );
}

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

interface Suggestions { kinds: string[]; moods: string[]; themes: string[]; tags: string[]; }

function JournalEditor({ filename, toast, suggestions, onClose, onSaved }: {
  filename?: string; toast: any; suggestions: Suggestions; onClose: () => void; onSaved: () => void;
}) {
  const isEdit = !!filename;
  const [title, setTitle] = useState('');
  const [kind, setKind] = useState('Reflection');
  const [mood, setMood] = useState('');
  const [theme, setTheme] = useState('');
  const [tags, setTags] = useState<string[]>([]);
  const [body, setBody] = useState('');
  const [date, setDate] = useState(today());
  const [time, setTime] = useState(nowTime());
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!filename) return;
    workmgrApi.getJournal(filename).then(l => {
      const fm = l.frontmatter;
      setTitle(fm.title || ''); setKind(fm.kind || 'Reflection');
      setMood(fm.mood || ''); setTheme(fm.theme || '');
      setTags(Array.isArray(fm.tags) ? fm.tags : []); setBody(l.body || '');
      setDate(String(fm.date || today())); setTime(String(fm.time || nowTime()));
    }).catch(e => toast.error(`Load failed: ${e.message}`));
  }, [filename, toast]);

  const canSave = !!(title.trim() || body.trim());

  const save = async () => {
    if (!canSave) { toast.error('Write a thought, or give it a short title'); return; }
    setSaving(true);
    const fm: JournalFm = {
      title: title.trim() || undefined, kind,
      mood: mood.trim() || undefined, theme: theme.trim() || undefined,
      tags, date, time,
    };
    try {
      if (isEdit) { await workmgrApi.patchJournal(filename!, { frontmatter: fm, body }); toast.success('Thought saved'); }
      else { await workmgrApi.createJournal({ frontmatter: fm, body }); toast.success('Thought captured'); }
      onSaved();
    } catch (e: any) { toast.error(`Save failed: ${e.message}`); } finally { setSaving(false); }
  };
  const remove = async () => {
    if (!filename || !confirm('Delete this thought?')) return;
    try { await workmgrApi.deleteJournal(filename); toast.success('Deleted'); onSaved(); } catch (e: any) { toast.error(`Delete failed: ${e.message}`); }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/70 flex items-start justify-center p-4 overflow-y-auto">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-lg shadow-2xl my-6">
        <div className="flex items-center justify-between p-4 border-b border-slate-800">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-100"><BookHeart className="w-5 h-5 text-blue-400" /> {isEdit ? 'Edit thought' : 'New thought'}</h2>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Headline <span className="text-slate-600">(optional — a line that names the thought)</span></label>
            <input autoFocus value={title} onChange={e => setTitle(e.target.value)} className={field} placeholder="e.g. What if onboarding started from the customer's first failure, not ours?" />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <ComboField label="Kind" value={kind} onChange={setKind} suggestions={suggestions.kinds} listId="jrn-kinds" placeholder="Idea / Reflection…" />
            <ComboField label="Mood" value={mood} onChange={setMood} suggestions={suggestions.moods} listId="jrn-moods" placeholder="Focused / Restless…" />
            <ComboField label="Theme" value={theme} onChange={setTheme} suggestions={suggestions.themes} listId="jrn-themes" placeholder="what it's about" />
            <div>
              <label className="block text-xs text-slate-400 mb-1">When</label>
              <div className="flex gap-1.5">
                <input type="date" value={date} onChange={e => setDate(e.target.value)} className={field} />
                <input type="time" value={time} onChange={e => setTime(e.target.value)} className={`${field} w-24`} />
              </div>
            </div>
          </div>

          <div>
            <label className="flex items-center gap-1 text-xs text-slate-400 mb-1"><Tag className="w-3 h-3" /> Tags</label>
            <ChipMulti value={tags} suggestions={suggestions.tags} onChange={setTags} placeholder="pick a tag or type + Enter" listId="jrn-tags" />
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">The thought <span className="text-slate-600">(let it be unfinished — write it as it comes)</span></label>
            <textarea value={body} onChange={e => setBody(e.target.value)} className={`${field} h-56 leading-relaxed`} placeholder="What's on your mind? The idea, the question, what you're noticing, how it feels…" />
          </div>

          <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
            {isEdit && <button onClick={remove} className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-red-400 hover:bg-red-500/10 rounded-md"><Trash2 className="w-4 h-4" /> Delete</button>}
            <div className="flex-1" />
            <button onClick={onClose} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
            <button onClick={save} disabled={saving || !canSave} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30 disabled:opacity-50">
              <Save className="w-4 h-4" /> {saving ? 'Saving…' : isEdit ? 'Save' : 'Capture thought'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
