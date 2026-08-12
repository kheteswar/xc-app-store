/**
 * Learnings — a personal knowledge base of things learned during work, so they
 * can be found and reused later. Every learning is tagged with Product, Feature,
 * Platform (Web/Mobile/…), Environment (SaaS/On-Prem/AWS/GCP/…), Topic, Sub-topic
 * and a Category (Product Knowledge / Process Learning / Troubleshooting / …).
 * Each tag field offers previously-used values as a dropdown while still allowing
 * any new custom value. Stored as markdown files in mywork/learnings/.
 */
import { useMemo, useState, useEffect } from 'react';
import {
  GraduationCap, Plus, Search, X, Save, Trash2, Pencil, BookOpen, Layers,
  Package, Monitor, Cloud, Tag, Calendar, Link as LinkIcon, BarChart3, Filter,
  ListChecks, Target, CheckCircle2, PlayCircle, Circle, ArrowRight, ArrowLeft,
  ExternalLink, CalendarClock, Flag, BookMarked,
} from 'lucide-react';
import {
  workmgrApi,
  type Learning, type LearningFm,
  type LearningTask, type LearningTaskFm, type LearningTaskStatus,
} from '../../services/work-mgr';
import { useAsync, fmtRel } from './shared';

const CATEGORIES: { key: string; color: string }[] = [
  { key: 'Product Knowledge', color: '#3b82f6' },
  { key: 'Process Learning', color: '#8b5cf6' },
  { key: 'Troubleshooting', color: '#ef4444' },
  { key: 'Configuration', color: '#14b8a6' },
  { key: 'Best Practice', color: '#22c55e' },
  { key: 'Gotcha / Pitfall', color: '#f59e0b' },
  { key: 'How-to', color: '#06b6d4' },
  { key: 'Concept', color: '#0ea5e9' },
  { key: 'Tooling', color: '#eab308' },
  { key: 'Other', color: '#94a3b8' },
];
const CAT_COLOR = (c?: string) => CATEGORIES.find(x => x.key === c)?.color || '#94a3b8';

// Seed suggestions — merged with previously-used values, all editable as custom text.
const PRODUCT_SEED = ['Distributed Cloud WAAP', 'Distributed Cloud WAF', 'Distributed Cloud DDoS', 'Distributed Cloud Bot Defense', 'Distributed Cloud API Security', 'Distributed Cloud MCN', 'Distributed Cloud CDN', 'Distributed Cloud DNS', 'Distributed Cloud App Stack', 'BIG-IP', 'BIG-IP Next', 'NGINX', 'F5 XC Platform'];
const PLATFORM_SEED = ['Web', 'Mobile', 'API', 'CLI', 'Console / UI', 'Terraform', 'Kubernetes', 'Desktop'];
const ENVIRONMENT_SEED = ['SaaS', 'On-Prem', 'AWS', 'GCP', 'Azure', 'Hybrid', 'Edge / CE', 'Private Cloud', 'Multi-Cloud'];

const today = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
const nowTime = () => { const d = new Date(); return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`; };
const field = 'w-full px-2.5 py-1.5 text-sm bg-slate-900 border border-slate-700 rounded-md text-slate-100 placeholder-slate-600 focus:border-blue-500 focus:outline-none';
const uniq = (arr: (string | undefined)[]) => [...new Set(arr.filter(Boolean) as string[])];

// =========================================================================
// Learning & Knowledge — hub with two views:
//   • Knowledge Base — things you've learned (the original Learnings feed)
//   • Learning Queue — things to learn, courses to do, topics to explore
// =========================================================================
type LrnView = 'knowledge' | 'queue';

export function LearningsTab({ toast }: { toast: any }) {
  const [view, setView] = useState<LrnView>('knowledge');
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold text-slate-100"><GraduationCap className="w-5 h-5 text-blue-400" /> Learning &amp; Knowledge</h1>
          <p className="text-xs text-slate-500 mt-0.5">Manage what you're learning and everything you've learned — a queue of things to explore, and a searchable knowledge base.</p>
        </div>
        <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-800/60 border border-slate-700/60">
          <SubTab active={view === 'knowledge'} onClick={() => setView('knowledge')} icon={BookMarked} label="Knowledge Base" />
          <SubTab active={view === 'queue'} onClick={() => setView('queue')} icon={ListChecks} label="Learning Queue" />
        </div>
      </div>
      {view === 'knowledge' ? <KnowledgeView toast={toast} /> : <LearningQueueView toast={toast} />}
    </div>
  );
}

function SubTab({ active, onClick, icon: Icon, label }: { active: boolean; onClick: () => void; icon: any; label: string }) {
  return (
    <button onClick={onClick} className={`flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-md transition-colors ${active ? 'bg-blue-500/20 text-blue-300' : 'text-slate-400 hover:text-slate-200'}`}>
      <Icon className="w-4 h-4" /> {label}
    </button>
  );
}

function KnowledgeView({ toast }: { toast: any }) {
  const { data, loading, reload } = useAsync<Learning[]>(() => workmgrApi.listLearnings(), []);
  const [category, setCategory] = useState('');
  const [product, setProduct] = useState('');
  const [platform, setPlatform] = useState('');
  const [environment, setEnvironment] = useState('');
  const [q, setQ] = useState('');
  const [editing, setEditing] = useState<{ filename?: string } | null>(null);

  const items = data || [];

  // suggestion pools = seeds ∪ past values
  const sugg = useMemo(() => ({
    products: uniq([...PRODUCT_SEED, ...items.map(i => i.frontmatter.product)]).sort(),
    features: uniq(items.map(i => i.frontmatter.feature)).sort(),
    platforms: uniq([...PLATFORM_SEED, ...items.map(i => i.frontmatter.platform)]).sort(),
    environments: uniq([...ENVIRONMENT_SEED, ...items.map(i => i.frontmatter.environment)]).sort(),
    topics: uniq(items.map(i => i.frontmatter.topic)).sort(),
    subtopics: uniq(items.map(i => i.frontmatter.subtopic)).sort(),
    sources: uniq(items.map(i => i.frontmatter.source)).sort(),
    categories: uniq([...CATEGORIES.map(c => c.key), ...items.map(i => i.frontmatter.category)]),
    tags: uniq(items.flatMap(i => i.frontmatter.tags || [])).sort(),
  }), [items]);

  const filtered = items.filter(i => {
    const fm = i.frontmatter;
    if (category && fm.category !== category) return false;
    if (product && fm.product !== product) return false;
    if (platform && fm.platform !== platform) return false;
    if (environment && fm.environment !== environment) return false;
    if (q) {
      const hay = `${fm.title} ${fm.product} ${fm.feature} ${fm.platform} ${fm.environment} ${fm.topic} ${fm.subtopic} ${fm.category} ${(fm.tags || []).join(' ')} ${i.body}`.toLowerCase();
      if (!hay.includes(q.toLowerCase())) return false;
    }
    return true;
  });

  const anyFilter = category || product || platform || environment || q;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-500">Note down what you learn as you work — tagged by product, platform, environment &amp; topic so you can find it again.</p>
        <button onClick={() => setEditing({})} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30">
          <Plus className="w-4 h-4" /> New learning
        </button>
      </div>

      <AnalysisPanel items={items} />

      {/* category chips */}
      <div className="flex flex-wrap gap-1.5">
        <button onClick={() => setCategory('')} className={`px-2.5 py-1 text-xs rounded-full border ${!category ? 'bg-slate-700 border-slate-500 text-slate-100' : 'border-slate-700 text-slate-400 hover:border-slate-500'}`}>All ({items.length})</button>
        {CATEGORIES.filter(c => items.some(i => i.frontmatter.category === c.key)).map(c => {
          const n = items.filter(i => i.frontmatter.category === c.key).length;
          return (
            <button key={c.key} onClick={() => setCategory(category === c.key ? '' : c.key)} className="px-2.5 py-1 text-xs rounded-full border"
              style={category === c.key ? { borderColor: c.color, color: c.color, background: c.color + '22' } : { borderColor: '#33415580', color: '#94a3b8' }}>
              {c.key} ({n})
            </button>
          );
        })}
      </div>

      {/* filter row */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-slate-800/40 border border-slate-700/60">
          <Search className="w-4 h-4 text-slate-500" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search learnings…" className="bg-transparent text-sm text-slate-100 focus:outline-none" />
        </div>
        <FilterSelect icon={Package} value={product} onChange={setProduct} options={sugg.products} allLabel="All products" />
        <FilterSelect icon={Monitor} value={platform} onChange={setPlatform} options={sugg.platforms} allLabel="All platforms" />
        <FilterSelect icon={Cloud} value={environment} onChange={setEnvironment} options={sugg.environments} allLabel="All environments" />
        {anyFilter && <button onClick={() => { setCategory(''); setProduct(''); setPlatform(''); setEnvironment(''); setQ(''); }} className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200"><Filter className="w-3.5 h-3.5" /> Clear</button>}
        <span className="text-xs text-slate-500 ml-auto">{filtered.length} learnings</span>
      </div>

      {loading && <div className="text-slate-400">Loading…</div>}
      {!loading && filtered.length === 0 && (
        <p className="text-sm text-slate-500 italic">
          {items.length === 0
            ? 'No learnings yet. Capture your first with “New learning” — e.g. a config gotcha, a troubleshooting trick, or how a feature really behaves.'
            : 'No learnings match these filters.'}
        </p>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {filtered.map(i => <LearningCard key={i.filename} item={i} onOpen={() => setEditing({ filename: i.filename })} />)}
      </div>

      {editing && (
        <LearningEditor
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

function LearningCard({ item, onOpen }: { item: Learning; onOpen: () => void }) {
  const fm = item.frontmatter;
  const color = CAT_COLOR(fm.category);
  return (
    <div className="flex rounded-lg bg-slate-800/40 border border-slate-700/60 hover:border-slate-600 transition-colors overflow-hidden">
      <div className="w-1 flex-shrink-0" style={{ background: color }} />
      <div className="flex-1 min-w-0 p-4">
        <div className="flex items-start gap-2">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <span className="px-2 py-0.5 text-[11px] rounded-full border font-medium" style={{ borderColor: color + '66', color, background: color + '14' }}>{fm.category || 'Learning'}</span>
              <span className="flex items-center gap-1 text-[11px] text-slate-500"><Calendar className="w-3 h-3" />{fm.date}{fm.time ? ` ${fm.time}` : ''} · {fmtRel(String(fm.date))}</span>
            </div>
            <h3 className="text-sm font-semibold text-slate-100 leading-snug">{fm.title}</h3>
          </div>
          <button onClick={onOpen} title="Edit" className="flex-shrink-0 p-1 rounded text-slate-500 hover:text-slate-100 hover:bg-slate-700/60"><Pencil className="w-3.5 h-3.5" /></button>
        </div>

        {item.body && <p className="text-sm text-slate-400 mt-2 whitespace-pre-wrap line-clamp-4">{item.body}</p>}

        <div className="flex flex-wrap gap-1.5 mt-2.5">
          <MetaChip icon={Package} value={fm.product} />
          <MetaChip icon={Layers} value={fm.feature} />
          <MetaChip icon={Monitor} value={fm.platform} />
          <MetaChip icon={Cloud} value={fm.environment} />
          <MetaChip icon={BookOpen} value={fm.topic} />
          {fm.subtopic && <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded-full bg-slate-700/40 border border-slate-600 text-slate-300">{fm.topic ? '› ' : ''}{fm.subtopic}</span>}
        </div>

        {(fm.tags && fm.tags.length > 0 || fm.source) && (
          <div className="flex flex-wrap items-center gap-1.5 mt-2">
            {fm.source && (/^https?:\/\//.test(fm.source)
              ? <a href={fm.source} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-[10px] text-blue-400 hover:underline"><LinkIcon className="w-2.5 h-2.5" /> source</a>
              : <span className="inline-flex items-center gap-1 text-[10px] text-slate-500"><LinkIcon className="w-2.5 h-2.5" />{fm.source}</span>)}
            {(fm.tags || []).map(t => <span key={t} className="px-1.5 py-0.5 text-[10px] rounded-full border border-slate-700 text-slate-400">#{t}</span>)}
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- analysis
function AnalysisPanel({ items }: { items: Learning[] }) {
  const stats = useMemo(() => {
    const tally = (get: (i: Learning) => string | undefined) => {
      const o: Record<string, number> = {};
      for (const i of items) { const v = get(i); if (v) o[v] = (o[v] || 0) + 1; }
      return Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 6);
    };
    return {
      byProduct: tally(i => i.frontmatter.product),
      byCategory: tally(i => i.frontmatter.category),
      byTopic: tally(i => i.frontmatter.topic),
      byEnv: tally(i => i.frontmatter.environment),
    };
  }, [items]);
  if (items.length === 0) return null;
  return (
    <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50 space-y-3">
      <h3 className="flex items-center gap-1.5 text-sm font-semibold text-slate-200"><BarChart3 className="w-4 h-4" /> At a glance</h3>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <TopList title="By product" items={stats.byProduct} />
        <TopList title="By category" items={stats.byCategory} />
        <TopList title="By topic" items={stats.byTopic} />
        <TopList title="By environment" items={stats.byEnv} />
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

interface Suggestions {
  products: string[]; features: string[]; platforms: string[]; environments: string[];
  topics: string[]; subtopics: string[]; sources: string[]; categories: string[]; tags: string[];
}

function LearningEditor({ filename, toast, suggestions, onClose, onSaved }: {
  filename?: string; toast: any; suggestions: Suggestions; onClose: () => void; onSaved: () => void;
}) {
  const isEdit = !!filename;
  const [title, setTitle] = useState('');
  const [category, setCategory] = useState('Product Knowledge');
  const [product, setProduct] = useState('');
  const [feature, setFeature] = useState('');
  const [platform, setPlatform] = useState('');
  const [environment, setEnvironment] = useState('');
  const [topic, setTopic] = useState('');
  const [subtopic, setSubtopic] = useState('');
  const [source, setSource] = useState('');
  const [tags, setTags] = useState<string[]>([]);
  const [body, setBody] = useState('');
  const [date, setDate] = useState(today());
  const [time, setTime] = useState(nowTime());
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!filename) return;
    workmgrApi.getLearning(filename).then(l => {
      const fm = l.frontmatter;
      setTitle(fm.title || ''); setCategory(fm.category || 'Product Knowledge');
      setProduct(fm.product || ''); setFeature(fm.feature || ''); setPlatform(fm.platform || '');
      setEnvironment(fm.environment || ''); setTopic(fm.topic || ''); setSubtopic(fm.subtopic || '');
      setSource(fm.source || ''); setTags(Array.isArray(fm.tags) ? fm.tags : []); setBody(l.body || '');
      setDate(String(fm.date || today())); setTime(String(fm.time || nowTime()));
    }).catch(e => toast.error(`Load failed: ${e.message}`));
  }, [filename, toast]);

  const save = async () => {
    if (!title.trim()) { toast.error('A title / what you learned is required'); return; }
    setSaving(true);
    const fm: LearningFm = {
      title: title.trim(), category,
      product: product.trim() || undefined, feature: feature.trim() || undefined,
      platform: platform.trim() || undefined, environment: environment.trim() || undefined,
      topic: topic.trim() || undefined, subtopic: subtopic.trim() || undefined,
      source: source.trim() || undefined, tags, date, time,
    };
    try {
      if (isEdit) { await workmgrApi.patchLearning(filename!, { frontmatter: fm, body }); toast.success('Learning saved'); }
      else { await workmgrApi.createLearning({ frontmatter: fm, body }); toast.success('Learning captured'); }
      onSaved();
    } catch (e: any) { toast.error(`Save failed: ${e.message}`); } finally { setSaving(false); }
  };
  const remove = async () => {
    if (!filename || !confirm('Delete this learning?')) return;
    try { await workmgrApi.deleteLearning(filename); toast.success('Deleted'); onSaved(); } catch (e: any) { toast.error(`Delete failed: ${e.message}`); }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/70 flex items-start justify-center p-4 overflow-y-auto">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-lg shadow-2xl my-6">
        <div className="flex items-center justify-between p-4 border-b border-slate-800">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-100"><GraduationCap className="w-5 h-5 text-blue-400" /> {isEdit ? 'Edit learning' : 'New learning'}</h2>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="block text-xs text-slate-400 mb-1">What did you learn? <span className="text-red-400">*</span></label>
            <input autoFocus value={title} onChange={e => setTitle(e.target.value)} className={field} placeholder="e.g. XC WAF exclusion rules apply before signature scoring, not after" />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <ComboField label="Category" value={category} onChange={setCategory} suggestions={suggestions.categories} listId="lrn-categories" placeholder="pick or type" />
            <ComboField label="Product" value={product} onChange={setProduct} suggestions={suggestions.products} listId="lrn-products" placeholder="e.g. Distributed Cloud WAF" />
            <ComboField label="Feature" value={feature} onChange={setFeature} suggestions={suggestions.features} listId="lrn-features" placeholder="e.g. Service Policy" />
            <ComboField label="Platform" value={platform} onChange={setPlatform} suggestions={suggestions.platforms} listId="lrn-platforms" placeholder="Web / Mobile / API…" />
            <ComboField label="Environment" value={environment} onChange={setEnvironment} suggestions={suggestions.environments} listId="lrn-environments" placeholder="SaaS / On-Prem / AWS…" />
            <ComboField label="Topic" value={topic} onChange={setTopic} suggestions={suggestions.topics} listId="lrn-topics" placeholder="e.g. Security" />
            <ComboField label="Sub-topic" value={subtopic} onChange={setSubtopic} suggestions={suggestions.subtopics} listId="lrn-subtopics" placeholder="e.g. Rate limiting" />
            <ComboField label="Source / reference" value={source} onChange={setSource} suggestions={suggestions.sources} listId="lrn-sources" placeholder="URL, doc, colleague…" />
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
            <ChipMulti value={tags} suggestions={suggestions.tags} onChange={setTags} placeholder="pick a tag or type + Enter" listId="lrn-tags" />
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Details / notes <span className="text-slate-600">(the actual learning — steps, context, why it matters)</span></label>
            <textarea value={body} onChange={e => setBody(e.target.value)} className={`${field} h-40 font-mono text-xs`} placeholder="Capture the detail you'll want when you hit this again. Commands, config snippets, links, the gotcha…" spellCheck={false} />
          </div>

          <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
            {isEdit && <button onClick={remove} className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-red-400 hover:bg-red-500/10 rounded-md"><Trash2 className="w-4 h-4" /> Delete</button>}
            <div className="flex-1" />
            <button onClick={onClose} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
            <button onClick={save} disabled={saving || !title.trim()} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30 disabled:opacity-50">
              <Save className="w-4 h-4" /> {saving ? 'Saving…' : isEdit ? 'Save' : 'Capture learning'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// =========================================================================
// LEARNING QUEUE — things to learn, courses to do, topics to explore.
// A three-lane board (To Learn → Learning → Learned). Finished items can be
// captured straight into the Knowledge Base above.
// =========================================================================

const LT_TYPES: { key: string; color: string }[] = [
  { key: 'Course', color: '#6366f1' },
  { key: 'Topic', color: '#06b6d4' },
  { key: 'Skill', color: '#22c55e' },
  { key: 'Certification', color: '#eab308' },
  { key: 'Book', color: '#f59e0b' },
  { key: 'Article', color: '#8b5cf6' },
  { key: 'Video', color: '#ec4899' },
  { key: 'Concept', color: '#0ea5e9' },
  { key: 'Documentation', color: '#14b8a6' },
  { key: 'Practice', color: '#94a3b8' },
];
const LT_TYPE_COLOR = (t?: string) => LT_TYPES.find(x => x.key === t)?.color || '#94a3b8';

const LT_STATUSES: { key: LearningTaskStatus; label: string; icon: any; color: string }[] = [
  { key: 'backlog', label: 'To Learn', icon: Circle, color: '#64748b' },
  { key: 'in_progress', label: 'Learning', icon: PlayCircle, color: '#3b82f6' },
  { key: 'done', label: 'Learned', icon: CheckCircle2, color: '#22c55e' },
];
const LT_STATUS_META = (s?: string) => LT_STATUSES.find(x => x.key === s) || LT_STATUSES[0];
const nextStatus = (s: LearningTaskStatus): LearningTaskStatus | null => s === 'backlog' ? 'in_progress' : s === 'in_progress' ? 'done' : null;
const prevStatus = (s: LearningTaskStatus): LearningTaskStatus | null => s === 'done' ? 'in_progress' : s === 'in_progress' ? 'backlog' : null;

const LT_PRIORITY_COLOR: Record<string, string> = {
  High: 'text-red-400 border-red-500/40 bg-red-500/10',
  Medium: 'text-amber-400 border-amber-500/40 bg-amber-500/10',
  Low: 'text-slate-400 border-slate-600 bg-slate-700/30',
};

const TYPE_SEED = LT_TYPES.map(t => t.key);
const PROVIDER_SEED = ['F5 University', 'Coursera', 'Udemy', 'Pluralsight', 'LinkedIn Learning', 'A Cloud Guru', 'YouTube', 'Documentation', 'Book', 'Internal / Colleague'];

const daysToTarget = (d?: string): number | null => {
  if (!d) return null;
  const t = new Date(d + 'T00:00:00'); if (isNaN(t.getTime())) return null;
  const today0 = new Date(); today0.setHours(0, 0, 0, 0);
  return Math.round((t.getTime() - today0.getTime()) / 86400000);
};

function LearningQueueView({ toast }: { toast: any }) {
  const { data, loading, reload } = useAsync<LearningTask[]>(() => workmgrApi.listLearningTasks(), []);
  const [q, setQ] = useState('');
  const [typeF, setTypeF] = useState('');
  const [priorityF, setPriorityF] = useState('');
  const [editing, setEditing] = useState<{ filename?: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const items = data || [];

  const sugg = useMemo(() => ({
    types: uniq([...TYPE_SEED, ...items.map(i => i.frontmatter.type)]),
    providers: uniq([...PROVIDER_SEED, ...items.map(i => i.frontmatter.provider)]).sort(),
    products: uniq([...PRODUCT_SEED, ...items.map(i => i.frontmatter.product)]).sort(),
    topics: uniq(items.map(i => i.frontmatter.topic)).sort(),
    tags: uniq(items.flatMap(i => i.frontmatter.tags || [])).sort(),
  }), [items]);

  const filtered = items.filter(i => {
    const fm = i.frontmatter;
    if (typeF && fm.type !== typeF) return false;
    if (priorityF && fm.priority !== priorityF) return false;
    if (q) {
      const hay = `${fm.title} ${fm.type} ${fm.product} ${fm.topic} ${fm.provider} ${(fm.tags || []).join(' ')} ${i.body}`.toLowerCase();
      if (!hay.includes(q.toLowerCase())) return false;
    }
    return true;
  });

  const PRIO_RANK: Record<string, number> = { High: 0, Medium: 1, Low: 2 };
  const laneItems = (s: LearningTaskStatus) => filtered
    .filter(i => (i.frontmatter.status || 'backlog') === s)
    .sort((a, b) => {
      const pr = (PRIO_RANK[a.frontmatter.priority || 'Medium'] ?? 1) - (PRIO_RANK[b.frontmatter.priority || 'Medium'] ?? 1);
      if (pr !== 0) return pr;
      const ta = a.frontmatter.target_date || '9999', tb = b.frontmatter.target_date || '9999';
      return ta.localeCompare(tb);
    });

  const move = async (t: LearningTask, to: LearningTaskStatus) => {
    setBusy(t.filename);
    try {
      const patch: LearningTaskFm = { status: to };
      if (to === 'done') patch.progress = 100;
      else if (to === 'in_progress' && !t.frontmatter.progress) patch.progress = 10;
      await workmgrApi.patchLearningTask(t.filename, { frontmatter: patch });
      reload();
    } catch (e: any) { toast.error(`Update failed: ${e.message}`); }
    finally { setBusy(null); }
  };

  const captureToKnowledge = async (t: LearningTask) => {
    if (!confirm(`Capture “${t.frontmatter.title}” into your Knowledge Base?`)) return;
    setBusy(t.filename);
    try {
      const fm = t.frontmatter;
      await workmgrApi.createLearning({
        frontmatter: {
          title: fm.title, category: 'Product Knowledge',
          product: fm.product || undefined, topic: fm.topic || undefined,
          source: fm.url || fm.provider || undefined, tags: fm.tags || [],
        },
        body: t.body || '',
      });
      toast.success('Captured into Knowledge Base — refine it in the Knowledge tab');
    } catch (e: any) { toast.error(`Capture failed: ${e.message}`); }
    finally { setBusy(null); }
  };

  const anyFilter = q || typeF || priorityF;
  const counts = {
    backlog: items.filter(i => (i.frontmatter.status || 'backlog') === 'backlog').length,
    in_progress: items.filter(i => i.frontmatter.status === 'in_progress').length,
    done: items.filter(i => i.frontmatter.status === 'done').length,
  };
  const overdue = items.filter(i => i.frontmatter.status !== 'done' && (daysToTarget(i.frontmatter.target_date) ?? 99) < 0).length;

  return (
    <div className="space-y-5">
      {/* action + summary bar */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <p className="text-xs text-slate-500">Everything you want to learn — courses, topics, skills. Move a card <span className="text-slate-300">To Learn → Learning → Learned</span>, then capture it into your Knowledge Base.</p>
        <button onClick={() => setEditing({})} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30">
          <Plus className="w-4 h-4" /> Add to learn
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatTile label="To Learn" value={counts.backlog} color="#64748b" icon={Circle} />
        <StatTile label="Learning" value={counts.in_progress} color="#3b82f6" icon={PlayCircle} />
        <StatTile label="Learned" value={counts.done} color="#22c55e" icon={CheckCircle2} />
        <StatTile label="Overdue" value={overdue} color="#ef4444" icon={CalendarClock} />
      </div>

      {/* filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-slate-800/40 border border-slate-700/60">
          <Search className="w-4 h-4 text-slate-500" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search the queue…" className="bg-transparent text-sm text-slate-100 focus:outline-none" />
        </div>
        <FilterSelect icon={Layers} value={typeF} onChange={setTypeF} options={sugg.types} allLabel="All types" />
        <FilterSelect icon={Flag} value={priorityF} onChange={setPriorityF} options={['High', 'Medium', 'Low']} allLabel="Any priority" />
        {anyFilter && <button onClick={() => { setQ(''); setTypeF(''); setPriorityF(''); }} className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200"><Filter className="w-3.5 h-3.5" /> Clear</button>}
        <span className="text-xs text-slate-500 ml-auto">{filtered.length} items</span>
      </div>

      {loading && <div className="text-slate-400">Loading…</div>}
      {!loading && items.length === 0 && (
        <p className="text-sm text-slate-500 italic">
          Nothing queued yet. Add your first with “Add to learn” — a course you want to take, a topic to explore, a skill to build.
        </p>
      )}

      {/* board */}
      {!loading && items.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {LT_STATUSES.map(st => {
            const rows = laneItems(st.key);
            return (
              <div key={st.key} className="p-3 rounded-lg bg-slate-800/20 border border-slate-700/50">
                <div className="flex items-center gap-2 mb-3">
                  <st.icon className="w-4 h-4" style={{ color: st.color }} />
                  <span className="text-sm font-semibold text-slate-200">{st.label}</span>
                  <span className="text-xs text-slate-500">{rows.length}</span>
                </div>
                <div className="space-y-2 max-h-[64vh] overflow-y-auto pr-1">
                  {rows.length === 0 && <p className="text-xs text-slate-600 italic px-1">Empty.</p>}
                  {rows.map(t => (
                    <LearningTaskCard
                      key={t.filename}
                      item={t}
                      busy={busy === t.filename}
                      onEdit={() => setEditing({ filename: t.filename })}
                      onMove={to => move(t, to)}
                      onCapture={() => captureToKnowledge(t)}
                    />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {editing && (
        <LearningTaskEditor
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

function StatTile({ label, value, color, icon: Icon }: { label: string; value: number; color: string; icon: any }) {
  return (
    <div className="p-3 rounded-lg bg-slate-800/40 border border-slate-700/50">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-slate-500">{label}</span>
        <Icon className="w-4 h-4" style={{ color }} />
      </div>
      <div className="mt-1 text-2xl font-bold text-slate-100">{value}</div>
    </div>
  );
}

function LearningTaskCard({ item, busy, onEdit, onMove, onCapture }: {
  item: LearningTask; busy: boolean; onEdit: () => void; onMove: (to: LearningTaskStatus) => void; onCapture: () => void;
}) {
  const fm = item.frontmatter;
  const status = (fm.status || 'backlog') as LearningTaskStatus;
  const typeColor = LT_TYPE_COLOR(fm.type);
  const prev = prevStatus(status), next = nextStatus(status);
  const dToTarget = daysToTarget(fm.target_date);
  const overdue = status !== 'done' && dToTarget !== null && dToTarget < 0;
  const progress = typeof fm.progress === 'number' ? Math.max(0, Math.min(100, fm.progress)) : undefined;

  return (
    <div className={`rounded-lg bg-slate-800/50 border border-slate-700/60 hover:border-slate-600 transition-colors p-3 ${busy ? 'opacity-60' : ''}`}>
      <div className="flex items-start gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5 flex-wrap mb-1">
            <span className="px-1.5 py-0.5 text-[10px] rounded-full border font-medium" style={{ borderColor: typeColor + '66', color: typeColor, background: typeColor + '14' }}>{fm.type || 'Topic'}</span>
            {fm.priority && <span className={`px-1.5 py-0.5 text-[10px] rounded-full border font-medium ${LT_PRIORITY_COLOR[fm.priority] || ''}`}>{fm.priority}</span>}
          </div>
          <h4 className="text-sm font-semibold text-slate-100 leading-snug">{fm.title}</h4>
        </div>
        <button onClick={onEdit} title="Edit" className="flex-shrink-0 p-1 rounded text-slate-500 hover:text-slate-100 hover:bg-slate-700/60"><Pencil className="w-3.5 h-3.5" /></button>
      </div>

      {item.body && <p className="text-xs text-slate-400 mt-1.5 whitespace-pre-wrap line-clamp-2">{item.body}</p>}

      {progress !== undefined && status !== 'backlog' && (
        <div className="mt-2 flex items-center gap-2">
          <div className="flex-1 h-1.5 rounded-full bg-slate-700 overflow-hidden">
            <div className="h-full rounded-full" style={{ width: `${progress}%`, background: status === 'done' ? '#22c55e' : '#3b82f6' }} />
          </div>
          <span className="text-[10px] text-slate-500 w-8 text-right">{progress}%</span>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-1.5 mt-2">
        {fm.product && <MetaChip icon={Package} value={fm.product} />}
        {fm.topic && <MetaChip icon={BookOpen} value={fm.topic} />}
        {fm.provider && <MetaChip icon={GraduationCap} value={fm.provider} />}
        {fm.target_date && (
          <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded-full border ${overdue ? 'text-red-400 border-red-500/40 bg-red-500/10' : 'text-slate-400 border-slate-600 bg-slate-700/30'}`}>
            <CalendarClock className="w-2.5 h-2.5" />{fm.target_date}{dToTarget !== null && status !== 'done' ? ` (${dToTarget >= 0 ? `${dToTarget}d` : `${Math.abs(dToTarget)}d late`})` : ''}
          </span>
        )}
        {fm.url && (
          <a href={fm.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded-full border border-blue-500/40 text-blue-400 hover:bg-blue-500/10"><ExternalLink className="w-2.5 h-2.5" /> open</a>
        )}
      </div>

      {(fm.tags && fm.tags.length > 0) && (
        <div className="flex flex-wrap gap-1 mt-1.5">{fm.tags.map(t => <span key={t} className="px-1.5 py-0.5 text-[10px] rounded-full border border-slate-700 text-slate-500">#{t}</span>)}</div>
      )}

      {/* actions */}
      <div className="flex items-center gap-1.5 mt-2.5 pt-2 border-t border-slate-700/50">
        {prev && (
          <button disabled={busy} onClick={() => onMove(prev)} title={`Move to ${LT_STATUS_META(prev).label}`} className="p-1 rounded text-slate-500 hover:text-slate-200 hover:bg-slate-700/60 disabled:opacity-40"><ArrowLeft className="w-3.5 h-3.5" /></button>
        )}
        {next && (
          <button disabled={busy} onClick={() => onMove(next)} className="flex items-center gap-1 px-2 py-1 text-[11px] font-medium rounded text-blue-300 bg-blue-500/15 border border-blue-500/30 hover:bg-blue-500/25 disabled:opacity-40">
            {LT_STATUS_META(next).label} <ArrowRight className="w-3 h-3" />
          </button>
        )}
        <div className="flex-1" />
        {status === 'done' && (
          <button disabled={busy} onClick={onCapture} title="Capture into your Knowledge Base" className="flex items-center gap-1 px-2 py-1 text-[11px] font-medium rounded text-emerald-300 bg-emerald-500/15 border border-emerald-500/30 hover:bg-emerald-500/25 disabled:opacity-40">
            <BookMarked className="w-3 h-3" /> To Knowledge
          </button>
        )}
      </div>
    </div>
  );
}

interface QueueSuggestions { types: string[]; providers: string[]; products: string[]; topics: string[]; tags: string[]; }

function LearningTaskEditor({ filename, toast, suggestions, onClose, onSaved }: {
  filename?: string; toast: any; suggestions: QueueSuggestions; onClose: () => void; onSaved: () => void;
}) {
  const isEdit = !!filename;
  const [title, setTitle] = useState('');
  const [type, setType] = useState('Topic');
  const [status, setStatus] = useState<LearningTaskStatus>('backlog');
  const [priority, setPriority] = useState<'High' | 'Medium' | 'Low'>('Medium');
  const [product, setProduct] = useState('');
  const [topic, setTopic] = useState('');
  const [provider, setProvider] = useState('');
  const [url, setUrl] = useState('');
  const [targetDate, setTargetDate] = useState('');
  const [progress, setProgress] = useState(0);
  const [tags, setTags] = useState<string[]>([]);
  const [body, setBody] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!filename) return;
    workmgrApi.getLearningTask(filename).then(l => {
      const fm = l.frontmatter;
      setTitle(fm.title || ''); setType(fm.type || 'Topic');
      setStatus((fm.status as LearningTaskStatus) || 'backlog');
      setPriority((fm.priority as any) || 'Medium');
      setProduct(fm.product || ''); setTopic(fm.topic || '');
      setProvider(fm.provider || ''); setUrl(fm.url || '');
      setTargetDate(fm.target_date || ''); setProgress(typeof fm.progress === 'number' ? fm.progress : 0);
      setTags(Array.isArray(fm.tags) ? fm.tags : []); setBody(l.body || '');
    }).catch(e => toast.error(`Load failed: ${e.message}`));
  }, [filename, toast]);

  const save = async () => {
    if (!title.trim()) { toast.error('What do you want to learn? A title is required'); return; }
    setSaving(true);
    const fm: LearningTaskFm = {
      title: title.trim(), type, status, priority,
      product: product.trim() || undefined, topic: topic.trim() || undefined,
      provider: provider.trim() || undefined, url: url.trim() || undefined,
      target_date: targetDate || undefined,
      progress: status === 'backlog' ? undefined : progress,
      tags,
    };
    try {
      if (isEdit) { await workmgrApi.patchLearningTask(filename!, { frontmatter: fm, body }); toast.success('Saved'); }
      else { await workmgrApi.createLearningTask({ frontmatter: fm, body }); toast.success('Added to your learning queue'); }
      onSaved();
    } catch (e: any) { toast.error(`Save failed: ${e.message}`); } finally { setSaving(false); }
  };
  const remove = async () => {
    if (!filename || !confirm('Remove this from your learning queue?')) return;
    try { await workmgrApi.deleteLearningTask(filename); toast.success('Removed'); onSaved(); } catch (e: any) { toast.error(`Delete failed: ${e.message}`); }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/70 flex items-start justify-center p-4 overflow-y-auto">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-lg shadow-2xl my-6">
        <div className="flex items-center justify-between p-4 border-b border-slate-800">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-100"><Target className="w-5 h-5 text-blue-400" /> {isEdit ? 'Edit learning item' : 'Add to learn'}</h2>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="block text-xs text-slate-400 mb-1">What do you want to learn? <span className="text-red-400">*</span></label>
            <input autoFocus value={title} onChange={e => setTitle(e.target.value)} className={field} placeholder="e.g. Deep-dive XC Bot Defense, or “Terraform Associate cert”" />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <ComboField label="Type" value={type} onChange={setType} suggestions={suggestions.types} listId="lt-types" placeholder="Course / Topic…" />
            <div>
              <label className="block text-xs text-slate-400 mb-1">Status</label>
              <select value={status} onChange={e => setStatus(e.target.value as LearningTaskStatus)} className={field}>
                {LT_STATUSES.map(s => <option key={s.key} value={s.key}>{s.label}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Priority</label>
              <select value={priority} onChange={e => setPriority(e.target.value as any)} className={field}>
                <option>High</option><option>Medium</option><option>Low</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Target date</label>
              <input type="date" value={targetDate} onChange={e => setTargetDate(e.target.value)} className={field} />
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <ComboField label="Product" value={product} onChange={setProduct} suggestions={suggestions.products} listId="lt-products" placeholder="e.g. Distributed Cloud WAF" />
            <ComboField label="Topic" value={topic} onChange={setTopic} suggestions={suggestions.topics} listId="lt-topics" placeholder="e.g. Security" />
            <ComboField label="Provider" value={provider} onChange={setProvider} suggestions={suggestions.providers} listId="lt-providers" placeholder="Coursera / F5 University…" />
          </div>

          <div>
            <label className="flex items-center gap-1 text-xs text-slate-400 mb-1"><LinkIcon className="w-3 h-3" /> Link / resource</label>
            <input value={url} onChange={e => setUrl(e.target.value)} className={field} placeholder="https://… (course, doc, video)" />
          </div>

          {status !== 'backlog' && (
            <div>
              <label className="block text-xs text-slate-400 mb-1">Progress — <span className="text-slate-300 font-medium">{progress}%</span></label>
              <input type="range" min={0} max={100} step={5} value={progress} onChange={e => setProgress(Number(e.target.value))} className="w-full accent-blue-500" />
            </div>
          )}

          <div>
            <label className="flex items-center gap-1 text-xs text-slate-400 mb-1"><Tag className="w-3 h-3" /> Tags</label>
            <ChipMulti value={tags} suggestions={suggestions.tags} onChange={setTags} placeholder="pick a tag or type + Enter" listId="lt-tags" />
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Notes <span className="text-slate-600">(why it matters, what to cover, resources)</span></label>
            <textarea value={body} onChange={e => setBody(e.target.value)} className={`${field} h-28`} placeholder="Outline what you want to get out of this, sub-topics to cover, links…" />
          </div>

          <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
            {isEdit && <button onClick={remove} className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-red-400 hover:bg-red-500/10 rounded-md"><Trash2 className="w-4 h-4" /> Delete</button>}
            <div className="flex-1" />
            <button onClick={onClose} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
            <button onClick={save} disabled={saving || !title.trim()} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30 disabled:opacity-50">
              <Save className="w-4 h-4" /> {saving ? 'Saving…' : isEdit ? 'Save' : 'Add to queue'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
