/**
 * Updates — a categorized feed of team / manager / company / product updates.
 * Each is a markdown file in mywork/updates/ with rich frontmatter (type, date,
 * account, source, tags, links, files). Surfaces in the global + account timelines.
 */
import { useMemo, useState, useEffect } from 'react';
import {
  Megaphone, Plus, Search, X, Save, Trash2, Link2, Paperclip, ExternalLink,
  Calendar, Tag, User, Files, Star, Pencil, Copy,
} from 'lucide-react';
import {
  workmgrApi, type UpdatePost, type UpdatePostFm, type TaskLink, type TaskFileRef,
} from '../../services/work-mgr';
import { useAsync, useAccounts, fmtRel } from './shared';

export const UPDATE_TYPES: { key: string; color: string }[] = [
  { key: 'Team Update', color: '#3b82f6' },
  { key: 'Manager Update', color: '#8b5cf6' },
  { key: 'Company Update', color: '#ec4899' },
  { key: 'Product Update', color: '#22c55e' },
  { key: 'Customer / Account Update', color: '#f59e0b' },
  { key: 'Process / Ops', color: '#14b8a6' },
  { key: 'Learning / Enablement', color: '#06b6d4' },
  { key: 'Recognition / Kudos', color: '#eab308' },
  { key: 'Industry / Competitive', color: '#ef4444' },
  { key: 'Personal', color: '#64748b' },
  { key: 'Other', color: '#94a3b8' },
];
const TYPE_COLOR = (t?: string) => UPDATE_TYPES.find(x => x.key === t)?.color || '#94a3b8';
const IMPORTANCE = ['low', 'normal', 'high'];
const today = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
const field = 'w-full px-2.5 py-1.5 text-sm bg-slate-900 border border-slate-700 rounded-md text-slate-100 placeholder-slate-600 focus:border-blue-500 focus:outline-none';

export function UpdatesTab({ toast, onOpenAccount }: { toast: any; onOpenAccount?: (n: string) => void }) {
  const { data, loading, reload } = useAsync<UpdatePost[]>(() => workmgrApi.listUpdatePosts(), []);
  const [type, setType] = useState('');
  const [account, setAccount] = useState('');
  const [q, setQ] = useState('');
  const [editing, setEditing] = useState<{ filename?: string } | null>(null);

  const posts = data || [];
  const accounts = useMemo(() => [...new Set(posts.map(p => p.frontmatter.account).filter(Boolean) as string[])].sort(), [posts]);
  const sources = useMemo(() => [...new Set(posts.map(p => p.frontmatter.source).filter(Boolean) as string[])].sort(), [posts]);
  const allTags = useMemo(() => [...new Set(posts.flatMap(p => p.frontmatter.tags || []))].sort(), [posts]);
  const filtered = posts.filter(p => {
    const fm = p.frontmatter;
    if (type && fm.type !== type) return false;
    if (account && fm.account !== account) return false;
    if (q && !`${fm.title} ${fm.source} ${fm.type} ${(fm.tags || []).join(' ')} ${p.body_preview}`.toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  });
  const countsByType = useMemo(() => {
    const m: Record<string, number> = {};
    posts.forEach(p => { const t = p.frontmatter.type || 'Other'; m[t] = (m[t] || 0) + 1; });
    return m;
  }, [posts]);

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-lg font-semibold text-slate-100"><Megaphone className="w-5 h-5 text-blue-400" /> Updates</h1>
        <button onClick={() => setEditing({})} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30">
          <Plus className="w-4 h-4" /> New update
        </button>
      </div>

      {/* Type quick-filter chips */}
      <div className="flex flex-wrap gap-1.5">
        <button onClick={() => setType('')} className={`px-2.5 py-1 text-xs rounded-full border ${!type ? 'bg-slate-700 border-slate-500 text-slate-100' : 'border-slate-700 text-slate-400 hover:border-slate-500'}`}>All ({posts.length})</button>
        {UPDATE_TYPES.filter(t => countsByType[t.key]).map(t => (
          <button key={t.key} onClick={() => setType(type === t.key ? '' : t.key)}
            className={`px-2.5 py-1 text-xs rounded-full border`}
            style={type === t.key ? { borderColor: t.color, color: t.color, background: t.color + '22' } : { borderColor: '#33415580', color: '#94a3b8' }}>
            {t.key} ({countsByType[t.key]})
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-slate-800/40 border border-slate-700/60">
          <Search className="w-4 h-4 text-slate-500" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search updates…" className="bg-transparent text-sm text-slate-100 focus:outline-none" />
        </div>
        <select value={account} onChange={e => setAccount(e.target.value)} className={`${field} w-auto`}>
          <option value="">All accounts</option>
          {accounts.map(a => <option key={a} value={a}>{a}</option>)}
        </select>
        <span className="text-xs text-slate-500 ml-auto">{filtered.length} updates</span>
      </div>

      {loading && <div className="text-slate-400">Loading…</div>}
      {!loading && filtered.length === 0 && <p className="text-sm text-slate-500 italic">No updates yet. Capture a team / manager / company / product update with “New update”.</p>}

      <div className="space-y-3">
        {filtered.map(p => (
          <UpdateCard key={p.filename} post={p} onOpen={() => setEditing({ filename: p.filename })} onOpenAccount={onOpenAccount} />
        ))}
      </div>

      {editing && (
        <UpdateEditor
          filename={editing.filename}
          accounts={accounts}
          sources={sources}
          tagSuggestions={allTags}
          toast={toast}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); reload(); }}
        />
      )}
    </div>
  );
}

function UpdateCard({ post, onOpen, onOpenAccount }: { post: UpdatePost; onOpen: () => void; onOpenAccount?: (n: string) => void }) {
  const fm = post.frontmatter;
  const color = TYPE_COLOR(fm.type);
  const body = (post.body ?? post.body_preview ?? '').trim();
  const links = fm.links || [];
  const files = fm.files || [];
  const tags = fm.tags || [];
  return (
    <div className="flex rounded-lg bg-slate-800/40 border border-slate-700/60 hover:border-slate-600 transition-colors overflow-hidden">
      {/* color accent bar */}
      <div className="w-1 flex-shrink-0" style={{ background: color }} />
      <div className="flex-1 min-w-0 p-4">
        {/* header */}
        <div className="flex items-start gap-2">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="px-2 py-0.5 text-[11px] rounded-full border font-medium" style={{ borderColor: color + '66', color, background: color + '14' }}>{fm.type || 'Update'}</span>
              {fm.importance === 'high' && <span className="flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded-full bg-amber-500/15 border border-amber-500/40 text-amber-300"><Star className="w-3 h-3 fill-amber-400" /> high</span>}
              {fm.account && <button onClick={() => onOpenAccount?.(fm.account!)} className="text-[11px] px-2 py-0.5 rounded-full border border-slate-600 text-slate-300 hover:border-slate-400">{fm.account}</button>}
            </div>
            <h3 className="text-base font-semibold text-slate-100 mt-2 leading-snug">{fm.title || post.filename}</h3>
            <div className="flex items-center gap-3 mt-1 text-xs text-slate-500 flex-wrap">
              <span className="flex items-center gap-1"><Calendar className="w-3 h-3" />{fm.date}{fm.time ? ` ${fm.time}` : ''} · {fmtRel(String(fm.date))}</span>
              {fm.source && <span className="flex items-center gap-1"><User className="w-3 h-3" />{fm.source}</span>}
            </div>
          </div>
          <button onClick={onOpen} title="Edit update" className="flex-shrink-0 p-1.5 rounded-md text-slate-500 hover:text-slate-100 hover:bg-slate-700/60"><Pencil className="w-4 h-4" /></button>
        </div>

        {/* full details */}
        {body && <div className="text-sm text-slate-300 mt-3 whitespace-pre-wrap leading-relaxed">{body}</div>}

        {/* tags */}
        {tags.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mt-3">
            {tags.map(t => <span key={t} className="px-2 py-0.5 text-[10px] rounded-full border border-slate-700 text-slate-400"><Tag className="inline w-2.5 h-2.5 mr-0.5 -mt-0.5" />{t}</span>)}
          </div>
        )}

        {/* links + files */}
        {(links.length > 0 || files.length > 0) && (
          <div className="flex flex-wrap gap-2 mt-3 pt-3 border-t border-slate-700/50">
            {links.map((l, i) => (
              <a key={i} href={l.url} target="_blank" rel="noreferrer" className="flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-md bg-blue-500/10 border border-blue-500/30 text-blue-300 hover:bg-blue-500/20 max-w-xs">
                <Link2 className="w-3.5 h-3.5 flex-shrink-0" /><span className="truncate">{l.label || l.url}</span><ExternalLink className="w-3 h-3 flex-shrink-0 opacity-60" />
              </a>
            ))}
            {files.map((f, i) => (
              <button key={i} onClick={() => navigator.clipboard?.writeText(f.path)} title={`Copy path: ${f.path}`} className="flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-md bg-slate-700/40 border border-slate-600 text-slate-300 hover:bg-slate-700 max-w-xs">
                <Files className="w-3.5 h-3.5 flex-shrink-0" /><span className="truncate">{f.label || f.path.split('/').pop()}</span><Copy className="w-3 h-3 flex-shrink-0 opacity-60" />
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function UpdateEditor({ filename, accounts, sources, tagSuggestions, toast, onClose, onSaved }: {
  filename?: string; accounts: string[]; sources: string[]; tagSuggestions: string[]; toast: any; onClose: () => void; onSaved: () => void;
}) {
  const isEdit = !!filename;
  const { data: accountList } = useAccounts();
  const allAccounts = useMemo(() => [...new Set([...(accountList || []).map(a => a.name), ...accounts])].sort(), [accountList, accounts]);

  const [type, setType] = useState('Team Update');
  const [title, setTitle] = useState('');
  const [date, setDate] = useState(today());
  const [account, setAccount] = useState('');
  const [source, setSource] = useState('');
  const [importance, setImportance] = useState('normal');
  const [tags, setTags] = useState<string[]>([]);
  const [links, setLinks] = useState<TaskLink[]>([]);
  const [files, setFiles] = useState<TaskFileRef[]>([]);
  const [body, setBody] = useState('');
  const [saving, setSaving] = useState(false);
  const [newTag, setNewTag] = useState('');
  const [newLink, setNewLink] = useState({ label: '', url: '' });
  const [newFile, setNewFile] = useState({ label: '', path: '' });

  useEffect(() => {
    if (!filename) return;
    workmgrApi.getUpdatePost(filename).then(p => {
      const fm = p.frontmatter;
      setType(fm.type || 'Team Update'); setTitle(fm.title || ''); setDate(String(fm.date || today()));
      setAccount(String(fm.account || '')); setSource(String(fm.source || '')); setImportance(String(fm.importance || 'normal'));
      setTags(Array.isArray(fm.tags) ? fm.tags : []); setLinks(Array.isArray(fm.links) ? fm.links : []); setFiles(Array.isArray(fm.files) ? fm.files : []);
      setBody(p.body || '');
    }).catch(e => toast.error(`Load failed: ${e.message}`));
  }, [filename, toast]);

  const save = async () => {
    if (!title.trim()) { toast.error('Title is required'); return; }
    setSaving(true);
    const fm: UpdatePostFm = { type, title: title.trim(), date, account: account.trim() || undefined, source: source.trim() || undefined, importance, tags, links, files };
    try {
      if (isEdit) { await workmgrApi.patchUpdatePost(filename!, { frontmatter: fm, body }); toast.success('Update saved'); }
      else { await workmgrApi.createUpdatePost({ frontmatter: fm, body }); toast.success('Update created'); }
      onSaved();
    } catch (e: any) { toast.error(`Save failed: ${e.message}`); } finally { setSaving(false); }
  };
  const remove = async () => {
    if (!filename || !confirm('Delete this update?')) return;
    try { await workmgrApi.deleteUpdatePost(filename); toast.success('Deleted'); onSaved(); } catch (e: any) { toast.error(`Delete failed: ${e.message}`); }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/70 flex items-start justify-center p-4 overflow-y-auto">
      <div className="w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-lg shadow-2xl my-6">
        <div className="flex items-center justify-between p-4 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-slate-100">{isEdit ? 'Edit update' : 'New update'}</h2>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Type</label>
              <select value={type} onChange={e => setType(e.target.value)} className={field}>
                {UPDATE_TYPES.map(t => <option key={t.key} value={t.key}>{t.key}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Date</label>
              <input type="date" value={date} onChange={e => setDate(e.target.value)} className={field} />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Importance</label>
              <select value={importance} onChange={e => setImportance(e.target.value)} className={field}>
                {IMPORTANCE.map(i => <option key={i} value={i}>{i}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Title</label>
            <input autoFocus value={title} onChange={e => setTitle(e.target.value)} className={field} placeholder="e.g. Q3 XC roadmap shared at product all-hands" />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Account / customer (optional)</label>
              <input value={account} onChange={e => setAccount(e.target.value)} list="upd-accounts" className={field} placeholder="link to an account" />
              <datalist id="upd-accounts">{allAccounts.map(a => <option key={a} value={a} />)}</datalist>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Source (who / where)</label>
              <input value={source} onChange={e => setSource(e.target.value)} list="upd-sources" className={field} placeholder="pick a past source or type a new one" />
              <datalist id="upd-sources">{sources.map(s => <option key={s} value={s} />)}</datalist>
            </div>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Details</label>
            <textarea value={body} onChange={e => setBody(e.target.value)} className={`${field} h-40 font-mono text-xs`} placeholder="What's the update? Context, decisions, action items…" spellCheck={false} />
          </div>

          {/* Tags */}
          <div>
            <label className="block text-xs text-slate-400 mb-1">Tags</label>
            <div className="flex flex-wrap gap-1 mb-1">
              {tags.map((t, i) => <span key={i} className="px-2 py-0.5 text-xs rounded-full border border-slate-600 text-slate-300 flex items-center gap-1">{t}<button onClick={() => setTags(tags.filter((_, j) => j !== i))}><X className="w-3 h-3" /></button></span>)}
            </div>
            <input value={newTag} onChange={e => setNewTag(e.target.value)} list="upd-tags" onKeyDown={e => { if (e.key === 'Enter' && newTag.trim()) { const v = newTag.trim(); if (!tags.includes(v)) setTags([...tags, v]); setNewTag(''); } }} className={field} placeholder="pick a past tag or type a new one + Enter" />
            <datalist id="upd-tags">{tagSuggestions.filter(t => !tags.includes(t)).map(t => <option key={t} value={t} />)}</datalist>
          </div>

          {/* Links */}
          <div>
            <label className="block text-xs text-slate-400 mb-1 flex items-center gap-1"><Link2 className="w-3.5 h-3.5" /> URLs</label>
            <div className="space-y-1 mb-1">
              {links.map((l, i) => (
                <div key={i} className="flex items-center gap-1.5 text-xs">
                  <a href={l.url} target="_blank" rel="noreferrer" className="flex-1 truncate text-blue-400 hover:underline">{l.label || l.url}</a>
                  <button onClick={() => setLinks(links.filter((_, j) => j !== i))} className="text-slate-600 hover:text-red-400"><Trash2 className="w-3 h-3" /></button>
                </div>
              ))}
            </div>
            <div className="flex gap-1">
              <input value={newLink.label} onChange={e => setNewLink({ ...newLink, label: e.target.value })} className={`${field} w-40`} placeholder="label" />
              <input value={newLink.url} onChange={e => setNewLink({ ...newLink, url: e.target.value })} className={field} placeholder="https://…" />
              <button onClick={() => { if (newLink.url.trim()) { setLinks([...links, { label: newLink.label.trim() || undefined, url: newLink.url.trim() }]); setNewLink({ label: '', url: '' }); } }} className="px-2 py-1.5 bg-slate-800 border border-slate-700 rounded-md text-slate-300 hover:border-slate-500"><Plus className="w-4 h-4" /></button>
            </div>
          </div>

          {/* Files */}
          <div>
            <label className="block text-xs text-slate-400 mb-1 flex items-center gap-1"><Paperclip className="w-3.5 h-3.5" /> Files</label>
            <div className="space-y-1 mb-1">
              {files.map((f, i) => (
                <div key={i} className="flex items-center gap-1.5 text-xs">
                  <Files className="w-3 h-3 text-slate-500" />
                  <button onClick={() => navigator.clipboard?.writeText(f.path)} title="Copy path" className="flex-1 truncate text-left text-slate-300 hover:text-slate-100">{f.label || f.path}</button>
                  <button onClick={() => setFiles(files.filter((_, j) => j !== i))} className="text-slate-600 hover:text-red-400"><Trash2 className="w-3 h-3" /></button>
                </div>
              ))}
            </div>
            <div className="flex gap-1">
              <input value={newFile.label} onChange={e => setNewFile({ ...newFile, label: e.target.value })} className={`${field} w-40`} placeholder="label" />
              <input value={newFile.path} onChange={e => setNewFile({ ...newFile, path: e.target.value })} className={field} placeholder="Accounts/<C>/deck.pptx or absolute path" />
              <button onClick={() => { if (newFile.path.trim()) { setFiles([...files, { label: newFile.label.trim() || undefined, path: newFile.path.trim() }]); setNewFile({ label: '', path: '' }); } }} className="px-2 py-1.5 bg-slate-800 border border-slate-700 rounded-md text-slate-300 hover:border-slate-500"><Plus className="w-4 h-4" /></button>
            </div>
          </div>

          <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
            {isEdit && <button onClick={remove} className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-red-400 hover:bg-red-500/10 rounded-md"><Trash2 className="w-4 h-4" /> Delete</button>}
            <div className="flex-1" />
            <button onClick={onClose} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
            <button onClick={save} disabled={saving || !title.trim()} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30 disabled:opacity-50">
              <Save className="w-4 h-4" /> {saving ? 'Saving…' : isEdit ? 'Save' : 'Create update'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
