/**
 * RichTaskPanel — end-to-end task management: status/priority controls,
 * subtasks with progress, description (markdown), external links + file refs,
 * dependencies, activity history + comments, quick actions, and an advanced
 * raw editor. Backed by the same tasks/*.md files (frontmatter + body).
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { load as yamlLoad, dump as yamlDump } from 'js-yaml';
import {
  X, Save, Plus, Trash2, Link2, Paperclip, Calendar, Clock, Bell, User, Tag,
  GitBranch, CheckSquare, Square, ListChecks, Copy, Files, ChevronDown, ChevronRight,
  ExternalLink, MessageSquarePlus, History, Flag,
} from 'lucide-react';
import {
  workmgrApi, PRIORITY_COLORS, daysUntil,
  type TaskDetail, type TaskStatus, type TasksResponse, type Subtask, type TaskLink, type TaskFileRef,
} from '../../services/work-mgr';
import { fmtRel } from './shared';

const STATUSES: { key: TaskStatus; label: string; color: string }[] = [
  { key: 'open', label: 'Open', color: '#3b82f6' },
  { key: 'waiting', label: 'Waiting', color: '#a855f7' },
  { key: 'done', label: 'Done', color: '#22c55e' },
];
const PRIORITIES: ('P0' | 'P1' | 'P2' | 'P3')[] = ['P0', 'P1', 'P2', 'P3'];

function today() { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; }
// Date + wall-clock time for activity log lines, so same-day changes stay ordered.
function nowStamp() { const d = new Date(); const p = (n: number) => String(n).padStart(2, '0'); return `${today()} ${p(d.getHours())}:${p(d.getMinutes())}`; }

/** Split a task body into notes (everything except ## Log) + parsed log lines. */
function splitBody(body: string): { notes: string; log: string[] } {
  const re = /^##\s+Log\b[^\n]*\n/mi;
  const m = re.exec(body);
  if (!m) return { notes: body.trimEnd(), log: [] };
  const bodyStart = m.index + m[0].length;
  const after = body.slice(bodyStart);
  const nextH = after.search(/\n##\s/);
  const logRaw = nextH === -1 ? after : after.slice(0, nextH);
  const notes = (body.slice(0, m.index) + (nextH === -1 ? '' : after.slice(nextH))).trimEnd();
  const log = logRaw.split('\n').map(l => l.trim()).filter(l => l.startsWith('- '));
  return { notes, log };
}
function buildBody(notes: string, log: string[]): string {
  return `${notes.trimEnd()}\n\n## Log\n${log.join('\n')}\n`;
}
function parseLogLine(line: string): { date?: string; time?: string; text: string } {
  const m = /^-\s+(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}(?::\d{2})?))?\s+—\s+(.+)$/.exec(line);
  return m ? { date: m[1], time: m[2], text: m[3] } : { text: line.replace(/^-\s*/, '') };
}

export function RichTaskPanel({ initial, onClose, onSaved }: {
  initial: { status: TaskStatus; filename: string };
  onClose: () => void;
  onSaved: () => void;
}) {
  const [detail, setDetail] = useState<TaskDetail | null>(null);
  const [status, setStatus] = useState<TaskStatus>(initial.status);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [allTasks, setAllTasks] = useState<TasksResponse | null>(null);

  // editable fields
  const [title, setTitle] = useState('');
  const [customer, setCustomer] = useState('');
  const [priority, setPriority] = useState<'P0' | 'P1' | 'P2' | 'P3'>('P1');
  const [owner, setOwner] = useState('');
  const [estimate, setEstimate] = useState('');
  const [due, setDue] = useState('');
  const [start, setStart] = useState('');
  const [reminder, setReminder] = useState('');
  const [tags, setTags] = useState<string[]>([]);
  const [subtasks, setSubtasks] = useState<Subtask[]>([]);
  const [links, setLinks] = useState<TaskLink[]>([]);
  const [files, setFiles] = useState<TaskFileRef[]>([]);
  const [related, setRelated] = useState<string[]>([]);
  const [blocked, setBlocked] = useState<string[]>([]);
  const [notes, setNotes] = useState('');
  const [log, setLog] = useState<string[]>([]);

  // small inputs
  const [newSub, setNewSub] = useState('');
  const [editingSub, setEditingSub] = useState<number | null>(null);
  const [editSubText, setEditSubText] = useState('');
  const [newTag, setNewTag] = useState('');
  const [newLink, setNewLink] = useState({ label: '', url: '' });
  const [newFile, setNewFile] = useState({ label: '', path: '' });
  const [newDep, setNewDep] = useState('');
  const [comment, setComment] = useState('');
  const [previewNotes, setPreviewNotes] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  const [rawFm, setRawFm] = useState('');
  const [rawBody, setRawBody] = useState('');
  const [waitingPrompt, setWaitingPrompt] = useState(false);
  const [waitingOn, setWaitingOn] = useState('');

  const hydrate = useCallback((d: TaskDetail) => {
    setDetail(d); setStatus(d.status);
    const fm = d.frontmatter;
    setTitle(fm.title || ''); setCustomer(String(fm.customer || '')); setPriority((fm.priority as any) || 'P1');
    setOwner(String(fm.owner || '')); setEstimate(String(fm.estimate || ''));
    setDue(String(fm.due || '')); setStart(String(fm.start || '')); setReminder(String(fm.reminder || ''));
    setTags(Array.isArray(fm.tags) ? fm.tags.map(String) : []);
    setSubtasks(Array.isArray(fm.subtasks) ? fm.subtasks : []);
    setLinks(Array.isArray(fm.links) ? fm.links : []);
    setFiles(Array.isArray(fm.files) ? fm.files : (Array.isArray(fm.artifacts) ? fm.artifacts.map((p: string) => ({ path: p })) : []));
    setRelated(Array.isArray(fm.related_tasks) ? fm.related_tasks.map(String) : []);
    setBlocked(Array.isArray(fm.blocked_by) ? fm.blocked_by.map(String) : []);
    const { notes, log } = splitBody(d.body);
    setNotes(notes); setLog(log);
    setRawFm(yamlDump(fm, { lineWidth: 120 }).trimEnd()); setRawBody(d.body);
    setDirty(false);
  }, []);

  const reload = useCallback((st: TaskStatus, fn: string) => {
    setLoading(true);
    workmgrApi.getTask(st, fn).then(hydrate).finally(() => setLoading(false));
  }, [hydrate]);

  useEffect(() => { reload(initial.status, initial.filename); }, [reload, initial.status, initial.filename]);
  useEffect(() => { workmgrApi.listTasks().then(setAllTasks).catch(() => {}); }, []);

  const filename = initial.filename;
  const touch = () => setDirty(true);

  const collectFm = () => ({
    title, customer, priority, owner, estimate,
    due, start, reminder,
    tags, subtasks, links, files,
    related_tasks: related, blocked_by: blocked,
  });

  const save = useCallback(async (activity?: string) => {
    if (!detail) return;
    setSaving(true);
    try {
      const nextLog = activity ? [...log, `- ${nowStamp()} — ${activity}`] : log;
      const updated = await workmgrApi.updateTask(status, filename, {
        frontmatter: collectFm(),
        body: buildBody(notes, nextLog),
      });
      hydrate(updated);
      onSaved();
    } finally { setSaving(false); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail, status, filename, notes, log, title, customer, priority, owner, estimate, due, start, reminder, tags, subtasks, links, files, related, blocked, hydrate, onSaved]);

  const changeStatus = async (to: TaskStatus, wo?: string) => {
    if (to === status || !detail) return;
    setSaving(true);
    try {
      if (dirty) {
        await workmgrApi.updateTask(status, filename, { frontmatter: collectFm(), body: buildBody(notes, log) });
      }
      await workmgrApi.moveTask(status, filename, to, wo ? { waiting_on: wo } : {});
      const updated = await workmgrApi.getTask(to, filename);
      hydrate(updated);
      onSaved();
    } finally { setSaving(false); }
  };

  const onStatusClick = (to: TaskStatus) => {
    if (to === 'waiting') { setWaitingOn(''); setWaitingPrompt(true); }
    else changeStatus(to);
  };

  // subtasks
  const addSub = () => { if (!newSub.trim()) return; setSubtasks(s => [...s, { text: newSub.trim(), done: false }]); setNewSub(''); touch(); };
  const toggleSub = (i: number) => setSubtasks(s => s.map((x, j) => j === i ? { ...x, done: !x.done, done_at: !x.done ? today() : undefined } : x));
  const rmSub = (i: number) => { setSubtasks(s => s.filter((_, j) => j !== i)); setEditingSub(null); touch(); };
  const startEditSub = (i: number) => { setEditingSub(i); setEditSubText(subtasks[i].text); };
  const commitEditSub = () => {
    if (editingSub === null) return;
    const i = editingSub; const text = editSubText.trim();
    setEditingSub(null);
    if (text && text !== subtasks[i].text) { setSubtasks(s => s.map((x, j) => j === i ? { ...x, text } : x)); touch(); }
  };
  const progress = subtasks.length ? Math.round(100 * subtasks.filter(s => s.done).length / subtasks.length) : 0;

  const rawSave = async () => {
    setSaving(true);
    try {
      const fm = yamlLoad(rawFm) as any;
      const updated = await workmgrApi.updateTask(status, filename, { frontmatter: fm, body: rawBody });
      hydrate(updated); onSaved();
    } catch (e: any) { alert(`Invalid YAML/body: ${e.message}`); } finally { setSaving(false); }
  };

  const duplicate = async () => {
    if (!detail) return;
    const base = filename.replace(/\.md$/, '');
    const id = `${base}-copy`;
    await workmgrApi.createTask({
      id,
      frontmatter: { ...collectFm(), id, status: 'open', created: today(), completed: undefined } as any,
      body: buildBody(notes, [`- ${today()} — Duplicated from ${filename}`]),
      status: 'open',
    });
    onSaved();
    alert(`Created tasks/open/${id}.md`);
  };

  const taskIndex = useMemo(() => {
    const map: Record<string, { title: string; status: TaskStatus }> = {};
    if (allTasks) [...allTasks.open, ...allTasks.waiting, ...allTasks.done].forEach(t => {
      map[t.filename.replace(/\.md$/, '')] = { title: t.frontmatter.title || t.filename, status: t.status };
    });
    return map;
  }, [allTasks]);

  const field = 'w-full px-2.5 py-1.5 text-sm bg-slate-900 border border-slate-700 rounded-md text-slate-100 placeholder-slate-600 focus:border-blue-500 focus:outline-none';
  const chip = 'px-2 py-0.5 text-xs rounded-full border';

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/70 flex items-start justify-center p-4 overflow-y-auto">
      <div className="w-full max-w-5xl bg-slate-900 border border-slate-700 rounded-lg shadow-2xl my-6">
        {/* Header */}
        <div className="sticky top-0 z-10 bg-slate-900/95 backdrop-blur flex items-start gap-3 p-4 border-b border-slate-800 rounded-t-lg">
          <div className="flex-1 min-w-0">
            <input value={title} onChange={e => { setTitle(e.target.value); touch(); }}
              className="w-full bg-transparent text-lg font-semibold text-slate-100 focus:outline-none" placeholder="Task title" />
            <div className="text-[11px] text-slate-500 mt-0.5">tasks/{status}/{filename}</div>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <button onClick={() => save()} disabled={!dirty || saving} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30 disabled:opacity-40">
              <Save className="w-4 h-4" /> {saving ? 'Saving…' : dirty ? 'Save' : 'Saved'}
            </button>
            <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X className="w-5 h-5" /></button>
          </div>
        </div>

        {loading || !detail ? <div className="p-8 text-slate-400">Loading…</div> : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-0">
          {/* Main column */}
          <div className="lg:col-span-2 p-4 space-y-5 border-r border-slate-800">
            {/* Status + priority */}
            <div className="flex flex-wrap items-center gap-4">
              <div>
                <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Status</div>
                <div className="flex rounded-lg border border-slate-700 overflow-hidden">
                  {STATUSES.map(s => (
                    <button key={s.key} onClick={() => onStatusClick(s.key)}
                      className={`px-3 py-1.5 text-sm transition-colors ${status === s.key ? 'text-white' : 'text-slate-400 hover:text-slate-200'}`}
                      style={status === s.key ? { background: s.color + '33', color: s.color } : {}}>
                      {s.label}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Priority</div>
                <div className="flex rounded-lg border border-slate-700 overflow-hidden">
                  {PRIORITIES.map(p => (
                    <button key={p} onClick={() => { const old = priority; setPriority(p); touch(); if (old !== p) save(`Priority: ${old} → ${p}`); }}
                      className={`px-2.5 py-1.5 text-sm border-r border-slate-700 last:border-r-0 ${priority === p ? PRIORITY_COLORS[p] : 'text-slate-400 hover:text-slate-200'}`}>
                      {p}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Subtasks */}
            <section>
              <div className="flex items-center justify-between mb-2">
                <h3 className="flex items-center gap-1.5 text-sm font-semibold text-slate-200"><ListChecks className="w-4 h-4" /> Subtasks</h3>
                {subtasks.length > 0 && <span className="text-xs text-slate-500">{subtasks.filter(s => s.done).length}/{subtasks.length} · {progress}%</span>}
              </div>
              {subtasks.length > 0 && (
                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden mb-2"><div className="h-full bg-emerald-500 transition-all" style={{ width: `${progress}%` }} /></div>
              )}
              <div className="space-y-1">
                {subtasks.map((s, i) => (
                  <div key={i} className="flex items-center gap-2 group px-2 py-1 rounded hover:bg-slate-800/50">
                    <button onClick={() => { toggleSub(i); const willDone = !s.done; save(willDone ? `Subtask done: ${s.text}` : undefined); }} className="text-slate-400 hover:text-emerald-400">
                      {s.done ? <CheckSquare className="w-4 h-4 text-emerald-400" /> : <Square className="w-4 h-4" />}
                    </button>
                    {editingSub === i ? (
                      <input
                        autoFocus
                        value={editSubText}
                        onChange={e => setEditSubText(e.target.value)}
                        onBlur={commitEditSub}
                        onKeyDown={e => { if (e.key === 'Enter') commitEditSub(); else if (e.key === 'Escape') setEditingSub(null); }}
                        className="flex-1 px-1.5 py-0.5 text-sm bg-slate-900 border border-blue-500/60 rounded text-slate-100 focus:outline-none"
                      />
                    ) : (
                      <span
                        onClick={() => startEditSub(i)}
                        title="Click to edit"
                        className={`flex-1 text-sm cursor-text ${s.done ? 'line-through text-slate-500' : 'text-slate-200'}`}
                      >{s.text}</span>
                    )}
                    <button onClick={() => rmSub(i)} className="opacity-0 group-hover:opacity-100 text-slate-600 hover:text-red-400"><Trash2 className="w-3.5 h-3.5" /></button>
                  </div>
                ))}
              </div>
              <div className="flex gap-2 mt-2">
                <input value={newSub} onChange={e => setNewSub(e.target.value)} onKeyDown={e => e.key === 'Enter' && addSub()} placeholder="Add a subtask…" className={field} />
                <button onClick={addSub} className="px-2.5 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-300 hover:border-slate-500"><Plus className="w-4 h-4" /></button>
              </div>
            </section>

            {/* Description / notes */}
            <section>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-semibold text-slate-200">Details</h3>
                <button onClick={() => setPreviewNotes(p => !p)} className="text-xs text-slate-500 hover:text-slate-300">{previewNotes ? 'Edit' : 'Preview'}</button>
              </div>
              {previewNotes
                ? <pre className="text-sm text-slate-300 whitespace-pre-wrap font-sans p-3 rounded-lg bg-slate-800/40 border border-slate-700/50 min-h-[8rem]">{notes || '_No details._'}</pre>
                : <textarea value={notes} onChange={e => { setNotes(e.target.value); touch(); }} spellCheck={false} className={`${field} h-56 font-mono text-xs`} placeholder="## Context&#10;Why this task exists…&#10;&#10;## Definition of done&#10;- [ ] …&#10;&#10;## Next physical step&#10;…" />}
            </section>

            {/* Activity / history */}
            <section>
              <h3 className="flex items-center gap-1.5 text-sm font-semibold text-slate-200 mb-2"><History className="w-4 h-4" /> Activity &amp; history</h3>
              <div className="flex gap-2 mb-3">
                <input value={comment} onChange={e => setComment(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && comment.trim()) { save(comment.trim()); setComment(''); } }} placeholder="Add a comment / note…" className={field} />
                <button onClick={() => { if (comment.trim()) { save(comment.trim()); setComment(''); } }} className="px-2.5 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-300 hover:border-slate-500"><MessageSquarePlus className="w-4 h-4" /></button>
              </div>
              <div className="relative pl-4 space-y-2">
                <div className="absolute left-1.5 top-1 bottom-1 w-px bg-slate-800" />
                {log.length === 0 && <p className="text-xs text-slate-500 italic">No activity yet.</p>}
                {[...log].reverse().map((line, i) => {
                  const p = parseLogLine(line);
                  return (
                    <div key={i} className="relative">
                      <span className="absolute -left-[13px] top-1.5 w-2 h-2 rounded-full bg-slate-600" />
                      <div className="text-sm text-slate-300">{p.text}</div>
                      {p.date && <div className="text-[10px] text-slate-600">{p.date}{p.time ? ` ${p.time}` : ''} · {fmtRel(p.date)}</div>}
                    </div>
                  );
                })}
              </div>
            </section>
          </div>

          {/* Sidebar */}
          <div className="p-4 space-y-4 bg-slate-900/40">
            <SideField icon={User} label="Owner"><input value={owner} onChange={e => { setOwner(e.target.value); touch(); }} className={field} placeholder="KB" /></SideField>
            <div className="grid grid-cols-2 gap-2">
              <SideField icon={Calendar} label="Due"><input type="date" value={due} onChange={e => { setDue(e.target.value); touch(); }} className={field} /></SideField>
              <SideField icon={Clock} label="Start"><input type="date" value={start} onChange={e => { setStart(e.target.value); touch(); }} className={field} /></SideField>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <SideField icon={Bell} label="Follow-up"><input type="date" value={reminder} onChange={e => { setReminder(e.target.value); touch(); }} className={field} /></SideField>
              <SideField icon={Flag} label="Estimate"><input value={estimate} onChange={e => { setEstimate(e.target.value); touch(); }} className={field} placeholder="2h / 3d" /></SideField>
            </div>
            {due && <div className={`text-[11px] ${daysUntil(due) !== null && daysUntil(due)! < 0 ? 'text-red-400' : 'text-slate-500'}`}>Due {fmtRel(due)}</div>}
            <SideField icon={User} label="Customer"><input value={customer} onChange={e => { setCustomer(e.target.value); touch(); }} className={field} placeholder="SMBC / internal / career" /></SideField>

            {/* Tags */}
            <SideField icon={Tag} label="Tags">
              <div className="flex flex-wrap gap-1 mb-1">
                {tags.map((t, i) => <span key={i} className={`${chip} border-slate-600 text-slate-300 flex items-center gap-1`}>{t}<button onClick={() => { setTags(tags.filter((_, j) => j !== i)); touch(); }}><X className="w-3 h-3" /></button></span>)}
              </div>
              <input value={newTag} onChange={e => setNewTag(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && newTag.trim()) { setTags([...tags, newTag.trim()]); setNewTag(''); touch(); } }} className={field} placeholder="add tag + Enter" />
            </SideField>

            {/* Links */}
            <SideField icon={Link2} label="External links">
              <div className="space-y-1 mb-1">
                {links.map((l, i) => (
                  <div key={i} className="flex items-center gap-1.5 text-xs">
                    <a href={l.url} target="_blank" rel="noreferrer" className="flex-1 truncate text-blue-400 hover:underline flex items-center gap-1"><ExternalLink className="w-3 h-3" />{l.label || l.url}</a>
                    <button onClick={() => { setLinks(links.filter((_, j) => j !== i)); touch(); }} className="text-slate-600 hover:text-red-400"><Trash2 className="w-3 h-3" /></button>
                  </div>
                ))}
              </div>
              <div className="space-y-1">
                <input value={newLink.label} onChange={e => setNewLink({ ...newLink, label: e.target.value })} className={field} placeholder="label (Jira, Salesforce…)" />
                <div className="flex gap-1">
                  <input value={newLink.url} onChange={e => setNewLink({ ...newLink, url: e.target.value })} className={field} placeholder="https://…" />
                  <button onClick={() => { if (newLink.url.trim()) { setLinks([...links, { label: newLink.label.trim() || undefined, url: newLink.url.trim() }]); setNewLink({ label: '', url: '' }); touch(); } }} className="px-2 py-1.5 bg-slate-800 border border-slate-700 rounded-md text-slate-300 hover:border-slate-500"><Plus className="w-4 h-4" /></button>
                </div>
              </div>
            </SideField>

            {/* Files */}
            <SideField icon={Paperclip} label="Files">
              <div className="space-y-1 mb-1">
                {files.map((f, i) => (
                  <div key={i} className="flex items-center gap-1.5 text-xs">
                    <Files className="w-3 h-3 text-slate-500 flex-shrink-0" />
                    <button onClick={() => navigator.clipboard?.writeText(f.path)} title="Copy path" className="flex-1 truncate text-left text-slate-300 hover:text-slate-100">{f.label || f.path}</button>
                    <button onClick={() => { setFiles(files.filter((_, j) => j !== i)); touch(); }} className="text-slate-600 hover:text-red-400"><Trash2 className="w-3 h-3" /></button>
                  </div>
                ))}
              </div>
              <div className="flex gap-1">
                <input value={newFile.path} onChange={e => setNewFile({ ...newFile, path: e.target.value })} className={field} placeholder="Accounts/<C>/file.xlsx" />
                <button onClick={() => { if (newFile.path.trim()) { setFiles([...files, { path: newFile.path.trim() }]); setNewFile({ label: '', path: '' }); touch(); } }} className="px-2 py-1.5 bg-slate-800 border border-slate-700 rounded-md text-slate-300 hover:border-slate-500"><Plus className="w-4 h-4" /></button>
              </div>
            </SideField>

            {/* Dependencies */}
            <SideField icon={GitBranch} label="Blocked by / related">
              <div className="flex flex-wrap gap-1 mb-1">
                {[...blocked.map(b => ({ id: b, kind: 'blocked' })), ...related.map(r => ({ id: r, kind: 'related' }))].map((d, i) => {
                  const meta = taskIndex[d.id];
                  return (
                    <span key={i} className={`${chip} ${d.kind === 'blocked' ? 'border-red-500/40 text-red-300' : 'border-slate-600 text-slate-300'} flex items-center gap-1`} title={meta?.title}>
                      {meta ? meta.title.slice(0, 20) : d.id}
                      <button onClick={() => { if (d.kind === 'blocked') setBlocked(blocked.filter(x => x !== d.id)); else setRelated(related.filter(x => x !== d.id)); touch(); }}><X className="w-3 h-3" /></button>
                    </span>
                  );
                })}
              </div>
              <div className="flex gap-1">
                <input value={newDep} onChange={e => setNewDep(e.target.value)} list="task-ids" className={field} placeholder="task id" />
                <button onClick={() => { if (newDep.trim()) { setBlocked([...blocked, newDep.replace(/\.md$/, '').trim()]); setNewDep(''); touch(); } }} className="px-2 py-1.5 bg-slate-800 border border-slate-700 rounded-md text-slate-300 hover:border-slate-500" title="Add as blocker"><Plus className="w-4 h-4" /></button>
              </div>
              <datalist id="task-ids">{Object.keys(taskIndex).map(id => <option key={id} value={id}>{taskIndex[id].title}</option>)}</datalist>
            </SideField>

            {/* Quick actions + advanced */}
            <div className="pt-2 border-t border-slate-800 space-y-1">
              <button onClick={duplicate} className="flex items-center gap-2 w-full px-2 py-1.5 text-sm text-slate-400 hover:bg-slate-800/60 rounded"><Copy className="w-4 h-4" /> Duplicate task</button>
              <button onClick={() => navigator.clipboard?.writeText(`tasks/${status}/${filename}`)} className="flex items-center gap-2 w-full px-2 py-1.5 text-sm text-slate-400 hover:bg-slate-800/60 rounded"><Files className="w-4 h-4" /> Copy file path</button>
              <button onClick={() => setShowRaw(r => !r)} className="flex items-center gap-2 w-full px-2 py-1.5 text-sm text-slate-400 hover:bg-slate-800/60 rounded">{showRaw ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />} Advanced (raw)</button>
            </div>
            {showRaw && (
              <div className="space-y-2">
                <label className="text-[10px] uppercase tracking-wider text-slate-500">Frontmatter (YAML)</label>
                <textarea value={rawFm} onChange={e => setRawFm(e.target.value)} spellCheck={false} className={`${field} h-40 font-mono text-[11px]`} />
                <label className="text-[10px] uppercase tracking-wider text-slate-500">Body</label>
                <textarea value={rawBody} onChange={e => setRawBody(e.target.value)} spellCheck={false} className={`${field} h-40 font-mono text-[11px]`} />
                <button onClick={rawSave} className="px-3 py-1.5 text-sm bg-amber-500/20 border border-amber-500/40 text-amber-300 rounded-md hover:bg-amber-500/30">Save raw (overwrites)</button>
              </div>
            )}
          </div>
        </div>
        )}
      </div>

      {waitingPrompt && (
        <div className="fixed inset-0 z-[60] bg-slate-950/70 flex items-center justify-center p-4" onClick={() => setWaitingPrompt(false)}>
          <div className="w-full max-w-md bg-slate-900 border border-slate-700 rounded-lg p-4" onClick={e => e.stopPropagation()}>
            <h3 className="text-sm font-semibold text-slate-100 mb-2">Move to Waiting — what's it waiting on?</h3>
            <input autoFocus value={waitingOn} onChange={e => setWaitingOn(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && waitingOn.trim()) { setWaitingPrompt(false); changeStatus('waiting', waitingOn.trim()); } }} className={field} placeholder='e.g. "Customer to schedule session"' />
            <div className="flex justify-end gap-2 mt-3">
              <button onClick={() => setWaitingPrompt(false)} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
              <button onClick={() => { setWaitingPrompt(false); changeStatus('waiting', waitingOn.trim()); }} disabled={!waitingOn.trim()} className="px-3 py-1.5 text-sm bg-purple-500/20 border border-purple-500/40 text-purple-300 rounded-md disabled:opacity-40">Move to Waiting</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SideField({ icon: Icon, label, children }: { icon: any; label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-slate-500 mb-1"><Icon className="w-3 h-3" /> {label}</div>
      {children}
    </div>
  );
}
