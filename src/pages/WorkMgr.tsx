import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Briefcase, LayoutDashboard, Kanban, Building2, Trophy, Search,
  Plus, RefreshCw, ChevronRight, AlertTriangle, Clock, Users, Award,
  Calendar, ArrowRight, X, FileText, Save, ExternalLink, ArrowRightCircle,
  Folder, Sparkles, CalendarDays, ClipboardCheck, Download, CheckSquare, Square,
  GitCommitHorizontal, Star, Megaphone, Workflow, GraduationCap, BookHeart,
} from 'lucide-react';
import { useToast } from '../context/ToastContext';
import {
  workmgrApi, PRIORITY_COLORS, STATUS_COLORS, daysUntil,
  type TaskListItem, type TaskDetail, type TaskStatus, type TasksResponse,
  type AccountSummary, type AccountDetail, type WinsResponse, type SummaryResponse,
  type SearchHit, type OneOnOneSummary, type TimelineItem, type WeeklyReview,
} from '../services/work-mgr';
import {
  usePins, PinStar, withPinnedFirst, accountProductDefs, ProductChips, fmtRel,
  ProductConfigPanel, CustomerDetailsPanel, PRODUCTS,
} from './workmgr/shared';
import { GlobalTimeline } from './workmgr/GlobalTimeline';
import { RichTaskPanel } from './workmgr/TaskPanel';
import { UpdatesTab } from './workmgr/Updates';
import { WorkPatternsTab } from './workmgr/Patterns';
import { LearningsTab } from './workmgr/Learnings';
import { JournalTab } from './workmgr/Journal';
import { STATUS_DOT } from '../services/work-mgr/catalog';

type Tab = 'dashboard' | 'tasks' | 'accounts' | 'timeline' | 'updates' | 'patterns' | 'learnings' | 'journal' | 'career' | 'quickadd' | 'search' | 'review';

const NAV: { key: Tab; label: string; icon: any }[] = [
  { key: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { key: 'accounts', label: 'Accounts', icon: Building2 },
  { key: 'timeline', label: 'Global Timeline', icon: GitCommitHorizontal },
  { key: 'updates', label: 'Updates', icon: Megaphone },
  { key: 'patterns', label: 'Work Patterns', icon: Workflow },
  { key: 'learnings', label: 'Learnings', icon: GraduationCap },
  { key: 'journal', label: 'Thought Journal', icon: BookHeart },
  { key: 'tasks', label: 'Tasks', icon: Kanban },
  { key: 'review', label: 'Weekly Review', icon: ClipboardCheck },
  { key: 'career', label: 'Career', icon: Trophy },
  { key: 'quickadd', label: 'Quick Add', icon: Plus },
  { key: 'search', label: 'Search', icon: Search },
];

// =========================================================================
// Root component
// =========================================================================
export function WorkMgr() {
  const [tab, setTab] = useState<Tab>('dashboard');
  const [jumpAccount, setJumpAccount] = useState<string | null>(null);
  const [taskCustomer, setTaskCustomer] = useState<string | null>(null);
  const toast = useToast();
  const [health, setHealth] = useState<{ ok: boolean; root?: string; error?: string }>({ ok: true });

  useEffect(() => {
    workmgrApi.health()
      .then(h => setHealth({ ok: true, root: h.mywork_root }))
      .catch(e => setHealth({ ok: false, error: String(e.message || e) }));
  }, []);

  const openAccount = (name: string) => { setJumpAccount(name); setTab('accounts'); };
  const openTasksFor = (customer: string) => { setTaskCustomer(customer); setTab('tasks'); };

  return (
    <div className="flex min-h-[calc(100vh-4rem)] bg-slate-900">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 border-r border-slate-800 flex flex-col">
        <div className="px-4 py-4 flex items-center gap-2.5 border-b border-slate-800/60">
          <div className="w-9 h-9 rounded-lg bg-blue-500/15 border border-blue-500/30 flex items-center justify-center"><Briefcase className="w-5 h-5 text-blue-400" /></div>
          <div>
            <div className="text-sm font-bold text-slate-100">Work Manager</div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider">mywork/ GUI</div>
          </div>
        </div>
        <nav className="p-3 flex flex-col gap-0.5">
          {NAV.map(n => (
            <button key={n.key} onClick={() => { if (n.key === 'tasks') setTaskCustomer(null); setTab(n.key); }}
              className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors ${tab === n.key ? 'bg-blue-500/15 text-blue-300' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'}`}>
              <n.icon className="w-4 h-4" /> {n.label}
            </button>
          ))}
        </nav>
        <PinnedSidebar onOpen={openAccount} />
        <div className="mt-auto p-3 text-[10px] text-slate-600 border-t border-slate-800/60">
          {health.ok && health.root ? <span className="break-all">Data: {health.root.split('/').slice(-1)[0]}/</span> : null}
        </div>
      </aside>

      {/* Content */}
      <main className="flex-1 min-w-0 px-6 py-6">
        {!health.ok && (
          <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/40 text-red-300 text-sm">
            Backend unreachable: {health.error}. Restart <code>npm run dev</code>.
          </div>
        )}
        {tab === 'dashboard' && <DashboardTab onJump={setTab} onOpenAccount={openAccount} toast={toast} />}
        {tab === 'accounts' && <AccountsTab toast={toast} jumpAccount={jumpAccount} onConsumeJump={() => setJumpAccount(null)} onOpenTasks={openTasksFor} />}
        {tab === 'timeline' && (
          <div className="max-w-4xl">
            <h1 className="text-lg font-semibold text-slate-100 mb-4">Global Timeline</h1>
            <GlobalTimeline tone="dark" onOpenAccount={openAccount} />
          </div>
        )}
        {tab === 'updates' && <UpdatesTab toast={toast} onOpenAccount={openAccount} />}
        {tab === 'patterns' && <WorkPatternsTab toast={toast} />}
        {tab === 'learnings' && <LearningsTab toast={toast} />}
        {tab === 'journal' && <JournalTab toast={toast} />}
        {tab === 'tasks' && <TasksTab toast={toast} initialCustomer={taskCustomer} />}
        {tab === 'review' && <ReviewTab toast={toast} />}
        {tab === 'career' && <CareerTab toast={toast} />}
        {tab === 'quickadd' && <QuickAddTab toast={toast} />}
        {tab === 'search' && <SearchTab />}
      </main>
    </div>
  );
}

function PinnedSidebar({ onOpen }: { onOpen: (n: string) => void }) {
  const { pins } = usePins();
  const [accounts, setAccounts] = useState<AccountSummary[]>([]);
  useEffect(() => { workmgrApi.listAccounts().then(setAccounts).catch(() => {}); }, []);
  const pinned = accounts.filter(a => pins.includes(a.name));
  if (pinned.length === 0) return null;
  return (
    <div className="px-3 pb-3">
      <div className="flex items-center gap-1.5 px-2 mb-1.5 text-[10px] uppercase tracking-wider text-slate-600"><Star className="w-3 h-3 text-amber-400" /> Pinned</div>
      <div className="flex flex-col gap-0.5">
        {pinned.map(a => (
          <button key={a.name} onClick={() => onOpen(a.name)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm text-slate-400 hover:bg-slate-800/60 hover:text-slate-200">
            <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: STATUS_DOT[String(a.overview?.status || '')] || '#475569' }} />
            <span className="truncate">{a.overview?.customer || a.name}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

// =========================================================================
// Dashboard Tab
// =========================================================================
function DashboardTab({ onJump, onOpenAccount, toast }: { onJump: (t: Tab) => void; onOpenAccount: (n: string) => void; toast: any }) {
  const [data, setData] = useState<SummaryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [modalTask, setModalTask] = useState<{ status: TaskStatus; filename: string } | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    workmgrApi.summary()
      .then(setData)
      .catch(e => toast.error(`Failed to load summary: ${e.message}`))
      .finally(() => setLoading(false));
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  if (loading && !data) return <div className="text-slate-400">Loading dashboard…</div>;
  if (!data) return null;

  const customerBars = Object.entries(data.counts_by_customer)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12);
  const maxCust = customerBars.length ? Math.max(...customerBars.map(c => c[1])) : 1;

  return (
    <div id="dashboard-content" className="space-y-6">
      <div className="flex items-center justify-end gap-2">
        <button onClick={() => exportElementToPdf('dashboard-content', `WorkMgr-Dashboard-${new Date().toISOString().slice(0,10)}.pdf`, toast)} className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200">
          <Download className="w-4 h-4" /> Export PDF
        </button>
        <button onClick={load} className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Counts strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Open" value={data.counts.open} icon={Kanban} color="text-blue-400" onClick={() => onJump('tasks')} />
        <StatCard label="Waiting" value={data.counts.waiting} icon={Clock} color="text-purple-400" onClick={() => onJump('tasks')} />
        <StatCard label="Overdue" value={data.counts.overdue} icon={AlertTriangle} color="text-red-400" />
        <StatCard label="Done (7d)" value={data.counts.done_last_7} icon={Award} color="text-emerald-400" />
      </div>

      <PinnedAccountsRail onOpen={onOpenAccount} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Section title="🔥 Overdue" empty="No overdue tasks — nice!">
          {data.overdue.map(t => (
            <TaskRow key={t.filename} task={t} onOpen={() => setModalTask({ status: t.status, filename: t.filename })} />
          ))}
        </Section>

        <Section title="⚡ Top 5 (P0/P1)" empty="No P0/P1 open tasks.">
          {data.top_5.map(t => (
            <TaskRow key={t.filename} task={t} onOpen={() => setModalTask({ status: t.status, filename: t.filename })} />
          ))}
        </Section>

        <Section title="📅 Due this week" empty="Nothing due this week.">
          {data.due_this_week.map(t => (
            <TaskRow key={t.filename} task={t} onOpen={() => setModalTask({ status: t.status, filename: t.filename })} />
          ))}
        </Section>

        <Section title="🏆 Recent wins (7d)" empty="No wins logged this week.">
          {data.recent_wins.map((w, i) => (
            <div key={i} className="text-sm px-3 py-2 rounded-lg bg-slate-800/50 border border-slate-700/50">
              <span className="text-emerald-400 font-medium">{w.date}</span> — <span className="text-slate-300">{w.text.length > 200 ? w.text.slice(0, 200) + '…' : w.text}</span>
            </div>
          ))}
        </Section>

        <Section title="📞 Upcoming 1-1s (7d)" empty="No 1-1s in the next 7 days.">
          {data.upcoming_1on1s.map(x => (
            <div key={x.filename} className="text-sm px-3 py-2 rounded-lg bg-slate-800/50 border border-slate-700/50">
              <span className="text-blue-400 font-medium">{x.date}</span> — <span className="text-slate-200 capitalize">{x.person}</span>
            </div>
          ))}
        </Section>

        <Section title="👥 Open+Waiting by customer">
          <div className="space-y-1.5">
            {customerBars.map(([name, count]) => (
              <div key={name} className="flex items-center gap-2 text-xs">
                <span className="w-32 truncate text-slate-300">{name}</span>
                <div className="flex-1 h-4 bg-slate-800 rounded overflow-hidden">
                  <div
                    className="h-full bg-blue-500/60"
                    style={{ width: `${(count / maxCust) * 100}%` }}
                  />
                </div>
                <span className="w-6 text-right text-slate-400">{count}</span>
              </div>
            ))}
          </div>
        </Section>
      </div>

      {modalTask && (
        <TaskDetailModal
          initial={modalTask}
          onClose={() => setModalTask(null)}
          onSaved={load}
        />
      )}
    </div>
  );
}

function PinnedAccountsRail({ onOpen }: { onOpen: (n: string) => void }) {
  const { pins } = usePins();
  const [accounts, setAccounts] = useState<AccountSummary[]>([]);
  useEffect(() => { workmgrApi.listAccounts().then(setAccounts).catch(() => {}); }, []);
  const pinned = accounts.filter(a => pins.includes(a.name));
  return (
    <div>
      <div className="flex items-center gap-2 mb-2"><Star className="w-4 h-4 text-amber-400" /><h3 className="text-sm font-semibold text-slate-200">Pinned accounts</h3></div>
      {pinned.length === 0 ? (
        <p className="text-xs text-slate-500 italic">No pinned accounts yet — open Accounts and hit the ★ to keep frequently-used ones here and in the sidebar.</p>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
          {pinned.map(a => {
            const defs = accountProductDefs(null, a.overview?.products as string[]);
            return (
              <div key={a.name} onClick={() => onOpen(a.name)} className="cursor-pointer text-left p-3 rounded-lg bg-slate-800/40 border border-slate-700/60 hover:border-blue-500/50 transition-colors">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: STATUS_DOT[String(a.overview?.status || '')] || '#64748b' }} />
                  <span className="text-sm font-medium text-slate-100 truncate">{a.overview?.customer || a.name}</span>
                  <div className="ml-auto"><PinStar name={a.name} size={14} /></div>
                </div>
                <div className="mt-2"><ProductChips defs={defs} max={4} /></div>
                {a.overview?.last_touched && <div className="text-[10px] text-slate-500 mt-1.5">touched {fmtRel(String(a.overview.last_touched))}</div>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, icon: Icon, color, onClick }: any) {
  return (
    <button
      onClick={onClick}
      className="p-4 rounded-lg bg-slate-800/40 border border-slate-700/50 hover:border-slate-600 transition-colors text-left"
    >
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-slate-500">{label}</span>
        <Icon className={`w-4 h-4 ${color}`} />
      </div>
      <div className="mt-1 text-3xl font-bold text-slate-100">{value}</div>
    </button>
  );
}

function Section({ title, children, empty }: { title: string; children: React.ReactNode; empty?: string }) {
  const isEmpty = Array.isArray(children) ? children.length === 0 : !children;
  return (
    <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
      <h3 className="text-sm font-semibold text-slate-200 mb-3">{title}</h3>
      {isEmpty ? <p className="text-xs text-slate-500 italic">{empty || 'Nothing here.'}</p> : (
        <div className="space-y-1.5">{children}</div>
      )}
    </div>
  );
}

function TaskRow({ task, onOpen }: { task: TaskListItem; onOpen: () => void }) {
  const fm = task.frontmatter;
  const daysLeft = daysUntil(fm.due);
  const overdue = daysLeft !== null && daysLeft < 0;
  return (
    <button
      onClick={onOpen}
      className="w-full text-left px-3 py-2 rounded-lg bg-slate-800/50 hover:bg-slate-800 border border-slate-700/50 hover:border-slate-600 transition-colors group"
    >
      <div className="flex items-start gap-2">
        {fm.priority && (
          <span className={`px-1.5 py-0.5 text-[10px] font-semibold rounded border ${PRIORITY_COLORS[fm.priority] || ''}`}>
            {fm.priority}
          </span>
        )}
        <div className="flex-1 min-w-0">
          <div className="text-sm text-slate-200 truncate group-hover:text-white">{fm.title || fm.id || task.filename}</div>
          <div className="flex items-center gap-2 mt-0.5 text-xs text-slate-500">
            {fm.customer && <span>· {fm.customer}</span>}
            {fm.due && (
              <span className={overdue ? 'text-red-400' : ''}>
                · due {fm.due}{daysLeft !== null && ` (${daysLeft >= 0 ? `${daysLeft}d` : `${Math.abs(daysLeft)}d late`})`}
              </span>
            )}
            {task.last_activity && <span className="flex items-center gap-0.5 ml-auto text-slate-600" title={`Last activity ${task.last_activity}`}><Clock className="w-3 h-3" />{task.last_activity.slice(5)}</span>}
          </div>
        </div>
        <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-slate-400" />
      </div>
    </button>
  );
}

// =========================================================================
// Tasks Tab (Kanban with drag-and-drop, bulk actions, calendar toggle)
// =========================================================================
type TasksView = 'kanban' | 'calendar';

function TasksTab({ toast, initialCustomer }: { toast: any; initialCustomer?: string | null }) {
  const [tasks, setTasks] = useState<TasksResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<TasksView>('kanban');
  const [filterCustomer, setFilterCustomer] = useState(initialCustomer || '');
  const [filterPriority, setFilterPriority] = useState('');
  const [filterText, setFilterText] = useState('');
  const [modalTask, setModalTask] = useState<{ status: TaskStatus; filename: string } | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [dragOver, setDragOver] = useState<TaskStatus | null>(null);
  const [pendingWaiting, setPendingWaiting] = useState<{ from: TaskStatus; filename: string } | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set()); // "status/filename" tokens
  const [bulkPendingWaiting, setBulkPendingWaiting] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    workmgrApi.listTasks()
      .then(setTasks)
      .catch(e => toast.error(`Failed to load tasks: ${e.message}`))
      .finally(() => setLoading(false));
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const customers = useMemo(() => {
    if (!tasks) return [] as string[];
    const set = new Set<string>();
    [...tasks.open, ...tasks.waiting, ...tasks.done].forEach(t => {
      if (t.frontmatter.customer) set.add(String(t.frontmatter.customer));
    });
    return [...set].sort();
  }, [tasks]);

  const filter = useCallback((arr: TaskListItem[]) => arr.filter(t => {
    if (filterCustomer && String(t.frontmatter.customer || '') !== filterCustomer) return false;
    if (filterPriority && String(t.frontmatter.priority || '') !== filterPriority) return false;
    if (filterText) {
      const hay = `${t.frontmatter.title || ''} ${t.frontmatter.id || ''} ${t.body_preview}`.toLowerCase();
      if (!hay.includes(filterText.toLowerCase())) return false;
    }
    return true;
  }), [filterCustomer, filterPriority, filterText]);

  // -------------- drag & drop ------------------------------------------------
  const onDragStart = (e: React.DragEvent, task: TaskListItem) => {
    e.dataTransfer.setData('application/x-workmgr-task', JSON.stringify({ status: task.status, filename: task.filename }));
    e.dataTransfer.effectAllowed = 'move';
  };
  const onDragOver = (e: React.DragEvent, st: TaskStatus) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    setDragOver(st);
  };
  const onDragLeave = () => setDragOver(null);
  const onDrop = async (e: React.DragEvent, to: TaskStatus) => {
    e.preventDefault();
    setDragOver(null);
    try {
      const payload = JSON.parse(e.dataTransfer.getData('application/x-workmgr-task') || '{}');
      if (!payload.filename || !payload.status || payload.status === to) return;
      if (to === 'waiting') {
        setPendingWaiting({ from: payload.status, filename: payload.filename });
        return;
      }
      await workmgrApi.moveTask(payload.status, payload.filename, to);
      toast.success(`Moved to ${to}/`);
      load();
    } catch (err: any) {
      toast.error(`Move failed: ${err.message}`);
    }
  };

  // -------------- selection helpers ------------------------------------------
  const key = (t: TaskListItem) => `${t.status}/${t.filename}`;
  const toggle = (t: TaskListItem) => {
    setSelected(prev => {
      const next = new Set(prev);
      const k = key(t);
      if (next.has(k)) next.delete(k); else next.add(k);
      return next;
    });
  };
  const clearSelection = () => setSelected(new Set());
  const selectedList = useMemo(() => {
    if (!tasks) return [] as { status: TaskStatus; filename: string }[];
    const all = [...tasks.open, ...tasks.waiting, ...tasks.done];
    return all.filter(t => selected.has(key(t))).map(t => ({ status: t.status, filename: t.filename }));
  }, [tasks, selected]);

  // -------------- bulk actions ------------------------------------------------
  const bulkMove = async (to: TaskStatus, extraFm: Record<string, any> = {}) => {
    if (selectedList.length === 0) return;
    if (!confirm(`Move ${selectedList.length} tasks to ${to}/ ?`)) return;
    try {
      for (const s of selectedList) {
        if (s.status !== to) {
          await workmgrApi.moveTask(s.status, s.filename, to, extraFm);
        }
      }
      toast.success(`Moved ${selectedList.length} → ${to}/`);
      clearSelection();
      load();
    } catch (err: any) {
      toast.error(`Bulk move failed: ${err.message}`);
    }
  };

  if (loading && !tasks) return <div className="text-slate-400">Loading tasks…</div>;
  if (!tasks) return null;

  return (
    <div className="space-y-4">
      {/* Filters + view toggle */}
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="text"
          placeholder="Filter…"
          value={filterText}
          onChange={e => setFilterText(e.target.value)}
          className="px-3 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none"
        />
        <select value={filterCustomer} onChange={e => setFilterCustomer(e.target.value)} className="px-3 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-200">
          <option value="">All customers</option>
          {customers.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <select value={filterPriority} onChange={e => setFilterPriority(e.target.value)} className="px-3 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-200">
          <option value="">All priorities</option>
          <option>P0</option><option>P1</option><option>P2</option><option>P3</option>
        </select>
        <div className="flex-1" />
        <div className="flex items-center rounded-md border border-slate-700 overflow-hidden">
          <button onClick={() => setView('kanban')} className={`px-3 py-1.5 text-sm flex items-center gap-1.5 ${view === 'kanban' ? 'bg-blue-500/20 text-blue-300' : 'text-slate-400 hover:text-slate-200'}`}>
            <Kanban className="w-4 h-4" /> Kanban
          </button>
          <button onClick={() => setView('calendar')} className={`px-3 py-1.5 text-sm flex items-center gap-1.5 border-l border-slate-700 ${view === 'calendar' ? 'bg-blue-500/20 text-blue-300' : 'text-slate-400 hover:text-slate-200'}`}>
            <CalendarDays className="w-4 h-4" /> Calendar
          </button>
        </div>
        <button onClick={() => setShowCreate(true)} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30">
          <Plus className="w-4 h-4" /> New task
        </button>
        <button onClick={load} className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Bulk-selection toolbar (sticky when >0 selected) */}
      {selected.size > 0 && (
        <div className="sticky top-16 z-30 flex items-center gap-2 p-3 rounded-lg bg-blue-500/10 border border-blue-500/40">
          <span className="text-sm text-blue-200 font-medium">{selected.size} selected</span>
          <div className="flex-1" />
          <button onClick={() => bulkMove('open')} className="px-3 py-1.5 text-xs bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded hover:bg-blue-500/30">→ Open</button>
          <button onClick={() => setBulkPendingWaiting(true)} className="px-3 py-1.5 text-xs bg-purple-500/20 border border-purple-500/40 text-purple-300 rounded hover:bg-purple-500/30">→ Waiting</button>
          <button onClick={() => bulkMove('done')} className="px-3 py-1.5 text-xs bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 rounded hover:bg-emerald-500/30">→ Done</button>
          <button onClick={clearSelection} className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200">Clear</button>
        </div>
      )}

      {view === 'kanban' ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {(['open', 'waiting', 'done'] as TaskStatus[]).map(st => {
            const rows = filter(tasks[st]);
            const isDragOver = dragOver === st;
            return (
              <div
                key={st}
                onDragOver={e => onDragOver(e, st)}
                onDragLeave={onDragLeave}
                onDrop={e => onDrop(e, st)}
                className={`p-3 rounded-lg border transition-colors ${
                  isDragOver ? 'bg-blue-500/10 border-blue-500/60' : 'bg-slate-800/20 border-slate-700/50'
                }`}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 text-xs font-semibold rounded border ${STATUS_COLORS[st]}`}>
                      {st}
                    </span>
                    <span className="text-xs text-slate-500">{rows.length}</span>
                  </div>
                </div>
                <div className="space-y-1.5 max-h-[70vh] overflow-y-auto pr-1">
                  {rows.length === 0 && <p className="text-xs text-slate-500 italic">No tasks.</p>}
                  {rows.map(t => (
                    <div key={t.filename} draggable onDragStart={e => onDragStart(e, t)} className="flex items-start gap-1.5">
                      <button
                        onClick={(e) => { e.stopPropagation(); toggle(t); }}
                        className="mt-2 text-slate-500 hover:text-blue-400 flex-shrink-0"
                        title="Select for bulk actions"
                      >
                        {selected.has(key(t)) ? <CheckSquare className="w-4 h-4 text-blue-400" /> : <Square className="w-4 h-4" />}
                      </button>
                      <div className="flex-1 min-w-0">
                        <TaskRow task={t} onOpen={() => setModalTask({ status: t.status, filename: t.filename })} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <CalendarView
          tasks={[...tasks.open, ...tasks.waiting]}
          filter={filter}
          onOpenTask={t => setModalTask({ status: t.status, filename: t.filename })}
        />
      )}

      {modalTask && (
        <TaskDetailModal
          initial={modalTask}
          onClose={() => setModalTask(null)}
          onSaved={load}
        />
      )}

      {showCreate && (
        <CreateTaskModal onClose={() => setShowCreate(false)} onCreated={(created) => { setShowCreate(false); load(); setModalTask(created); }} toast={toast} customers={customers} defaultCustomer={filterCustomer} />
      )}

      {pendingWaiting && (
        <WaitingOnPromptModal
          onClose={() => setPendingWaiting(null)}
          onConfirm={async (waitingOn) => {
            try {
              await workmgrApi.moveTask(pendingWaiting.from, pendingWaiting.filename, 'waiting', { waiting_on: waitingOn });
              toast.success('Moved to waiting/');
              setPendingWaiting(null);
              load();
            } catch (err: any) {
              toast.error(`Move failed: ${err.message}`);
            }
          }}
        />
      )}

      {bulkPendingWaiting && (
        <WaitingOnPromptModal
          onClose={() => setBulkPendingWaiting(false)}
          onConfirm={async (waitingOn) => {
            setBulkPendingWaiting(false);
            await bulkMove('waiting', { waiting_on: waitingOn });
          }}
        />
      )}
    </div>
  );
}

// ------------------------- Calendar view ------------------------------------
function CalendarView({ tasks, filter, onOpenTask }: {
  tasks: TaskListItem[];
  filter: (arr: TaskListItem[]) => TaskListItem[];
  onOpenTask: (t: TaskListItem) => void;
}) {
  const [monthOffset, setMonthOffset] = useState(0);

  const { year, month, weeks, monthLabel } = useMemo(() => {
    const today = new Date();
    const cursor = new Date(today.getFullYear(), today.getMonth() + monthOffset, 1);
    const year = cursor.getFullYear();
    const month = cursor.getMonth();
    const first = new Date(year, month, 1);
    const last = new Date(year, month + 1, 0);
    // start on Monday
    const startDay = first.getDay(); // 0=Sun, 1=Mon...
    const daysBefore = startDay === 0 ? 6 : startDay - 1;
    const gridStart = new Date(year, month, 1 - daysBefore);
    const weeks: Date[][] = [];
    let cur = new Date(gridStart);
    while (cur <= last || weeks.length === 0 || cur.getDay() !== 1) {
      const week: Date[] = [];
      for (let i = 0; i < 7; i++) { week.push(new Date(cur)); cur.setDate(cur.getDate() + 1); }
      weeks.push(week);
      if (weeks.length > 6) break;
    }
    return { year, month, weeks, monthLabel: cursor.toLocaleDateString('en-US', { year: 'numeric', month: 'long' }) };
  }, [monthOffset]);

  const byDay = useMemo(() => {
    const map = new Map<string, TaskListItem[]>();
    for (const t of filter(tasks)) {
      const due = t.frontmatter.due;
      if (!due) continue;
      const key = String(due).slice(0, 10);
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(t);
    }
    return map;
  }, [tasks, filter]);

  const todayStr = new Date().toISOString().slice(0, 10);

  return (
    <div className="p-3 rounded-lg bg-slate-800/20 border border-slate-700/50">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <button onClick={() => setMonthOffset(o => o - 1)} className="px-2 py-1 text-sm text-slate-400 hover:text-slate-100">‹ Prev</button>
          <button onClick={() => setMonthOffset(0)} className="px-2 py-1 text-sm text-slate-400 hover:text-slate-100">Today</button>
          <button onClick={() => setMonthOffset(o => o + 1)} className="px-2 py-1 text-sm text-slate-400 hover:text-slate-100">Next ›</button>
        </div>
        <h3 className="text-sm font-semibold text-slate-200">{monthLabel}</h3>
        <span className="text-xs text-slate-500">Tasks placed on their <code>due</code> date</span>
      </div>
      <div className="grid grid-cols-7 gap-1 text-xs">
        {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map(d => (
          <div key={d} className="text-center font-semibold text-slate-500 py-1">{d}</div>
        ))}
        {weeks.flat().map((day, i) => {
          const iso = day.toISOString().slice(0, 10);
          const inMonth = day.getMonth() === month;
          const isToday = iso === todayStr;
          const isPast = iso < todayStr;
          const items = byDay.get(iso) || [];
          return (
            <div
              key={i}
              className={`min-h-[80px] p-1.5 rounded border ${
                isToday ? 'bg-blue-500/10 border-blue-500/60' :
                inMonth ? 'bg-slate-800/30 border-slate-700/40' :
                'bg-slate-900/40 border-slate-800/40'
              }`}
            >
              <div className={`text-[10px] ${inMonth ? isPast ? 'text-slate-500' : 'text-slate-300' : 'text-slate-600'} ${isToday ? 'font-bold text-blue-300' : ''}`}>
                {day.getDate()}
              </div>
              <div className="mt-1 space-y-0.5">
                {items.slice(0, 3).map(t => (
                  <button
                    key={t.filename}
                    onClick={() => onOpenTask(t)}
                    className={`w-full text-left text-[10px] leading-tight px-1 py-0.5 rounded truncate ${
                      isPast && t.status !== 'done'
                        ? 'bg-red-500/20 text-red-300 hover:bg-red-500/30'
                        : 'bg-slate-700/50 text-slate-200 hover:bg-slate-700'
                    }`}
                    title={`${t.frontmatter.title || t.filename} · ${t.frontmatter.customer || ''}`}
                  >
                    {t.frontmatter.priority && <span className="mr-0.5">{t.frontmatter.priority}</span>}
                    {(t.frontmatter.title || t.filename).slice(0, 22)}
                  </button>
                ))}
                {items.length > 3 && <div className="text-[10px] text-slate-500 pl-1">+{items.length - 3} more</div>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function WaitingOnPromptModal({ onClose, onConfirm }: { onClose: () => void; onConfirm: (waitingOn: string) => Promise<void> | void }) {
  const [text, setText] = useState('');
  const [saving, setSaving] = useState(false);
  return (
    <ModalShell onClose={onClose} title="Moving to Waiting" subtitle="What is this task waiting on?">
      <input
        autoFocus
        value={text}
        onChange={e => setText(e.target.value)}
        placeholder='e.g. "Customer to schedule session" · "Pratik approval" · "Vendor patch"'
        className={inputCls}
        onKeyDown={async e => {
          if (e.key === 'Enter' && text.trim() && !saving) {
            setSaving(true);
            try { await onConfirm(text.trim()); } finally { setSaving(false); }
          }
        }}
      />
      <div className="flex justify-end gap-2 mt-3 pt-3 border-t border-slate-800">
        <button onClick={onClose} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
        <button
          disabled={!text.trim() || saving}
          onClick={async () => { setSaving(true); try { await onConfirm(text.trim()); } finally { setSaving(false); } }}
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-purple-500/20 border border-purple-500/40 text-purple-300 rounded-md hover:bg-purple-500/30 disabled:opacity-50"
        >
          <ArrowRightCircle className="w-4 h-4" /> {saving ? 'Moving…' : 'Move to Waiting'}
        </button>
      </div>
    </ModalShell>
  );
}

// =========================================================================
// Task Detail Modal
// =========================================================================
function TaskDetailModal({ initial, onClose, onSaved }: {
  initial: { status: TaskStatus; filename: string };
  onClose: () => void;
  onSaved: () => void;
}) {
  return <RichTaskPanel initial={initial} onClose={onClose} onSaved={onSaved} />;
}

// =========================================================================
// Create Task Modal
// =========================================================================
function CreateTaskModal({ onClose, onCreated, toast, customers, defaultCustomer }: { onClose: () => void; onCreated: (created: { status: TaskStatus; filename: string }) => void; toast: any; customers: string[]; defaultCustomer?: string }) {
  const [title, setTitle] = useState('');
  const [customer, setCustomer] = useState(defaultCustomer || '');
  const [priority, setPriority] = useState<'P0' | 'P1' | 'P2' | 'P3'>('P1');
  const [due, setDue] = useState('');
  const [saving, setSaving] = useState(false);

  const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  const cust = customer.trim();
  const prefix = cust && !['internal', 'personal', 'career'].includes(cust.toLowerCase()) ? slug(cust).split('-')[0] + '-' : '';
  const previewId = ((prefix + slug(title)).slice(0, 60)) || 'task';

  const submit = async () => {
    if (!title.trim()) { toast.error('Title is required'); return; }
    setSaving(true);
    const today = new Date().toISOString().slice(0, 10);
    const base = previewId;
    try {
      let created: { filename: string; status: TaskStatus } | null = null;
      for (let attempt = 0; attempt < 5; attempt++) {
        const id = attempt === 0 ? base : `${base}-${attempt + 1}`;
        try {
          created = await workmgrApi.createTask({
            id,
            frontmatter: {
              id, title: title.trim(), customer: cust || 'internal', priority,
              status: 'open', created: today, due: due || undefined, owner: 'KB',
              tags: [], subtasks: [], links: [], files: [],
            },
            body: `## Context\n\n## Next physical step\n\n## Log\n- ${today} — Created.\n`,
            status: 'open',
          });
          break;
        } catch (e: any) {
          if (String(e.message).includes('already exists') && attempt < 4) continue;
          throw e;
        }
      }
      if (created) {
        toast.success(`Created ${created.filename} — opening…`);
        onCreated({ status: created.status, filename: created.filename });
      }
    } catch (e: any) {
      toast.error(`Create failed: ${e.message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <ModalShell onClose={onClose} title="New task" subtitle="Fill the essentials — add subtasks, links, files & more in the next step.">
      <div className="space-y-3">
        <Field label="Title">
          <input value={title} autoFocus onChange={e => setTitle(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && title.trim() && !saving) submit(); }} className={inputCls} placeholder="e.g. Finalize RBAC role matrix before Friday call" />
        </Field>
        <div className="grid grid-cols-3 gap-3">
          <Field label="Customer / bucket">
            <input value={customer} onChange={e => setCustomer(e.target.value)} className={inputCls} list="customers-list" placeholder="SMBC / internal / career" />
            <datalist id="customers-list">
              {customers.map(c => <option key={c} value={c} />)}
            </datalist>
          </Field>
          <Field label="Priority">
            <select value={priority} onChange={e => setPriority(e.target.value as any)} className={inputCls}>
              <option>P0</option><option>P1</option><option>P2</option><option>P3</option>
            </select>
          </Field>
          <Field label="Due (optional)">
            <input type="date" value={due} onChange={e => setDue(e.target.value)} className={inputCls} />
          </Field>
        </div>
        <p className="text-xs text-slate-500">Creates <code>tasks/open/{previewId}.md</code> and opens the full task panel so you can add subtasks, description, links, files, dependencies and more.</p>
        <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
          <button onClick={onClose} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
          <button onClick={submit} disabled={saving || !title.trim()} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30 disabled:opacity-50">
            <Save className="w-4 h-4" /> {saving ? 'Creating…' : 'Create & open'}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

// =========================================================================
// Accounts Tab
// =========================================================================
type AcctSection = 'overview' | 'products' | 'details';

function AccountsTab({ toast, jumpAccount, onConsumeJump, onOpenTasks }: { toast: any; jumpAccount?: string | null; onConsumeJump?: () => void; onOpenTasks?: (customer: string) => void }) {
  const [accounts, setAccounts] = useState<AccountSummary[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [section, setSection] = useState<AcctSection>('overview');
  const [detail, setDetail] = useState<AccountDetail | null>(null);
  const [timeline, setTimeline] = useState<TimelineItem[] | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [modalTask, setModalTask] = useState<{ status: TaskStatus; filename: string } | null>(null);
  const [showHistory, setShowHistory] = useState(false);
  const [showTimeline, setShowTimeline] = useState(false);
  const [filterAccount, setFilterAccount] = useState('');
  const [showNewAccount, setShowNewAccount] = useState(false);
  const { pins } = usePins();

  const loadAccounts = useCallback(() => {
    workmgrApi.listAccounts().then(setAccounts).catch(e => toast.error(`Failed to load accounts: ${e.message}`));
  }, [toast]);
  useEffect(() => { loadAccounts(); }, [loadAccounts]);

  // Jump-to-account from dashboard / timeline / sidebar
  useEffect(() => {
    if (jumpAccount) { setSelected(jumpAccount); setSection('overview'); onConsumeJump?.(); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jumpAccount]);

  const loadDetail = useCallback((name: string) => {
    setLoadingDetail(true);
    Promise.all([
      workmgrApi.getAccount(name),
      workmgrApi.getAccountTimeline(name).catch(() => [] as TimelineItem[]),
    ]).then(([d, tl]) => {
      setDetail(d); setTimeline(tl);
    }).catch(e => toast.error(`Load failed: ${e.message}`))
      .finally(() => setLoadingDetail(false));
  }, [toast]);

  useEffect(() => { if (selected) loadDetail(selected); }, [selected, loadDetail]);

  if (!accounts) return <div className="text-slate-400">Loading accounts…</div>;

  const filtered = withPinnedFirst(
    filterAccount ? accounts.filter(a => a.name.toLowerCase().includes(filterAccount.toLowerCase())) : accounts,
    pins,
  );

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      <div className="p-3 rounded-lg bg-slate-800/30 border border-slate-700/50 max-h-[80vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-2 px-1">
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">{filtered.length}/{accounts.length}</div>
          <button onClick={() => setShowNewAccount(true)} className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300"><Plus className="w-3.5 h-3.5" /> New</button>
        </div>
        <input
          type="text"
          placeholder="Filter accounts…"
          value={filterAccount}
          onChange={e => setFilterAccount(e.target.value)}
          className="w-full mb-2 px-2 py-1 text-xs bg-slate-900 border border-slate-700 rounded text-slate-200 placeholder-slate-500"
        />
        {filtered.map(a => (
          <div
            key={a.name}
            className={`w-full flex items-center gap-2 px-2 py-2 rounded text-sm cursor-pointer ${selected === a.name ? 'bg-blue-500/20 text-blue-300' : 'text-slate-300 hover:bg-slate-700/50'}`}
            onClick={() => setSelected(a.name)}
          >
            <PinStar name={a.name} size={13} />
            <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: STATUS_DOT[String(a.overview?.status || '')] || '#475569' }} />
            <span className="truncate flex-1">{a.overview?.customer || a.name}</span>
            {!a.has_overview && <span className="text-[9px] text-slate-600">new</span>}
          </div>
        ))}
      </div>

      <div className="md:col-span-3">
        {!selected && <div className="text-slate-500 italic">Pick an account to see overview, files, timeline, and open tasks.</div>}
        {selected && loadingDetail && <div className="text-slate-400">Loading…</div>}
        {selected && detail && (
          <div className="space-y-4">
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-start gap-2.5 min-w-0">
                <div className="pt-1"><PinStar name={detail.name} size={20} /></div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-xl font-semibold text-slate-100">{detail.overview?.customer || detail.name}</h2>
                    {detail.overview?.status && <span className="flex items-center gap-1 text-xs" style={{ color: STATUS_DOT[String(detail.overview.status)] || '#94a3b8' }}><span className="w-2 h-2 rounded-full" style={{ background: STATUS_DOT[String(detail.overview.status)] || '#94a3b8' }} />{String(detail.overview.status)}</span>}
                    {detail.overview?.region && <span className="text-xs text-slate-500">· {String(detail.overview.region)}</span>}
                    {detail.overview?.last_touched && <span className="text-xs text-slate-500">· touched {fmtRel(String(detail.overview.last_touched))}</span>}
                  </div>
                  <div className="mt-1.5"><ProductChips defs={accountProductDefs(null, detail.overview?.products as string[])} max={8} /></div>
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <button onClick={() => onOpenTasks?.(detail.name)} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-slate-700/50 border border-slate-600 text-slate-200 rounded-md hover:bg-slate-700">
                  <Kanban className="w-4 h-4" /> Tasks ({detail.tasks.open.length + detail.tasks.waiting.length})
                </button>
                <button onClick={() => setShowTimeline(true)} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-slate-700/50 border border-slate-600 text-slate-200 rounded-md hover:bg-slate-700">
                  <Calendar className="w-4 h-4" /> Timeline ({timeline?.length || 0})
                </button>
                <button onClick={() => setShowHistory(true)} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30">
                  <Plus className="w-4 h-4" /> Log entry
                </button>
              </div>
            </div>

            {/* Sub-tabs */}
            <div className="flex items-center gap-1 border-b border-slate-800">
              {([['overview', 'Overview'], ['products', 'Products & Config'], ['details', 'Customer Details']] as [AcctSection, string][]).map(([k, label]) => (
                <button key={k} onClick={() => setSection(k)}
                  className={`px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${section === k ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>
                  {label}
                </button>
              ))}
            </div>

            {section === 'overview' && (
              <div className="space-y-4">
                {detail.overview && (
                  <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                      {Object.entries(detail.overview).slice(0, 12).map(([k, v]) => (
                        <div key={k}>
                          <div className="text-xs uppercase tracking-wider text-slate-500">{k}</div>
                          <div className="text-slate-200 break-words">{Array.isArray(v) ? v.join(', ') : String(v)}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <Section title={`Open + Waiting tasks (${detail.tasks.open.length + detail.tasks.waiting.length})`}>
                    {[...detail.tasks.open, ...detail.tasks.waiting].map(t => (
                      <TaskRow key={t.filename} task={t} onOpen={() => setModalTask({ status: t.status, filename: t.filename })} />
                    ))}
                  </Section>

                  <Section title={`Recent files (${detail.files.length})`}>
                    <div className="space-y-1 max-h-96 overflow-y-auto pr-1">
                      {detail.files.map(f => (
                        <div key={f.path} className="text-xs px-2 py-1.5 rounded bg-slate-800/40 flex items-center gap-2">
                          {f.type === 'dir' ? <Folder className="w-3.5 h-3.5 text-blue-400" /> : <FileText className="w-3.5 h-3.5 text-slate-500" />}
                          <span className="text-slate-300 truncate">{f.path}</span>
                          {f.size && <span className="text-slate-600 ml-auto">{Math.round(f.size / 1024)}KB</span>}
                        </div>
                      ))}
                    </div>
                  </Section>
                </div>

                {detail.overview_body && (
                  <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
                    <h3 className="text-sm font-semibold text-slate-200 mb-2">Overview (00-overview.md body)</h3>
                    <pre className="text-xs text-slate-300 whitespace-pre-wrap font-sans max-h-96 overflow-y-auto">{detail.overview_body}</pre>
                  </div>
                )}
              </div>
            )}

            {section === 'products' && <ProductConfigPanel name={detail.name} tone="dark" onSaved={() => loadDetail(detail.name)} />}
            {section === 'details' && <CustomerDetailsPanel name={detail.name} tone="dark" onSaved={() => loadDetail(detail.name)} />}
          </div>
        )}
      </div>

      {modalTask && <TaskDetailModal initial={modalTask} onClose={() => setModalTask(null)} onSaved={() => selected && loadDetail(selected)} />}
      {showHistory && selected && (
        <QuickTextModal
          title={`Append history entry — ${selected}`}
          placeholder="One-line entry to append under ## History in 00-overview.md"
          onClose={() => setShowHistory(false)}
          onSubmit={async (text) => {
            await workmgrApi.appendAccountHistory(selected, text);
            toast.success('History updated');
            loadDetail(selected);
          }}
        />
      )}
      {showTimeline && selected && timeline && (
        <TimelineModal name={selected} items={timeline} onClose={() => setShowTimeline(false)} />
      )}
      {showNewAccount && (
        <CreateAccountModal
          toast={toast}
          onClose={() => setShowNewAccount(false)}
          onCreated={(name) => { setShowNewAccount(false); loadAccounts(); setSelected(name); setSection('overview'); }}
        />
      )}
    </div>
  );
}

function CreateAccountModal({ onClose, onCreated, toast }: { onClose: () => void; onCreated: (name: string) => void; toast: any }) {
  const [name, setName] = useState('');
  const [region, setRegion] = useState('APCJ');
  const [status, setStatus] = useState('active');
  const [products, setProducts] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);

  const toggle = (k: string) => setProducts(p => p.includes(k) ? p.filter(x => x !== k) : [...p, k]);

  const submit = async () => {
    if (!name.trim()) { toast.error('Account name is required'); return; }
    setSaving(true);
    try {
      const r = await workmgrApi.createAccount({ name: name.trim(), customer: name.trim(), region, status, products });
      toast.success(`Created Accounts/${r.name}/00-overview.md`);
      onCreated(r.name);
    } catch (e: any) {
      toast.error(`Create failed: ${e.message}`);
    } finally { setSaving(false); }
  };

  return (
    <ModalShell onClose={onClose} title="New account" subtitle="Creates Accounts/<name>/00-overview.md">
      <div className="space-y-3">
        <Field label="Account name (folder + customer)">
          <input value={name} onChange={e => setName(e.target.value)} className={inputCls} placeholder="e.g. DBS Bank" autoFocus />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Region">
            <select value={region} onChange={e => setRegion(e.target.value)} className={inputCls}>
              {['APCJ', 'India', 'ASEAN', 'Greater China', 'ANZ', 'MEA', 'EMEA', 'Americas'].map(r => <option key={r}>{r}</option>)}
            </select>
          </Field>
          <Field label="Status">
            <select value={status} onChange={e => setStatus(e.target.value)} className={inputCls}>
              {['active', 'monitoring', 'dormant', 'archived'].map(s => <option key={s}>{s}</option>)}
            </select>
          </Field>
        </div>
        <Field label="F5 XC products (optional — refine later in Products & Config)">
          <div className="flex flex-wrap gap-1.5">
            {PRODUCTS.map(p => {
              const on = products.includes(p.key);
              return (
                <button key={p.key} type="button" onClick={() => toggle(p.key)}
                  className={`px-2 py-1 text-xs rounded-full border ${on ? '' : 'text-slate-400 border-slate-700 hover:border-slate-500'}`}
                  style={on ? { borderColor: p.color, color: p.color } : {}}>
                  {p.short}
                </button>
              );
            })}
          </div>
        </Field>
        <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
          <button onClick={onClose} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
          <button onClick={submit} disabled={saving || !name.trim()} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30 disabled:opacity-50">
            <Save className="w-4 h-4" /> {saving ? 'Creating…' : 'Create account'}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

const TIMELINE_KIND_STYLE: Record<string, { bg: string; label: string; icon: any }> = {
  'task-created':   { bg: 'bg-blue-500/15 border-blue-500/40 text-blue-300',      label: '➕ Created',  icon: Plus },
  'task-completed': { bg: 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300', label: '✅ Done',    icon: Award },
  'task-due':       { bg: 'bg-amber-500/15 border-amber-500/40 text-amber-300',   label: '📅 Due',     icon: Calendar },
  'history':        { bg: 'bg-purple-500/15 border-purple-500/40 text-purple-300', label: '📝 History', icon: FileText },
  'task-log':       { bg: 'bg-indigo-500/15 border-indigo-500/40 text-indigo-300', label: '💬 Task',    icon: FileText },
  'update':         { bg: 'bg-teal-500/15 border-teal-500/40 text-teal-300',       label: '🗒️ Update',  icon: FileText },
  'win':            { bg: 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300', label: '🏆 Win',    icon: Award },
  'file':           { bg: 'bg-slate-700/40 border-slate-600 text-slate-300',      label: '📎 File',    icon: FileText },
};

function TimelineModal({ name, items, onClose }: { name: string; items: TimelineItem[]; onClose: () => void }) {
  // Group by date
  const grouped = useMemo(() => {
    const map = new Map<string, TimelineItem[]>();
    for (const it of items) {
      if (!map.has(it.date)) map.set(it.date, []);
      map.get(it.date)!.push(it);
    }
    return [...map.entries()];
  }, [items]);

  return (
    <ModalShell onClose={onClose} title={`${name} — timeline`} subtitle={`${items.length} events aggregated from tasks, history, and file changes`}>
      <div className="space-y-4 max-h-[70vh] overflow-y-auto">
        {grouped.length === 0 && <p className="text-sm text-slate-500 italic">No timeline events found.</p>}
        {grouped.map(([date, list]) => (
          <div key={date}>
            <div className="sticky top-0 z-10 bg-slate-900 py-1 mb-2 border-b border-slate-800">
              <span className="text-sm font-semibold text-slate-100">{date}</span>
              <span className="ml-2 text-xs text-slate-500">({list.length})</span>
            </div>
            <div className="space-y-1.5 pl-2 border-l-2 border-slate-800">
              {list.map((it, i) => {
                const st = TIMELINE_KIND_STYLE[it.kind] || TIMELINE_KIND_STYLE['file'];
                return (
                  <div key={i} className={`px-3 py-2 rounded border ${st.bg}`}>
                    <div className="flex items-center gap-2 text-xs">
                      <span className="font-semibold">{st.label}</span>
                      {it.time && <span className="text-slate-400 font-mono">{it.time}</span>}
                      {it.path && <span className="text-slate-500">· {it.path}</span>}
                    </div>
                    <div className="text-sm text-slate-100 mt-0.5">{it.label}</div>
                    {it.detail && <div className="text-xs text-slate-400 mt-0.5">{it.detail}</div>}
                    {it.body && <div className="text-xs text-slate-300 mt-1.5 whitespace-pre-wrap leading-relaxed border-l-2 border-slate-700 pl-2.5">{it.body}</div>}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </ModalShell>
  );
}

// =========================================================================
// Career Tab
// =========================================================================
// Renders a Career/*.md doc: interactive checkbox toggling (- [ ] / - [x]),
// a progress bar, lightweight markdown formatting, and a raw-edit fallback.
function MarkdownDoc({ name, toast, emptyHint }: { name: string; toast: any; emptyHint?: string }) {
  const [content, setContent] = useState<string | null>(null);
  const [raw, setRaw] = useState(false);
  const [draft, setDraft] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(() => {
    workmgrApi.getCareerDoc(name)
      .then(d => { setContent(d.content); setDraft(d.content); })
      .catch(e => toast.error(`Load failed: ${e.message}`));
  }, [name, toast]);
  useEffect(() => { load(); }, [load]);

  if (content === null) return <div className="text-slate-500 text-sm px-1 py-4">Loading {name}…</div>;

  const lines = content.split('\n');
  const checks = lines.filter(l => /^\s*[-*]\s*\[[ xX]\]/.test(l));
  const done = checks.filter(l => /\[[xX]\]/.test(l)).length;
  const clean = (s: string) => s.replace(/\*\*/g, '').replace(/`/g, '').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1');

  const toggle = async (idx: number) => {
    const l = lines[idx];
    const next = /\[\s\]/.test(l) ? l.replace(/\[\s\]/, '[x]') : l.replace(/\[[xX]\]/, '[ ]');
    const nl = [...lines]; nl[idx] = next;
    const nc = nl.join('\n');
    setContent(nc); setDraft(nc);
    try { await workmgrApi.saveCareerDoc(name, nc); } catch (e: any) { toast.error(e.message); load(); }
  };

  const saveRaw = async () => {
    setSaving(true);
    try { await workmgrApi.saveCareerDoc(name, draft); setContent(draft); setRaw(false); toast.success('Saved'); }
    catch (e: any) { toast.error(e.message); }
    finally { setSaving(false); }
  };

  if (!content.trim() && !raw) return (
    <div className="p-6 text-center text-slate-500 text-sm rounded-lg bg-slate-800/30 border border-dashed border-slate-700">
      {emptyHint || `${name} is empty.`}
      <button onClick={() => { setDraft(''); setRaw(true); }} className="text-blue-400 ml-1 hover:underline">Create it</button>
    </div>
  );

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-500">{name}{checks.length > 0 && ` · ${done}/${checks.length} done`}</div>
        <div className="flex items-center gap-2">
          <button onClick={load} className="text-xs text-slate-500 hover:text-slate-300 flex items-center gap-1"><RefreshCw className="w-3 h-3" /></button>
          <button onClick={() => { setDraft(content); setRaw(r => !r); }} className="text-xs text-slate-400 hover:text-slate-200">{raw ? 'Cancel' : 'Edit raw'}</button>
        </div>
      </div>
      {checks.length > 0 && !raw && (
        <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
          <div className="h-full bg-emerald-500 transition-all" style={{ width: `${Math.round(100 * done / Math.max(1, checks.length))}%` }} />
        </div>
      )}
      {raw ? (
        <div className="space-y-2">
          <textarea value={draft} onChange={e => setDraft(e.target.value)} spellCheck={false}
            className="w-full h-[60vh] font-mono text-xs bg-slate-900 border border-slate-700 rounded-md p-3 text-slate-200 focus:outline-none focus:border-blue-500" />
          <button onClick={saveRaw} disabled={saving} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md disabled:opacity-50 hover:bg-blue-500/30">
            <Save className="w-4 h-4" /> {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      ) : (
        <div className="rounded-lg bg-slate-800/30 border border-slate-700/50 p-4 max-h-[65vh] overflow-y-auto">
          {lines.map((l, idx) => {
            const cb = /^(\s*)[-*]\s*\[([ xX])\]\s*(.*)$/.exec(l);
            if (cb) {
              const checked = cb[2].toLowerCase() === 'x';
              return (
                <div key={idx} className="flex items-start gap-2 py-0.5" style={{ marginLeft: cb[1].length * 10 }}>
                  <button onClick={() => toggle(idx)} className="mt-0.5 flex-shrink-0">
                    {checked ? <CheckSquare className="w-4 h-4 text-emerald-400" /> : <Square className="w-4 h-4 text-slate-500 hover:text-slate-300" />}
                  </button>
                  <span className={`text-sm ${checked ? 'line-through text-slate-500' : 'text-slate-200'}`}>{clean(cb[3])}</span>
                </div>
              );
            }
            let m: RegExpExecArray | null;
            if ((m = /^#\s+(.*)$/.exec(l))) return <div key={idx} className="text-base font-bold text-slate-100 mt-3 mb-1">{clean(m[1])}</div>;
            if ((m = /^##\s+(.*)$/.exec(l))) return <div key={idx} className="text-sm font-bold text-slate-100 mt-3 mb-1">{clean(m[1])}</div>;
            if ((m = /^###\s+(.*)$/.exec(l))) return <div key={idx} className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mt-2 mb-0.5">{clean(m[1])}</div>;
            if ((m = /^(\s*)[-*]\s+(.*)$/.exec(l))) return <div key={idx} className="text-sm text-slate-300 flex gap-2" style={{ marginLeft: m[1].length * 10 }}><span className="text-slate-600">•</span><span>{clean(m[2])}</span></div>;
            if (/^\s*\|(.+)\|\s*$/.test(l)) return <div key={idx} className="text-xs font-mono text-slate-400 whitespace-pre">{clean(l)}</div>;
            if (!l.trim()) return <div key={idx} className="h-2" />;
            return <div key={idx} className="text-sm text-slate-400">{clean(l)}</div>;
          })}
        </div>
      )}
    </div>
  );
}

// KPI dashboard for the Career hub: goal/training progress, career-task counts,
// upcoming 1-1s and win count — each card jumps to its sub-tab.
function CareerOverview({ toast, onGo }: { toast: any; onGo: (s: string) => void }) {
  const [goals, setGoals] = useState({ done: 0, total: 0 });
  const [train, setTrain] = useState({ done: 0, total: 0 });
  const [tasks, setTasks] = useState({ open: 0, waiting: 0, done: 0 });
  const [wins, setWins] = useState(0);
  const [upcoming, setUpcoming] = useState<OneOnOneSummary[]>([]);

  useEffect(() => {
    const count = (c: string) => {
      const cs = c.split('\n').filter(l => /^\s*[-*]\s*\[[ xX]\]/.test(l));
      return { done: cs.filter(l => /\[[xX]\]/.test(l)).length, total: cs.length };
    };
    workmgrApi.getCareerDoc('goals-FY26.md').then(d => setGoals(count(d.content))).catch(() => {});
    workmgrApi.getCareerDoc('trainings.md').then(d => setTrain(count(d.content))).catch(() => {});
    workmgrApi.listTasks().then((t: any) => {
      const f = (a: any[]) => (a || []).filter(x => String(x.frontmatter?.customer || '').toLowerCase() === 'career');
      setTasks({ open: f(t.open).length, waiting: f(t.waiting).length, done: f(t.done).length });
    }).catch(() => {});
    workmgrApi.getWins().then(w => setWins(w.entries.length)).catch(() => {});
    const today = new Date().toISOString().slice(0, 10);
    workmgrApi.listOneOnOnes().then(list => setUpcoming(list.filter(x => x.date >= today && x.date !== '0000-00-00').slice(0, 6))).catch(() => {});
  }, [toast]);

  const pct = (d: number, t: number) => (t ? Math.round(100 * d / t) : 0);
  const Card = ({ onClick, label, icon: Icon, tint, value, bar }: any) => (
    <button onClick={onClick} className="p-4 rounded-lg bg-slate-800/40 border border-slate-700/60 text-left hover:border-blue-500/50 transition-colors">
      <div className="flex items-center justify-between"><span className="text-[10px] uppercase tracking-wider text-slate-500">{label}</span><Icon className={`w-4 h-4 ${tint}`} /></div>
      <div className="text-2xl font-bold text-slate-100 mt-1">{value}</div>
      {bar !== undefined && <div className="h-1 bg-slate-800 rounded mt-2 overflow-hidden"><div className={`h-full ${tint.replace('text-', 'bg-')}`} style={{ width: `${bar}%` }} /></div>}
    </button>
  );

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card onClick={() => onGo('goals')} label="Goals FY26" icon={Trophy} tint="text-amber-400" value={`${goals.done}/${goals.total}`} bar={pct(goals.done, goals.total)} />
        <Card onClick={() => onGo('trainings')} label="Trainings" icon={Award} tint="text-violet-400" value={`${train.done}/${train.total}`} bar={pct(train.done, train.total)} />
        <Card onClick={() => onGo('tasks')} label="Career tasks" icon={Kanban} tint="text-blue-400" value={tasks.open + tasks.waiting} bar={undefined} />
        <Card onClick={() => onGo('log')} label="Wins logged" icon={Sparkles} tint="text-emerald-400" value={wins} bar={undefined} />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-slate-200">📞 Upcoming 1-1s</h3>
            <button onClick={() => onGo('log')} className="text-xs text-blue-400 hover:underline">Manage</button>
          </div>
          {upcoming.length === 0
            ? <p className="text-xs text-slate-500 italic">None scheduled.</p>
            : <div className="space-y-1.5">{upcoming.map(x => (
                <div key={x.filename} className="text-sm px-3 py-1.5 rounded bg-slate-800/60 flex justify-between">
                  <span className="text-slate-200 capitalize">{x.person.replace(/^_/, '').replace(/-/g, ' ')}</span>
                  <span className="text-xs text-blue-400">{x.date}</span>
                </div>))}
              </div>}
        </div>
        <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
          <div className="flex items-center gap-2 mb-2"><span className="text-sm font-semibold text-slate-200">🧭 Career task pipeline</span></div>
          <div className="grid grid-cols-3 gap-2 text-center">
            <div className="rounded-lg bg-slate-800/60 py-3"><div className="text-xl font-bold text-blue-300">{tasks.open}</div><div className="text-[10px] uppercase tracking-wider text-slate-500">Open</div></div>
            <div className="rounded-lg bg-slate-800/60 py-3"><div className="text-xl font-bold text-amber-300">{tasks.waiting}</div><div className="text-[10px] uppercase tracking-wider text-slate-500">Waiting</div></div>
            <div className="rounded-lg bg-slate-800/60 py-3"><div className="text-xl font-bold text-emerald-300">{tasks.done}</div><div className="text-[10px] uppercase tracking-wider text-slate-500">Done</div></div>
          </div>
          <p className="text-[11px] text-slate-500 mt-3">Career tasks are ordinary tasks tagged to the <span className="text-slate-300">career</span> account — create them from the Tasks tab.</p>
        </div>
      </div>
    </div>
  );
}

const JOURNAL_CATEGORIES = ['Idea', 'Strategy', 'Update', 'Visibility', 'Growth', 'Recognition', 'Networking', 'Reflection', 'Thought'];
const JOURNAL_CAT_TINT: Record<string, string> = {
  Idea: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
  Strategy: 'bg-violet-500/20 text-violet-300 border-violet-500/40',
  Update: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
  Visibility: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
  Growth: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
  Recognition: 'bg-pink-500/20 text-pink-300 border-pink-500/40',
  Networking: 'bg-indigo-500/20 text-indigo-300 border-indigo-500/40',
  Reflection: 'bg-slate-500/20 text-slate-300 border-slate-500/40',
  Thought: 'bg-slate-500/20 text-slate-300 border-slate-500/40',
};

// A timestamped, categorized career journal (career-journal.md): capture ideas,
// strategy, visibility moves, growth notes. Entries are markdown "## <stamp> · <category>" blocks.
function CareerJournal({ toast }: { toast: any }) {
  const NAME = 'career-journal.md';
  const [content, setContent] = useState<string | null>(null);
  const [category, setCategory] = useState('Idea');
  const [text, setText] = useState('');
  const [saving, setSaving] = useState(false);
  const [filter, setFilter] = useState('All');
  const [raw, setRaw] = useState(false);
  const [draft, setDraft] = useState('');

  const load = useCallback(() => {
    workmgrApi.getCareerDoc(NAME)
      .then(d => { setContent(d.content); setDraft(d.content); })
      .catch(e => toast.error(`Load failed: ${e.message}`));
  }, [toast]);
  useEffect(() => { load(); }, [load]);

  const stamp = () => { const d = new Date(); const p = (n: number) => String(n).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`; };

  const parse = (c: string) => {
    const lines = (c || '').split('\n');
    const out: { stamp: string; category: string; body: string }[] = [];
    let cur: { stamp: string; category: string; body: string } | null = null;
    for (const l of lines) {
      const h = /^##\s+(.*)$/.exec(l);
      if (h) {
        if (cur) out.push(cur);
        const parts = h[1].split('·').map(s => s.trim());
        cur = { stamp: parts[0] || '', category: parts[1] || 'Note', body: '' };
      } else if (cur) {
        cur.body += (cur.body ? '\n' : '') + l;
      }
    }
    if (cur) out.push(cur);
    return out.map(e => ({ ...e, body: e.body.trim() }));
  };

  const rebuild = (entries: { stamp: string; category: string; body: string }[]) =>
    '# Career Journal\n\n_Ideas, thoughts, strategy and progress on career development, visibility and growth._\n\n' +
    entries.map(e => `## ${e.stamp} · ${e.category}\n${e.body}`).join('\n\n') + (entries.length ? '\n' : '');

  const entries = content === null ? [] : parse(content);

  const add = async () => {
    if (!text.trim()) return;
    setSaving(true);
    const next = [{ stamp: stamp(), category: category.trim() || 'Note', body: text.trim() }, ...entries];
    const nc = rebuild(next);
    try { await workmgrApi.saveCareerDoc(NAME, nc); setContent(nc); setDraft(nc); setText(''); toast.success('Entry added'); }
    catch (e: any) { toast.error(e.message); }
    finally { setSaving(false); }
  };

  const remove = async (entry: { stamp: string; category: string; body: string }) => {
    if (!window.confirm('Delete this journal entry?')) return;
    const nc = rebuild(entries.filter(e => e !== entry));
    try { await workmgrApi.saveCareerDoc(NAME, nc); setContent(nc); setDraft(nc); toast.success('Deleted'); }
    catch (e: any) { toast.error(e.message); }
  };

  const saveRaw = async () => {
    setSaving(true);
    try { await workmgrApi.saveCareerDoc(NAME, draft); setContent(draft); setRaw(false); toast.success('Saved'); }
    catch (e: any) { toast.error(e.message); } finally { setSaving(false); }
  };

  const cats = ['All', ...JOURNAL_CATEGORIES];
  const shown = filter === 'All' ? entries : entries.filter(e => e.category === filter);
  const clean = (s: string) => s.replace(/\*\*/g, '').replace(/`/g, '');

  return (
    <div className="space-y-4">
      <div className="p-4 rounded-lg bg-slate-800/40 border border-slate-700/60">
        <div className="flex items-center gap-2 mb-2">
          <FileText className="w-4 h-4 text-blue-400" />
          <h3 className="text-sm font-semibold text-slate-200">Capture a career note</h3>
        </div>
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <input list="career-journal-cats" value={category} onChange={e => setCategory(e.target.value)}
            className="px-2.5 py-1.5 text-sm bg-slate-900 border border-slate-700 rounded-md text-slate-200 focus:outline-none focus:border-blue-500 w-44"
            placeholder="Category" />
          <datalist id="career-journal-cats">{JOURNAL_CATEGORIES.map(c => <option key={c} value={c} />)}</datalist>
          <span className="text-xs text-slate-500">Idea · Strategy · Visibility · Growth · Recognition …</span>
        </div>
        <textarea value={text} onChange={e => setText(e.target.value)}
          onKeyDown={e => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') add(); }}
          placeholder="What's on your mind about your career growth, visibility, strategy, a win to remember, an idea to pursue…"
          className="w-full h-28 text-sm bg-slate-900 border border-slate-700 rounded-md p-3 text-slate-200 focus:outline-none focus:border-blue-500 resize-y" />
        <div className="flex items-center justify-between mt-2">
          <span className="text-[11px] text-slate-500">⌘/Ctrl + Enter to save</span>
          <button onClick={add} disabled={saving || !text.trim()} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md disabled:opacity-40 hover:bg-blue-500/30">
            <Plus className="w-4 h-4" /> {saving ? 'Saving…' : 'Add entry'}
          </button>
        </div>
      </div>

      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-1 flex-wrap">
          {cats.map(c => (
            <button key={c} onClick={() => setFilter(c)}
              className={`px-2.5 py-1 text-xs rounded-full border ${filter === c ? 'bg-blue-500/20 border-blue-500/50 text-blue-300' : 'border-slate-700 text-slate-400 hover:text-slate-200'}`}>
              {c}{c !== 'All' && ` (${entries.filter(e => e.category === c).length})`}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">{entries.length} entries</span>
          <button onClick={() => { setDraft(content || ''); setRaw(r => !r); }} className="text-xs text-slate-400 hover:text-slate-200">{raw ? 'Close raw' : 'Edit raw'}</button>
        </div>
      </div>

      {raw ? (
        <div className="space-y-2">
          <textarea value={draft} onChange={e => setDraft(e.target.value)} spellCheck={false}
            className="w-full h-[55vh] font-mono text-xs bg-slate-900 border border-slate-700 rounded-md p-3 text-slate-200 focus:outline-none focus:border-blue-500" />
          <button onClick={saveRaw} disabled={saving} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md disabled:opacity-50 hover:bg-blue-500/30">
            <Save className="w-4 h-4" /> {saving ? 'Saving…' : 'Save raw'}
          </button>
        </div>
      ) : content === null ? (
        <div className="text-slate-500 text-sm">Loading…</div>
      ) : shown.length === 0 ? (
        <div className="p-8 text-center text-slate-500 text-sm rounded-lg bg-slate-800/30 border border-dashed border-slate-700">
          {entries.length === 0 ? 'No career notes yet. Capture your first idea or strategy above.' : `No ${filter} entries.`}
        </div>
      ) : (
        <div className="space-y-2.5">
          {shown.map((e, i) => (
            <div key={i} className="p-3.5 rounded-lg bg-slate-800/40 border border-slate-700/50 group">
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 text-[11px] rounded-full border ${JOURNAL_CAT_TINT[e.category] || 'bg-slate-500/20 text-slate-300 border-slate-500/40'}`}>{e.category}</span>
                  <span className="text-xs text-slate-500">{e.stamp}</span>
                </div>
                <button onClick={() => remove(e)} className="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-red-400 transition-opacity" title="Delete entry">
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
              <div className="text-sm text-slate-200 whitespace-pre-wrap leading-relaxed">{clean(e.body)}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function CareerTab({ toast }: { toast: any }) {
  const [sub, setSub] = useState<'overview' | 'journal' | 'goals' | 'trainings' | 'tasks' | 'log' | 'growth'>('overview');
  const [wins, setWins] = useState<WinsResponse | null>(null);
  const [oneOnOnes, setOneOnOnes] = useState<OneOnOneSummary[] | null>(null);
  const [promo, setPromo] = useState<any | null>(null);
  const [addingWin, setAddingWin] = useState(false);
  const [addingTouchpoint, setAddingTouchpoint] = useState(false);
  const [creatingOneOnOne, setCreatingOneOnOne] = useState(false);
  const [openNote, setOpenNote] = useState<string | null>(null);

  const loadAll = useCallback(() => {
    workmgrApi.getWins().then(setWins).catch(e => toast.error(`Wins load failed: ${e.message}`));
    workmgrApi.listOneOnOnes().then(setOneOnOnes).catch(e => toast.error(`1-1 load failed: ${e.message}`));
    workmgrApi.getPromotion().then(setPromo).catch(e => toast.error(`Promotion load failed: ${e.message}`));
  }, [toast]);

  useEffect(() => { loadAll(); }, [loadAll]);

  const TABS: { key: typeof sub; label: string; icon: any }[] = [
    { key: 'overview', label: 'Overview', icon: LayoutDashboard },
    { key: 'journal', label: 'Journal', icon: FileText },
    { key: 'goals', label: 'Goals', icon: Trophy },
    { key: 'trainings', label: 'Trainings', icon: Award },
    { key: 'tasks', label: 'Tasks', icon: Kanban },
    { key: 'log', label: 'Wins & 1-1s', icon: Users },
    { key: 'growth', label: 'Growth & Promotion', icon: Sparkles },
  ];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold text-slate-100 mb-2">Career</h1>
        <div className="flex items-center gap-1 border-b border-slate-800 overflow-x-auto">
          {TABS.map(t => (
            <button key={t.key} onClick={() => setSub(t.key)}
              className={`flex items-center gap-1.5 px-3 py-2 text-sm whitespace-nowrap border-b-2 -mb-px transition-colors ${sub === t.key ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>
              <t.icon className="w-4 h-4" /> {t.label}
            </button>
          ))}
        </div>
      </div>

      {sub === 'overview' && <CareerOverview toast={toast} onGo={(s) => setSub(s as any)} />}
      {sub === 'journal' && <CareerJournal toast={toast} />}
      {sub === 'goals' && <MarkdownDoc name="goals-FY26.md" toast={toast} emptyHint="No goals file yet." />}
      {sub === 'trainings' && <MarkdownDoc name="trainings.md" toast={toast} emptyHint="No trainings file yet." />}
      {sub === 'tasks' && <TasksTab toast={toast} initialCustomer="career" />}

      {sub === 'log' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-slate-200">🏆 Wins log</h3>
              <div className="flex items-center gap-2">
                <button onClick={() => setAddingTouchpoint(true)} className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 rounded hover:bg-cyan-500/30">
                  <Users className="w-3.5 h-3.5" /> Log sponsor touchpoint
                </button>
                <button onClick={() => setAddingWin(true)} className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 rounded hover:bg-emerald-500/30">
                  <Plus className="w-3.5 h-3.5" /> Add manual win
                </button>
              </div>
            </div>
            <div className="space-y-1.5 max-h-[60vh] overflow-y-auto pr-1">
              {wins?.entries.map((w, i) => (
                <div key={i} className="text-sm px-3 py-2 rounded bg-slate-800/60">
                  <span className="text-emerald-400 text-xs font-medium mr-2">{w.date}</span>
                  <span className="text-slate-300">{w.text}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-slate-200">📞 1-1 notes</h3>
              <button onClick={() => setCreatingOneOnOne(true)} className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded hover:bg-blue-500/30">
                <Plus className="w-3.5 h-3.5" /> New
              </button>
            </div>
            <div className="space-y-1.5 max-h-[60vh] overflow-y-auto pr-1">
              {oneOnOnes?.map(x => (
                <button key={x.filename} onClick={() => setOpenNote(x.filename)} className="w-full text-left px-3 py-2 rounded bg-slate-800/60 hover:bg-slate-700 flex items-center justify-between text-sm">
                  <span className="text-slate-200 capitalize">{x.person.replace(/^_/, '').replace(/-/g, ' ')}</span>
                  <span className="text-xs text-blue-400">{x.date === '0000-00-00' ? '(plan)' : x.date}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {sub === 'growth' && (
        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">🧭 Skills matrix</h3>
            <MarkdownDoc name="skills-matrix.md" toast={toast} emptyHint="No skills matrix yet." />
          </div>
          <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">🎯 Promotion strategy</h3>
            <MarkdownDoc name="promotion-strategy-fy26.md" toast={toast} emptyHint="No promotion strategy yet." />
          </div>
          {promo && (
            <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-slate-200">🚀 Promotion artifacts (raw)</h3>
                <button onClick={() => setAddingTouchpoint(true)} className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 rounded hover:bg-cyan-500/30">
                  <Users className="w-3.5 h-3.5" /> Log touchpoint
                </button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {Object.entries(promo).map(([f, v]: any) => (
                  <details key={f} className="rounded bg-slate-800/50 border border-slate-700/50">
                    <summary className="cursor-pointer px-3 py-2 text-xs text-slate-300 hover:text-white">
                      {f} {v.exists ? '' : '(missing)'}
                    </summary>
                    <pre className="text-[11px] text-slate-400 px-3 py-2 max-h-64 overflow-auto whitespace-pre-wrap font-sans">{v.raw || v.error}</pre>
                  </details>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {addingWin && (
        <QuickTextModal
          title="Add manual win to wins-log.md"
          placeholder="Prepended today under ## Manual entries. Include customer + measurable outcome."
          onClose={() => setAddingWin(false)}
          onSubmit={async (text) => {
            await workmgrApi.appendWin(text);
            toast.success('Win added');
            loadAll();
          }}
        />
      )}

      {addingTouchpoint && (
        <NewTouchpointModal
          onClose={() => setAddingTouchpoint(false)}
          onSaved={() => { toast.success('Touchpoint logged in sponsors-map.md'); loadAll(); }}
        />
      )}

      {creatingOneOnOne && (
        <NewOneOnOneModal
          onClose={() => setCreatingOneOnOne(false)}
          onCreated={(fn) => { toast.success(`Created ${fn}`); setCreatingOneOnOne(false); loadAll(); setOpenNote(fn); }}
        />
      )}

      {openNote && <OneOnOneModal filename={openNote} onClose={() => setOpenNote(null)} onSaved={loadAll} />}
    </div>
  );
}

function NewOneOnOneModal({ onClose, onCreated }: { onClose: () => void; onCreated: (filename: string) => void }) {
  const [date, setDate] = useState(new Date().toISOString().slice(0, 10));
  const [person, setPerson] = useState('');
  const [purpose, setPurpose] = useState('');
  const [saving, setSaving] = useState(false);
  const toast = useToast();

  const submit = async () => {
    if (!date || !person.trim()) { toast.error('Date and person are required'); return; }
    setSaving(true);
    try {
      const result = await workmgrApi.createOneOnOne({ date, person: person.trim(), purpose: purpose.trim() || undefined });
      onCreated(result.filename);
    } catch (e: any) {
      toast.error(`Create failed: ${e.message}`);
    } finally { setSaving(false); }
  };

  return (
    <ModalShell onClose={onClose} title="New 1-1 note" subtitle="Creates Career/1-1-notes/YYYY-MM-DD-<person>.md with a template">
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Date"><input type="date" value={date} onChange={e => setDate(e.target.value)} className={inputCls} /></Field>
          <Field label="Person (name)"><input value={person} onChange={e => setPerson(e.target.value)} className={inputCls} placeholder="e.g. Ravi, Pratik, Varun" /></Field>
        </div>
        <Field label="Purpose (optional)">
          <input value={purpose} onChange={e => setPurpose(e.target.value)} className={inputCls} placeholder="e.g. Weekly sync · Skip-level check-in · Career discussion" />
        </Field>
        <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
          <button onClick={onClose} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
          <button onClick={submit} disabled={saving} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30 disabled:opacity-50">
            <Save className="w-4 h-4" /> {saving ? 'Creating…' : 'Create'}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

function NewTouchpointModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [date, setDate] = useState(new Date().toISOString().slice(0, 10));
  const [person, setPerson] = useState('');
  const [topic, setTopic] = useState('');
  const [outcome, setOutcome] = useState('');
  const [nextStep, setNextStep] = useState('');
  const [saving, setSaving] = useState(false);
  const toast = useToast();

  const submit = async () => {
    if (!person.trim() || !topic.trim()) { toast.error('Person and topic are required'); return; }
    setSaving(true);
    try {
      await workmgrApi.appendSponsorTouchpoint({
        date, person: person.trim(), topic: topic.trim(),
        outcome: outcome.trim() || undefined,
        next_step: nextStep.trim() || undefined,
      });
      onSaved();
      onClose();
    } catch (e: any) {
      toast.error(`Save failed: ${e.message}`);
    } finally { setSaving(false); }
  };

  return (
    <ModalShell onClose={onClose} title="Log sponsor / advocate touchpoint" subtitle="Appended to sponsors-map.md → Rolling touchpoint log">
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Date"><input type="date" value={date} onChange={e => setDate(e.target.value)} className={inputCls} /></Field>
          <Field label="Person"><input value={person} onChange={e => setPerson(e.target.value)} className={inputCls} placeholder="e.g. Ravi, Pratik, Kiran Menon" /></Field>
        </div>
        <Field label="Topic"><input value={topic} onChange={e => setTopic(e.target.value)} className={inputCls} placeholder="What was discussed?" /></Field>
        <Field label="Outcome (optional)"><input value={outcome} onChange={e => setOutcome(e.target.value)} className={inputCls} placeholder="Decision · signal · framing shift" /></Field>
        <Field label="Next step (optional)"><input value={nextStep} onChange={e => setNextStep(e.target.value)} className={inputCls} placeholder="Follow-up you'll take" /></Field>
        <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
          <button onClick={onClose} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
          <button onClick={submit} disabled={saving} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 rounded-md hover:bg-cyan-500/30 disabled:opacity-50">
            <Users className="w-4 h-4" /> {saving ? 'Saving…' : 'Log touchpoint'}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

function OneOnOneModal({ filename, onClose, onSaved }: { filename: string; onClose: () => void; onSaved: () => void }) {
  const [data, setData] = useState<{ frontmatter: any; body: string } | null>(null);
  const [body, setBody] = useState('');
  const [fmYaml, setFmYaml] = useState('');
  const [saving, setSaving] = useState(false);
  const toast = useToast();

  useEffect(() => {
    workmgrApi.getOneOnOne(filename).then(d => {
      setData(d);
      setBody(d.body);
      setFmYaml(Object.keys(d.frontmatter || {}).length ? prettyYaml(d.frontmatter) : '');
    }).catch(e => toast.error(`Load failed: ${e.message}`));
  }, [filename, toast]);

  const save = async () => {
    setSaving(true);
    try {
      let fmObj: any = undefined;
      if (fmYaml.trim()) {
        try { fmObj = parseYaml(fmYaml); } catch (e: any) { toast.error(`Invalid YAML: ${e.message}`); setSaving(false); return; }
      }
      await workmgrApi.updateOneOnOne(filename, { frontmatter: fmObj, body });
      toast.success('Saved');
      onSaved();
      onClose();
    } catch (e: any) {
      toast.error(`Save failed: ${e.message}`);
    } finally { setSaving(false); }
  };

  return (
    <ModalShell onClose={onClose} title={filename}>
      {!data && <div className="text-slate-400">Loading…</div>}
      {data && (
        <div className="space-y-3">
          {fmYaml && (
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Frontmatter (optional YAML)</label>
              <textarea value={fmYaml} onChange={e => setFmYaml(e.target.value)} className={`${inputCls} h-32 font-mono text-xs`} spellCheck={false} />
            </div>
          )}
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Body</label>
            <textarea value={body} onChange={e => setBody(e.target.value)} className={`${inputCls} h-96 font-mono text-xs`} spellCheck={false} />
          </div>
          <div className="flex justify-end pt-2 border-t border-slate-800">
            <button onClick={save} disabled={saving} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30 disabled:opacity-50">
              <Save className="w-4 h-4" /> {saving ? 'Saving…' : 'Save'}
            </button>
          </div>
        </div>
      )}
    </ModalShell>
  );
}

// =========================================================================
// Quick Add Tab (with customer auto-detect)
// =========================================================================
function QuickAddTab({ toast }: { toast: any }) {
  const [text, setText] = useState('');
  const [creating, setCreating] = useState(false);
  const [customers, setCustomers] = useState<string[]>([]);
  const [detectedCustomer, setDetectedCustomer] = useState<string>('unassigned');
  const [priority, setPriority] = useState<'P0' | 'P1' | 'P2' | 'P3'>('P2');

  useEffect(() => {
    workmgrApi.listAccounts()
      .then(list => setCustomers(list.map(a => a.name)))
      .catch(() => {});
  }, []);

  // Auto-detect customer from paste content
  useEffect(() => {
    if (!text || customers.length === 0) { setDetectedCustomer('unassigned'); return; }
    const lower = text.toLowerCase();
    let best: string | null = null;
    for (const c of customers) {
      const cl = c.toLowerCase();
      // whole-word-ish match
      if (new RegExp(`\\b${cl.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')}\\b`, 'i').test(text) ||
          lower.includes(cl)) {
        // prefer longer match
        if (!best || c.length > best.length) best = c;
      }
    }
    if (best) setDetectedCustomer(best);
    else setDetectedCustomer('unassigned');
  }, [text, customers]);

  // Auto-detect priority keywords
  useEffect(() => {
    if (!text) return;
    const lower = text.toLowerCase();
    if (/\b(urgent|p0|critical|asap|blocker)\b/.test(lower)) setPriority('P0');
    else if (/\b(p1|today|end of day|eod)\b/.test(lower)) setPriority('P1');
    else if (/\b(p3|whenever|someday|later)\b/.test(lower)) setPriority('P3');
  }, [text]);

  const quickCreate = async () => {
    if (!text.trim()) return;
    setCreating(true);
    try {
      const firstLine = text.split('\n')[0].trim();
      const idBase = detectedCustomer !== 'unassigned' ? `${detectedCustomer.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-` : '';
      const idTitle = firstLine.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 50);
      const id = (idBase + idTitle) || `note-${Date.now()}`;
      const body = `## Context\n${text}\n\n## Definition of done\n- [ ] \n\n## Log\n- ${new Date().toISOString().slice(0, 10)} — Created via Quick Add.\n`;
      await workmgrApi.createTask({
        id,
        frontmatter: {
          id,
          title: firstLine.slice(0, 120),
          customer: detectedCustomer,
          priority,
          status: 'open',
          created: new Date().toISOString().slice(0, 10),
          owner: 'KB',
          tags: ['quick-add'],
        },
        body,
        status: 'open',
      });
      toast.success(`Created tasks/open/${id}.md`);
      setText('');
    } catch (e: any) {
      toast.error(`Failed: ${e.message}`);
    } finally { setCreating(false); }
  };

  return (
    <div className="max-w-3xl space-y-3">
      <p className="text-sm text-slate-400 flex items-center gap-1.5"><Sparkles className="w-4 h-4 text-amber-400" /> Paste anything — first line becomes the task title. Customer + priority auto-detected from content.</p>
      <textarea
        value={text}
        onChange={e => setText(e.target.value)}
        placeholder="Example:&#10;OCBC — Vipul asked us to sync on staging config drift by Thursday&#10;&#10;Details, links, whatever…"
        className={`${inputCls} h-64 text-sm`}
      />
      <div className="flex flex-wrap items-center gap-3 p-3 rounded-lg bg-slate-800/30 border border-slate-700/50">
        <Field label="Customer (auto-detected · override if wrong)">
          <input value={detectedCustomer} onChange={e => setDetectedCustomer(e.target.value)} className={inputCls} list="qa-customers" />
          <datalist id="qa-customers">
            {customers.map(c => <option key={c} value={c} />)}
          </datalist>
        </Field>
        <Field label="Priority">
          <select value={priority} onChange={e => setPriority(e.target.value as any)} className={inputCls}>
            <option>P0</option><option>P1</option><option>P2</option><option>P3</option>
          </select>
        </Field>
      </div>
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-500">Creates <code>tasks/open/&lt;slug&gt;.md</code>. Refine any field on the Tasks tab afterwards.</p>
        <button onClick={quickCreate} disabled={creating || !text.trim()} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30 disabled:opacity-50">
          <Plus className="w-4 h-4" /> {creating ? 'Creating…' : 'Create task'}
        </button>
      </div>
    </div>
  );
}

// =========================================================================
// Weekly Review Tab
// =========================================================================
function ReviewTab({ toast }: { toast: any }) {
  const [weekStart, setWeekStart] = useState<string>(() => {
    const d = new Date();
    const dow = d.getDay(); // 0=Sun
    const monOffset = dow === 0 ? -6 : 1 - dow;
    d.setDate(d.getDate() + monOffset);
    // local YYYY-MM-DD (avoid TZ shift from toISOString)
    const y = d.getFullYear(), m = String(d.getMonth() + 1).padStart(2, '0'), dd = String(d.getDate()).padStart(2, '0');
    return `${y}-${m}-${dd}`;
  });
  const [data, setData] = useState<WeeklyReview | null>(null);
  const [loading, setLoading] = useState(false);
  const [modalTask, setModalTask] = useState<{ status: TaskStatus; filename: string } | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    workmgrApi.getWeeklyReview(weekStart)
      .then(setData)
      .catch(e => toast.error(`Review load failed: ${e.message}`))
      .finally(() => setLoading(false));
  }, [weekStart, toast]);

  useEffect(() => { load(); }, [load]);

  const shiftWeek = (delta: number) => {
    const d = new Date(weekStart + 'T00:00:00');
    d.setDate(d.getDate() + delta * 7);
    const y = d.getFullYear(), m = String(d.getMonth() + 1).padStart(2, '0'), dd = String(d.getDate()).padStart(2, '0');
    setWeekStart(`${y}-${m}-${dd}`);
  };

  const addAsWin = async (task: TaskListItem) => {
    const fm = task.frontmatter;
    const suggestion = `**${fm.customer || 'Customer'}** — ${fm.title || task.filename}. _(from ${task.filename})_`;
    if (!confirm(`Append to wins-log.md?\n\n${suggestion}`)) return;
    try {
      await workmgrApi.appendWin(suggestion);
      toast.success('Win logged');
      load();
    } catch (e: any) {
      toast.error(`Failed: ${e.message}`);
    }
  };

  if (loading && !data) return <div className="text-slate-400">Loading review…</div>;
  if (!data) return null;

  const totalCompleted = data.counts.completed;

  return (
    <div id="weekly-review-content" className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <button onClick={() => shiftWeek(-1)} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-100">‹ Prev week</button>
          <div className="px-3 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-200">
            <span className="text-slate-500">Week of </span><strong className="text-slate-100">{data.week_start}</strong> <span className="text-slate-500">to {data.week_end}</span>
          </div>
          <button onClick={() => shiftWeek(1)} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-100">Next week ›</button>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => exportElementToPdf('weekly-review-content', `Weekly-Review-${data.week_start}.pdf`, toast)} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-slate-700/50 border border-slate-600 text-slate-200 rounded-md hover:bg-slate-700">
            <Download className="w-4 h-4" /> Export PDF
          </button>
          <button onClick={load} className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">
            <RefreshCw className="w-4 h-4" /> Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <StatCard label="Completed" value={data.counts.completed} icon={Award} color="text-emerald-400" />
        <StatCard label="Created" value={data.counts.created} icon={Plus} color="text-blue-400" />
        <StatCard label="Due this week" value={data.counts.due_in_window} icon={Calendar} color="text-amber-400" />
        <StatCard label="Overdue now" value={data.counts.overdue} icon={AlertTriangle} color="text-red-400" />
        <StatCard label="Waiting" value={data.counts.waiting} icon={Clock} color="text-purple-400" />
        <StatCard label="Wins logged" value={data.counts.wins_logged} icon={Trophy} color="text-emerald-300" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
          <h3 className="text-sm font-semibold text-slate-200 mb-3">✅ Completed — grouped by customer ({totalCompleted})</h3>
          <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-1">
            {Object.entries(data.completions_by_customer).length === 0 && <p className="text-xs text-slate-500 italic">Nothing completed this week yet.</p>}
            {Object.entries(data.completions_by_customer)
              .sort((a, b) => b[1].length - a[1].length)
              .map(([cust, tasks]) => (
                <div key={cust}>
                  <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">{cust} · {tasks.length}</div>
                  <div className="space-y-1.5">
                    {tasks.map(t => (
                      <TaskRow key={t.filename} task={t} onOpen={() => setModalTask({ status: t.status, filename: t.filename })} />
                    ))}
                  </div>
                </div>
              ))}
          </div>
        </div>

        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">💡 Suggested wins to log ({data.suggested_wins.length})</h3>
            <p className="text-xs text-slate-500 italic mb-2">Customer-facing tasks completed this week that aren't obviously in wins-log yet.</p>
            <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
              {data.suggested_wins.length === 0 && <p className="text-xs text-slate-500 italic">Nothing new to suggest.</p>}
              {data.suggested_wins.map(t => (
                <div key={t.filename} className="flex items-start gap-2 px-3 py-2 rounded bg-slate-800/60">
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-slate-200 truncate">{t.frontmatter.title || t.filename}</div>
                    <div className="text-xs text-slate-500">{t.frontmatter.customer} · {t.frontmatter.priority || ''}</div>
                  </div>
                  <button onClick={() => addAsWin(t)} className="flex-shrink-0 px-2 py-1 text-xs bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 rounded hover:bg-emerald-500/30">
                    + Win
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">🏆 Wins logged this week ({data.wins_this_week.length})</h3>
            <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
              {data.wins_this_week.length === 0 && <p className="text-xs text-slate-500 italic">None yet.</p>}
              {data.wins_this_week.map((w, i) => (
                <div key={i} className="text-xs px-3 py-2 rounded bg-slate-800/60">
                  <span className="text-emerald-400 font-medium mr-2">{w.date}</span>
                  <span className="text-slate-300">{w.text}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
          <h3 className="text-sm font-semibold text-slate-200 mb-3">🔥 Overdue now ({data.counts.overdue})</h3>
          <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
            {data.overdue.length === 0 && <p className="text-xs text-slate-500 italic">No overdue tasks — clean!</p>}
            {data.overdue.map(t => <TaskRow key={t.filename} task={t} onOpen={() => setModalTask({ status: t.status, filename: t.filename })} />)}
          </div>
        </div>
        <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50">
          <h3 className="text-sm font-semibold text-slate-200 mb-3">📞 1-1s this week ({data.one_on_ones_this_week.length})</h3>
          <div className="space-y-1.5">
            {data.one_on_ones_this_week.length === 0 && <p className="text-xs text-slate-500 italic">None scheduled.</p>}
            {data.one_on_ones_this_week.map(x => (
              <div key={x.filename} className="text-sm px-3 py-2 rounded bg-slate-800/60">
                <span className="text-blue-400 font-medium mr-2">{x.date}</span>
                <span className="text-slate-200 capitalize">{x.person.replace(/-/g, ' ')}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {modalTask && <TaskDetailModal initial={modalTask} onClose={() => setModalTask(null)} onSaved={load} />}
    </div>
  );
}

// PDF export helper (uses jsPDF + html2canvas already installed by other tools)
async function exportElementToPdf(elementId: string, filename: string, toast: any) {
  try {
    const [{ default: html2canvas }, jspdfMod] = await Promise.all([
      import('html2canvas'),
      import('jspdf'),
    ]);
    const jsPDF = (jspdfMod as any).jsPDF || (jspdfMod as any).default;
    const el = document.getElementById(elementId);
    if (!el) { toast.error('Nothing to export'); return; }
    toast.info?.('Rendering PDF…');
    const canvas = await html2canvas(el, { backgroundColor: '#0f172a', scale: 2, useCORS: true });
    const imgData = canvas.toDataURL('image/png');
    const pdf = new jsPDF({ orientation: 'portrait', unit: 'pt', format: 'a4' });
    const pageWidth = pdf.internal.pageSize.getWidth();
    const pageHeight = pdf.internal.pageSize.getHeight();
    const imgWidth = pageWidth - 40;
    const imgHeight = (canvas.height * imgWidth) / canvas.width;
    let heightLeft = imgHeight;
    let position = 20;
    pdf.addImage(imgData, 'PNG', 20, position, imgWidth, imgHeight);
    heightLeft -= (pageHeight - 40);
    while (heightLeft > 0) {
      pdf.addPage();
      position = 20 - (imgHeight - heightLeft);
      pdf.addImage(imgData, 'PNG', 20, position, imgWidth, imgHeight);
      heightLeft -= (pageHeight - 40);
    }
    pdf.save(filename);
    toast.success(`Saved ${filename}`);
  } catch (e: any) {
    toast.error(`PDF export failed: ${e.message}`);
  }
}

// =========================================================================
// Search Tab
// =========================================================================
function SearchTab() {
  const [q, setQ] = useState('');
  const [results, setResults] = useState<SearchHit[] | null>(null);
  const [loading, setLoading] = useState(false);
  const toast = useToast();

  const run = useCallback(async () => {
    if (!q.trim()) { setResults(null); return; }
    setLoading(true);
    try {
      const r = await workmgrApi.search(q.trim());
      setResults(r.results);
    } catch (e: any) {
      toast.error(`Search failed: ${e.message}`);
    } finally { setLoading(false); }
  }, [q, toast]);

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <input
          value={q}
          onChange={e => setQ(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') run(); }}
          placeholder="Search across tasks, accounts, career…"
          className={`${inputCls} flex-1`}
        />
        <button onClick={run} className="px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30">Search</button>
      </div>
      {loading && <div className="text-slate-400 text-sm">Searching…</div>}
      {results && (
        <div className="space-y-2">
          <div className="text-xs text-slate-500">{results.length} hits</div>
          {results.map((h, i) => (
            <div key={i} className="p-3 rounded bg-slate-800/40 border border-slate-700/50">
              <div className="flex items-center gap-2 text-xs mb-1">
                <span className="px-1.5 py-0.5 rounded bg-slate-700 text-slate-300">{h.kind}</span>
                <span className="text-slate-500">{h.path}</span>
              </div>
              <div className="text-sm text-slate-300">…{h.snippet}…</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// =========================================================================
// Small helpers / shared UI
// =========================================================================
const inputCls = 'w-full px-3 py-1.5 text-sm bg-slate-900 border border-slate-700 rounded-md text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none';

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-400 mb-1">{label}</label>
      {children}
    </div>
  );
}

function ModalShell({ title, subtitle, onClose, children }: { title: string; subtitle?: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 bg-slate-950/70 flex items-start justify-center p-4 overflow-y-auto">
      <div className="w-full max-w-4xl bg-slate-900 border border-slate-700 rounded-lg shadow-2xl mt-8">
        <div className="flex items-start justify-between p-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
            {subtitle && <p className="text-xs text-slate-500 mt-0.5">{subtitle}</p>}
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}

function QuickTextModal({ title, placeholder, onClose, onSubmit }: {
  title: string;
  placeholder: string;
  onClose: () => void;
  onSubmit: (text: string) => Promise<void>;
}) {
  const [text, setText] = useState('');
  const [saving, setSaving] = useState(false);
  return (
    <ModalShell onClose={onClose} title={title}>
      <textarea value={text} onChange={e => setText(e.target.value)} placeholder={placeholder} className={`${inputCls} h-40 text-sm`} />
      <div className="flex justify-end gap-2 mt-3 pt-3 border-t border-slate-800">
        <button onClick={onClose} className="px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
        <button disabled={!text.trim() || saving} onClick={async () => { setSaving(true); try { await onSubmit(text); onClose(); } finally { setSaving(false); } }} className="px-3 py-1.5 text-sm bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-md hover:bg-blue-500/30 disabled:opacity-50">
          {saving ? 'Saving…' : 'Save'}
        </button>
      </div>
    </ModalShell>
  );
}

// -------- Tiny YAML helpers (dumb: relies on browser JSON fallback) ---------
// Real yaml lib on the frontend would add ~30KB; we already handle YAML parsing
// on the backend. For the modal editor we keep a naive round-trip.
function prettyYaml(obj: any): string {
  if (!obj) return '';
  const lines: string[] = [];
  const write = (k: string, v: any) => {
    if (v === null || v === undefined) return;
    if (Array.isArray(v)) {
      if (v.length === 0) return;
      lines.push(`${k}:`);
      for (const item of v) lines.push(`  - ${String(item)}`);
    } else if (typeof v === 'object') {
      lines.push(`${k}:`);
      for (const [kk, vv] of Object.entries(v)) lines.push(`  ${kk}: ${JSON.stringify(vv)}`);
    } else {
      const s = String(v);
      if (/[:#\[\]{},'"&*!|>%@`]/.test(s) || s.includes('\n')) {
        lines.push(`${k}: ${JSON.stringify(s)}`);
      } else {
        lines.push(`${k}: ${s}`);
      }
    }
  };
  for (const [k, v] of Object.entries(obj)) write(k, v);
  return lines.join('\n');
}

function parseYaml(text: string): any {
  // Very small parser: handles top-level scalars and simple `- item` lists.
  // For complex edits, users should stick to formats our prettyYaml emits.
  const out: any = {};
  const lines = text.split(/\r?\n/);
  let lastKey: string | null = null;
  let listBuf: any[] | null = null;
  const flushList = () => { if (lastKey && listBuf) { out[lastKey] = listBuf; listBuf = null; } };
  for (const raw of lines) {
    const line = raw.replace(/\s+$/, '');
    if (!line.trim()) continue;
    if (line.startsWith('  - ')) {
      if (!listBuf) listBuf = [];
      listBuf.push(unquote(line.slice(4).trim()));
      continue;
    }
    flushList();
    const m = /^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.*)$/.exec(line);
    if (!m) continue;
    lastKey = m[1];
    const val = m[2];
    if (val === '' || val === '~') { listBuf = null; out[lastKey] = null; continue; }
    if (/^-?\d+(\.\d+)?$/.test(val)) { out[lastKey] = Number(val); continue; }
    if (val === 'true' || val === 'false') { out[lastKey] = val === 'true'; continue; }
    out[lastKey] = unquote(val);
  }
  flushList();
  // Clean nulls
  for (const k of Object.keys(out)) if (out[k] === null) delete out[k];
  return out;
}

function unquote(s: string): string {
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    try { return JSON.parse(s.replace(/^'/, '"').replace(/'$/, '"')); } catch { return s.slice(1, -1); }
  }
  return s;
}
