/**
 * Work Manager — types & API client.
 * Backed by the /api/workmgr/* Vite middleware which reads/writes markdown
 * files under `mywork/`.
 */

export type TaskStatus = 'open' | 'waiting' | 'done';

export interface Subtask { text: string; done: boolean; done_at?: string; }
export interface TaskLink { label?: string; url: string; }
export interface TaskFileRef { label?: string; path: string; }

export interface TaskFrontmatter {
  id?: string;
  title?: string;
  customer?: string;
  priority?: 'P0' | 'P1' | 'P2' | 'P3';
  status?: TaskStatus;
  created?: string;
  updated?: string; // "YYYY-MM-DD HH:MM" — bumped on every change
  start?: string;
  due?: string;
  reminder?: string;
  completed?: string;
  owner?: string;
  estimate?: string;
  waiting_on?: string;
  artifacts?: string[];
  files?: TaskFileRef[];
  links?: TaskLink[];
  subtasks?: Subtask[];
  related_tasks?: string[];
  blocked_by?: string[];
  tags?: string[];
  outcome?: string;
  [key: string]: any;
}

export interface TaskListItem {
  filename: string;
  status: TaskStatus;
  frontmatter: TaskFrontmatter;
  body_preview: string;
  last_activity?: string; // "YYYY-MM-DD HH:MM" — newest activity, for ordering + display
}

export interface TaskDetail {
  filename: string;
  status: TaskStatus;
  frontmatter: TaskFrontmatter;
  body: string;
}

export interface TasksResponse {
  open: TaskListItem[];
  waiting: TaskListItem[];
  done: TaskListItem[];
}

export interface AccountFrontmatter {
  customer?: string;
  region?: string;
  status?: string;
  spoc?: string;
  f5_owner?: string;
  products?: string[];
  last_touched?: string;
  freshness_window_days?: number;
  [key: string]: any;
}

export interface AccountSummary {
  name: string;
  overview: AccountFrontmatter | null;
  overview_body: string | null;
  has_overview: boolean;
}

export interface AccountFile {
  name: string;
  path: string;
  type: 'file' | 'dir';
  size?: number;
  modified?: string;
}

export interface AccountDetail extends AccountSummary {
  files: AccountFile[];
  tasks: {
    open: TaskListItem[];
    waiting: TaskListItem[];
    done: TaskListItem[];
  };
}

export interface WinEntry { date: string; text: string; }
export interface WinsResponse { raw: string; entries: WinEntry[]; }

export interface OneOnOneSummary { filename: string; date: string; person: string; }

export interface TimelineItem {
  date: string;
  time?: string; // real captured "HH:MM", when known
  kind: 'task-created' | 'task-completed' | 'task-due' | 'history' | 'file' | 'win' | 'update' | 'task-log';
  label: string;
  detail?: string;
  body?: string; // full text (e.g. the whole update post body), for expanded views
  path?: string;
  customer?: string;
}

export interface AccountConfig {
  products: string[];
  config: Record<string, Record<string, any>>;
  details: Record<string, any>;
  updated_at?: string;
}

export interface UpdateEntry { date: string; customer: string; text: string; }

export interface UpdatePostFm {
  id?: string; type?: string; title?: string; date?: string; source?: string;
  account?: string; importance?: string;
  tags?: string[]; links?: TaskLink[]; files?: TaskFileRef[];
  [key: string]: any;
}
export interface UpdatePost {
  filename: string;
  frontmatter: UpdatePostFm;
  body?: string;
  body_preview?: string;
}

export interface WorkPatternFm {
  id?: string; category?: string; trigger?: string; action?: string;
  effectiveness?: string; uses?: number; created?: string; last_used?: string;
  tools?: string[]; tags?: string[];
  [key: string]: any;
}
export interface WorkPattern { filename: string; frontmatter: WorkPatternFm; body?: string; }

export interface LearningFm {
  id?: string; title?: string; date?: string; time?: string;
  product?: string; feature?: string; platform?: string; environment?: string;
  topic?: string; subtopic?: string; category?: string; source?: string;
  tags?: string[]; links?: TaskLink[];
  [key: string]: any;
}
export interface Learning { filename: string; frontmatter: LearningFm; body?: string; body_preview?: string; }

export type LearningTaskStatus = 'backlog' | 'in_progress' | 'done';
export interface LearningTaskFm {
  id?: string; title?: string;
  type?: string;      // Course / Topic / Skill / Book / Video / Certification / …
  status?: LearningTaskStatus;
  priority?: 'High' | 'Medium' | 'Low';
  product?: string; topic?: string;   // shared taxonomy with Learnings
  provider?: string;  // Coursera / Udemy / F5 University / YouTube / …
  url?: string;       // link to the course / resource
  target_date?: string;
  progress?: number;  // 0–100
  created?: string; updated?: string; completed?: string;
  tags?: string[]; links?: TaskLink[];
  [key: string]: any;
}
export interface LearningTask { filename: string; frontmatter: LearningTaskFm; body?: string; body_preview?: string; }

export interface JournalFm {
  id?: string; title?: string; date?: string; time?: string;
  kind?: string;   // Idea / Reflection / Insight / Question / Feeling / Intention / …
  mood?: string;   // mental / emotional state while writing
  theme?: string;  // what this thought orbits — free text
  tags?: string[]; links?: TaskLink[];
  [key: string]: any;
}
export interface JournalEntry { filename: string; frontmatter: JournalFm; body?: string; body_preview?: string; }

export interface SummaryResponse {
  counts: { open: number; waiting: number; done_last_7: number; overdue: number; };
  overdue: TaskListItem[];
  due_this_week: TaskListItem[];
  top_5: TaskListItem[];
  recent_wins: WinEntry[];
  upcoming_1on1s: OneOnOneSummary[];
  counts_by_customer: Record<string, number>;
  generated_at: string;
  mywork_root: string;
}

export interface SearchHit { path: string; kind: string; snippet: string; }
export interface SearchResponse { term: string; results: SearchHit[]; }

export interface WeeklyReview {
  week_start: string;
  week_end: string;
  counts: {
    completed: number;
    created: number;
    overdue: number;
    due_in_window: number;
    waiting: number;
    wins_logged: number;
  };
  completed_this_week: TaskListItem[];
  created_this_week: TaskListItem[];
  overdue: TaskListItem[];
  due_in_window: TaskListItem[];
  completions_by_customer: Record<string, TaskListItem[]>;
  wins_this_week: WinEntry[];
  one_on_ones_this_week: OneOnOneSummary[];
  suggested_wins: TaskListItem[];
}

const BASE = '/api/workmgr';

async function j<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export const workmgrApi = {
  health: () => j<any>(`${BASE}/health`),
  summary: () => j<SummaryResponse>(`${BASE}/summary`),

  // Tasks
  listTasks: () => j<TasksResponse>(`${BASE}/tasks`),
  getTask: (status: TaskStatus, filename: string) =>
    j<TaskDetail>(`${BASE}/tasks/${status}/${encodeURIComponent(filename)}`),
  createTask: (input: { id: string; frontmatter: TaskFrontmatter; body: string; status?: TaskStatus }) =>
    j<{ filename: string; status: TaskStatus }>(`${BASE}/tasks`, {
      method: 'POST',
      body: JSON.stringify(input),
    }),
  updateTask: (status: TaskStatus, filename: string, patch: { frontmatter?: TaskFrontmatter; body?: string }) =>
    j<TaskDetail>(`${BASE}/tasks/${status}/${encodeURIComponent(filename)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),
  moveTask: (fromStatus: TaskStatus, filename: string, toStatus: TaskStatus, extra: TaskFrontmatter = {}) =>
    j<{ filename: string; status: TaskStatus }>(`${BASE}/tasks/${fromStatus}/${encodeURIComponent(filename)}/move`, {
      method: 'POST',
      body: JSON.stringify({ to: toStatus, frontmatter: extra }),
    }),

  // Quick updates
  getUpdates: () => j<UpdateEntry[]>(`${BASE}/updates`),
  addUpdate: (input: { customer: string; text: string; date?: string }) =>
    j<{ ok: true; target: string }>(`${BASE}/updates`, { method: 'POST', body: JSON.stringify(input) }),

  // Rich update feed (updates/ folder)
  listUpdatePosts: () => j<UpdatePost[]>(`${BASE}/updates/items`),
  getUpdatePost: (filename: string) => j<UpdatePost>(`${BASE}/updates/items/${encodeURIComponent(filename)}`),
  createUpdatePost: (input: { frontmatter: UpdatePostFm; body?: string }) =>
    j<{ filename: string }>(`${BASE}/updates/items`, { method: 'POST', body: JSON.stringify(input) }),
  patchUpdatePost: (filename: string, patch: { frontmatter?: UpdatePostFm; body?: string }) =>
    j<UpdatePost>(`${BASE}/updates/items/${encodeURIComponent(filename)}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  deleteUpdatePost: (filename: string) =>
    j<{ ok: true }>(`${BASE}/updates/items/${encodeURIComponent(filename)}`, { method: 'DELETE' }),

  // Work patterns
  listWorkPatterns: () => j<WorkPattern[]>(`${BASE}/patterns`),
  getWorkPattern: (filename: string) => j<WorkPattern>(`${BASE}/patterns/${encodeURIComponent(filename)}`),
  createWorkPattern: (input: { frontmatter: WorkPatternFm; body?: string }) =>
    j<{ filename: string }>(`${BASE}/patterns`, { method: 'POST', body: JSON.stringify(input) }),
  patchWorkPattern: (filename: string, patch: { frontmatter?: WorkPatternFm; body?: string }) =>
    j<WorkPattern>(`${BASE}/patterns/${encodeURIComponent(filename)}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  deleteWorkPattern: (filename: string) =>
    j<{ ok: true }>(`${BASE}/patterns/${encodeURIComponent(filename)}`, { method: 'DELETE' }),

  // Learnings knowledge base
  listLearnings: () => j<Learning[]>(`${BASE}/learnings`),
  getLearning: (filename: string) => j<Learning>(`${BASE}/learnings/${encodeURIComponent(filename)}`),
  createLearning: (input: { frontmatter: LearningFm; body?: string }) =>
    j<{ filename: string }>(`${BASE}/learnings`, { method: 'POST', body: JSON.stringify(input) }),
  patchLearning: (filename: string, patch: { frontmatter?: LearningFm; body?: string }) =>
    j<Learning>(`${BASE}/learnings/${encodeURIComponent(filename)}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  deleteLearning: (filename: string) =>
    j<{ ok: true }>(`${BASE}/learnings/${encodeURIComponent(filename)}`, { method: 'DELETE' }),

  // Learning Queue (things to learn / courses / topics to explore)
  listLearningTasks: () => j<LearningTask[]>(`${BASE}/learning-tasks`),
  getLearningTask: (filename: string) => j<LearningTask>(`${BASE}/learning-tasks/${encodeURIComponent(filename)}`),
  createLearningTask: (input: { frontmatter: LearningTaskFm; body?: string }) =>
    j<{ filename: string }>(`${BASE}/learning-tasks`, { method: 'POST', body: JSON.stringify(input) }),
  patchLearningTask: (filename: string, patch: { frontmatter?: LearningTaskFm; body?: string }) =>
    j<LearningTask>(`${BASE}/learning-tasks/${encodeURIComponent(filename)}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  deleteLearningTask: (filename: string) =>
    j<{ ok: true }>(`${BASE}/learning-tasks/${encodeURIComponent(filename)}`, { method: 'DELETE' }),

  // Thought Journal
  listJournal: () => j<JournalEntry[]>(`${BASE}/journal`),
  getJournal: (filename: string) => j<JournalEntry>(`${BASE}/journal/${encodeURIComponent(filename)}`),
  createJournal: (input: { frontmatter: JournalFm; body?: string }) =>
    j<{ filename: string }>(`${BASE}/journal`, { method: 'POST', body: JSON.stringify(input) }),
  patchJournal: (filename: string, patch: { frontmatter?: JournalFm; body?: string }) =>
    j<JournalEntry>(`${BASE}/journal/${encodeURIComponent(filename)}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  deleteJournal: (filename: string) =>
    j<{ ok: true }>(`${BASE}/journal/${encodeURIComponent(filename)}`, { method: 'DELETE' }),

  // Accounts
  listAccounts: () => j<AccountSummary[]>(`${BASE}/accounts`),
  createAccount: (input: { name: string; customer?: string; region?: string; status?: string; products?: string[]; freshness_window_days?: number }) =>
    j<{ name: string }>(`${BASE}/accounts`, { method: 'POST', body: JSON.stringify(input) }),
  getAccount: (name: string) => j<AccountDetail>(`${BASE}/accounts/${encodeURIComponent(name)}`),
  appendAccountHistory: (name: string, entry: string) =>
    j<{ ok: true }>(`${BASE}/accounts/${encodeURIComponent(name)}/history`, {
      method: 'POST',
      body: JSON.stringify({ entry }),
    }),
  getAccountTimeline: (name: string) =>
    j<TimelineItem[]>(`${BASE}/accounts/${encodeURIComponent(name)}/timeline`),
  getGlobalTimeline: (limit = 800) =>
    j<TimelineItem[]>(`${BASE}/timeline?limit=${limit}`),
  getAccountConfig: (name: string) =>
    j<AccountConfig>(`${BASE}/accounts/${encodeURIComponent(name)}/config`),
  saveAccountConfig: (name: string, data: Partial<AccountConfig>) =>
    j<AccountConfig>(`${BASE}/accounts/${encodeURIComponent(name)}/config`, {
      method: 'PUT', body: JSON.stringify(data),
    }),

  // Career
  getWins: () => j<WinsResponse>(`${BASE}/career/wins`),
  appendWin: (entry: string) =>
    j<{ ok: true }>(`${BASE}/career/wins`, { method: 'POST', body: JSON.stringify({ entry }) }),
  listOneOnOnes: () => j<OneOnOneSummary[]>(`${BASE}/career/1-1s`),
  getOneOnOne: (filename: string) => j<{ frontmatter: any; body: string }>(`${BASE}/career/1-1s/${encodeURIComponent(filename)}`),
  updateOneOnOne: (filename: string, patch: { frontmatter?: any; body?: string }) =>
    j<{ frontmatter: any; body: string }>(`${BASE}/career/1-1s/${encodeURIComponent(filename)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),
  createOneOnOne: (input: { date: string; person: string; purpose?: string; agenda?: string[] }) =>
    j<{ filename: string }>(`${BASE}/career/1-1s`, { method: 'POST', body: JSON.stringify(input) }),
  appendSponsorTouchpoint: (entry: { date?: string; person: string; topic: string; outcome?: string; next_step?: string }) =>
    j<{ ok: true }>(`${BASE}/career/sponsors/touchpoint`, { method: 'POST', body: JSON.stringify(entry) }),
  getPromotion: () => j<Record<string, { exists: boolean; raw?: string; error?: string }>>(`${BASE}/career/promotion`),
  listCareerDocs: () => j<string[]>(`${BASE}/career/docs`),
  getCareerDoc: (name: string) => j<{ name: string; content: string }>(`${BASE}/career/doc/${encodeURIComponent(name)}`),
  saveCareerDoc: (name: string, content: string) =>
    j<{ ok: true }>(`${BASE}/career/doc/${encodeURIComponent(name)}`, { method: 'PUT', body: JSON.stringify({ content }) }),

  // Search
  search: (q: string) => j<SearchResponse>(`${BASE}/search?q=${encodeURIComponent(q)}`),

  // Weekly Review
  getWeeklyReview: (weekStart?: string) => j<WeeklyReview>(`${BASE}/review/week${weekStart ? `?start=${encodeURIComponent(weekStart)}` : ''}`),
};

// -------------------------- UI helpers --------------------------
export const PRIORITY_COLORS: Record<string, string> = {
  P0: 'bg-red-500/20 text-red-300 border-red-500/40',
  P1: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
  P2: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
  P3: 'bg-slate-500/20 text-slate-300 border-slate-500/40',
};

export const STATUS_COLORS: Record<TaskStatus, string> = {
  open: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
  waiting: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
  done: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
};

export function daysUntil(dateStr: string | undefined): number | null {
  if (!dateStr) return null;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const due = new Date(dateStr + 'T00:00:00');
  const diff = Math.floor((due.getTime() - today.getTime()) / 86400000);
  return diff;
}
