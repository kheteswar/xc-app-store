/**
 * Work Manager Vite Plugin
 *
 * Provides a filesystem-backed backend for the Work Manager (WorkMgr) app.
 * All data lives in `mywork/` (the parent folder of `xc-app-store/`).
 * The GUI and Copilot chat operate on the same files — no separate DB.
 *
 * Endpoints (mounted at /api/workmgr/*):
 *
 *   Tasks
 *     GET    /api/workmgr/tasks                      → List all tasks (grouped by status)
 *     GET    /api/workmgr/tasks/:status/:filename    → Read single task
 *     POST   /api/workmgr/tasks                      → Create new task
 *     PATCH  /api/workmgr/tasks/:status/:filename    → Update task (frontmatter + body)
 *     POST   /api/workmgr/tasks/:status/:filename/move  → Move to open/waiting/done
 *
 *   Accounts
 *     GET    /api/workmgr/accounts                   → List all customer folders
 *     GET    /api/workmgr/accounts/:name             → Read customer overview + files
 *     POST   /api/workmgr/accounts/:name/history     → Append history entry
 *
 *   Career
 *     GET    /api/workmgr/career/wins                → Read wins-log
 *     POST   /api/workmgr/career/wins                → Append manual win entry
 *     GET    /api/workmgr/career/1-1s                → List 1-1 notes
 *     GET    /api/workmgr/career/1-1s/:filename      → Read one 1-1 note
 *     PATCH  /api/workmgr/career/1-1s/:filename      → Update 1-1 note
 *     GET    /api/workmgr/career/promotion           → Snapshot from promotion-*.md files
 *
 *   Search + Meta
 *     GET    /api/workmgr/search?q=<term>            → Global full-text search
 *     GET    /api/workmgr/summary                    → Dashboard summary counts
 *     GET    /api/workmgr/health                     → Health check
 */

import type { Plugin } from 'vite';
import type { IncomingMessage, ServerResponse } from 'http';
import { promises as fs } from 'node:fs';
import * as fsSync from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as os from 'node:os';
import * as yaml from 'js-yaml';

// -------------------------------------------------------------------------
// Paths
// -------------------------------------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Root of the workspace. server/ → xc-app-store/ → mywork/ */
const MYWORK_ROOT = path.resolve(__dirname, '..', '..');
const TASKS_DIR = path.join(MYWORK_ROOT, 'tasks');
const ACCOUNTS_DIR = path.join(MYWORK_ROOT, 'Accounts');
const CAREER_DIR = path.join(MYWORK_ROOT, 'Career');
const ONE_ON_ONE_DIR = path.join(CAREER_DIR, '1-1-notes');
const UPDATES_LOG = path.join(MYWORK_ROOT, 'updates-log.md');

/** Audit log lives outside mywork/ to keep customer data separate */
const AUDIT_DIR = path.join(os.homedir(), '.config', 'workmgr');
const AUDIT_LOG = path.join(AUDIT_DIR, 'audit.log');

// -------------------------------------------------------------------------
// HTTP helpers
// -------------------------------------------------------------------------
function parseBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk: string) => { body += chunk; });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function sendJSON(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(JSON.stringify(data));
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJSON(res, status, { error: message });
}

function getPathSegments(url: string): string[] {
  const clean = url.split('?')[0];
  return clean.replace(/^\//, '').replace(/\/$/, '').split('/').filter(Boolean);
}

function parseQuery(url: string): Record<string, string> {
  const q = url.split('?')[1];
  if (!q) return {};
  const params: Record<string, string> = {};
  for (const part of q.split('&')) {
    const [k, v = ''] = part.split('=');
    params[decodeURIComponent(k)] = decodeURIComponent(v);
  }
  return params;
}

// -------------------------------------------------------------------------
// Markdown frontmatter helpers
// -------------------------------------------------------------------------
export interface Frontmatter {
  [key: string]: any;
}

export interface ParsedMarkdown {
  frontmatter: Frontmatter;
  body: string;
}

function parseFrontmatter(text: string): ParsedMarkdown {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  if (!match) return { frontmatter: {}, body: text };
  try {
    const fm = (yaml.load(match[1]) as Frontmatter) || {};
    return { frontmatter: normalizeDates(fm), body: match[2] || '' };
  } catch {
    return { frontmatter: {}, body: text };
  }
}

/** js-yaml parses `2026-07-13` as JS Date. Convert back to YYYY-MM-DD strings
 *  for consistent handling and clean re-serialization. */
function normalizeDates(fm: Frontmatter): Frontmatter {
  const out: Frontmatter = {};
  for (const [k, v] of Object.entries(fm)) {
    if (v instanceof Date) {
      out[k] = v.toISOString().slice(0, 10);
    } else if (Array.isArray(v)) {
      out[k] = v.map(item => item instanceof Date ? item.toISOString().slice(0, 10) : item);
    } else {
      out[k] = v;
    }
  }
  return out;
}

function serializeFrontmatter(fm: Frontmatter, body: string): string {
  const yamlStr = yaml.dump(fm, { lineWidth: 120, quotingType: '"', forceQuotes: false }).trimEnd();
  return `---\n${yamlStr}\n---\n\n${body.replace(/^\n+/, '')}`;
}

// -------------------------------------------------------------------------
// Audit logging
// -------------------------------------------------------------------------
async function ensureAuditDir(): Promise<void> {
  try { await fs.mkdir(AUDIT_DIR, { recursive: true }); } catch { /* ignore */ }
}

async function audit(action: string, target: string, meta: Record<string, any> = {}): Promise<void> {
  await ensureAuditDir();
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    action,
    target,
    ...meta,
  }) + '\n';
  try { await fs.appendFile(AUDIT_LOG, line, 'utf8'); } catch { /* ignore */ }
}

// -------------------------------------------------------------------------
// Filesystem safety
// -------------------------------------------------------------------------
function safeJoin(base: string, ...segments: string[]): string {
  const resolved = path.resolve(base, ...segments);
  // prevent path traversal
  if (!resolved.startsWith(path.resolve(base))) {
    throw new Error('Path traversal attempt blocked');
  }
  return resolved;
}

// -------------------------------------------------------------------------
// Tasks
// -------------------------------------------------------------------------
type TaskStatus = 'open' | 'waiting' | 'done';
const TASK_STATUSES: TaskStatus[] = ['open', 'waiting', 'done'];

interface TaskListItem {
  filename: string;
  status: TaskStatus;
  frontmatter: Frontmatter;
  body_preview: string;
  last_activity?: string; // "YYYY-MM-DD HH:MM" — newest of log/updated/created, for ordering
}

async function readTaskFile(status: TaskStatus, filename: string): Promise<ParsedMarkdown & { filename: string; status: TaskStatus }> {
  const fp = safeJoin(TASKS_DIR, status, filename);
  const raw = await fs.readFile(fp, 'utf8');
  const parsed = parseFrontmatter(raw);
  return { ...parsed, filename, status };
}

async function listTasksInStatus(status: TaskStatus): Promise<TaskListItem[]> {
  const dir = safeJoin(TASKS_DIR, status);
  let entries: string[] = [];
  try { entries = await fs.readdir(dir); } catch { return []; }

  const results: TaskListItem[] = [];
  for (const entry of entries) {
    if (!entry.endsWith('.md') || entry === 'README.md' || entry === 'BOARD.md') continue;
    try {
      const parsed = await readTaskFile(status, entry);
      results.push({
        filename: entry,
        status,
        frontmatter: parsed.frontmatter,
        body_preview: parsed.body.slice(0, 200),
        last_activity: taskActivityTs(parsed.frontmatter, parsed.body),
      });
    } catch {
      // skip unreadable files
    }
  }
  // Newest activity first (day + time), so recently touched tasks rise to the top.
  results.sort((a, b) => String(b.last_activity || '').localeCompare(String(a.last_activity || '')));
  return results;
}

async function listAllTasks(): Promise<Record<TaskStatus, TaskListItem[]>> {
  const [open, waiting, done] = await Promise.all(TASK_STATUSES.map(listTasksInStatus));
  return { open, waiting, done };
}

async function createTask(input: { id: string; frontmatter: Frontmatter; body: string; status?: TaskStatus }): Promise<{ filename: string; status: TaskStatus }> {
  const status: TaskStatus = input.status || 'open';
  const id = input.id.trim();
  if (!id) throw new Error('Task id is required');
  if (!/^[a-z0-9][a-z0-9-]*$/.test(id)) throw new Error('id must be lowercase kebab-case (a-z, 0-9, -)');
  const filename = `${id}.md`;
  const fp = safeJoin(TASKS_DIR, status, filename);
  try {
    await fs.access(fp);
    throw new Error(`Task ${filename} already exists in ${status}/`);
  } catch (e: any) {
    if (e.code !== 'ENOENT' && !String(e.message).includes('already exists')) throw e;
    if (String(e.message).includes('already exists')) throw e;
  }
  const fm: Frontmatter = {
    id,
    ...input.frontmatter,
    status,
    created: input.frontmatter.created || new Date().toISOString().slice(0, 10),
    updated: nowStamp(),
  };
  const content = serializeFrontmatter(fm, input.body || '');
  await fs.writeFile(fp, content, 'utf8');
  await audit('task.create', fp, { id, status });
  return { filename, status };
}

async function updateTask(status: TaskStatus, filename: string, updates: { frontmatter?: Frontmatter; body?: string }): Promise<void> {
  const fp = safeJoin(TASKS_DIR, status, filename);
  const raw = await fs.readFile(fp, 'utf8');
  const parsed = parseFrontmatter(raw);
  const merged: Frontmatter = { ...parsed.frontmatter, ...(updates.frontmatter || {}), updated: nowStamp() };
  const body = updates.body !== undefined ? updates.body : parsed.body;
  const content = serializeFrontmatter(merged, body);
  await fs.writeFile(fp, content, 'utf8');
  await audit('task.update', fp, { filename, status });
}

/** Locate a `## <heading>` section span within a markdown doc (index-based, robust). */
function sectionSpan(raw: string, heading: string): { start: number; bodyStart: number; end: number } | null {
  const re = new RegExp(`^##\\s+${heading}\\b[^\\n]*\\n`, 'mi');
  const m = re.exec(raw);
  if (!m) return null;
  const start = m.index;
  const bodyStart = m.index + m[0].length;
  const after = raw.slice(bodyStart);
  const nextH = after.search(/\n##\s/);
  const end = nextH === -1 ? raw.length : bodyStart + nextH;
  return { start, bodyStart, end };
}

/** Append a dated activity line to a task's `## Log` section (creates it if missing). */
/** Local wall-clock stamp "YYYY-MM-DD HH:MM" for ordered activity logging. */
function nowStamp(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** Local wall-clock "HH:MM". */
function nowTime(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** Newest activity timestamp ("YYYY-MM-DD HH:MM") for a task, from its Log lines / updated / created. */
function taskActivityTs(fm: Frontmatter, body: string): string {
  const cands: string[] = [];
  const push = (d?: string, t?: string) => {
    const dm = /^(\d{4}-\d{2}-\d{2})/.exec(String(d || ''));
    if (dm) cands.push(`${dm[1]} ${(t || '00:00').slice(0, 5)}`);
  };
  const re = /^-\s+(?:\*\*)?(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}))?/gm; // "- YYYY-MM-DD[ HH:MM] — ..."
  let m: RegExpExecArray | null;
  while ((m = re.exec(body))) push(m[1], m[2]);
  const um = /^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}))?/.exec(String(fm.updated || ''));
  if (um) push(um[1], um[2]);
  push(String(fm.created || ''), undefined);
  cands.sort();
  return cands.length ? cands[cands.length - 1] : '';
}

async function appendTaskLog(status: TaskStatus, filename: string, entry: string): Promise<void> {
  const fp = safeJoin(TASKS_DIR, status, filename);
  let raw: string;
  try { raw = await fs.readFile(fp, 'utf8'); } catch { return; }
  const parsed = parseFrontmatter(raw);
  let body = parsed.body;
  const line = `- ${nowStamp()} — ${entry.trim()}`;
  const span = sectionSpan(body, 'Log');
  if (span) {
    const before = body.slice(0, span.end).replace(/\s*$/, '');
    const after = body.slice(span.end);
    body = `${before}\n${line}\n${after}`;
  } else {
    body = body.replace(/\s*$/, '') + `\n\n## Log\n${line}\n`;
  }
  // Re-serialize so the activity timestamp also bumps the task's `updated` field.
  const fm: Frontmatter = { ...parsed.frontmatter, updated: nowStamp() };
  await fs.writeFile(fp, serializeFrontmatter(fm, body), 'utf8');
}

async function moveTask(fromStatus: TaskStatus, filename: string, toStatus: TaskStatus, extraFrontmatter: Frontmatter = {}): Promise<{ filename: string; status: TaskStatus }> {
  if (fromStatus === toStatus) return { filename, status: toStatus };
  const src = safeJoin(TASKS_DIR, fromStatus, filename);
  const dst = safeJoin(TASKS_DIR, toStatus, filename);
  const raw = await fs.readFile(src, 'utf8');
  const parsed = parseFrontmatter(raw);
  const merged: Frontmatter = {
    ...parsed.frontmatter,
    ...extraFrontmatter,
    status: toStatus,
    updated: nowStamp(),
  };
  if (toStatus === 'done' && !merged.completed) {
    merged.completed = new Date().toISOString().slice(0, 10);
  }
  const content = serializeFrontmatter(merged, parsed.body);
  await fs.writeFile(dst, content, 'utf8');
  await fs.unlink(src);
  await audit('task.move', dst, { filename, from: fromStatus, to: toStatus });
  const note = extraFrontmatter.waiting_on ? `Status: ${fromStatus} → ${toStatus} (waiting on ${extraFrontmatter.waiting_on})` : `Status: ${fromStatus} → ${toStatus}`;
  await appendTaskLog(toStatus, filename, note);
  return { filename, status: toStatus };
}

// -------------------------------------------------------------------------
// Accounts
// -------------------------------------------------------------------------
interface AccountSummary {
  name: string;
  overview: Frontmatter | null;
  overview_body: string | null;
  has_overview: boolean;
}

async function listAccounts(): Promise<AccountSummary[]> {
  let entries: import('node:fs').Dirent[] = [];
  try {
    entries = await fs.readdir(ACCOUNTS_DIR, { withFileTypes: true });
  } catch {
    return [];
  }
  const results: AccountSummary[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith('.')) continue;
    const overviewPath = safeJoin(ACCOUNTS_DIR, entry.name, '00-overview.md');
    let overview: Frontmatter | null = null;
    let body: string | null = null;
    let has = false;
    try {
      const raw = await fs.readFile(overviewPath, 'utf8');
      const parsed = parseFrontmatter(raw);
      overview = parsed.frontmatter;
      body = parsed.body;
      has = true;
    } catch { /* no overview */ }
    results.push({ name: entry.name, overview, overview_body: body, has_overview: has });
  }
  return results.sort((a, b) => a.name.localeCompare(b.name));
}

interface FileNode {
  name: string;
  path: string;
  type: 'file' | 'dir';
  size?: number;
  modified?: string;
}

async function listAccountFiles(name: string, subdir = ''): Promise<FileNode[]> {
  const dir = safeJoin(ACCOUNTS_DIR, name, subdir);
  let entries: import('node:fs').Dirent[] = [];
  try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return []; }
  const results: FileNode[] = [];
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    const full = path.join(dir, entry.name);
    const rel = path.relative(safeJoin(ACCOUNTS_DIR, name), full);
    if (entry.isDirectory()) {
      results.push({ name: entry.name, path: rel, type: 'dir' });
    } else {
      let size: number | undefined;
      let modified: string | undefined;
      try {
        const stat = await fs.stat(full);
        size = stat.size;
        modified = stat.mtime.toISOString();
      } catch { /* ignore */ }
      results.push({ name: entry.name, path: rel, type: 'file', size, modified });
    }
  }
  return results.sort((a, b) => {
    if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}

async function getAccountDetail(name: string): Promise<any> {
  const summaries = await listAccounts();
  const summary = summaries.find(a => a.name === name);
  if (!summary) throw new Error(`Account not found: ${name}`);
  const files = await listAccountFiles(name);
  const allTasks = await listAllTasks();
  const flat = [...allTasks.open, ...allTasks.waiting, ...allTasks.done];
  const relatedTasks = flat.filter(t => {
    const c = String(t.frontmatter.customer || '').toLowerCase();
    return c === name.toLowerCase();
  });
  return {
    ...summary,
    files,
    tasks: {
      open: relatedTasks.filter(t => t.status === 'open'),
      waiting: relatedTasks.filter(t => t.status === 'waiting'),
      done: relatedTasks.filter(t => t.status === 'done').slice(0, 20),
    },
  };
}

async function appendAccountHistory(name: string, entry: string, dateOverride?: string): Promise<void> {
  const fp = safeJoin(ACCOUNTS_DIR, name, '00-overview.md');
  let raw: string;
  try { raw = await fs.readFile(fp, 'utf8'); } catch { throw new Error(`No 00-overview.md for ${name}`); }
  const date = (dateOverride && /^\d{4}-\d{2}-\d{2}$/.test(dateOverride)) ? dateOverride : new Date().toISOString().slice(0, 10);
  // Stamp date + time so the timeline orders same-day entries precisely, and
  // preserve the full multi-line text: the first line sits on the dated bullet,
  // any further lines are indented 2 spaces so they stay part of this list item
  // (and are recovered verbatim by parseHistoryEntries).
  const time = nowTime();
  const [first, ...rest] = entry.trim().split('\n');
  const continuation = rest.map(l => (l.trim() ? `  ${l}` : '')).join('\n');
  const line = `- **${date} ${time}** — ${first}${rest.length ? '\n' + continuation : ''}`;
  // Insert under a "## History" heading if present (newest first); otherwise append a new section
  if (/^##\s+History\b/mi.test(raw)) {
    raw = raw.replace(/(^##\s+History[^\n]*\n)/mi, `$1${line}\n`);
  } else {
    raw = raw.trimEnd() + `\n\n## History\n${line}\n`;
  }
  await fs.writeFile(fp, raw, 'utf8');
  await audit('account.history.append', fp, { name, entry });
}

/** Build a chronological timeline for a customer, aggregating:
 *  - task events (created + completed + due-based milestones)
 *  - lines from the ## History section of 00-overview.md
 *  - file mtimes under Accounts/<name>/
 */
interface TimelineItem {
  date: string;
  time?: string; // real captured "HH:MM", when known (shown next to the entry)
  kind: 'task-created' | 'task-completed' | 'task-due' | 'history' | 'file' | 'win' | 'update' | 'task-log';
  label: string;
  detail?: string;
  body?: string; // full text (e.g. the whole update post body), for expanded views
  path?: string;
  ts?: string;   // full sortable timestamp "YYYY-MM-DD HH:MM:SS"
}

async function getCustomerTimeline(name: string): Promise<TimelineItem[]> {
  const items: TimelineItem[] = [];

  /** Normalize a date value (which YAML may parse as a JS Date) to YYYY-MM-DD. */
  const normDate = (v: any): string | null => {
    if (v == null) return null;
    if (v instanceof Date) return v.toISOString().slice(0, 10);
    const s = String(v).trim();
    // If it already looks like ISO date, use its first 10 chars
    if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(0, 10);
    const d = new Date(s);
    if (!isNaN(d.getTime())) return d.toISOString().slice(0, 10);
    return null;
  };

  // 1. Tasks linked to this customer
  const all = await listAllTasks();
  const flat = [...all.open, ...all.waiting, ...all.done];
  const c = name.toLowerCase();
  const mine = flat.filter(t => String(t.frontmatter.customer || '').toLowerCase() === c);
  for (const t of mine) {
    const fm = t.frontmatter;
    const created = normDate(fm.created);
    if (created) items.push({
      date: created, ts: tsOf(created, undefined, TS_START),
      kind: 'task-created',
      label: `Task created: ${fm.title || t.filename}`,
      detail: `${fm.priority || ''} · ${t.filename}`,
      path: `tasks/${t.status}/${t.filename}`,
    });
    const completed = normDate(fm.completed);
    if (completed && t.status === 'done') items.push({
      date: completed, ts: tsOf(completed, undefined, TS_END),
      kind: 'task-completed',
      label: `Task completed: ${fm.title || t.filename}`,
      detail: t.filename,
      path: `tasks/${t.status}/${t.filename}`,
    });
    const due = normDate(fm.due);
    if (due && t.status !== 'done') items.push({
      date: due, ts: tsOf(due, undefined, TS_START),
      kind: 'task-due',
      label: `Due: ${fm.title || t.filename}`,
      detail: `${fm.priority || ''} · ${t.status}`,
      path: `tasks/${t.status}/${t.filename}`,
    });
  }

  // 1b. Task activity — every ## Log line for this customer's tasks (uses its exact time)
  for (const t of mine) {
    try {
      const full = await readTaskFile(t.status, t.filename);
      for (const l of parseLogLines(full.body)) {
        if (/^Created\b/i.test(l.text)) continue;
        items.push({ date: l.date, time: l.time, ts: tsOf(l.date, l.time), kind: 'task-log', label: l.text, detail: t.frontmatter.title || t.filename, path: `tasks/${t.status}/${t.filename}` });
      }
    } catch { /* ignore */ }
  }

  // 2. History lines from 00-overview.md
  try {
    const raw = await fs.readFile(safeJoin(ACCOUNTS_DIR, name, '00-overview.md'), 'utf8');
    const hBody = extractSectionBody(raw, 'History');
    if (hBody) {
      for (const e of parseHistoryEntries(hBody)) {
        const firstLine = e.text.split('\n')[0].trim();
        items.push({
          date: e.date, time: e.time, ts: tsOf(e.date, e.time), kind: 'history',
          label: firstLine,
          body: e.text.includes('\n') ? e.text : undefined,
        });
      }
    }
  } catch { /* no overview */ }

  // 2b. Quick updates logged against this account's name (updates-log.md)
  try {
    const ups = await readUpdatesLog();
    for (const u of ups) {
      if (u.customer.toLowerCase() === name.toLowerCase()) items.push({ date: u.date, time: u.time, ts: tsOf(u.date, u.time), kind: 'update', label: u.text });
    }
  } catch { /* ignore */ }

  // 2c. Rich update-feed posts linked to this account
  try {
    const posts = await listUpdates();
    for (const p of posts) {
      const fm = p.frontmatter; const date = normDateStr(fm.date);
      if (date && fm.account && String(fm.account).toLowerCase() === name.toLowerCase()) {
        items.push({ date, time: fm.time ? String(fm.time) : undefined, ts: tsOf(date, fm.time ? String(fm.time) : undefined), kind: 'update', label: `${fm.type ? `[${fm.type}] ` : ''}${fm.title || p.filename}`, detail: fm.source ? String(fm.source) : '', body: p.body || '', path: `updates/${p.filename}` });
      }
    }
  } catch { /* ignore */ }

  // 3. Recent file mtimes (top 20)
  const files = await listAccountFiles(name);
  const fileMtimes: Array<{ date: string; ts: string; path: string; name: string }> = [];
  const walk = async (subdir: string, depth: number) => {
    if (depth > 2) return;
    const dir = safeJoin(ACCOUNTS_DIR, name, subdir);
    let entries: import('node:fs').Dirent[] = [];
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name.startsWith('.')) continue;
      const rel = path.join(subdir, e.name);
      if (e.isDirectory()) await walk(rel, depth + 1);
      else {
        try {
          const stat = await fs.stat(safeJoin(ACCOUNTS_DIR, name, rel));
          const iso = stat.mtime.toISOString();
          fileMtimes.push({ date: iso.slice(0, 10), ts: iso.replace('T', ' ').slice(0, 19), path: rel, name: e.name });
        } catch { /* ignore */ }
      }
    }
  };
  // walk root and one level down only
  void files; // (files was for the AccountsTab, we recompute here for depth)
  await walk('', 0);
  fileMtimes.sort((a, b) => b.ts.localeCompare(a.ts));
  for (const f of fileMtimes.slice(0, 20)) {
    items.push({ date: f.date, ts: f.ts, kind: 'file', label: `File: ${f.name}`, detail: f.path, path: f.path });
  }

  // Sort by full timestamp so same-day activity is in true chronological order.
  items.sort((a, b) => (b.ts || b.date).localeCompare(a.ts || a.date));
  return items;
}

/** Slice the body of a `## <heading>` section to the next `## ` or end-of-file.
 *  (Robust replacement for regexes using `\Z`, which is a literal "Z" in JS.) */
function extractSectionBody(raw: string, heading: string): string | null {
  const re = new RegExp(`^##\\s+${heading}`, 'mi');
  const m = re.exec(raw);
  if (!m) return null;
  const after = raw.slice(m.index + m[0].length);
  const next = after.search(/\n##\s/);
  return next === -1 ? after : after.slice(0, next);
}

// A history/log entry starts with "- [**]YYYY-MM-DD[ HH:MM][**] — ".
const HISTORY_ENTRY_START = /^-\s+(?:\*\*)?(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}(?::\d{2})?))?(?:\*\*)?\s+—\s+(.*)$/;

/**
 * Parse a `## History` section into entries, preserving the FULL multi-line text
 * of each entry (a Log Entry may span many lines). An entry runs from its dated
 * bullet until the next dated bullet (or end of section); continuation lines are
 * de-indented by up to two spaces (how they're stored) and rejoined.
 */
function parseHistoryEntries(hBody: string): Array<{ date: string; time?: string; text: string }> {
  const lines = hBody.split('\n');
  const out: Array<{ date: string; time?: string; text: string }> = [];
  let cur: { date: string; time?: string; parts: string[] } | null = null;
  const flush = () => {
    if (!cur) return;
    const text = cur.parts.join('\n').replace(/\*\*/g, '').replace(/\s+$/, '');
    out.push({ date: cur.date, time: cur.time, text });
    cur = null;
  };
  for (const line of lines) {
    const m = HISTORY_ENTRY_START.exec(line);
    if (m) {
      flush();
      cur = { date: m[1], time: m[2], parts: [m[3]] };
    } else if (cur) {
      cur.parts.push(line.replace(/^ {1,2}/, '')); // continuation of the current entry
    }
  }
  flush();
  return out;
}

/** Parse a task/body `## Log` section into dated activity lines (with optional time). */
function parseLogLines(body: string): Array<{ date: string; time?: string; text: string }> {
  const logBody = extractSectionBody(body, 'Log');
  if (!logBody) return [];
  const re = /^-\s+(?:\*\*)?(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}(?::\d{2})?))?(?:\*\*)?\s+—\s+(.+)$/gm;
  const out: Array<{ date: string; time?: string; text: string }> = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(logBody))) out.push({ date: m[1], time: m[2], text: m[3].trim() });
  return out;
}

/** Build a sortable "YYYY-MM-DD HH:MM:SS" timestamp; fills a per-kind default time. */
const TS_MIDDAY = '12:00:00', TS_START = '00:00:01', TS_END = '23:59:59';
function tsOf(date: string, time?: string, fallback: string = TS_MIDDAY): string {
  const t = time ? (time.length === 5 ? `${time}:00` : time) : fallback;
  return `${date} ${t}`;
}

/** Normalize a date value (YAML may parse as JS Date) to YYYY-MM-DD. */
function normDateStr(v: any): string | null {
  if (v == null) return null;
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  const s = String(v).trim();
  if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(0, 10);
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}

/** Global cross-account timeline: tasks + account history + career wins. */
async function getGlobalTimeline(limit = 800): Promise<Array<TimelineItem & { customer?: string }>> {
  const items: Array<TimelineItem & { customer?: string }> = [];

  // 1. All task events (created / completed / due), tagged by customer
  const all = await listAllTasks();
  const flat = [...all.open, ...all.waiting, ...all.done];
  for (const t of flat) {
    const fm = t.frontmatter;
    const cust = String(fm.customer || 'unassigned');
    const created = normDateStr(fm.created);
    if (created) items.push({ date: created, ts: tsOf(created, undefined, TS_START), kind: 'task-created', customer: cust, label: `${fm.title || t.filename}`, detail: `${fm.priority || ''} · ${t.filename}`, path: `tasks/${t.status}/${t.filename}` });
    const completed = normDateStr(fm.completed);
    if (completed && t.status === 'done') items.push({ date: completed, ts: tsOf(completed, undefined, TS_END), kind: 'task-completed', customer: cust, label: `${fm.title || t.filename}`, detail: t.filename, path: `tasks/${t.status}/${t.filename}` });
    const due = normDateStr(fm.due);
    if (due && t.status !== 'done') items.push({ date: due, ts: tsOf(due, undefined, TS_START), kind: 'task-due', customer: cust, label: `${fm.title || t.filename}`, detail: `${fm.priority || ''} · ${t.status}`, path: `tasks/${t.status}/${t.filename}` });
  }

  // 1b. Task activity — every ## Log line (comments, status/priority changes, subtask completions), by exact time
  for (const t of flat) {
    try {
      const full = await readTaskFile(t.status, t.filename);
      const cust = String(t.frontmatter.customer || 'unassigned');
      for (const l of parseLogLines(full.body)) {
        if (/^Created\b/i.test(l.text)) continue; // avoid dup with task-created
        items.push({ date: l.date, time: l.time, ts: tsOf(l.date, l.time), kind: 'task-log', customer: cust, label: l.text, detail: t.frontmatter.title || t.filename, path: `tasks/${t.status}/${t.filename}` });
      }
    } catch { /* ignore */ }
  }

  // 2. History lines from every account's 00-overview.md
  const accounts = await listAccounts();
  for (const a of accounts) {
    if (!a.has_overview) continue;
    try {
      const raw = await fs.readFile(safeJoin(ACCOUNTS_DIR, a.name, '00-overview.md'), 'utf8');
      const hBody = extractSectionBody(raw, 'History');
      if (hBody) {
        for (const e of parseHistoryEntries(hBody)) {
          const firstLine = e.text.split('\n')[0].trim();
          items.push({
            date: e.date, time: e.time, ts: tsOf(e.date, e.time), kind: 'history', customer: a.name,
            label: firstLine,
            body: e.text.includes('\n') ? e.text : undefined,
          });
        }
      }
    } catch { /* ignore */ }
  }

  // 3. Career wins
  try {
    const wins = await readWinsLog();
    for (const w of wins.entries) items.push({ date: w.date, ts: tsOf(w.date), kind: 'win', customer: 'career', label: w.text });
  } catch { /* ignore */ }

  // 4. Quick updates for non-account buckets (updates-log.md)
  try {
    const ups = await readUpdatesLog();
    for (const u of ups) items.push({ date: u.date, time: u.time, ts: tsOf(u.date, u.time), kind: 'update', customer: u.customer, label: u.text });
  } catch { /* ignore */ }

  // 5. Rich update feed (updates/ folder)
  try {
    const posts = await listUpdates();
    for (const p of posts) {
      const fm = p.frontmatter; const date = normDateStr(fm.date);
      if (!date) continue;
      items.push({ date, time: fm.time ? String(fm.time) : undefined, ts: tsOf(date, fm.time ? String(fm.time) : undefined), kind: 'update', customer: fm.account ? String(fm.account) : '', label: `${fm.type ? `[${fm.type}] ` : ''}${fm.title || p.filename}`, detail: fm.source ? String(fm.source) : '', body: p.body || '', path: `updates/${p.filename}` });
    }
  } catch { /* ignore */ }

  // Sort by full timestamp so same-day activity is in true chronological order.
  items.sort((a, b) => (b.ts || b.date).localeCompare(a.ts || a.date));
  return items.slice(0, limit);
}

// -------------------------------------------------------------------------
// Account config sidecar (_workmgr.json) — products + per-product config +
// extended customer-details. Kept separate so we never rewrite the
// hand-authored 00-overview.md.
// -------------------------------------------------------------------------
const ACCOUNT_CONFIG_FILE = '_workmgr.json';

interface AccountConfig {
  products: string[];
  config: Record<string, Record<string, any>>;
  details: Record<string, any>;
  updated_at?: string;
}

async function getAccountConfig(name: string): Promise<AccountConfig> {
  const fp = safeJoin(ACCOUNTS_DIR, name, ACCOUNT_CONFIG_FILE);
  let stored: Partial<AccountConfig> = {};
  try { stored = JSON.parse(await fs.readFile(fp, 'utf8')); } catch { /* none yet */ }

  // Seed products from the overview frontmatter if the sidecar has none yet.
  if (!stored.products || stored.products.length === 0) {
    try {
      const raw = await fs.readFile(safeJoin(ACCOUNTS_DIR, name, '00-overview.md'), 'utf8');
      const fm = parseFrontmatter(raw).frontmatter;
      const prods = Array.isArray(fm.products) ? fm.products.map(String) : [];
      stored.products = prods;
      stored.details = stored.details || {
        region: fm.region, status: fm.status, last_touched: normDateStr(fm.last_touched) || undefined,
        freshness_window_days: fm.freshness_window_days, se: fm.f5_owner,
      };
    } catch { /* ignore */ }
  }
  return { products: stored.products || [], config: stored.config || {}, details: stored.details || {}, updated_at: stored.updated_at };
}

async function saveAccountConfig(name: string, data: Partial<AccountConfig>): Promise<AccountConfig> {
  const current = await getAccountConfig(name);
  const merged: AccountConfig = {
    products: data.products ?? current.products,
    config: { ...current.config, ...(data.config || {}) },
    details: { ...current.details, ...(data.details || {}) },
    updated_at: new Date().toISOString(),
  };
  const fp = safeJoin(ACCOUNTS_DIR, name, ACCOUNT_CONFIG_FILE);
  await fs.writeFile(fp, JSON.stringify(merged, null, 2), 'utf8');
  await audit('account.config.save', fp, { name, products: merged.products.length });
  return merged;
}

// -------------------------------------------------------------------------
// Quick updates — capture recent work against an account or a general bucket.
// Real accounts append to their ## History; other buckets go to updates-log.md.
// Both feed the global + per-account timelines.
// -------------------------------------------------------------------------
async function readUpdatesLog(): Promise<Array<{ date: string; time?: string; customer: string; text: string }>> {
  let raw = '';
  try { raw = await fs.readFile(UPDATES_LOG, 'utf8'); } catch { return []; }
  const re = /^-\s+(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}(?::\d{2})?))?\s+—\s+\[([^\]]+)\]\s+(.+)$/gm;
  const out: Array<{ date: string; time?: string; customer: string; text: string }> = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) out.push({ date: m[1], time: m[2], customer: m[3].trim(), text: m[4].trim() });
  out.sort((a, b) => `${b.date} ${b.time || ''}`.localeCompare(`${a.date} ${a.time || ''}`));
  return out;
}

async function appendUpdate(input: { customer: string; text: string; date?: string }): Promise<{ target: string }> {
  const customer = (input.customer || '').trim();
  const text = (input.text || '').trim();
  if (!customer || !text) throw new Error('customer and text are required');
  const date = (input.date && /^\d{4}-\d{2}-\d{2}$/.test(input.date)) ? input.date : new Date().toISOString().slice(0, 10);
  // Real account with an overview → append to its ## History (canonical; shows in both timelines)
  const overviewPath = safeJoin(ACCOUNTS_DIR, customer, '00-overview.md');
  if (fsSync.existsSync(overviewPath)) {
    await appendAccountHistory(customer, text, date);
    return { target: `Accounts/${customer}/00-overview.md` };
  }
  // Otherwise → central updates-log.md (newest first)
  const line = `- ${date} — [${customer}] ${text}`;
  let raw = '';
  try { raw = await fs.readFile(UPDATES_LOG, 'utf8'); } catch {
    raw = '# Updates log\n\n_Quick cross-cutting updates captured from Work Manager (non-account buckets). Newest first._\n';
  }
  const lines = raw.split('\n');
  const firstEntry = lines.findIndex(l => /^-\s+\d{4}-\d{2}-\d{2}\s+—/.test(l));
  if (firstEntry === -1) raw = raw.replace(/\s*$/, '') + '\n' + line + '\n';
  else { lines.splice(firstEntry, 0, line); raw = lines.join('\n'); }
  await fs.writeFile(UPDATES_LOG, raw, 'utf8');
  await audit('updates.append', UPDATES_LOG, { customer, date });
  return { target: 'updates-log.md' };
}

// -------------------------------------------------------------------------
// Updates feed — categorized team/manager/company/product updates, each a
// markdown file in mywork/updates/ with frontmatter (type, title, date,
// account, source, tags, links, files, importance) + a body.
// -------------------------------------------------------------------------
const UPDATES_DIR = path.join(MYWORK_ROOT, 'updates');

function slugifyStr(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 50);
}

async function listUpdates(): Promise<Array<{ filename: string; frontmatter: Frontmatter; body: string; body_preview: string }>> {
  let entries: string[] = [];
  try { entries = await fs.readdir(UPDATES_DIR); } catch { return []; }
  const out: Array<{ filename: string; frontmatter: Frontmatter; body: string; body_preview: string }> = [];
  for (const e of entries) {
    if (!e.endsWith('.md') || e === 'README.md') continue;
    try {
      const p = parseFrontmatter(await fs.readFile(path.join(UPDATES_DIR, e), 'utf8'));
      out.push({ filename: e, frontmatter: p.frontmatter, body: p.body.trim(), body_preview: p.body.slice(0, 280) });
    } catch { /* skip */ }
  }
  out.sort((a, b) => `${b.frontmatter.date || ''} ${b.frontmatter.time || ''}`.localeCompare(`${a.frontmatter.date || ''} ${a.frontmatter.time || ''}`));
  return out;
}

async function getUpdate(filename: string): Promise<{ filename: string; frontmatter: Frontmatter; body: string }> {
  const p = parseFrontmatter(await fs.readFile(safeJoin(UPDATES_DIR, filename), 'utf8'));
  return { filename, frontmatter: p.frontmatter, body: p.body };
}

async function createUpdate(input: { frontmatter?: Frontmatter; body?: string }): Promise<{ filename: string }> {
  const fm0 = input.frontmatter || {};
  const title = String(fm0.title || '').trim();
  if (!title) throw new Error('Update title is required');
  const date = (typeof fm0.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(fm0.date)) ? fm0.date : new Date().toISOString().slice(0, 10);
  const time = (typeof fm0.time === 'string' && /^\d{2}:\d{2}$/.test(fm0.time)) ? fm0.time : nowTime();
  await fs.mkdir(UPDATES_DIR, { recursive: true });
  const base = `${date}-${slugifyStr(title)}` || `${date}-update`;
  let filename = `${base}.md`; let n = 2;
  while (fsSync.existsSync(path.join(UPDATES_DIR, filename))) { filename = `${base}-${n}.md`; n++; }
  const fm: Frontmatter = { ...fm0, id: filename.replace(/\.md$/, ''), title, date, time, type: fm0.type || 'Team Update' };
  await fs.writeFile(path.join(UPDATES_DIR, filename), serializeFrontmatter(fm, input.body || ''), 'utf8');
  await audit('update.create', filename, { type: fm.type });
  return { filename };
}

async function patchUpdate(filename: string, patch: { frontmatter?: Frontmatter; body?: string }): Promise<{ filename: string; frontmatter: Frontmatter; body: string }> {
  const fp = safeJoin(UPDATES_DIR, filename);
  const p = parseFrontmatter(await fs.readFile(fp, 'utf8'));
  const fm = { ...p.frontmatter, ...(patch.frontmatter || {}) };
  const body = patch.body !== undefined ? patch.body : p.body;
  await fs.writeFile(fp, serializeFrontmatter(fm, body), 'utf8');
  await audit('update.patch', filename, {});
  return getUpdate(filename);
}

async function deleteUpdate(filename: string): Promise<void> {
  await fs.unlink(safeJoin(UPDATES_DIR, filename));
  await audit('update.delete', filename, {});
}

// -------------------------------------------------------------------------
// Work patterns — reusable "trigger → action" playbooks captured during work,
// for later reference and analysis. Each is a markdown file in mywork/patterns/.
// -------------------------------------------------------------------------
const PATTERNS_DIR = path.join(MYWORK_ROOT, 'patterns');

async function listPatterns(): Promise<Array<{ filename: string; frontmatter: Frontmatter; body: string }>> {
  let entries: string[] = [];
  try { entries = await fs.readdir(PATTERNS_DIR); } catch { return []; }
  const out: Array<{ filename: string; frontmatter: Frontmatter; body: string }> = [];
  for (const e of entries) {
    if (!e.endsWith('.md') || e === 'README.md') continue;
    try {
      const p = parseFrontmatter(await fs.readFile(path.join(PATTERNS_DIR, e), 'utf8'));
      out.push({ filename: e, frontmatter: p.frontmatter, body: p.body.trim() });
    } catch { /* skip */ }
  }
  out.sort((a, b) => (Number(b.frontmatter.uses || 0) - Number(a.frontmatter.uses || 0)) || String(b.frontmatter.created || '').localeCompare(String(a.frontmatter.created || '')));
  return out;
}

async function getPattern(filename: string): Promise<{ filename: string; frontmatter: Frontmatter; body: string }> {
  const p = parseFrontmatter(await fs.readFile(safeJoin(PATTERNS_DIR, filename), 'utf8'));
  return { filename, frontmatter: p.frontmatter, body: p.body };
}

async function createPattern(input: { frontmatter?: Frontmatter; body?: string }): Promise<{ filename: string }> {
  const fm0 = input.frontmatter || {};
  const trigger = String(fm0.trigger || '').trim();
  if (!trigger) throw new Error('A trigger / situation is required');
  const action = String(fm0.action || '').trim();
  await fs.mkdir(PATTERNS_DIR, { recursive: true });
  const today = new Date().toISOString().slice(0, 10);
  const base = slugifyStr(`${trigger}-${action}`) || slugifyStr(trigger) || 'pattern';
  let filename = `${base}.md`; let n = 2;
  while (fsSync.existsSync(path.join(PATTERNS_DIR, filename))) { filename = `${base}-${n}.md`; n++; }
  const fm: Frontmatter = { ...fm0, id: filename.replace(/\.md$/, ''), trigger, action, category: fm0.category || 'General', uses: Number(fm0.uses) || 0, created: fm0.created || today };
  await fs.writeFile(path.join(PATTERNS_DIR, filename), serializeFrontmatter(fm, input.body || ''), 'utf8');
  await audit('pattern.create', filename, { category: fm.category });
  return { filename };
}

async function patchPattern(filename: string, patch: { frontmatter?: Frontmatter; body?: string }): Promise<{ filename: string; frontmatter: Frontmatter; body: string }> {
  const fp = safeJoin(PATTERNS_DIR, filename);
  const p = parseFrontmatter(await fs.readFile(fp, 'utf8'));
  const fm = { ...p.frontmatter, ...(patch.frontmatter || {}) };
  const body = patch.body !== undefined ? patch.body : p.body;
  await fs.writeFile(fp, serializeFrontmatter(fm, body), 'utf8');
  await audit('pattern.patch', filename, {});
  return getPattern(filename);
}

async function deletePattern(filename: string): Promise<void> {
  await fs.unlink(safeJoin(PATTERNS_DIR, filename));
  await audit('pattern.delete', filename, {});
}

// -------------------------------------------------------------------------
// Learnings — a personal knowledge base of things learned during work, tagged
// by product / feature / platform / environment / topic / subtopic / category
// for later reference. Each is a markdown file in mywork/learnings/.
// -------------------------------------------------------------------------
const LEARNINGS_DIR = path.join(MYWORK_ROOT, 'learnings');

async function listLearnings(): Promise<Array<{ filename: string; frontmatter: Frontmatter; body: string; body_preview: string }>> {
  let entries: string[] = [];
  try { entries = await fs.readdir(LEARNINGS_DIR); } catch { return []; }
  const out: Array<{ filename: string; frontmatter: Frontmatter; body: string; body_preview: string }> = [];
  for (const e of entries) {
    if (!e.endsWith('.md') || e === 'README.md') continue;
    try {
      const p = parseFrontmatter(await fs.readFile(path.join(LEARNINGS_DIR, e), 'utf8'));
      out.push({ filename: e, frontmatter: p.frontmatter, body: p.body.trim(), body_preview: p.body.slice(0, 280) });
    } catch { /* skip */ }
  }
  // Newest first, by captured day + time.
  out.sort((a, b) => `${b.frontmatter.date || ''} ${b.frontmatter.time || ''}`.localeCompare(`${a.frontmatter.date || ''} ${a.frontmatter.time || ''}`));
  return out;
}

async function getLearning(filename: string): Promise<{ filename: string; frontmatter: Frontmatter; body: string }> {
  const p = parseFrontmatter(await fs.readFile(safeJoin(LEARNINGS_DIR, filename), 'utf8'));
  return { filename, frontmatter: p.frontmatter, body: p.body };
}

async function createLearning(input: { frontmatter?: Frontmatter; body?: string }): Promise<{ filename: string }> {
  const fm0 = input.frontmatter || {};
  const title = String(fm0.title || '').trim();
  if (!title) throw new Error('A title / what you learned is required');
  const date = (typeof fm0.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(fm0.date)) ? fm0.date : new Date().toISOString().slice(0, 10);
  const time = (typeof fm0.time === 'string' && /^\d{2}:\d{2}$/.test(fm0.time)) ? fm0.time : nowTime();
  await fs.mkdir(LEARNINGS_DIR, { recursive: true });
  const base = `${date}-${slugifyStr(title)}` || `${date}-learning`;
  let filename = `${base}.md`; let n = 2;
  while (fsSync.existsSync(path.join(LEARNINGS_DIR, filename))) { filename = `${base}-${n}.md`; n++; }
  const fm: Frontmatter = { ...fm0, id: filename.replace(/\.md$/, ''), title, date, time, category: fm0.category || 'Product Knowledge' };
  await fs.writeFile(path.join(LEARNINGS_DIR, filename), serializeFrontmatter(fm, input.body || ''), 'utf8');
  await audit('learning.create', filename, { category: fm.category });
  return { filename };
}

async function patchLearning(filename: string, patch: { frontmatter?: Frontmatter; body?: string }): Promise<{ filename: string; frontmatter: Frontmatter; body: string }> {
  const fp = safeJoin(LEARNINGS_DIR, filename);
  const p = parseFrontmatter(await fs.readFile(fp, 'utf8'));
  const fm = { ...p.frontmatter, ...(patch.frontmatter || {}) };
  const body = patch.body !== undefined ? patch.body : p.body;
  await fs.writeFile(fp, serializeFrontmatter(fm, body), 'utf8');
  await audit('learning.patch', filename, {});
  return getLearning(filename);
}

async function deleteLearning(filename: string): Promise<void> {
  await fs.unlink(safeJoin(LEARNINGS_DIR, filename));
  await audit('learning.delete', filename, {});
}

// -------------------------------------------------------------------------
// Learning Queue — the "to learn" side of knowledge management: things you
// want to learn, courses to take, topics to explore. Each item moves through
// backlog → learning → done, carries a type/priority/target and optional
// progress, and shares the Learnings taxonomy (product / topic / tags) so a
// finished item can be captured into the Learnings knowledge base. Stored as
// markdown files in mywork/learning-tasks/.
// -------------------------------------------------------------------------
const LEARNING_TASKS_DIR = path.join(MYWORK_ROOT, 'learning-tasks');
const LEARNING_STATUSES = ['backlog', 'in_progress', 'done'];

async function listLearningTasks(): Promise<Array<{ filename: string; frontmatter: Frontmatter; body: string; body_preview: string }>> {
  let entries: string[] = [];
  try { entries = await fs.readdir(LEARNING_TASKS_DIR); } catch { return []; }
  const out: Array<{ filename: string; frontmatter: Frontmatter; body: string; body_preview: string }> = [];
  for (const e of entries) {
    if (!e.endsWith('.md') || e === 'README.md') continue;
    try {
      const p = parseFrontmatter(await fs.readFile(path.join(LEARNING_TASKS_DIR, e), 'utf8'));
      out.push({ filename: e, frontmatter: p.frontmatter, body: p.body.trim(), body_preview: p.body.slice(0, 280) });
    } catch { /* skip */ }
  }
  // Most-recently-touched first; the UI re-groups these into status lanes.
  out.sort((a, b) => String(b.frontmatter.updated || b.frontmatter.created || '').localeCompare(String(a.frontmatter.updated || a.frontmatter.created || '')));
  return out;
}

async function getLearningTask(filename: string): Promise<{ filename: string; frontmatter: Frontmatter; body: string }> {
  const p = parseFrontmatter(await fs.readFile(safeJoin(LEARNING_TASKS_DIR, filename), 'utf8'));
  return { filename, frontmatter: p.frontmatter, body: p.body };
}

async function createLearningTask(input: { frontmatter?: Frontmatter; body?: string }): Promise<{ filename: string }> {
  const fm0 = input.frontmatter || {};
  const title = String(fm0.title || '').trim();
  if (!title) throw new Error('What do you want to learn? A title is required');
  const now = new Date();
  const created = now.toISOString().slice(0, 10);
  const status = LEARNING_STATUSES.includes(String(fm0.status)) ? String(fm0.status) : 'backlog';
  await fs.mkdir(LEARNING_TASKS_DIR, { recursive: true });
  const base = `${created}-${slugifyStr(title)}` || `${created}-to-learn`;
  let filename = `${base}.md`; let n = 2;
  while (fsSync.existsSync(path.join(LEARNING_TASKS_DIR, filename))) { filename = `${base}-${n}.md`; n++; }
  const fm: Frontmatter = {
    ...fm0, id: filename.replace(/\.md$/, ''), title, status,
    type: fm0.type || 'Topic', created, updated: `${created} ${nowTime()}`,
  };
  await fs.writeFile(path.join(LEARNING_TASKS_DIR, filename), serializeFrontmatter(fm, input.body || ''), 'utf8');
  await audit('learning_task.create', filename, { status: fm.status, type: fm.type });
  return { filename };
}

async function patchLearningTask(filename: string, patch: { frontmatter?: Frontmatter; body?: string }): Promise<{ filename: string; frontmatter: Frontmatter; body: string }> {
  const fp = safeJoin(LEARNING_TASKS_DIR, filename);
  const p = parseFrontmatter(await fs.readFile(fp, 'utf8'));
  const fm = { ...p.frontmatter, ...(patch.frontmatter || {}) };
  fm.updated = `${new Date().toISOString().slice(0, 10)} ${nowTime()}`;
  // Stamp / clear the completion date as the item crosses the done boundary.
  if (patch.frontmatter && 'status' in patch.frontmatter) {
    if (fm.status === 'done' && !fm.completed) fm.completed = new Date().toISOString().slice(0, 10);
    if (fm.status !== 'done') delete fm.completed;
  }
  const body = patch.body !== undefined ? patch.body : p.body;
  await fs.writeFile(fp, serializeFrontmatter(fm, body), 'utf8');
  await audit('learning_task.patch', filename, { status: fm.status });
  return getLearningTask(filename);
}

async function deleteLearningTask(filename: string): Promise<void> {
  await fs.unlink(safeJoin(LEARNING_TASKS_DIR, filename));
  await audit('learning_task.delete', filename, {});
}

// -------------------------------------------------------------------------
// Thought Journal — an intimate space to capture ideas, thoughts, reflections
// and feelings as you work. Distinct from Learnings (knowledge for reuse),
// Updates (customer/account activity) and Work Patterns (reusable methods):
// this is for structuring your own understanding and mindspace. Each entry is
// a markdown file in mywork/journal/, tagged by kind, mood and theme.
// -------------------------------------------------------------------------
const JOURNAL_DIR = path.join(MYWORK_ROOT, 'journal');

// First non-empty line of a body, used to derive a headline when none is given.
function firstLine(body: string): string {
  for (const raw of String(body || '').split('\n')) {
    const t = raw.replace(/^#+\s*/, '').trim();
    if (t) return t;
  }
  return '';
}

async function listJournal(): Promise<Array<{ filename: string; frontmatter: Frontmatter; body: string; body_preview: string }>> {
  let entries: string[] = [];
  try { entries = await fs.readdir(JOURNAL_DIR); } catch { return []; }
  const out: Array<{ filename: string; frontmatter: Frontmatter; body: string; body_preview: string }> = [];
  for (const e of entries) {
    if (!e.endsWith('.md') || e === 'README.md') continue;
    try {
      const p = parseFrontmatter(await fs.readFile(path.join(JOURNAL_DIR, e), 'utf8'));
      out.push({ filename: e, frontmatter: p.frontmatter, body: p.body.trim(), body_preview: p.body.slice(0, 280) });
    } catch { /* skip */ }
  }
  // Newest first, by captured day + time.
  out.sort((a, b) => `${b.frontmatter.date || ''} ${b.frontmatter.time || ''}`.localeCompare(`${a.frontmatter.date || ''} ${a.frontmatter.time || ''}`));
  return out;
}

async function getJournal(filename: string): Promise<{ filename: string; frontmatter: Frontmatter; body: string }> {
  const p = parseFrontmatter(await fs.readFile(safeJoin(JOURNAL_DIR, filename), 'utf8'));
  return { filename, frontmatter: p.frontmatter, body: p.body };
}

async function createJournal(input: { frontmatter?: Frontmatter; body?: string }): Promise<{ filename: string }> {
  const fm0 = input.frontmatter || {};
  const body = input.body || '';
  // A headline is nice-to-have but not required — fall back to the first line of
  // the thought so raw, unstructured entries are frictionless to capture.
  const title = String(fm0.title || '').trim() || firstLine(body);
  if (!title) throw new Error('Write a thought, or give it a short title');
  const date = (typeof fm0.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(fm0.date)) ? fm0.date : new Date().toISOString().slice(0, 10);
  const time = (typeof fm0.time === 'string' && /^\d{2}:\d{2}$/.test(fm0.time)) ? fm0.time : nowTime();
  await fs.mkdir(JOURNAL_DIR, { recursive: true });
  const base = `${date}-${slugifyStr(title)}` || `${date}-thought`;
  let filename = `${base}.md`; let n = 2;
  while (fsSync.existsSync(path.join(JOURNAL_DIR, filename))) { filename = `${base}-${n}.md`; n++; }
  const fm: Frontmatter = { ...fm0, id: filename.replace(/\.md$/, ''), title, date, time, kind: fm0.kind || 'Reflection' };
  await fs.writeFile(path.join(JOURNAL_DIR, filename), serializeFrontmatter(fm, body), 'utf8');
  await audit('journal.create', filename, { kind: fm.kind, mood: fm.mood });
  return { filename };
}

async function patchJournal(filename: string, patch: { frontmatter?: Frontmatter; body?: string }): Promise<{ filename: string; frontmatter: Frontmatter; body: string }> {
  const fp = safeJoin(JOURNAL_DIR, filename);
  const p = parseFrontmatter(await fs.readFile(fp, 'utf8'));
  const fm = { ...p.frontmatter, ...(patch.frontmatter || {}) };
  const body = patch.body !== undefined ? patch.body : p.body;
  await fs.writeFile(fp, serializeFrontmatter(fm, body), 'utf8');
  await audit('journal.patch', filename, {});
  return getJournal(filename);
}

async function deleteJournal(filename: string): Promise<void> {
  await fs.unlink(safeJoin(JOURNAL_DIR, filename));
  await audit('journal.delete', filename, {});
}

// -------------------------------------------------------------------------
// Create account (scaffold Accounts/<name>/00-overview.md)
// -------------------------------------------------------------------------
async function createAccount(input: { name: string; customer?: string; region?: string; status?: string; products?: string[]; freshness_window_days?: number }): Promise<{ name: string }> {
  const rawName = (input.name || '').trim();
  if (!rawName) throw new Error('Account name is required');
  if (/[\\/]/.test(rawName) || rawName.includes('..') || rawName.startsWith('.')) throw new Error('Invalid account name');
  const dir = safeJoin(ACCOUNTS_DIR, rawName);
  const fp = path.join(dir, '00-overview.md');
  if (fsSync.existsSync(fp)) throw new Error(`Account "${rawName}" already exists`);
  await fs.mkdir(dir, { recursive: true });
  const today = new Date().toISOString().slice(0, 10);
  const customer = (input.customer || rawName).trim();
  const fm: Frontmatter = {
    customer,
    region: input.region || '',
    status: input.status || 'active',
    spoc: '<fill in>',
    f5_owner: 'KB',
    products: Array.isArray(input.products) ? input.products : [],
    last_touched: today,
    freshness_window_days: input.freshness_window_days || 30,
  };
  const body = `# ${customer}\n\n## Snapshot\n_One-paragraph what/why._\n\n## Active workstreams\n- [ ] \n\n## Next 3 actions\n1. \n2. \n3. \n\n## Key links\n- Salesforce / Jira: <fill in>\n\n## Contacts\n| Name | Role | Notes |\n|------|------|-------|\n\n## History (rolling, newest first)\n- ${today} — Account created in Work Manager.\n`;
  await fs.writeFile(fp, serializeFrontmatter(fm, body), 'utf8');
  await audit('account.create', fp, { name: rawName });
  return { name: rawName };
}

// -------------------------------------------------------------------------
// Career
// -------------------------------------------------------------------------
async function readCareerFile(filename: string): Promise<string> {
  const fp = safeJoin(CAREER_DIR, filename);
  return fs.readFile(fp, 'utf8');
}

async function readWinsLog(): Promise<{ raw: string; entries: Array<{ date: string; text: string }> }> {
  const raw = await readCareerFile('wins-log.md');
  // Parse "- YYYY-MM-DD — text" and "- **YYYY-MM-DD** — text"
  const re = /^-\s+(?:\*\*)?(\d{4}-\d{2}-\d{2})(?:\*\*)?\s+—\s+(.+)$/gm;
  const entries: Array<{ date: string; text: string }> = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) entries.push({ date: m[1], text: m[2].trim() });
  entries.sort((a, b) => b.date.localeCompare(a.date));
  return { raw, entries };
}

async function appendManualWin(entry: string): Promise<void> {
  const fp = safeJoin(CAREER_DIR, 'wins-log.md');
  let raw = await fs.readFile(fp, 'utf8');
  const date = new Date().toISOString().slice(0, 10);
  const line = `- **${date}** — ${entry.trim()}`;
  // Insert right after "## Manual entries" heading
  if (/^##\s+Manual entries\b/mi.test(raw)) {
    raw = raw.replace(/(^##\s+Manual entries[^\n]*\n)/mi, `$1${line}\n`);
  } else {
    // Fallback: insert at top of file after any leading heading
    raw = raw.trimEnd() + `\n\n## Manual entries\n${line}\n`;
  }
  await fs.writeFile(fp, raw, 'utf8');
  await audit('career.wins.append', fp, { entry });
}

async function listOneOnOnes(): Promise<Array<{ filename: string; date: string; person: string }>> {
  let entries: string[] = [];
  try { entries = await fs.readdir(ONE_ON_ONE_DIR); } catch { return []; }
  const results: Array<{ filename: string; date: string; person: string }> = [];
  for (const entry of entries) {
    if (!entry.endsWith('.md')) continue;
    if (entry === 'README.md') continue;
    const m = /^(\d{4}-\d{2}-\d{2})-(.+)\.md$/.exec(entry);
    if (m) results.push({ filename: entry, date: m[1], person: m[2] });
    else results.push({ filename: entry, date: '0000-00-00', person: entry.replace(/\.md$/, '') });
  }
  results.sort((a, b) => b.date.localeCompare(a.date));
  return results;
}

async function readOneOnOne(filename: string): Promise<ParsedMarkdown> {
  const fp = safeJoin(ONE_ON_ONE_DIR, filename);
  const raw = await fs.readFile(fp, 'utf8');
  return parseFrontmatter(raw);
}

async function updateOneOnOne(filename: string, updates: { frontmatter?: Frontmatter; body?: string }): Promise<void> {
  const fp = safeJoin(ONE_ON_ONE_DIR, filename);
  const raw = await fs.readFile(fp, 'utf8');
  const parsed = parseFrontmatter(raw);
  const merged: Frontmatter = { ...parsed.frontmatter, ...(updates.frontmatter || {}) };
  const body = updates.body !== undefined ? updates.body : parsed.body;
  // If the file has no frontmatter (older 1-1 notes are pure markdown), preserve that.
  const content = Object.keys(parsed.frontmatter).length === 0 && !updates.frontmatter
    ? body
    : serializeFrontmatter(merged, body);
  await fs.writeFile(fp, content, 'utf8');
  await audit('career.1on1.update', fp, { filename });
}

/** Create a new 1-1 note file with a sensible template. */
async function createOneOnOne(input: { date: string; person: string; purpose?: string; agenda?: string[] }): Promise<{ filename: string }> {
  const date = (input.date || '').trim();
  const person = (input.person || '').trim().toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error('date must be YYYY-MM-DD');
  if (!person) throw new Error('person is required');
  const filename = `${date}-${person}.md`;
  const fp = safeJoin(ONE_ON_ONE_DIR, filename);
  try {
    await fs.access(fp);
    throw new Error(`1-1 note already exists: ${filename}`);
  } catch (e: any) {
    if (String(e.message).includes('already exists')) throw e;
    if (e.code !== 'ENOENT') throw e;
  }
  const nicePerson = person.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
  const agendaLines = (input.agenda && input.agenda.length ? input.agenda : ['Opening — 2 min', 'My updates — 8 min', 'Discussion / their feedback — 15 min', 'Decisions & next steps — 5 min'])
    .map((a, i) => `### ${i + 1}. ${a}\n\n`).join('');
  const body = `# 1-1 with ${nicePerson} — ${date}\n\n` +
    `**Purpose:** ${input.purpose || '_(fill in)_'}\n\n` +
    `_Complete BEFORE the meeting; log outcomes AFTER._\n\n` +
    `## Prep BEFORE the meeting\n\n- [ ] Recent wins one-pager ready\n- [ ] Open items from last 1-1 reviewed\n- [ ] Any specific asks noted\n\n` +
    `## Bring to the meeting\n\n- Notepad + open ears\n- Any artifacts they've asked for\n\n` +
    `## Agenda (~30 min)\n\n${agendaLines}` +
    `## My updates\n\n- Customer highlights:\n- Blockers:\n- Wins:\n\n` +
    `## Their updates / feedback\n\n- \n\n` +
    `## Decisions & follow-ups\n\n- [ ] Owner — item — due YYYY-MM-DD\n\n` +
    `## Next meeting date\n\n`;
  await fs.writeFile(fp, body, 'utf8');
  await audit('career.1on1.create', fp, { filename, date, person });
  return { filename };
}

/** Append a new touchpoint entry to Career/sponsors-map.md under the Rolling touchpoint log section. */
async function appendSponsorTouchpoint(entry: { date?: string; person: string; topic: string; outcome?: string; next_step?: string }): Promise<void> {
  const fp = safeJoin(CAREER_DIR, 'sponsors-map.md');
  let raw = await fs.readFile(fp, 'utf8');
  const date = entry.date || new Date().toISOString().slice(0, 10);
  const person = (entry.person || '').trim();
  const topic = (entry.topic || '').trim();
  if (!person || !topic) throw new Error('person and topic are required');
  const parts = [topic];
  if (entry.outcome) parts.push(`outcome: ${entry.outcome}`);
  if (entry.next_step) parts.push(`next: ${entry.next_step}`);
  const line = `- ${date} — ${person} — ${parts.join(' · ')}`;
  // Insert right after the "Rolling touchpoint log" heading + its intro paragraph.
  // Format target:  `## Rolling touchpoint log ...\n\n_Append here .../\n\n- 2026-...`
  const heading = /^##\s+Rolling touchpoint log[^\n]*\n(?:.|\n)*?\n(?=- \d{4}-\d{2}-\d{2})/mi;
  if (heading.test(raw)) {
    raw = raw.replace(heading, (m) => `${m}${line}\n`);
  } else if (/^##\s+Rolling touchpoint log/mi.test(raw)) {
    raw = raw.replace(/(^##\s+Rolling touchpoint log[^\n]*\n)/mi, `$1\n${line}\n`);
  } else {
    raw = raw.trimEnd() + `\n\n## Rolling touchpoint log (newest first)\n\n${line}\n`;
  }
  await fs.writeFile(fp, raw, 'utf8');
  await audit('career.sponsors.touchpoint', fp, { entry });
}

async function getPromotionSnapshot(): Promise<any> {
  const files = ['promotion-case.md', 'promotion-cycle-tracker.md', 'promotion-strategy-fy26.md', 'sponsors-map.md', 'feedback-log.md', 'skills-matrix.md'];
  const out: Record<string, { exists: boolean; raw?: string; error?: string }> = {};
  for (const f of files) {
    try {
      const raw = await readCareerFile(f);
      out[f] = { exists: true, raw };
    } catch (e: any) {
      out[f] = { exists: false, error: e.message };
    }
  }
  return out;
}

// -------------------------------------------------------------------------
// Search
// -------------------------------------------------------------------------
async function searchAll(term: string, limit = 50): Promise<Array<{ path: string; kind: string; snippet: string }>> {
  if (!term) return [];
  const results: Array<{ path: string; kind: string; snippet: string }> = [];
  const t = term.toLowerCase();

  async function walkAndGrep(root: string, kind: string, depth = 0): Promise<void> {
    if (results.length >= limit) return;
    if (depth > 4) return;
    let entries: import('node:fs').Dirent[] = [];
    try { entries = await fs.readdir(root, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (results.length >= limit) return;
      if (e.name.startsWith('.') || e.name === 'node_modules') continue;
      const full = path.join(root, e.name);
      if (e.isDirectory()) {
        await walkAndGrep(full, kind, depth + 1);
      } else if (e.name.endsWith('.md')) {
        try {
          const raw = await fs.readFile(full, 'utf8');
          const idx = raw.toLowerCase().indexOf(t);
          if (idx !== -1) {
            const start = Math.max(0, idx - 60);
            const end = Math.min(raw.length, idx + 120);
            results.push({
              path: path.relative(MYWORK_ROOT, full),
              kind,
              snippet: raw.slice(start, end).replace(/\s+/g, ' ').trim(),
            });
          }
        } catch { /* ignore */ }
      }
    }
  }

  await walkAndGrep(TASKS_DIR, 'task');
  await walkAndGrep(ACCOUNTS_DIR, 'account');
  await walkAndGrep(CAREER_DIR, 'career');
  return results.slice(0, limit);
}

// -------------------------------------------------------------------------
// Weekly Review
// -------------------------------------------------------------------------
/** Format a Date as YYYY-MM-DD in the LOCAL timezone (avoids UTC-shift bugs). */
function toLocalDateStr(d: Date): string {
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

function currentWeekMonday(): string {
  const today = new Date();
  const dayOfWeek = today.getDay(); // 0=Sun, 1=Mon, ...
  const daysToMonday = dayOfWeek === 0 ? -6 : 1 - dayOfWeek;
  const monday = new Date(today);
  monday.setDate(monday.getDate() + daysToMonday);
  monday.setHours(0, 0, 0, 0);
  return toLocalDateStr(monday);
}

async function getWeeklyReview(startDate?: string): Promise<any> {
  const startStr = (startDate && /^\d{4}-\d{2}-\d{2}$/.test(startDate)) ? startDate : currentWeekMonday();
  const start = new Date(startStr + 'T00:00:00');
  const end = new Date(start);
  end.setDate(end.getDate() + 6);
  const endStr = toLocalDateStr(end);
  const todayStr = toLocalDateStr(new Date());

  const all = await listAllTasks();

  const inWeek = (v: any): boolean => {
    if (!v) return false;
    const s = String(v).slice(0, 10);
    return s >= startStr && s <= endStr;
  };

  const completedThisWeek = all.done.filter(t => inWeek(t.frontmatter.completed) || (!t.frontmatter.completed && inWeek(t.frontmatter.due)));
  const createdThisWeek = [...all.open, ...all.waiting, ...all.done].filter(t => inWeek(t.frontmatter.created));

  const overdue = all.open.filter(t => {
    const d = t.frontmatter.due;
    if (!d) return false;
    return String(d).slice(0, 10) < todayStr;
  });

  const dueInWindow = all.open.filter(t => inWeek(t.frontmatter.due));

  const completionsByCustomer: Record<string, TaskListItem[]> = {};
  for (const t of completedThisWeek) {
    const c = String(t.frontmatter.customer || 'unassigned');
    (completionsByCustomer[c] = completionsByCustomer[c] || []).push(t);
  }

  let winsThisWeek: Array<{ date: string; text: string }> = [];
  try {
    const w = await readWinsLog();
    winsThisWeek = w.entries.filter(e => e.date >= startStr && e.date <= endStr);
  } catch { /* ignore */ }

  let oneOnOnesThisWeek: Array<{ filename: string; date: string; person: string }> = [];
  try {
    const all1on1 = await listOneOnOnes();
    oneOnOnesThisWeek = all1on1.filter(x => x.date >= startStr && x.date <= endStr);
  } catch { /* ignore */ }

  // Suggested wins-log entries: completed customer-facing tasks whose title isn't already in wins-log
  const winsText = winsThisWeek.map(w => w.text.toLowerCase()).join(' | ');
  const suggestedWins = completedThisWeek
    .filter(t => {
      const cust = String(t.frontmatter.customer || '').toLowerCase();
      if (['personal', 'internal', 'career', ''].includes(cust)) return false;
      const title = String(t.frontmatter.title || '').toLowerCase();
      return title && !winsText.includes(title.slice(0, 25));
    })
    .slice(0, 20);

  return {
    week_start: startStr,
    week_end: endStr,
    counts: {
      completed: completedThisWeek.length,
      created: createdThisWeek.length,
      overdue: overdue.length,
      due_in_window: dueInWindow.length,
      waiting: all.waiting.length,
      wins_logged: winsThisWeek.length,
    },
    completed_this_week: completedThisWeek,
    created_this_week: createdThisWeek,
    overdue,
    due_in_window: dueInWindow,
    completions_by_customer: completionsByCustomer,
    wins_this_week: winsThisWeek,
    one_on_ones_this_week: oneOnOnesThisWeek,
    suggested_wins: suggestedWins,
  };
}

// -------------------------------------------------------------------------
// Dashboard summary
// -------------------------------------------------------------------------
async function getSummary(): Promise<any> {
  const tasks = await listAllTasks();
  const today = new Date().toISOString().slice(0, 10);
  const in7 = new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10);
  const past7 = new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);

  const overdue = tasks.open.filter(t => {
    const due = t.frontmatter.due;
    return typeof due === 'string' && due < today;
  });
  const dueThisWeek = tasks.open.filter(t => {
    const due = t.frontmatter.due;
    return typeof due === 'string' && due >= today && due <= in7;
  });
  const top5 = tasks.open
    .filter(t => ['P0', 'P1'].includes(String(t.frontmatter.priority || '')))
    .sort((a, b) => {
      const da = String(a.frontmatter.due || '9999-12-31');
      const db = String(b.frontmatter.due || '9999-12-31');
      return da.localeCompare(db);
    })
    .slice(0, 5);

  const doneLast7 = tasks.done.filter(t => {
    const c = t.frontmatter.completed || t.frontmatter.due;
    return typeof c === 'string' && c >= past7;
  });

  const countsByCustomer: Record<string, number> = {};
  for (const t of [...tasks.open, ...tasks.waiting]) {
    const c = String(t.frontmatter.customer || 'unassigned');
    countsByCustomer[c] = (countsByCustomer[c] || 0) + 1;
  }

  let recentWins: Array<{ date: string; text: string }> = [];
  try {
    const wins = await readWinsLog();
    recentWins = wins.entries.filter(w => w.date >= past7).slice(0, 10);
  } catch { /* ignore */ }

  let upcoming1on1s: Array<{ filename: string; date: string; person: string }> = [];
  try {
    const all = await listOneOnOnes();
    upcoming1on1s = all.filter(x => x.date >= today && x.date <= in7);
  } catch { /* ignore */ }

  return {
    counts: {
      open: tasks.open.length,
      waiting: tasks.waiting.length,
      done_last_7: doneLast7.length,
      overdue: overdue.length,
    },
    overdue,
    due_this_week: dueThisWeek,
    top_5: top5,
    recent_wins: recentWins,
    upcoming_1on1s: upcoming1on1s,
    counts_by_customer: countsByCustomer,
    generated_at: new Date().toISOString(),
    mywork_root: MYWORK_ROOT,
  };
}

// -------------------------------------------------------------------------
// Plugin
// -------------------------------------------------------------------------
export function workmgrPlugin(): Plugin {
  return {
    name: 'workmgr',
    configureServer(server) {
      server.middlewares.use('/api/workmgr', async (req, res, next) => {
        try {
          const method = req.method || 'GET';
          const url = req.url || '/';
          const segments = getPathSegments(url);
          const query = parseQuery(url);

          // ---------------- Health / Summary ----------------
          if (method === 'GET' && segments[0] === 'health') {
            return sendJSON(res, 200, { status: 'ok', mywork_root: MYWORK_ROOT, exists: fsSync.existsSync(MYWORK_ROOT) });
          }
          if (method === 'GET' && segments[0] === 'summary') {
            return sendJSON(res, 200, await getSummary());
          }
          // Global cross-account timeline
          if (method === 'GET' && segments[0] === 'timeline') {
            const lim = query.limit ? parseInt(query.limit, 10) : 800;
            return sendJSON(res, 200, await getGlobalTimeline(isNaN(lim) ? 800 : lim));
          }
          // Updates
          if (segments[0] === 'updates') {
            // Rich update feed: /updates/items[/:filename]
            if (segments[1] === 'items') {
              const fn = segments[2] ? decodeURIComponent(segments[2]) : '';
              if (method === 'GET' && !fn) return sendJSON(res, 200, await listUpdates());
              if (method === 'POST' && !fn) {
                const body = JSON.parse(await parseBody(req) || '{}');
                return sendJSON(res, 201, await createUpdate(body));
              }
              if (method === 'GET' && fn) return sendJSON(res, 200, await getUpdate(fn));
              if (method === 'PATCH' && fn) {
                const body = JSON.parse(await parseBody(req) || '{}');
                return sendJSON(res, 200, await patchUpdate(fn, body));
              }
              if (method === 'DELETE' && fn) { await deleteUpdate(fn); return sendJSON(res, 200, { ok: true }); }
              return sendError(res, 404, 'Update route not found');
            }
            // Quick per-account log (existing)
            if (method === 'GET' && segments.length === 1) return sendJSON(res, 200, await readUpdatesLog());
            if (method === 'POST' && segments.length === 1) {
              const body = JSON.parse(await parseBody(req) || '{}');
              const r = await appendUpdate({ customer: body.customer, text: body.text, date: body.date });
              return sendJSON(res, 200, { ok: true, ...r });
            }
          }

          // Work patterns
          if (segments[0] === 'patterns') {
            const fn = segments[1] ? decodeURIComponent(segments[1]) : '';
            if (method === 'GET' && !fn) return sendJSON(res, 200, await listPatterns());
            if (method === 'POST' && !fn) {
              const body = JSON.parse(await parseBody(req) || '{}');
              return sendJSON(res, 201, await createPattern(body));
            }
            if (method === 'GET' && fn) return sendJSON(res, 200, await getPattern(fn));
            if (method === 'PATCH' && fn) {
              const body = JSON.parse(await parseBody(req) || '{}');
              return sendJSON(res, 200, await patchPattern(fn, body));
            }
            if (method === 'DELETE' && fn) { await deletePattern(fn); return sendJSON(res, 200, { ok: true }); }
            return sendError(res, 404, 'Pattern route not found');
          }

          // Learnings knowledge base
          if (segments[0] === 'learnings') {
            const fn = segments[1] ? decodeURIComponent(segments[1]) : '';
            if (method === 'GET' && !fn) return sendJSON(res, 200, await listLearnings());
            if (method === 'POST' && !fn) {
              const body = JSON.parse(await parseBody(req) || '{}');
              return sendJSON(res, 201, await createLearning(body));
            }
            if (method === 'GET' && fn) return sendJSON(res, 200, await getLearning(fn));
            if (method === 'PATCH' && fn) {
              const body = JSON.parse(await parseBody(req) || '{}');
              return sendJSON(res, 200, await patchLearning(fn, body));
            }
            if (method === 'DELETE' && fn) { await deleteLearning(fn); return sendJSON(res, 200, { ok: true }); }
            return sendError(res, 404, 'Learning route not found');
          }

          // Learning Queue (things to learn / courses / topics to explore)
          if (segments[0] === 'learning-tasks') {
            const fn = segments[1] ? decodeURIComponent(segments[1]) : '';
            if (method === 'GET' && !fn) return sendJSON(res, 200, await listLearningTasks());
            if (method === 'POST' && !fn) {
              const body = JSON.parse(await parseBody(req) || '{}');
              return sendJSON(res, 201, await createLearningTask(body));
            }
            if (method === 'GET' && fn) return sendJSON(res, 200, await getLearningTask(fn));
            if (method === 'PATCH' && fn) {
              const body = JSON.parse(await parseBody(req) || '{}');
              return sendJSON(res, 200, await patchLearningTask(fn, body));
            }
            if (method === 'DELETE' && fn) { await deleteLearningTask(fn); return sendJSON(res, 200, { ok: true }); }
            return sendError(res, 404, 'Learning task route not found');
          }

          // Thought Journal
          if (segments[0] === 'journal') {
            const fn = segments[1] ? decodeURIComponent(segments[1]) : '';
            if (method === 'GET' && !fn) return sendJSON(res, 200, await listJournal());
            if (method === 'POST' && !fn) {
              const body = JSON.parse(await parseBody(req) || '{}');
              return sendJSON(res, 201, await createJournal(body));
            }
            if (method === 'GET' && fn) return sendJSON(res, 200, await getJournal(fn));
            if (method === 'PATCH' && fn) {
              const body = JSON.parse(await parseBody(req) || '{}');
              return sendJSON(res, 200, await patchJournal(fn, body));
            }
            if (method === 'DELETE' && fn) { await deleteJournal(fn); return sendJSON(res, 200, { ok: true }); }
            return sendError(res, 404, 'Journal route not found');
          }

          // ---------------- Tasks ----------------
          if (segments[0] === 'tasks') {
            // POST /api/workmgr/tasks — create
            if (method === 'POST' && segments.length === 1) {
              const body = JSON.parse(await parseBody(req) || '{}');
              const result = await createTask({
                id: body.id,
                frontmatter: body.frontmatter || {},
                body: body.body || '',
                status: body.status,
              });
              return sendJSON(res, 201, result);
            }
            // GET /api/workmgr/tasks — list all
            if (method === 'GET' && segments.length === 1) {
              return sendJSON(res, 200, await listAllTasks());
            }
            // /api/workmgr/tasks/:status/:filename[/move]
            const [_, status, filename, subAction] = segments;
            if (!status || !TASK_STATUSES.includes(status as TaskStatus)) {
              return sendError(res, 400, 'Invalid task status');
            }
            const st = status as TaskStatus;
            if (method === 'GET' && filename && !subAction) {
              return sendJSON(res, 200, await readTaskFile(st, filename));
            }
            if (method === 'PATCH' && filename && !subAction) {
              const body = JSON.parse(await parseBody(req) || '{}');
              await updateTask(st, filename, { frontmatter: body.frontmatter, body: body.body });
              return sendJSON(res, 200, await readTaskFile(st, filename));
            }
            if (method === 'POST' && filename && subAction === 'move') {
              const body = JSON.parse(await parseBody(req) || '{}');
              const to = body.to as TaskStatus;
              if (!TASK_STATUSES.includes(to)) return sendError(res, 400, 'Invalid target status');
              const result = await moveTask(st, filename, to, body.frontmatter || {});
              return sendJSON(res, 200, result);
            }
            return sendError(res, 404, 'Task route not found');
          }

          // ---------------- Accounts ----------------
          if (segments[0] === 'accounts') {
            if (method === 'GET' && segments.length === 1) {
              return sendJSON(res, 200, await listAccounts());
            }
            if (method === 'POST' && segments.length === 1) {
              const body = JSON.parse(await parseBody(req) || '{}');
              const result = await createAccount(body);
              return sendJSON(res, 201, result);
            }
            const name = decodeURIComponent(segments[1] || '');
            if (!name) return sendError(res, 400, 'Missing account name');
            if (method === 'GET' && segments.length === 2) {
              return sendJSON(res, 200, await getAccountDetail(name));
            }
            if (method === 'POST' && segments[2] === 'history') {
              const body = JSON.parse(await parseBody(req) || '{}');
              await appendAccountHistory(name, body.entry || '');
              return sendJSON(res, 200, { ok: true });
            }
            if (method === 'GET' && segments[2] === 'timeline') {
              return sendJSON(res, 200, await getCustomerTimeline(name));
            }
            if (segments[2] === 'config') {
              if (method === 'GET') return sendJSON(res, 200, await getAccountConfig(name));
              if (method === 'PUT') {
                const body = JSON.parse(await parseBody(req) || '{}');
                return sendJSON(res, 200, await saveAccountConfig(name, body));
              }
            }
            return sendError(res, 404, 'Account route not found');
          }

          // ---------------- Career ----------------
          if (segments[0] === 'career') {
            const sub = segments[1];
            if (sub === 'wins') {
              if (method === 'GET') return sendJSON(res, 200, await readWinsLog());
              if (method === 'POST') {
                const body = JSON.parse(await parseBody(req) || '{}');
                await appendManualWin(body.entry || '');
                return sendJSON(res, 200, { ok: true });
              }
            }
            if (sub === '1-1s') {
              if (method === 'GET' && segments.length === 2) return sendJSON(res, 200, await listOneOnOnes());
              if (method === 'POST' && segments.length === 2) {
                const body = JSON.parse(await parseBody(req) || '{}');
                const result = await createOneOnOne({
                  date: body.date,
                  person: body.person,
                  purpose: body.purpose,
                  agenda: body.agenda,
                });
                return sendJSON(res, 201, result);
              }
              const filename = segments[2];
              if (method === 'GET' && filename) return sendJSON(res, 200, await readOneOnOne(filename));
              if (method === 'PATCH' && filename) {
                const body = JSON.parse(await parseBody(req) || '{}');
                await updateOneOnOne(filename, { frontmatter: body.frontmatter, body: body.body });
                return sendJSON(res, 200, await readOneOnOne(filename));
              }
            }
            if (sub === 'sponsors' && segments[2] === 'touchpoint' && method === 'POST') {
              const body = JSON.parse(await parseBody(req) || '{}');
              await appendSponsorTouchpoint(body);
              return sendJSON(res, 200, { ok: true });
            }
            if (sub === 'promotion' && method === 'GET') {
              return sendJSON(res, 200, await getPromotionSnapshot());
            }
            // List the Career/*.md docs
            if (sub === 'docs' && method === 'GET') {
              const entries = await fs.readdir(CAREER_DIR).catch(() => [] as string[]);
              return sendJSON(res, 200, entries.filter(e => e.endsWith('.md')).sort());
            }
            // Read / write a single Career/*.md doc (goals, trainings, skills, …)
            if (sub === 'doc') {
              const fname = segments[2] ? decodeURIComponent(segments[2]) : '';
              if (!fname.endsWith('.md')) return sendError(res, 400, 'Only .md docs are allowed');
              const fp = safeJoin(CAREER_DIR, fname);
              if (method === 'GET') {
                const content = await fs.readFile(fp, 'utf8').catch(() => '');
                return sendJSON(res, 200, { name: fname, content });
              }
              if (method === 'PUT') {
                const body = JSON.parse(await parseBody(req) || '{}');
                await fs.writeFile(fp, String(body.content ?? ''), 'utf8');
                await audit('career.doc.save', fp, { name: fname });
                return sendJSON(res, 200, { ok: true });
              }
            }
            return sendError(res, 404, 'Career route not found');
          }

          // ---------------- Search ----------------
          if (segments[0] === 'search' && method === 'GET') {
            const q = query.q || '';
            return sendJSON(res, 200, { term: q, results: await searchAll(q, 50) });
          }

          // ---------------- Weekly Review ----------------
          if (segments[0] === 'review' && segments[1] === 'week' && method === 'GET') {
            const start = query.start || undefined;
            return sendJSON(res, 200, await getWeeklyReview(start));
          }

          next();
        } catch (err: any) {
          console.error('[workmgr]', err);
          sendError(res, 500, err.message || String(err));
        }
      });

      console.log(' 🗂️  Work Manager API enabled at /api/workmgr  ');
      console.log(`     Data root: ${MYWORK_ROOT}`);
      console.log(`     Audit log: ${AUDIT_LOG}`);
    },
  };
}
