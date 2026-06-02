import type { GitHubFile, GitHubPRInfo } from './types';

const TOKEN_KEY = 'xc-app-store:diff-checker:github-token';

export function getStoredToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? '';
  } catch {
    return '';
  }
}

export function setStoredToken(token: string) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // ignore
  }
}

function authHeaders(token?: string): Record<string, string> {
  const h: Record<string, string> = { Accept: 'application/vnd.github+json' };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

export function parsePRUrl(url: string): { owner: string; repo: string; number: number } | null {
  const m = url.match(/github\.com\/([^/]+)\/([^/]+)\/pull\/(\d+)/);
  if (!m) return null;
  return { owner: m[1], repo: m[2], number: Number(m[3]) };
}

export function parseCommitUrl(url: string): { owner: string; repo: string; sha: string } | null {
  const m = url.match(/github\.com\/([^/]+)\/([^/]+)\/commit\/([0-9a-f]+)/i);
  if (!m) return null;
  return { owner: m[1], repo: m[2], sha: m[3] };
}

export async function fetchPR(url: string, token?: string): Promise<GitHubPRInfo> {
  const parsed = parsePRUrl(url);
  if (!parsed) throw new Error('Not a valid GitHub PR URL');
  const { owner, repo, number } = parsed;
  const headers = authHeaders(token);

  const [prRes, filesRes] = await Promise.all([
    fetch(`https://api.github.com/repos/${owner}/${repo}/pulls/${number}`, { headers }),
    fetch(`https://api.github.com/repos/${owner}/${repo}/pulls/${number}/files?per_page=100`, { headers }),
  ]);
  if (!prRes.ok) throw new Error(`GitHub API error ${prRes.status}: ${await prRes.text()}`);
  if (!filesRes.ok) throw new Error(`GitHub API error ${filesRes.status}: ${await filesRes.text()}`);
  const pr = await prRes.json();
  const files = (await filesRes.json()) as Array<Record<string, unknown>>;

  return {
    number: pr.number,
    title: pr.title,
    repo,
    owner,
    baseSha: pr.base.sha,
    headSha: pr.head.sha,
    files: files.map((f): GitHubFile => ({
      filename: String(f.filename ?? ''),
      status: (f.status as GitHubFile['status']) ?? 'modified',
      additions: Number(f.additions ?? 0),
      deletions: Number(f.deletions ?? 0),
      patch: typeof f.patch === 'string' ? f.patch : undefined,
      rawUrl: typeof f.raw_url === 'string' ? f.raw_url : undefined,
      blobUrl: typeof f.blob_url === 'string' ? f.blob_url : undefined,
      previousFilename: typeof f.previous_filename === 'string' ? f.previous_filename : undefined,
    })),
  };
}

export async function fetchCommit(url: string, token?: string): Promise<GitHubPRInfo> {
  const parsed = parseCommitUrl(url);
  if (!parsed) throw new Error('Not a valid GitHub commit URL');
  const { owner, repo, sha } = parsed;
  const headers = authHeaders(token);
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/commits/${sha}`, { headers });
  if (!res.ok) throw new Error(`GitHub API error ${res.status}: ${await res.text()}`);
  const commit = await res.json();
  return {
    number: 0,
    title: commit.commit?.message?.split('\n')[0] ?? sha,
    owner,
    repo,
    baseSha: commit.parents?.[0]?.sha ?? sha,
    headSha: sha,
    files: (commit.files ?? []).map((f: Record<string, unknown>): GitHubFile => ({
      filename: String(f.filename ?? ''),
      status: (f.status as GitHubFile['status']) ?? 'modified',
      additions: Number(f.additions ?? 0),
      deletions: Number(f.deletions ?? 0),
      patch: typeof f.patch === 'string' ? f.patch : undefined,
      rawUrl: typeof f.raw_url === 'string' ? f.raw_url : undefined,
      blobUrl: typeof f.blob_url === 'string' ? f.blob_url : undefined,
    })),
  };
}

export async function fetchFileAtSha(
  owner: string,
  repo: string,
  path: string,
  sha: string,
  token?: string,
): Promise<string> {
  const headers: Record<string, string> = { Accept: 'application/vnd.github.v3.raw' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${sha}`,
    { headers },
  );
  if (res.status === 404) return '';
  if (!res.ok) throw new Error(`GitHub fetch failed (${res.status}): ${await res.text()}`);
  return res.text();
}

export function parseUnifiedDiff(diffText: string): GitHubFile[] {
  const files: GitHubFile[] = [];
  const lines = diffText.split('\n');
  let current: GitHubFile | null = null;
  let buf: string[] = [];

  const flush = () => {
    if (current) {
      current.patch = buf.join('\n');
      files.push(current);
    }
    current = null;
    buf = [];
  };

  for (const line of lines) {
    if (line.startsWith('diff --git ')) {
      flush();
      const m = line.match(/^diff --git a\/(.+?) b\/(.+)$/);
      current = {
        filename: m ? m[2] : 'unknown',
        status: 'modified',
        additions: 0,
        deletions: 0,
      };
      buf = [];
    } else if (current) {
      if (line.startsWith('+') && !line.startsWith('+++')) current.additions++;
      else if (line.startsWith('-') && !line.startsWith('---')) current.deletions++;
      buf.push(line);
    }
  }
  flush();
  return files;
}

export function reconstructFromPatch(patch: string): { before: string; after: string } {
  const before: string[] = [];
  const after: string[] = [];
  const lines = patch.split('\n');
  for (const line of lines) {
    if (line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++') || line.startsWith('diff ') || line.startsWith('index ')) continue;
    if (line.startsWith('+')) {
      after.push(line.slice(1));
    } else if (line.startsWith('-')) {
      before.push(line.slice(1));
    } else if (line.startsWith(' ')) {
      const content = line.slice(1);
      before.push(content);
      after.push(content);
    }
  }
  return { before: before.join('\n'), after: after.join('\n') };
}
