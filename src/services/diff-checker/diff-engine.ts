import type {
  CharChange,
  DiffHunk,
  DiffLine,
  DiffOptions,
  DiffResult,
  DiffStats,
  IgnorePattern,
  SemanticFormat,
} from './types';

type Op =
  | { type: 'equal'; leftIdx: number; rightIdx: number }
  | { type: 'delete'; leftIdx: number }
  | { type: 'insert'; rightIdx: number };

const CHAR_DIFF_GUARD = 500;

export function myersDiff<T>(a: T[], b: T[], eq?: (x: T, y: T) => boolean): Op[] {
  const eqFn = eq ?? ((x: T, y: T) => x === y);
  const N = a.length;
  const M = b.length;
  if (N === 0 && M === 0) return [];
  if (N === 0) {
    const ops: Op[] = [];
    for (let i = 0; i < M; i++) ops.push({ type: 'insert', rightIdx: i });
    return ops;
  }
  if (M === 0) {
    const ops: Op[] = [];
    for (let i = 0; i < N; i++) ops.push({ type: 'delete', leftIdx: i });
    return ops;
  }

  const MAX = N + M;
  const v = new Int32Array(2 * MAX + 1);
  const trace: Int32Array[] = [];

  let foundD = -1;
  outer: for (let d = 0; d <= MAX; d++) {
    trace.push(new Int32Array(v));
    for (let k = -d; k <= d; k += 2) {
      let x: number;
      if (k === -d || (k !== d && v[k - 1 + MAX] < v[k + 1 + MAX])) {
        x = v[k + 1 + MAX];
      } else {
        x = v[k - 1 + MAX] + 1;
      }
      let y = x - k;
      while (x < N && y < M && eqFn(a[x], b[y])) {
        x++;
        y++;
      }
      v[k + MAX] = x;
      if (x >= N && y >= M) {
        foundD = d;
        break outer;
      }
    }
  }

  if (foundD < 0) return [];

  const ops: Op[] = [];
  let x = N;
  let y = M;
  for (let d = foundD; d > 0; d--) {
    const vd = trace[d];
    const k = x - y;
    let prevK: number;
    if (k === -d || (k !== d && vd[k - 1 + MAX] < vd[k + 1 + MAX])) {
      prevK = k + 1;
    } else {
      prevK = k - 1;
    }
    const prevX = vd[prevK + MAX];
    const prevY = prevX - prevK;

    while (x > prevX && y > prevY) {
      ops.push({ type: 'equal', leftIdx: x - 1, rightIdx: y - 1 });
      x--;
      y--;
    }

    if (x === prevX) {
      ops.push({ type: 'insert', rightIdx: y - 1 });
      y--;
    } else {
      ops.push({ type: 'delete', leftIdx: x - 1 });
      x--;
    }
  }

  while (x > 0 && y > 0) {
    ops.push({ type: 'equal', leftIdx: x - 1, rightIdx: y - 1 });
    x--;
    y--;
  }

  return ops.reverse();
}

function computeCharDiff(
  left: string,
  right: string,
): { left: CharChange[]; right: CharChange[] } {
  if (left.length > CHAR_DIFF_GUARD || right.length > CHAR_DIFF_GUARD) {
    return { left: [], right: [] };
  }
  const la = Array.from(left);
  const ra = Array.from(right);
  const ops = myersDiff(la, ra);

  const leftChanges: CharChange[] = [];
  const rightChanges: CharChange[] = [];

  let i = 0;
  while (i < ops.length) {
    const op = ops[i];
    if (op.type === 'delete') {
      const start = op.leftIdx;
      let end = start + 1;
      i++;
      while (i < ops.length && ops[i].type === 'delete' && (ops[i] as { leftIdx: number }).leftIdx === end) {
        end++;
        i++;
      }
      leftChanges.push({ side: 'left', start, end, type: 'delete' });
    } else if (op.type === 'insert') {
      const start = op.rightIdx;
      let end = start + 1;
      i++;
      while (i < ops.length && ops[i].type === 'insert' && (ops[i] as { rightIdx: number }).rightIdx === end) {
        end++;
        i++;
      }
      rightChanges.push({ side: 'right', start, end, type: 'insert' });
    } else {
      i++;
    }
  }

  return { left: leftChanges, right: rightChanges };
}

interface PreprocessResult {
  original: string[];
  normalized: string[];
  indexMap: number[];
}

function preprocessLines(text: string, options: DiffOptions): PreprocessResult {
  const original = text.split('\n');
  const normalized: string[] = [];
  const indexMap: number[] = [];

  for (let i = 0; i < original.length; i++) {
    const raw = original[i];
    if (options.ignoreBlankLines && raw.trim() === '') continue;
    let n = raw;
    if (options.ignoreCase) n = n.toLowerCase();
    if (options.ignoreWhitespace) n = n.replace(/\s+/g, ' ').trim();
    normalized.push(n);
    indexMap.push(i);
  }
  return { original, normalized, indexMap };
}

function buildPatternRegexes(patterns: IgnorePattern[]): RegExp[] {
  const out: RegExp[] = [];
  for (const p of patterns) {
    if (!p.enabled) continue;
    try {
      let src = p.pattern;
      let flags = 'g';
      const m = src.match(/^\/(.+)\/([a-z]*)$/);
      if (m) {
        src = m[1];
        flags = m[2].includes('g') ? m[2] : m[2] + 'g';
      }
      out.push(new RegExp(src, flags));
    } catch {
      // Ignore invalid regex
    }
  }
  return out;
}

function stripPatterns(text: string, regexes: RegExp[]): string {
  let out = text;
  for (const r of regexes) {
    r.lastIndex = 0;
    out = out.replace(r, '');
  }
  return out;
}

function opsToRows(
  ops: Op[],
  leftOriginal: string[],
  rightOriginal: string[],
  leftMap: number[],
  rightMap: number[],
): DiffLine[] {
  const rows: DiffLine[] = [];
  let i = 0;
  while (i < ops.length) {
    const op = ops[i];
    if (op.type === 'equal') {
      const leftReal = leftMap[op.leftIdx];
      const rightReal = rightMap[op.rightIdx];
      rows.push({
        type: 'equal',
        lineNumLeft: leftReal + 1,
        lineNumRight: rightReal + 1,
        leftContent: leftOriginal[leftReal],
        rightContent: rightOriginal[rightReal],
        content: leftOriginal[leftReal],
      });
      i++;
      continue;
    }

    const deletes: number[] = [];
    while (i < ops.length && ops[i].type === 'delete') {
      deletes.push((ops[i] as { leftIdx: number }).leftIdx);
      i++;
    }
    const inserts: number[] = [];
    while (i < ops.length && ops[i].type === 'insert') {
      inserts.push((ops[i] as { rightIdx: number }).rightIdx);
      i++;
    }

    const pairCount = Math.min(deletes.length, inserts.length);
    for (let p = 0; p < pairCount; p++) {
      const li = leftMap[deletes[p]];
      const ri = rightMap[inserts[p]];
      const lc = leftOriginal[li];
      const rc = rightOriginal[ri];
      const charDiff = computeCharDiff(lc, rc);
      rows.push({
        type: 'replace',
        lineNumLeft: li + 1,
        lineNumRight: ri + 1,
        leftContent: lc,
        rightContent: rc,
        content: rc,
        leftCharChanges: charDiff.left,
        rightCharChanges: charDiff.right,
      });
    }
    for (let p = pairCount; p < deletes.length; p++) {
      const li = leftMap[deletes[p]];
      rows.push({
        type: 'delete',
        lineNumLeft: li + 1,
        leftContent: leftOriginal[li],
        content: leftOriginal[li],
      });
    }
    for (let p = pairCount; p < inserts.length; p++) {
      const ri = rightMap[inserts[p]];
      rows.push({
        type: 'insert',
        lineNumRight: ri + 1,
        rightContent: rightOriginal[ri],
        content: rightOriginal[ri],
      });
    }
  }
  return rows;
}

function markNoise(rows: DiffLine[], regexes: RegExp[]): DiffLine[] {
  if (regexes.length === 0) return rows;
  return rows.map(row => {
    if (row.type === 'replace') {
      const leftStripped = stripPatterns(row.leftContent ?? '', regexes);
      const rightStripped = stripPatterns(row.rightContent ?? '', regexes);
      if (leftStripped === rightStripped) {
        return { ...row, isNoise: true };
      }
    }
    return row;
  });
}

function groupIntoHunks(rows: DiffLine[], contextLines: number): DiffHunk[] {
  const hunks: DiffHunk[] = [];
  let i = 0;
  const isChange = (r: DiffLine) => r.type !== 'equal' && !r.isNoise;

  while (i < rows.length) {
    if (!isChange(rows[i])) {
      i++;
      continue;
    }
    const hunkStart = Math.max(0, i - contextLines);
    let j = i;
    let lastChange = i;
    while (j < rows.length) {
      if (isChange(rows[j])) {
        lastChange = j;
        j++;
        continue;
      }
      let eq = j;
      while (eq < rows.length && !isChange(rows[eq])) eq++;
      if (eq < rows.length && eq - j <= 2 * contextLines) {
        j = eq;
      } else {
        break;
      }
    }
    const hunkEnd = Math.min(rows.length, lastChange + 1 + contextLines);
    const slice = rows.slice(hunkStart, hunkEnd);
    const hunkLines = slice.map(r => ({ ...r, isContext: r.type === 'equal' }));

    let firstLeft = 0;
    let firstRight = 0;
    let lastLeft = 0;
    let lastRight = 0;
    for (const r of hunkLines) {
      if (r.lineNumLeft && firstLeft === 0) firstLeft = r.lineNumLeft;
      if (r.lineNumRight && firstRight === 0) firstRight = r.lineNumRight;
      if (r.lineNumLeft) lastLeft = r.lineNumLeft;
      if (r.lineNumRight) lastRight = r.lineNumRight;
    }

    hunks.push({
      id: `hunk-${hunks.length}`,
      lines: hunkLines,
      leftStart: firstLeft,
      leftEnd: lastLeft,
      rightStart: firstRight,
      rightEnd: lastRight,
    });
    i = hunkEnd;
  }
  return hunks;
}

function computeStats(rows: DiffLine[], hunkCount: number): DiffStats {
  let additions = 0;
  let deletions = 0;
  let noiseLines = 0;
  for (const r of rows) {
    if (r.isNoise) {
      noiseLines++;
      continue;
    }
    if (r.type === 'insert') additions++;
    else if (r.type === 'delete') deletions++;
    else if (r.type === 'replace') {
      additions++;
      deletions++;
    }
  }
  const totalLines = rows.length;
  const changedLines = additions + deletions;
  const similarityPercent = totalLines === 0
    ? 100
    : Math.max(0, Math.round(((totalLines - changedLines) / totalLines) * 100));

  return {
    additions,
    deletions,
    hunkCount,
    changedLines,
    totalLines,
    noiseLines,
    similarityPercent,
  };
}

export function computeDiff(
  left: string,
  right: string,
  options: DiffOptions,
  patterns: IgnorePattern[] = [],
  format: SemanticFormat = 'none',
): DiffResult {
  const leftPre = preprocessLines(left, options);
  const rightPre = preprocessLines(right, options);
  const ops = myersDiff(leftPre.normalized, rightPre.normalized);
  const rows = opsToRows(ops, leftPre.original, rightPre.original, leftPre.indexMap, rightPre.indexMap);
  const regexes = buildPatternRegexes(patterns.filter(p => options.activePatterns.includes(p.id)));
  const noiseRows = markNoise(rows, regexes);
  const hunks = groupIntoHunks(noiseRows, options.contextLines);
  const stats = computeStats(noiseRows, hunks.length);

  return {
    hunks,
    stats,
    algorithm: 'myers',
    format,
  };
}

export function buildMergedOutput(hunks: DiffHunk[], leftFull: string, rightFull: string): string {
  const leftLines = leftFull.split('\n');
  const rightLines = rightFull.split('\n');
  const out: string[] = [];

  let cursor = 1;

  for (const hunk of hunks) {
    const startLine = hunk.leftStart > 0 ? hunk.leftStart : hunk.rightStart;
    while (cursor < startLine) {
      if (leftLines[cursor - 1] !== undefined) out.push(leftLines[cursor - 1]);
      cursor++;
    }

    const decision = hunk.mergeDecision ?? 'left';
    if (decision === 'manual' && typeof hunk.manualContent === 'string') {
      out.push(...hunk.manualContent.split('\n'));
    } else {
      for (const line of hunk.lines) {
        if (line.isContext) {
          if (line.leftContent !== undefined) out.push(line.leftContent);
          continue;
        }
        if (decision === 'skip') {
          if (line.leftContent !== undefined) out.push(line.leftContent);
        } else if (decision === 'left') {
          if (line.leftContent !== undefined) out.push(line.leftContent);
        } else if (decision === 'right') {
          if (line.rightContent !== undefined) out.push(line.rightContent);
        } else if (decision === 'both') {
          if (line.leftContent !== undefined) out.push(line.leftContent);
          if (line.rightContent !== undefined && line.rightContent !== line.leftContent) {
            out.push(line.rightContent);
          }
        }
      }
    }

    const endLine = hunk.leftEnd > 0 ? hunk.leftEnd + 1 : cursor;
    cursor = Math.max(cursor, endLine);
  }

  while (cursor <= leftLines.length) {
    out.push(leftLines[cursor - 1]);
    cursor++;
  }

  void rightLines;
  return out.join('\n');
}

export function detectFormat(text: string, hint?: string): SemanticFormat {
  if (hint) {
    const h = hint.toLowerCase();
    if (h === 'json') return 'json';
    if (h === 'yaml' || h === 'yml') return 'yaml';
    if (h === 'xml' || h === 'html' || h === 'svg') return 'xml';
  }
  const trimmed = text.trim();
  if (!trimmed) return 'none';
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      JSON.parse(trimmed);
      return 'json';
    } catch {
      // fall through
    }
  }
  if (trimmed.startsWith('<') && trimmed.endsWith('>')) return 'xml';
  if (/^[\w-]+:\s/.test(trimmed) || trimmed.startsWith('---')) return 'yaml';
  return 'none';
}

export function detectLanguage(filename?: string, content?: string): string {
  if (filename) {
    const ext = filename.split('.').pop()?.toLowerCase();
    const map: Record<string, string> = {
      js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
      ts: 'typescript', tsx: 'typescript',
      py: 'python', rb: 'ruby', go: 'go', rs: 'rust',
      java: 'java', kt: 'kotlin', scala: 'scala',
      c: 'c', h: 'c', cc: 'cpp', cpp: 'cpp', cxx: 'cpp', hpp: 'cpp',
      cs: 'csharp', swift: 'swift',
      json: 'json', yaml: 'yaml', yml: 'yaml', toml: 'ini', ini: 'ini', env: 'ini',
      xml: 'xml', html: 'xml', htm: 'xml', svg: 'xml',
      css: 'css', scss: 'scss', less: 'less',
      sql: 'sql', sh: 'bash', bash: 'bash', zsh: 'bash', fish: 'bash',
      md: 'markdown', markdown: 'markdown',
      tf: 'hcl', hcl: 'hcl', nomad: 'hcl',
      conf: 'nginx', nginx: 'nginx',
      dockerfile: 'dockerfile',
    };
    if (ext && map[ext]) return map[ext];
    if (filename.toLowerCase() === 'dockerfile') return 'dockerfile';
  }
  if (content) {
    const t = content.trim();
    if ((t.startsWith('{') || t.startsWith('[')) && t.length < 1_000_000) {
      try { JSON.parse(t); return 'json'; } catch { /* */ }
    }
    if (t.startsWith('<?xml') || (t.startsWith('<') && t.endsWith('>'))) return 'xml';
    if (t.startsWith('---') || /^[\w-]+:\s/.test(t)) return 'yaml';
    if (/^\s*#!\/.*\b(bash|sh|zsh)\b/m.test(t)) return 'bash';
    if (/^\s*(function|const|let|var|import|export)\s/.test(t)) return 'javascript';
    if (/^\s*(def|class|import|from)\s/.test(t)) return 'python';
  }
  return 'plaintext';
}
