import { useCallback, useEffect, useMemo, useState } from 'react';
import { ArrowLeft, GitCompare, Copy, Download, Github, ChevronDown } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useToast } from '../context/ToastContext';
import { InputPanel } from '../components/diff-checker/InputPanel';
import { DiffControls } from '../components/diff-checker/DiffControls';
import { DiffStatsBar } from '../components/diff-checker/DiffStats';
import { DiffView } from '../components/diff-checker/DiffView';
import { SemanticView } from '../components/diff-checker/SemanticView';
import { MergeView } from '../components/diff-checker/MergeView';
import { IgnorePatternsEditor } from '../components/diff-checker/IgnorePatterns';
import { HistoryPanel } from '../components/diff-checker/HistoryPanel';
import {
  DEFAULT_DIFF_OPTIONS,
  type DiffHunk,
  type DiffOptions,
  type DiffSnapshot,
  type IgnorePattern,
  type SemanticFormat,
  type ThreeWayInput,
} from '../services/diff-checker/types';
import { buildMergedOutput, computeDiff, detectFormat, detectLanguage } from '../services/diff-checker/diff-engine';
import { runSemanticDiff } from '../services/diff-checker/semantic-diff';
import { clearURLFragment, decodeDiffFromURL, encodeDiffToURL, estimateURLLength } from '../services/diff-checker/share-encoder';
import { loadPatterns } from '../services/diff-checker/ignore-patterns';
import { saveSnapshot } from '../services/diff-checker/history';
import {
  fetchCommit,
  fetchFileAtSha,
  fetchPR,
  getStoredToken,
  parseCommitUrl,
  parsePRUrl,
  parseUnifiedDiff,
  reconstructFromPatch,
  setStoredToken,
} from '../services/diff-checker/github-import';
import type { GitHubFile, GitHubPRInfo } from '../services/diff-checker/types';

import 'highlight.js/styles/atom-one-dark.css';
import './diff-checker.css';

type Mode = 'two-way' | 'three-way';

export function DiffChecker() {
  const toast = useToast();
  const [mode, setMode] = useState<Mode>('two-way');
  const [left, setLeft] = useState('');
  const [right, setRight] = useState('');
  const [leftFile, setLeftFile] = useState<string | undefined>();
  const [rightFile, setRightFile] = useState<string | undefined>();
  const [threeWay, setThreeWay] = useState<ThreeWayInput>({ base: '', left: '', right: '' });
  const [options, setOptions] = useState<DiffOptions>(DEFAULT_DIFF_OPTIONS);
  const [semanticFormat, setSemanticFormat] = useState<SemanticFormat>('none');
  const [patterns, setPatterns] = useState<IgnorePattern[]>(() => loadPatterns());
  const [patternsOpen, setPatternsOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [hunkDecisions, setHunkDecisions] = useState<Record<string, DiffHunk['mergeDecision']>>({});
  const [activeHunkIdx, setActiveHunkIdx] = useState(0);
  const [pr, setPr] = useState<GitHubPRInfo | null>(null);
  const [ghToken, setGhToken] = useState(getStoredToken());
  const [ghError, setGhError] = useState<string | null>(null);
  const [ghLoading, setGhLoading] = useState(false);

  useEffect(() => {
    const payload = decodeDiffFromURL();
    if (payload) {
      setLeft(payload.l);
      setRight(payload.r);
      if (payload.b !== undefined) setThreeWay(prev => ({ ...prev, base: payload.b!, left: payload.l, right: payload.r }));
      setOptions(payload.o);
      setSemanticFormat(payload.f);
      toast.success('Loaded shared diff from URL');
    }
  }, [toast]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if (e.key === ']') { e.preventDefault(); jumpHunk(1); }
      else if (e.key === '[') { e.preventDefault(); jumpHunk(-1); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  const language = options.language === 'auto'
    ? detectLanguage(leftFile ?? rightFile, left || right)
    : options.language;

  const autoFormat = useMemo(() => detectFormat(left, leftFile?.split('.').pop()), [left, leftFile]);
  const effectiveFormat: SemanticFormat = semanticFormat !== 'none' ? semanticFormat : autoFormat;

  const result = useMemo(() => {
    if (mode !== 'two-way') {
      return { hunks: [], stats: { additions: 0, deletions: 0, hunkCount: 0, changedLines: 0, totalLines: 0, noiseLines: 0, similarityPercent: 100 }, algorithm: 'myers' as const, format: 'none' as const };
    }
    return computeDiff(left, right, options, patterns, effectiveFormat);
  }, [mode, left, right, options, patterns, effectiveFormat]);

  const semantic = useMemo(() => {
    if (effectiveFormat === 'none' || mode !== 'two-way' || !left || !right) return { changes: [], error: undefined as string | undefined };
    return runSemanticDiff(effectiveFormat, left, right);
  }, [effectiveFormat, mode, left, right]);

  const hunksWithDecisions = useMemo(
    () => result.hunks.map(h => ({ ...h, mergeDecision: hunkDecisions[h.id] })),
    [result.hunks, hunkDecisions],
  );

  const activeHunkId = hunksWithDecisions[activeHunkIdx]?.id;

  const jumpHunk = useCallback((delta: number) => {
    setActiveHunkIdx(idx => {
      const next = Math.max(0, Math.min(result.hunks.length - 1, idx + delta));
      return next;
    });
  }, [result.hunks.length]);

  const handleDecision = useCallback((id: string, decision: DiffHunk['mergeDecision']) => {
    setHunkDecisions(prev => ({ ...prev, [id]: decision }));
  }, []);

  const handleSwap = useCallback(() => {
    setLeft(right);
    setRight(left);
    setLeftFile(rightFile);
    setRightFile(leftFile);
  }, [left, right, leftFile, rightFile]);

  const handleShare = useCallback(async () => {
    const len = estimateURLLength(left, right, options, effectiveFormat, mode === 'three-way' ? threeWay.base : undefined);
    if (len > 50_000) {
      toast.warning(`URL is ${len.toLocaleString()} chars — may be too large for some browsers`);
    }
    const url = encodeDiffToURL(left, right, options, effectiveFormat, mode === 'three-way' ? threeWay.base : undefined);
    try {
      await navigator.clipboard.writeText(url);
      toast.success('Share link copied to clipboard');
    } catch {
      toast.info(url);
    }
  }, [left, right, options, effectiveFormat, mode, threeWay.base, toast]);

  const handleSave = useCallback(() => {
    const snap = saveSnapshot(
      mode === 'three-way' ? threeWay.left : left,
      mode === 'three-way' ? threeWay.right : right,
      options,
      effectiveFormat,
      mode === 'three-way' ? threeWay.base : undefined,
    );
    toast.success(`Saved: ${snap.name}`);
  }, [left, right, options, effectiveFormat, mode, threeWay, toast]);

  const handleRestore = useCallback((snap: DiffSnapshot) => {
    if (snap.baseContent !== undefined) {
      setMode('three-way');
      setThreeWay({ base: snap.baseContent, left: snap.leftContent, right: snap.rightContent });
    } else {
      setMode('two-way');
      setLeft(snap.leftContent);
      setRight(snap.rightContent);
    }
    setOptions(snap.options);
    setSemanticFormat(snap.format);
    setHistoryOpen(false);
    toast.success(`Restored: ${snap.name}`);
  }, [toast]);

  const handleGitHubImport = useCallback(async (url: string) => {
    setGhError(null);
    setGhLoading(true);
    setPr(null);
    try {
      let info: GitHubPRInfo;
      if (parsePRUrl(url)) {
        info = await fetchPR(url, ghToken || undefined);
      } else if (parseCommitUrl(url)) {
        info = await fetchCommit(url, ghToken || undefined);
      } else if (url.includes('diff --git') || /^---\s/m.test(url) || url.endsWith('.diff') || url.endsWith('.patch')) {
        let diffText = url;
        if (url.startsWith('http')) {
          const res = await fetch(url);
          diffText = await res.text();
        }
        info = {
          number: 0, title: 'Pasted diff', repo: '', owner: '', baseSha: '', headSha: '',
          files: parseUnifiedDiff(diffText),
        };
      } else {
        throw new Error('Expected GitHub PR/commit URL, .diff URL, or pasted unified diff text');
      }
      setPr(info);
      toast.success(`Loaded ${info.files.length} files from ${info.repo || 'diff'}`);
    } catch (e) {
      setGhError(e instanceof Error ? e.message : String(e));
    } finally {
      setGhLoading(false);
    }
  }, [ghToken, toast]);

  const loadPRFile = useCallback(async (file: GitHubFile) => {
    if (!pr) return;
    if (pr.baseSha && pr.headSha) {
      try {
        const [before, after] = await Promise.all([
          fetchFileAtSha(pr.owner, pr.repo, file.previousFilename ?? file.filename, pr.baseSha, ghToken || undefined),
          fetchFileAtSha(pr.owner, pr.repo, file.filename, pr.headSha, ghToken || undefined),
        ]);
        setLeft(before);
        setRight(after);
        setLeftFile(file.previousFilename ?? file.filename);
        setRightFile(file.filename);
        toast.success(`Loaded ${file.filename}`);
        return;
      } catch (e) {
        toast.warning(`Could not load file contents: ${e instanceof Error ? e.message : 'unknown'}`);
      }
    }
    if (file.patch) {
      const { before, after } = reconstructFromPatch(file.patch);
      setLeft(before);
      setRight(after);
      setLeftFile(file.previousFilename ?? file.filename);
      setRightFile(file.filename);
      toast.info(`Reconstructed ${file.filename} from patch`);
    }
  }, [pr, ghToken, toast]);

  const mergedOutput = useMemo(() => {
    if (mode !== 'two-way') return '';
    return buildMergedOutput(hunksWithDecisions, left, right);
  }, [hunksWithDecisions, left, right, mode]);

  const copyMerged = async () => {
    try {
      await navigator.clipboard.writeText(mergedOutput);
      toast.success('Merged output copied');
    } catch {
      toast.error('Could not copy');
    }
  };
  const downloadMerged = () => {
    const blob = new Blob([mergedOutput], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = leftFile ? `merged-${leftFile}` : `merged-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const decidedCount = Object.values(hunkDecisions).filter(d => d !== undefined).length;

  return (
    <main className="max-w-7xl mx-auto px-6 py-6">
      <div className="mb-4 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-1 text-sm text-slate-400 hover:text-slate-100">
          <ArrowLeft className="w-4 h-4" /> Back
        </Link>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => { clearURLFragment(); }}
            className="hidden"
          />
          <button type="button" onClick={() => setHistoryOpen(true)} className="px-2 py-1 text-xs bg-slate-800 border border-slate-700 hover:border-slate-600 text-slate-300 rounded">History</button>
        </div>
      </div>

      <div className="mb-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-blue-500/15 rounded-xl flex items-center justify-center">
            <GitCompare className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Diff Checker</h1>
            <p className="text-sm text-slate-400">Client-side diff &amp; 3-way merge with semantic JSON/YAML/XML, char-level highlighting, ignore patterns, and GitHub PR import. No content leaves your browser.</p>
          </div>
        </div>
        <div className="inline-flex items-center bg-slate-800 border border-slate-700 rounded p-0.5">
          <button
            type="button"
            onClick={() => setMode('two-way')}
            className={`px-3 py-1.5 text-xs rounded ${mode === 'two-way' ? 'bg-blue-500/20 text-blue-300' : 'text-slate-400 hover:text-slate-200'}`}
          >
            2-Way Diff
          </button>
          <button
            type="button"
            onClick={() => setMode('three-way')}
            className={`px-3 py-1.5 text-xs rounded ${mode === 'three-way' ? 'bg-blue-500/20 text-blue-300' : 'text-slate-400 hover:text-slate-200'}`}
          >
            3-Way Merge
          </button>
        </div>
      </div>

      {mode === 'two-way' ? (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <InputPanel
              label="Original (Left)"
              value={left}
              onChange={(v, f) => { setLeft(v); if (f) setLeftFile(f); }}
              onClear={() => { setLeft(''); setLeftFile(undefined); }}
              filename={leftFile}
              language={language}
              showGitHub
              onGitHubImport={handleGitHubImport}
            />
            <InputPanel
              label="Changed (Right)"
              value={right}
              onChange={(v, f) => { setRight(v); if (f) setRightFile(f); }}
              onClear={() => { setRight(''); setRightFile(undefined); }}
              filename={rightFile}
              language={language}
            />
          </div>

          {pr && (
            <div className="mb-4 border border-violet-500/30 bg-violet-500/[0.04] rounded-lg overflow-hidden">
              <div className="flex items-center justify-between px-3 py-2 border-b border-slate-700">
                <div className="flex items-center gap-2 text-sm">
                  <Github className="w-4 h-4 text-violet-400" />
                  <span className="text-slate-200">{pr.repo ? `${pr.owner}/${pr.repo}` : 'Pasted diff'}</span>
                  {pr.number > 0 && <span className="text-slate-500">#{pr.number}</span>}
                  <span className="text-slate-400 truncate max-w-md">{pr.title}</span>
                </div>
                <button type="button" onClick={() => setPr(null)} className="text-xs text-slate-400 hover:text-slate-100">Close</button>
              </div>
              <div className="max-h-48 overflow-auto p-2">
                {pr.files.map(file => (
                  <button
                    key={file.filename}
                    type="button"
                    onClick={() => loadPRFile(file)}
                    className="w-full flex items-center gap-3 px-2 py-1 text-left text-xs text-slate-300 hover:bg-slate-800 rounded"
                  >
                    <span className={`w-14 ${file.status === 'added' ? 'text-emerald-400' : file.status === 'removed' ? 'text-rose-400' : 'text-amber-300'}`}>{file.status}</span>
                    <span className="flex-1 font-mono truncate">{file.filename}</span>
                    <span className="text-emerald-400">+{file.additions}</span>
                    <span className="text-rose-400">−{file.deletions}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {ghLoading && <div className="mb-2 text-xs text-slate-400">Loading from GitHub…</div>}
          {ghError && (
            <div className="mb-4 p-3 bg-rose-500/10 border border-rose-500/30 rounded text-xs text-rose-300">
              <div className="font-semibold mb-1">GitHub import failed</div>
              <div className="font-mono">{ghError}</div>
              <div className="mt-2 flex items-center gap-2">
                <input
                  type="password"
                  value={ghToken}
                  onChange={e => { setGhToken(e.target.value); setStoredToken(e.target.value); }}
                  placeholder="Optional: GitHub PAT for private repos / higher rate limits"
                  className="flex-1 px-2 py-1 bg-slate-900 border border-slate-700 rounded text-slate-200 text-xs outline-none"
                />
              </div>
            </div>
          )}

          <div className="border border-slate-700 rounded-lg overflow-hidden bg-slate-900/30">
            <DiffControls
              options={options}
              onChange={next => setOptions(o => ({ ...o, ...next }))}
              semanticFormat={effectiveFormat}
              onSemanticFormatChange={f => setSemanticFormat(f === effectiveFormat ? 'none' : f)}
              onShare={handleShare}
              onSave={handleSave}
              onSwap={handleSwap}
              onOpenPatterns={() => setPatternsOpen(true)}
              patternsActiveCount={patterns.filter(p => p.enabled).length}
            />
            <DiffStatsBar
              stats={result.stats}
              onPrev={() => jumpHunk(-1)}
              onNext={() => jumpHunk(1)}
              currentHunk={result.hunks.length ? activeHunkIdx : undefined}
              totalHunks={result.hunks.length}
            />

            {effectiveFormat !== 'none' && (left || right) ? (
              <SemanticView
                changes={semantic.changes}
                error={semantic.error}
                formatLabel={effectiveFormat.toUpperCase()}
              />
            ) : null}

            <DiffView
              result={{ ...result, hunks: hunksWithDecisions }}
              options={options}
              language={language}
              onHunkDecision={handleDecision}
              activeHunkId={activeHunkId}
            />
          </div>

          {decidedCount > 0 && (
            <details className="mt-4 border border-slate-700 rounded-lg bg-slate-900/30" open>
              <summary className="cursor-pointer px-3 py-2 text-sm text-slate-200 flex items-center gap-2">
                <ChevronDown className="w-4 h-4" /> Merged output ({decidedCount} of {result.hunks.length} hunks resolved)
                <span className="flex-1" />
                <button type="button" onClick={e => { e.preventDefault(); copyMerged(); }} className="flex items-center gap-1 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-700 rounded">
                  <Copy className="w-3.5 h-3.5" /> Copy
                </button>
                <button type="button" onClick={e => { e.preventDefault(); downloadMerged(); }} className="flex items-center gap-1 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-700 rounded">
                  <Download className="w-3.5 h-3.5" /> Download
                </button>
              </summary>
              <pre className="p-3 max-h-[400px] overflow-auto text-[12px] font-mono text-slate-200 whitespace-pre border-t border-slate-700">{mergedOutput}</pre>
            </details>
          )}
        </>
      ) : (
        <MergeView input={threeWay} onInputChange={setThreeWay} />
      )}

      {patternsOpen && (
        <IgnorePatternsEditor
          patterns={patterns}
          onChange={(next) => {
            setPatterns(next);
            setOptions(o => ({ ...o, activePatterns: next.filter(p => p.enabled).map(p => p.id) }));
          }}
          sampleText={left || right}
          onClose={() => setPatternsOpen(false)}
        />
      )}

      <HistoryPanel open={historyOpen} onClose={() => setHistoryOpen(false)} onRestore={handleRestore} />
    </main>
  );
}

export default DiffChecker;
