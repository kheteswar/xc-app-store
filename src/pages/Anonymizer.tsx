import { useCallback, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Download,
  EyeOff,
  FileText,
  HelpCircle,
  Key,
  Lock,
  Loader2,
  Plus,
  RefreshCcw,
  Search,
  Shield,
  Sparkles,
  Upload,
  XCircle,
} from 'lucide-react';
import {
  AUTO_RULE_LABELS,
  EMPTY_MAPPING,
  EXAMPLE_MAPPING,
  SUPPORTED_EXTS,
  appendMappingEntry,
  extractText,
  getExtension,
  parseMappingFull,
  processFile,
  rotateSecret,
  scanForLeaks,
  suggestEntry,
  type AutoConfig,
  type Direction,
  type MappingEntry,
  type ProcessResult,
  type SuggestedEntry,
} from '../services/anonymizer';
import { useToast } from '../context/ToastContext';

type Mode = Direction | 'scan';

const MAPPING_STORAGE_KEY = 'xc-app-store:anonymizer:mapping';

const MODES: Array<{ id: Mode; label: string; help: string }> = [
  {
    id: 'anonymize',
    label: 'Anonymize',
    help: 'Replace real values with placeholders before sharing the file.',
  },
  {
    id: 'deanonymize',
    label: 'Deanonymize',
    help: 'Replace placeholders with real values before customer delivery.',
  },
  {
    id: 'scan',
    label: 'Scan',
    help: 'Report identifying tokens (IPs, emails, names) not yet in the mapping.',
  },
];

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function Anonymizer() {
  const toast = useToast();
  const [mode, setMode] = useState<Mode>('anonymize');
  const [file, setFile] = useState<File | null>(null);
  const [mappingText, setMappingText] = useState<string>(() => {
    try {
      return localStorage.getItem(MAPPING_STORAGE_KEY) || EXAMPLE_MAPPING;
    } catch {
      return EXAMPLE_MAPPING;
    }
  });
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ProcessResult | null>(null);
  const [scanResult, setScanResult] = useState<Record<string, string[]> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [addedTokens, setAddedTokens] = useState<Set<string>>(new Set());
  const fileInputRef = useRef<HTMLInputElement>(null);

  interface ParsedState {
    entries: MappingEntry[];
    secret: string | null;
    auto: AutoConfig;
    error: string | null;
  }

  const parsedEntries = useMemo<ParsedState>(() => {
    try {
      const m = parseMappingFull(mappingText);
      return { entries: m.entries, secret: m.secret, auto: m.auto, error: null };
    } catch (e) {
      return {
        entries: [],
        secret: null,
        auto: { ipv4: false, uuid: false },
        error: (e as Error).message,
      };
    }
  }, [mappingText]);

  const existingPlaceholders = useMemo(
    () => new Set(parsedEntries.entries.map((e) => e.placeholder)),
    [parsedEntries.entries],
  );

  const activeAutoLabels = useMemo(() => {
    if (!parsedEntries.secret) return [];
    return (Object.keys(parsedEntries.auto) as Array<keyof AutoConfig>)
      .filter((k) => parsedEntries.auto[k])
      .map((k) => AUTO_RULE_LABELS[k]);
  }, [parsedEntries.secret, parsedEntries.auto]);

  const ext = file ? getExtension(file.name) : null;
  const fileValid = file !== null && ext !== null;

  const handleFile = useCallback((f: File | null) => {
    setResult(null);
    setScanResult(null);
    setError(null);
    setAddedTokens(new Set());
    if (!f) {
      setFile(null);
      return;
    }
    const ex = getExtension(f.name);
    if (!ex) {
      setFile(null);
      setError(`Unsupported file type. Supported: ${SUPPORTED_EXTS.join(', ')}`);
      return;
    }
    setFile(f);
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const f = e.dataTransfer.files?.[0];
      if (f) handleFile(f);
    },
    [handleFile],
  );

  const persistMapping = useCallback((text: string) => {
    setMappingText(text);
    try {
      localStorage.setItem(MAPPING_STORAGE_KEY, text);
    } catch {
      /* ignore quota */
    }
  }, []);

  const addToMapping = useCallback(
    (entry: SuggestedEntry): { ok: boolean; error?: string } => {
      const result = appendMappingEntry(mappingText, entry);
      if (result.error) {
        toast.error(result.error);
        return { ok: false, error: result.error };
      }
      persistMapping(result.text);
      setAddedTokens((prev) => {
        const next = new Set(prev);
        next.add(entry.real);
        return next;
      });
      toast.success(`Added ${entry.placeholder}`);
      return { ok: true };
    },
    [mappingText, persistMapping, toast],
  );

  const handleGenerateSecret = useCallback(() => {
    const hadSecret = !!parsedEntries.secret;
    if (hadSecret) {
      const ok = window.confirm(
        'Replace the existing secret? Documents anonymized with the old secret can no longer be deanonymized.',
      );
      if (!ok) return;
    }
    const { text } = rotateSecret(mappingText);
    persistMapping(text);
    toast.success(
      hadSecret
        ? 'Secret rotated. Auto-redaction is active for this engagement.'
        : 'Secret generated. Auto-redaction enabled for IPv4 and UUID.',
    );
  }, [mappingText, parsedEntries.secret, persistMapping, toast]);

  const downloadMapping = useCallback(() => {
    const blob = new Blob([mappingText], { type: 'text/yaml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'anonymizer-mapping.yaml';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast.success('Mapping downloaded.');
  }, [mappingText, toast]);

  const run = useCallback(async () => {
    if (!file || !ext) {
      setError('Choose a file first.');
      return;
    }
    if (parsedEntries.error) {
      setError(`Mapping error: ${parsedEntries.error}`);
      return;
    }
    if (
      mode !== 'scan' &&
      parsedEntries.entries.length === 0 &&
      !parsedEntries.secret
    ) {
      setError(
        'Mapping has no entries and no secret. Add at least one entry, or click Generate Secret to enable auto-redaction.',
      );
      return;
    }

    setRunning(true);
    setError(null);
    setResult(null);
    setScanResult(null);
    setAddedTokens(new Set());

    try {
      if (mode === 'scan') {
        const buf = await file.arrayBuffer();
        const text = await extractText(buf, ext);
        const findings = scanForLeaks(text, parsedEntries.entries);
        setScanResult(findings);
        if (Object.keys(findings).length === 0) {
          toast.success('No suspicious tokens found outside the mapping.');
        } else {
          toast.info(`Scan complete — ${Object.keys(findings).length} categor${Object.keys(findings).length === 1 ? 'y' : 'ies'} flagged.`);
        }
      } else {
        const r = await processFile(file, parsedEntries.entries, mode, {
          secret: parsedEntries.secret,
          auto: parsedEntries.auto,
        });
        setResult(r);
        const autoTotal = Object.values(r.autoCounts).reduce((s, n) => s + n, 0);
        if (mode === 'anonymize' && r.residuals.length > 0) {
          toast.error(`${r.residuals.length} real value(s) survived substitution. Inspect output before sharing.`);
        } else if (autoTotal > 0) {
          const summary = Object.entries(r.autoCounts)
            .map(([k, v]) => `${v} ${k}`)
            .join(', ');
          toast.success(
            `${mode === 'anonymize' ? 'Anonymized' : 'Deanonymized'} — ${summary} auto-${
              mode === 'anonymize' ? 'redacted' : 'restored'
            }.`,
          );
        } else {
          toast.success(`${mode === 'anonymize' ? 'Anonymized' : 'Deanonymized'} — ready to download.`);
        }
      }
    } catch (e) {
      const msg = (e as Error).message || 'Processing failed';
      setError(msg);
      toast.error(msg);
    } finally {
      setRunning(false);
    }
  }, [file, ext, mode, parsedEntries, toast]);

  const reset = useCallback(() => {
    setFile(null);
    setResult(null);
    setScanResult(null);
    setError(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  }, []);

  return (
    <main className="max-w-7xl mx-auto px-6 py-8">
      <div className="mb-6 flex items-center justify-between">
        <Link
          to="/"
          className="inline-flex items-center gap-2 text-slate-400 hover:text-slate-200 text-sm"
        >
          <ArrowLeft className="w-4 h-4" />
          Back
        </Link>
        <a
          href="https://github.com/kheteswar/xc-app-store"
          target="_blank"
          rel="noreferrer"
          className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-slate-600 text-slate-400 hover:text-slate-200 rounded-lg text-xs transition-colors"
        >
          <HelpCircle className="w-3.5 h-3.5" />
          Source
        </a>
      </div>

      <div className="mb-8 flex items-center gap-3">
        <div className="w-12 h-12 bg-emerald-500/15 rounded-xl flex items-center justify-center">
          <EyeOff className="w-6 h-6 text-emerald-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Anonymizer</h1>
          <p className="text-sm text-slate-400">
            Reversible find-and-replace for txt / docx / pptx / xlsx. Redact customer
            data before sharing, restore real values before delivery. Runs entirely
            in your browser — nothing is uploaded.
          </p>
        </div>
      </div>

      {/* Privacy callout */}
      <div className="mb-6 flex items-start gap-3 p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-xl">
        <Lock className="w-5 h-5 text-emerald-400 mt-0.5 shrink-0" />
        <div className="text-sm text-emerald-100">
          <strong className="font-semibold">Local-only.</strong> Your file and
          mapping never leave this browser tab. The mapping is the secret —
          treat it like a credential. Don't paste it into Claude, Slack, or
          any external tool.
        </div>
      </div>

      {/* Mode tabs */}
      <div className="mb-6 flex gap-2 p-1 bg-slate-800/50 border border-slate-700 rounded-xl w-fit">
        {MODES.map((m) => {
          const active = mode === m.id;
          return (
            <button
              key={m.id}
              onClick={() => {
                setMode(m.id);
                setResult(null);
                setScanResult(null);
                setError(null);
              }}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                active
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  : 'text-slate-400 hover:text-slate-200 border border-transparent'
              }`}
            >
              {m.id === 'anonymize' && <Shield className="w-4 h-4 inline mr-1.5 -mt-0.5" />}
              {m.id === 'deanonymize' && <RefreshCcw className="w-4 h-4 inline mr-1.5 -mt-0.5" />}
              {m.id === 'scan' && <Search className="w-4 h-4 inline mr-1.5 -mt-0.5" />}
              {m.label}
            </button>
          );
        })}
      </div>
      <p className="-mt-2 mb-6 text-xs text-slate-500">{MODES.find((m) => m.id === mode)?.help}</p>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: file + mapping inputs */}
        <div className="space-y-6">
          {/* File picker */}
          <section className="p-5 bg-slate-800/50 border border-slate-700 rounded-xl">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <FileText className="w-4 h-4" /> File
              </h2>
              {file && (
                <button
                  onClick={reset}
                  className="text-xs text-slate-400 hover:text-slate-200"
                >
                  Clear
                </button>
              )}
            </div>

            <label
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={onDrop}
              className={`flex flex-col items-center justify-center gap-2 p-8 border-2 border-dashed rounded-lg cursor-pointer transition-colors ${
                dragOver
                  ? 'border-emerald-500/60 bg-emerald-500/10'
                  : fileValid
                  ? 'border-emerald-500/40 bg-slate-900/40'
                  : 'border-slate-700 bg-slate-900/40 hover:border-slate-600'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept={SUPPORTED_EXTS.join(',')}
                onChange={(e) => handleFile(e.target.files?.[0] || null)}
                className="hidden"
              />
              {fileValid ? (
                <>
                  <CheckCircle2 className="w-8 h-8 text-emerald-400" />
                  <div className="text-sm text-slate-200 font-medium">{file!.name}</div>
                  <div className="text-xs text-slate-500">
                    {(file!.size / 1024).toFixed(1)} KB · {ext}
                  </div>
                </>
              ) : (
                <>
                  <Upload className="w-8 h-8 text-slate-500" />
                  <div className="text-sm text-slate-300">
                    Drop a file here or click to browse
                  </div>
                  <div className="text-xs text-slate-500">
                    Supported: {SUPPORTED_EXTS.join(', ')}
                  </div>
                </>
              )}
            </label>
          </section>

          {/* Mapping editor */}
          <section className="p-5 bg-slate-800/50 border border-slate-700 rounded-xl">
            <div className="mb-3 flex items-center justify-between flex-wrap gap-2">
              <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <Lock className="w-4 h-4" /> Mapping
                <span className="text-xs font-normal text-slate-500 normal-case">
                  ({parsedEntries.entries.length}{' '}
                  {parsedEntries.entries.length === 1 ? 'entry' : 'entries'})
                </span>
              </h2>
              <div className="flex items-center gap-3 text-xs flex-wrap">
                <button
                  onClick={handleGenerateSecret}
                  className="inline-flex items-center gap-1 px-2 py-1 bg-amber-500/15 text-amber-300 hover:bg-amber-500/25 rounded transition-colors"
                  title="Generate a random secret for auto-redaction (IPs, UUIDs)"
                >
                  <Key className="w-3.5 h-3.5" />
                  {parsedEntries.secret ? 'Rotate secret' : 'Generate secret'}
                </button>
                <button
                  onClick={downloadMapping}
                  className="inline-flex items-center gap-1 px-2 py-1 bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25 rounded transition-colors"
                  title="Download current mapping as YAML"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download
                </button>
                <button
                  onClick={() => persistMapping(EMPTY_MAPPING)}
                  className="text-slate-400 hover:text-slate-200"
                >
                  Start blank
                </button>
                <button
                  onClick={() => persistMapping(EXAMPLE_MAPPING)}
                  className="text-slate-400 hover:text-slate-200"
                >
                  Load example
                </button>
                <label className="text-slate-400 hover:text-slate-200 cursor-pointer">
                  Upload YAML
                  <input
                    type="file"
                    accept=".yaml,.yml"
                    className="hidden"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (!f) return;
                      const reader = new FileReader();
                      reader.onload = (ev) => {
                        const text = ev.target?.result as string;
                        if (typeof text === 'string') persistMapping(text);
                      };
                      reader.readAsText(f);
                    }}
                  />
                </label>
              </div>
            </div>

            <textarea
              value={mappingText}
              onChange={(e) => persistMapping(e.target.value)}
              spellCheck={false}
              className="w-full h-72 p-3 font-mono text-xs bg-slate-900 border border-slate-700 rounded-lg text-slate-200 focus:border-emerald-500/60 focus:outline-none"
            />

            {parsedEntries.error ? (
              <div className="mt-3 flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-200">
                <XCircle className="w-4 h-4 mt-0.5 shrink-0" />
                <span>{parsedEntries.error}</span>
              </div>
            ) : (
              <div className="mt-3 text-xs text-slate-500">
                Auto-saved in this browser only. <strong>Click Download</strong> to keep
                a copy on your laptop for the next session — the file is the secret,
                store it like a credential.
              </div>
            )}

            {/* Auto-redaction status */}
            {!parsedEntries.error && (
              parsedEntries.secret ? (
                <div className="mt-3 flex items-start gap-2 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-xs text-amber-100">
                  <Sparkles className="w-4 h-4 mt-0.5 shrink-0 text-amber-300" />
                  <div>
                    <div className="font-semibold text-amber-200">
                      Auto-redact ON: {activeAutoLabels.length > 0 ? activeAutoLabels.join(', ') : 'all rules disabled in YAML'}
                    </div>
                    <div className="mt-1 text-amber-100/80">
                      Each {activeAutoLabels.join('/')} value becomes a deterministic
                      <code className="mx-1 px-1 bg-amber-500/20 rounded">&lt;&lt;TYPE:CIPHER&gt;&gt;</code>
                      token. Same secret reverses it. Without this mapping, no one can.
                    </div>
                  </div>
                </div>
              ) : (
                <div className="mt-3 flex items-start gap-2 p-3 bg-slate-700/30 border border-slate-700 rounded-lg text-xs text-slate-400">
                  <Sparkles className="w-4 h-4 mt-0.5 shrink-0 text-slate-500" />
                  <div>
                    <div className="font-semibold text-slate-300">Auto-redact OFF</div>
                    <div className="mt-1">
                      Click <strong>Generate secret</strong> to auto-redact every IP and
                      UUID without writing manual entries. The secret stays in this YAML
                      and round-trips with it.
                    </div>
                  </div>
                </div>
              )
            )}

            {parsedEntries.entries.length === 0 && !parsedEntries.error && (
              <div className="mt-3 p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg text-xs text-blue-100 leading-relaxed">
                <strong className="font-semibold">No entries yet.</strong> Drop your
                file above, switch to <em>Scan</em> mode, and click <em>+ Map</em>{' '}
                next to each flagged token to build the mapping interactively.
              </div>
            )}
          </section>
        </div>

        {/* Right: action + results */}
        <div className="space-y-6">
          <section className="p-5 bg-slate-800/50 border border-slate-700 rounded-xl">
            <h2 className="mb-3 text-sm font-semibold text-slate-200 uppercase tracking-wider">
              Run
            </h2>

            <button
              onClick={run}
              disabled={running || !fileValid || !!parsedEntries.error}
              className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-700 disabled:text-slate-500 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
            >
              {running ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Processing…
                </>
              ) : (
                <>
                  {mode === 'anonymize' && <Shield className="w-5 h-5" />}
                  {mode === 'deanonymize' && <RefreshCcw className="w-5 h-5" />}
                  {mode === 'scan' && <Search className="w-5 h-5" />}
                  {mode === 'anonymize' && 'Anonymize file'}
                  {mode === 'deanonymize' && 'Deanonymize file'}
                  {mode === 'scan' && 'Scan for leaks'}
                </>
              )}
            </button>

            {error && (
              <div className="mt-4 flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-200">
                <XCircle className="w-4 h-4 mt-0.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </section>

          {/* Result: download + warnings */}
          {result && (
            <section className="p-5 bg-slate-800/50 border border-slate-700 rounded-xl">
              <h2 className="mb-3 text-sm font-semibold text-slate-200 uppercase tracking-wider">
                Output
              </h2>

              <button
                onClick={() => downloadBlob(result.blob, result.filename)}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-blue-500 hover:bg-blue-600 text-white rounded-lg font-medium transition-colors"
              >
                <Download className="w-5 h-5" />
                Download {result.filename}
              </button>

              {Object.keys(result.autoCounts).length > 0 && (
                <div className="mt-4 flex items-start gap-2 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-sm">
                  <Sparkles className="w-4 h-4 mt-0.5 shrink-0 text-amber-300" />
                  <div className="text-amber-100">
                    <div className="font-semibold text-amber-200 mb-0.5">
                      Auto-{mode === 'anonymize' ? 'redacted' : 'restored'}:{' '}
                      {Object.entries(result.autoCounts)
                        .map(([k, v]) => `${v} ${k}`)
                        .join(' · ')}
                    </div>
                    {mode === 'anonymize' && (
                      <div className="text-xs text-amber-100/80">
                        These values are recoverable only with the same secret in the
                        mapping. Keep the mapping local; share only the output file.
                      </div>
                    )}
                  </div>
                </div>
              )}

              {result.residuals.length > 0 && (
                <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <div className="flex items-center gap-2 mb-2 text-sm font-semibold text-red-300">
                    <XCircle className="w-4 h-4" />
                    Real values still present in output
                  </div>
                  <ul className="text-xs text-red-200 space-y-1">
                    {result.residuals.map((r) => (
                      <li key={r} className="font-mono">• {r}</li>
                    ))}
                  </ul>
                  <div className="mt-2 text-xs text-red-300/80">
                    These values matched in the mapping but survived substitution —
                    likely a regex/word-boundary edge case. Inspect before sharing.
                  </div>
                </div>
              )}

              {Object.keys(result.findings).length > 0 && (
                <FindingsPanel
                  findings={result.findings}
                  title="Potential leaks not in mapping"
                  existingPlaceholders={existingPlaceholders}
                  addedTokens={addedTokens}
                  onAdd={addToMapping}
                />
              )}

              {result.residuals.length === 0 && Object.keys(result.findings).length === 0 && (
                <div className="mt-4 flex items-start gap-2 p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-sm text-emerald-200">
                  <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0" />
                  <span>Output is clean. No residuals or unmapped suspicious tokens detected.</span>
                </div>
              )}
            </section>
          )}

          {scanResult !== null && (
            <section className="p-5 bg-slate-800/50 border border-slate-700 rounded-xl">
              <h2 className="mb-3 text-sm font-semibold text-slate-200 uppercase tracking-wider">
                Scan Results
              </h2>
              {Object.keys(scanResult).length === 0 ? (
                <div className="flex items-start gap-2 p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-sm text-emerald-200">
                  <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0" />
                  <span>No suspicious tokens found outside the mapping.</span>
                </div>
              ) : (
                <FindingsPanel
                  findings={scanResult}
                  title="Suspicious tokens"
                  existingPlaceholders={existingPlaceholders}
                  addedTokens={addedTokens}
                  onAdd={addToMapping}
                />
              )}
            </section>
          )}
        </div>
      </div>

      {/* Operating rules */}
      <section className="mt-10 p-6 bg-slate-800/30 border border-slate-700 rounded-xl">
        <h2 className="mb-4 text-sm font-semibold text-slate-200 uppercase tracking-wider">
          Operating rules
        </h2>
        <ol className="space-y-3 text-sm text-slate-300 list-decimal list-inside">
          <li>
            <strong>Map every variant.</strong> "Foo Bank", "Foo Bank Ltd", "Foo Banking Corp" —
            each form needs its own entry. Longest-first is automatic.
          </li>
          <li>
            <strong>Run scan on the original</strong> first to catch identifying tokens you
            forgot to map. Anonymize auto-runs scan on the output too.
          </li>
          <li>
            <strong>The mapping is the secret.</strong> Stays in your browser. Do not paste it
            to Claude, Slack, or any external tool.
          </li>
          <li>
            <strong>Round-trip is only safe for un-edited content.</strong> If Claude invents a
            placeholder you never defined, it will pass through deanonymize unchanged —
            review before customer delivery.
          </li>
          <li>
            <strong>What this does NOT protect:</strong> contextual leakage (specific
            metrics, "the largest bank in Singapore"), images, PDFs.
          </li>
        </ol>
      </section>
    </main>
  );
}

interface FindingsPanelProps {
  findings: Record<string, string[]>;
  title: string;
  existingPlaceholders: ReadonlySet<string>;
  addedTokens: ReadonlySet<string>;
  onAdd: (entry: SuggestedEntry) => { ok: boolean; error?: string };
}

function FindingsPanel({
  findings,
  title,
  existingPlaceholders,
  addedTokens,
  onAdd,
}: FindingsPanelProps) {
  return (
    <div className="mt-4 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
      <div className="flex items-center gap-2 mb-3 text-sm font-semibold text-amber-300">
        <AlertTriangle className="w-4 h-4" />
        {title}
        <span className="ml-auto text-xs font-normal text-amber-200/70">
          Click <em>+ Map</em> to add a token to the mapping.
        </span>
      </div>
      <div className="space-y-4">
        {Object.entries(findings).map(([category, items]) => (
          <div key={category}>
            <div className="text-xs font-semibold text-amber-200 mb-1.5">
              {category}{' '}
              <span className="text-amber-200/60 font-normal">({items.length})</span>
            </div>
            <ul className="space-y-1">
              {items.slice(0, 30).map((tok) => (
                <QuickAddRow
                  key={tok}
                  token={tok}
                  category={category}
                  added={addedTokens.has(tok)}
                  existingPlaceholders={existingPlaceholders}
                  onAdd={onAdd}
                />
              ))}
              {items.length > 30 && (
                <li className="text-xs text-amber-200/60 pl-2">
                  … +{items.length - 30} more (truncated)
                </li>
              )}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

interface QuickAddRowProps {
  token: string;
  category: string;
  added: boolean;
  existingPlaceholders: ReadonlySet<string>;
  onAdd: (entry: SuggestedEntry) => { ok: boolean; error?: string };
}

function QuickAddRow({
  token,
  category,
  added,
  existingPlaceholders,
  onAdd,
}: QuickAddRowProps) {
  const [expanded, setExpanded] = useState(false);
  const [draft, setDraft] = useState<SuggestedEntry | null>(null);

  const openEditor = () => {
    setDraft(suggestEntry(token, category, existingPlaceholders));
    setExpanded(true);
  };

  const close = () => {
    setExpanded(false);
    setDraft(null);
  };

  const submit = () => {
    if (!draft) return;
    if (!draft.real.trim()) return;
    if (!draft.placeholder.trim()) return;
    const result = onAdd(draft);
    if (result.ok) close();
  };

  if (added) {
    return (
      <li className="flex items-center justify-between gap-2 px-2 py-1 rounded bg-emerald-500/10 text-xs">
        <span className="font-mono text-emerald-200/80 line-through">{token}</span>
        <span className="inline-flex items-center gap-1 text-emerald-300 font-semibold">
          <CheckCircle2 className="w-3.5 h-3.5" />
          Added
        </span>
      </li>
    );
  }

  if (!expanded) {
    return (
      <li className="flex items-center justify-between gap-2 px-2 py-1 rounded hover:bg-amber-500/5 text-xs group">
        <span className="font-mono text-amber-100/90 break-all">{token}</span>
        <button
          onClick={openEditor}
          className="shrink-0 inline-flex items-center gap-1 px-2 py-0.5 bg-amber-500/20 hover:bg-amber-500/40 text-amber-200 rounded font-medium opacity-70 group-hover:opacity-100 transition-opacity"
        >
          <Plus className="w-3 h-3" />
          Map
        </button>
      </li>
    );
  }

  if (!draft) return null;

  return (
    <li className="p-3 rounded bg-slate-900/70 border border-amber-500/30 space-y-2 text-xs">
      <div className="flex items-center gap-2">
        <span className="text-amber-200/70 uppercase font-semibold tracking-wide">
          New entry
        </span>
        <span className="text-slate-500">·</span>
        <span className="text-slate-400">{category}</span>
      </div>

      <label className="block">
        <span className="text-slate-400">Real value</span>
        <input
          value={draft.real}
          onChange={(e) => setDraft({ ...draft, real: e.target.value })}
          className="mt-1 w-full px-2 py-1 font-mono bg-slate-800 border border-slate-700 rounded text-slate-100 focus:border-amber-500/60 focus:outline-none"
        />
      </label>

      <label className="block">
        <span className="text-slate-400">Placeholder</span>
        <input
          value={draft.placeholder}
          onChange={(e) => setDraft({ ...draft, placeholder: e.target.value })}
          className="mt-1 w-full px-2 py-1 font-mono bg-slate-800 border border-slate-700 rounded text-slate-100 focus:border-amber-500/60 focus:outline-none"
        />
      </label>

      <div className="flex items-center gap-4 pt-1">
        <label className="inline-flex items-center gap-1.5 text-slate-300 cursor-pointer">
          <input
            type="checkbox"
            checked={draft.wordBoundary}
            onChange={(e) => setDraft({ ...draft, wordBoundary: e.target.checked })}
            className="accent-emerald-500"
          />
          Word boundary
        </label>
        <label className="inline-flex items-center gap-1.5 text-slate-300 cursor-pointer">
          <input
            type="checkbox"
            checked={draft.caseSensitive}
            onChange={(e) => setDraft({ ...draft, caseSensitive: e.target.checked })}
            className="accent-emerald-500"
          />
          Case sensitive
        </label>
      </div>

      <div className="flex items-center justify-end gap-2 pt-1">
        <button
          onClick={close}
          className="px-3 py-1 text-slate-400 hover:text-slate-200 rounded"
        >
          Cancel
        </button>
        <button
          onClick={submit}
          disabled={!draft.real.trim() || !draft.placeholder.trim()}
          className="inline-flex items-center gap-1 px-3 py-1 bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded font-medium"
        >
          <Plus className="w-3.5 h-3.5" />
          Add to mapping
        </button>
      </div>
    </li>
  );
}

export default Anonymizer;
