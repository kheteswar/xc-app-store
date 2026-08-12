import { useState, useRef } from 'react';
import { 
  ArrowLeft, Play, Download, Upload,
  CheckCircle, XCircle, Activity, ChevronRight, ChevronLeft,
  ShieldAlert, ShieldCheck, Layers, Code, Trash2, Plus, Globe, FileText, X, ClipboardList,
  ExternalLink, AlertTriangle, HelpCircle
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { useToast } from '../context/ToastContext';
import { generateSanityCheckPdf } from '../services/sanity-checker/pdf-report';

// --- Types ---

interface TestRow {
  id: string;
  domain: string;
  targetIps: string[];
  path: string;
  method: string;
}

const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);
// Normalize a method token from input → a valid uppercase method; default GET.
const normalizeMethod = (m?: string): string => {
  const v = (m || '').trim().toUpperCase();
  return HTTP_METHODS.has(v) ? v : 'GET';
};

interface TlsCertInfo {
  subject: string;
  issuer: string;
  issuerOrg: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint256: string;
  subjectAltName: string;
  protocol: string;
}

interface RequestResult {
  status: number | string;
  statusText: string;
  size: number;
  headers: Record<string, string>;
  body: string;
  normalizedBody: string;
  duration: number;
  isBotChallenge: boolean;
  debugInfo?: string;
  error?: string;
  connectedIp?: string;
  tlsCert?: TlsCertInfo | null;
}

interface SpoofedResult {
  ip: string;
  result: RequestResult;
  score: number;
  statusMatch: boolean;
  passed: boolean;
}

interface ComparisonResult {
  row: TestRow;
  public: RequestResult;
  spoofedResults: SpoofedResult[];
  overallPassed: boolean;
  reasons: string[];
  timestamp: string;
}

interface UrlEntry {
  id: string;
  url: string;
}

// --- Configuration Constants ---

const IGNORED_HEADERS = new Set([
  'date', 'server', 'connection', 'keep-alive', 'age', 
  'transfer-encoding', 'set-cookie', 'content-length', 
  'etag', 'last-modified', 'strict-transport-security',
  'x-akamai-staging', 'x-akamai-transformed'
]);

const BOT_SIGNATURES = [
  '_imp_apg_r_',
  'id="challenge-form"',
  'f5_cspm',
  'challenge-platform'
];

// --- Helper Functions ---

const normalizeHtml = (html: string): string => {
  return html
    .replace(/<script\b[^>]*>([\s\S]*?)<\/script>/gim, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<style\b[^>]*>([\s\S]*?)<\/style>/gim, "")
    .replace(/\s+/g, " ")
    .trim();
};

const calculateSimilarity = (str1: string, str2: string): number => {
  if (str1 === str2) return 100;
  if (!str1 || !str2) return 0;
  
  const bigrams = (str: string) => {
    const s = str.toLowerCase();
    const v = new Array(Math.max(0, s.length - 1));
    for (let i = 0; i < v.length; i++) v[i] = s.slice(i, i + 2);
    return v;
  };

  const pairs1 = bigrams(str1);
  const pairs2 = bigrams(str2);
  const union = pairs1.length + pairs2.length;
  if (union === 0) return 100;

  let hit = 0;

  for (const x of pairs1) {
    for (let i = 0; i < pairs2.length; i++) {
      if (x === pairs2[i]) {
        hit++;
        pairs2.splice(i, 1);
        break;
      }
    }
  }

  return Math.floor((2.0 * hit) / union * 100);
};

const isValidIpv4 = (ip: string): boolean => {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = parseInt(p, 10);
    return n >= 0 && n <= 255;
  });
};

const isValidIpv6 = (ip: string): boolean => {
  // Basic IPv6 validation: 1-8 groups of hex separated by colons, with optional :: compression
  if (ip.includes('::')) {
    const sides = ip.split('::');
    if (sides.length > 2) return false;
    const left = sides[0] ? sides[0].split(':') : [];
    const right = sides[1] ? sides[1].split(':') : [];
    if (left.length + right.length > 7) return false;
    return [...left, ...right].every(g => /^[0-9a-fA-F]{1,4}$/.test(g));
  }
  const groups = ip.split(':');
  return groups.length === 8 && groups.every(g => /^[0-9a-fA-F]{1,4}$/.test(g));
};

const isValidIp = (ip: string): boolean => isValidIpv4(ip.trim()) || isValidIpv6(ip.trim());

const parseCSV = (text: string): TestRow[] => {
  const lines = text.split('\n').filter(l => l.trim().length > 0);
  const startIdx = lines[0]?.toLowerCase().startsWith('domain') ? 1 : 0;
  
  return lines.slice(startIdx).map((line, idx) => {
    const cols = line.split(',').map(c => c.trim());
    return {
      id: `row-${idx}-${Date.now()}`,
      domain: cols[0] || '',
      targetIps: cols[1] ? cols[1].split(';').map(ip => ip.trim()).filter(Boolean) : [],
      path: cols[2] || '/',
      // Optional 4th column "method"; default GET when absent/invalid.
      method: normalizeMethod(cols[3]),
    };
  }).filter(r => r.domain && r.path);
};

const parseUrlEntries = (entries: UrlEntry[], spoofIps: string[]): TestRow[] => {
  const validIps = spoofIps.map(ip => ip.trim()).filter(Boolean);
  return entries
    .filter(e => e.url.trim().length > 0)
    .map((entry, idx) => {
      try {
        const parsed = new URL(
          entry.url.startsWith('http') ? entry.url : `https://${entry.url}`
        );
        return {
          id: `url-${idx}-${Date.now()}`,
          domain: parsed.hostname,
          targetIps: validIps,
          path: parsed.pathname + parsed.search,
          method: 'GET',
        };
      } catch {
        return null;
      }
    })
    .filter(Boolean) as TestRow[];
};

// --- Components ---

// --- Spoof color palette ---
const SPOOF_COLORS = [
  { label: 'text-amber-400',  border: 'border-amber-500/40',  bg: 'bg-amber-500/10',  dot: 'bg-amber-400'  },
  { label: 'text-violet-400', border: 'border-violet-500/40', bg: 'bg-violet-500/10', dot: 'bg-violet-400' },
  { label: 'text-cyan-400',   border: 'border-cyan-500/40',   bg: 'bg-cyan-500/10',   dot: 'bg-cyan-400'   },
  { label: 'text-rose-400',   border: 'border-rose-500/40',   bg: 'bg-rose-500/10',   dot: 'bg-rose-400'   },
];
const getSpoofColor = (idx: number) => SPOOF_COLORS[idx % SPOOF_COLORS.length];

const getSpoofLabel = (idx: number) => {
  const labels = ['Prod', 'Stag'];
  return labels[idx] || `SPOOF ${idx + 1}`;
};

const ComparisonTable = ({ publicRes, spoofedResults }: { publicRes: RequestResult, spoofedResults: SpoofedResult[] }) => {
  const liveColor = { label: 'text-blue-400', dot: 'bg-blue-400' };
  const cols = [
    { label: 'LIVE', color: liveColor, result: publicRes, ip: null as string|null, score: null as number|null },
    ...spoofedResults.map((s, i) => ({ label: getSpoofLabel(i), color: getSpoofColor(i), result: s.result, ip: s.ip, score: s.score }))
  ];

  const metrics: { label: string; render: (r: RequestResult) => string }[] = [
    { label: 'Status',   render: r => r.status.toString() },
    { label: 'Time',     render: r => `${r.duration}ms` },
    { label: 'Size',     render: r => r.size > 0 ? `${(r.size/1024).toFixed(1)} KB` : '—' },
    { label: 'Bot?',     render: r => r.isBotChallenge ? '⚠ Yes' : 'No' },
    { label: 'Conn. IP', render: r => r.connectedIp || '—' },
  ];

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-700">
      <table className="w-full text-xs font-mono">
        <thead>
          <tr className="border-b border-slate-700 bg-slate-900/60">
            <th className="text-left py-2 px-3 text-slate-500 font-normal w-20">Metric</th>
            {cols.map((col, ci) => (
              <th key={ci} className={`py-2 px-3 text-left ${col.color.label}`}>
                <div className="flex items-center gap-1.5">
                  <div className={`w-1.5 h-1.5 rounded-full ${col.color.dot}`} />
                  {col.label}
                </div>
                {col.ip && <div className="text-[10px] text-slate-500 font-normal mt-0.5 truncate max-w-[140px]" title={col.ip}>{col.ip}</div>}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {metrics.map(({ label, render }, ri) => (
            <tr key={ri} className={`border-b border-slate-700/50 ${ri % 2 === 0 ? 'bg-slate-900/20' : ''}`}>
              <td className="py-2 px-3 text-slate-500">{label}</td>
              {cols.map((col, ci) => {
                const val = render(col.result);
                const liveVal = render(cols[0].result);
                const isBot   = label === 'Bot?'   && col.result.isBotChallenge;
                const isErr   = label === 'Status' && col.result.status === 'ERR';
                const isDrift = ci > 0 && val !== liveVal && label !== 'Size' && label !== 'Time' && label !== 'Conn. IP';
                return (
                  <td key={ci} className={`py-2 px-3 ${isBot ? 'text-amber-400 font-bold' : isErr ? 'text-red-400 font-bold' : isDrift ? 'text-amber-300 font-bold' : 'text-slate-200'}`}>
                    {val}
                  </td>
                );
              })}
            </tr>
          ))}
          <tr className="border-b border-slate-700/50 bg-slate-900/20">
            <td className="py-2 px-3 text-slate-500">Similarity</td>
            <td className="py-2 px-3 text-slate-500 text-[10px] italic">baseline</td>
            {cols.slice(1).map((col, ci) => (
              <td key={ci} className={`py-2 px-3 font-bold ${(col.score ?? 0) >= 95 ? 'text-emerald-400' : 'text-red-400'}`}>
                {col.score !== null ? `${col.score}%` : '—'}
              </td>
            ))}
          </tr>
          {cols.some(c => c.result.error) && (
            <tr>
              <td className="py-2 px-3 text-slate-500">Error</td>
              {cols.map((col, ci) => (
                <td key={ci} className="py-2 px-3 text-red-400 text-[10px] max-w-[200px] truncate" title={col.result.error}>
                  {col.result.error || '—'}
                </td>
              ))}
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
};

// Multi-column body comparison: LIVE + every spoofed source side by side.
const BodyCompare = ({ publicRes, spoofedResults, chars = 500 }: { publicRes: RequestResult, spoofedResults: SpoofedResult[], chars?: number }) => {
  const cols = [
    { label: 'LIVE', color: 'text-blue-400', dot: 'bg-blue-400', body: publicRes.normalizedBody },
    ...spoofedResults.map((s, i) => ({ label: getSpoofLabel(i), color: getSpoofColor(i).label, dot: getSpoofColor(i).dot, body: s.result.normalizedBody })),
  ];
  return (
    <div className="grid gap-3 text-xs font-mono" style={{ gridTemplateColumns: `repeat(${cols.length}, minmax(0, 1fr))` }}>
      {cols.map((col, ci) => (
        <div key={ci} className="bg-slate-900/50 p-2 rounded border border-slate-700/50 overflow-auto max-h-64">
          <div className={`mb-1 border-b border-slate-700 pb-1 flex items-center gap-1.5 ${col.color}`}>
            <div className={`w-1.5 h-1.5 rounded-full ${col.dot}`} />{col.label}
          </div>
          <pre className="whitespace-pre-wrap break-all text-slate-300">{(col.body || '').slice(0, chars) || '<empty>'}</pre>
        </div>
      ))}
    </div>
  );
};

// Single multi-column header table: LIVE + every spoofed source side by side.
// A cell is highlighted when it differs from LIVE for a non-ignored header.
const HeaderDiff = ({ publicRes, spoofedResults }: { publicRes: RequestResult, spoofedResults: SpoofedResult[] }) => {
  const cols = [
    { label: 'LIVE', labelColor: 'text-blue-400', dot: 'bg-blue-400', headers: publicRes.headers, ip: publicRes.connectedIp },
    ...spoofedResults.map((s, i) => ({ label: getSpoofLabel(i), labelColor: getSpoofColor(i).label, dot: getSpoofColor(i).dot, headers: s.result.headers, ip: s.result.connectedIp })),
  ];
  const liveHeaders = publicRes.headers;
  const allKeys = new Set<string>();
  cols.forEach(c => Object.keys(c.headers).forEach(k => allKeys.add(k)));
  const sortedKeys = Array.from(allKeys).sort();

  return (
    <div className="text-xs font-mono bg-slate-900/50 rounded border border-slate-700/50 max-h-96 overflow-auto">
      <table className="w-full text-left border-collapse">
        <thead className="bg-slate-800 sticky top-0 z-10">
          <tr>
            <th className="p-2 border-b border-slate-700">Header</th>
            {cols.map((col, ci) => (
              <th key={ci} className={`p-2 border-b border-slate-700 ${col.labelColor}`}>
                <div className="flex items-center gap-1.5"><div className={`w-1.5 h-1.5 rounded-full ${col.dot}`} />{col.label}</div>
                {col.ip && <div className="text-[10px] text-slate-500 font-normal truncate max-w-[140px]" title={col.ip}>{col.ip}</div>}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sortedKeys.map(key => {
            const isIgnored = IGNORED_HEADERS.has(key);
            const liveVal = liveHeaders[key];
            const anyDiff = !isIgnored && cols.slice(1).some(c => c.headers[key] !== liveVal);

            let rowClass = 'border-b border-slate-800 hover:bg-slate-800/50';
            let headerClass = 'p-2 truncate';
            if (anyDiff) { rowClass += ' bg-amber-900/10'; headerClass += ' text-amber-400 font-bold'; }
            else if (isIgnored) headerClass += ' text-slate-600';
            else headerClass += ' text-slate-400';

            return (
              <tr key={key} className={rowClass}>
                <td className={headerClass}>
                  {key}{isIgnored && <span className="ml-1 text-slate-700 text-[10px]">(ignored)</span>}
                </td>
                {cols.map((col, ci) => {
                  const val = col.headers[key];
                  const isDiffCell = ci > 0 && !isIgnored && val !== liveVal;
                  return (
                    <td key={ci} className={`p-2 truncate max-w-xs ${isDiffCell ? 'text-amber-300 font-semibold' : 'text-slate-300'}`} title={val}>
                      {val || <span className="text-slate-600">-</span>}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

const TlsCertComparison = ({ liveCert, spoofCerts }: {
  liveCert?: TlsCertInfo | null;
  spoofCerts: Array<{ label: string; ip: string; cert?: TlsCertInfo | null }>;
}) => {
  if (!liveCert && spoofCerts.every(s => !s.cert)) return null;

  const formatDate = (d: string) => {
    if (!d) return '—';
    try { return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }); }
    catch { return d; }
  };

  const isExpired = (d: string) => {
    if (!d) return false;
    try { return new Date(d) < new Date(); }
    catch { return false; }
  };

  const parseSANs = (san: string): string[] => {
    if (!san) return [];
    return san.split(',').map(s => s.trim().replace(/^DNS:/, '')).filter(Boolean);
  };

  const rows: Array<{ label: string; getValue: (c: TlsCertInfo | null | undefined) => string; highlight?: (live: string, spoof: string) => boolean }> = [
    { label: 'Subject (CN)', getValue: c => c?.subject || '—' },
    { label: 'Issuer', getValue: c => c ? `${c.issuer}${c.issuerOrg ? ` (${c.issuerOrg})` : ''}` : '—', highlight: (l, s) => l !== s },
    { label: 'Valid From', getValue: c => formatDate(c?.validFrom || '') },
    { label: 'Valid To', getValue: c => formatDate(c?.validTo || ''), highlight: (l, s) => l !== s },
    { label: 'Serial', getValue: c => c?.serialNumber || '—' },
    { label: 'TLS Protocol', getValue: c => c?.protocol || '—', highlight: (l, s) => l !== s },
    { label: 'Fingerprint (SHA256)', getValue: c => c?.fingerprint256 ? c.fingerprint256.slice(0, 32) + '…' : '—' },
  ];

  const liveSANs = parseSANs(liveCert?.subjectAltName || '');

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-700">
      <table className="w-full text-xs font-mono">
        <thead>
          <tr className="border-b border-slate-700 bg-slate-900/60">
            <th className="text-left py-2 px-3 text-slate-500 font-normal w-36">Field</th>
            <th className="py-2 px-3 text-left text-blue-400">
              <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-blue-400" /> LIVE</div>
            </th>
            {spoofCerts.map((s, i) => {
              const c = getSpoofColor(i);
              return (
                <th key={i} className={`py-2 px-3 text-left ${c.label}`}>
                  <div className="flex items-center gap-1.5"><div className={`w-1.5 h-1.5 rounded-full ${c.dot}`} /> {s.label}</div>
                  <div className="text-[10px] text-slate-500 font-normal mt-0.5">{s.ip}</div>
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.map(({ label, getValue, highlight }, ri) => {
            const liveVal = getValue(liveCert);
            return (
              <tr key={ri} className={`border-b border-slate-700/50 ${ri % 2 === 0 ? 'bg-slate-900/20' : ''}`}>
                <td className="py-2 px-3 text-slate-500">{label}</td>
                <td className={`py-2 px-3 ${label === 'Valid To' && isExpired(liveCert?.validTo || '') ? 'text-red-400 font-bold' : 'text-slate-200'}`}
                  title={label === 'Fingerprint (SHA256)' ? liveCert?.fingerprint256 || '' : undefined}>
                  {liveVal}
                </td>
                {spoofCerts.map((s, ci) => {
                  const spoofVal = getValue(s.cert);
                  const isDrift = highlight ? highlight(liveVal, spoofVal) : false;
                  const expired = label === 'Valid To' && isExpired(s.cert?.validTo || '');
                  return (
                    <td key={ci} className={`py-2 px-3 ${expired ? 'text-red-400 font-bold' : isDrift ? 'text-amber-300 font-bold' : 'text-slate-200'}`}
                      title={label === 'Fingerprint (SHA256)' ? s.cert?.fingerprint256 || '' : undefined}>
                      {spoofVal}
                    </td>
                  );
                })}
              </tr>
            );
          })}
          {/* SAN row */}
          <tr className="border-b border-slate-700/50">
            <td className="py-2 px-3 text-slate-500 align-top">SANs</td>
            <td className="py-2 px-3 text-slate-200 align-top">
              {liveSANs.length > 0
                ? <div className="flex flex-wrap gap-1">{liveSANs.slice(0, 8).map((s, i) => <span key={i} className="px-1.5 py-0.5 bg-slate-700/50 rounded text-[10px]">{s}</span>)}{liveSANs.length > 8 && <span className="text-[10px] text-slate-500">+{liveSANs.length - 8} more</span>}</div>
                : <span className="text-slate-600">—</span>}
            </td>
            {spoofCerts.map((s, ci) => {
              const spoofSANs = parseSANs(s.cert?.subjectAltName || '');
              const sanMismatch = liveSANs.join(',') !== spoofSANs.join(',');
              return (
                <td key={ci} className={`py-2 px-3 align-top ${sanMismatch ? 'text-amber-300' : 'text-slate-200'}`}>
                  {spoofSANs.length > 0
                    ? <div className="flex flex-wrap gap-1">{spoofSANs.slice(0, 8).map((ss, i) => <span key={i} className="px-1.5 py-0.5 bg-slate-700/50 rounded text-[10px]">{ss}</span>)}{spoofSANs.length > 8 && <span className="text-[10px] text-slate-500">+{spoofSANs.length - 8} more</span>}</div>
                    : <span className="text-slate-600">—</span>}
                </td>
              );
            })}
          </tr>
        </tbody>
      </table>
    </div>
  );
};

export function HttpSanityChecker() {
  const toast = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const bulkFileInputRef = useRef<HTMLInputElement>(null);
  
  const [inputMode, setInputMode] = useState<'csv' | 'url'>('csv');
  const [urlEntries, setUrlEntries] = useState<UrlEntry[]>([
    { id: `ue-${Date.now()}`, url: '' }
  ]);
  const [spoofIps, setSpoofIps] = useState<string[]>(['', '']);
  const addSpoofIp    = () => setSpoofIps(prev => [...prev, '']);
  const removeSpoofIp = (i: number) => setSpoofIps(prev => prev.length > 1 ? prev.filter((_, idx) => idx !== i) : prev);
  const updateSpoofIp = (i: number, val: string) => setSpoofIps(prev => prev.map((v, idx) => idx === i ? val : v));
  const [showBulkAdd, setShowBulkAdd] = useState(false);
  const [bulkText, setBulkText] = useState('');
  const [csvText, setCsvText] = useState<string>('example.com, 1.2.3.4, /api/health, GET');
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<ComparisonResult[]>([]);
  const [currentResultIdx, setCurrentResultIdx] = useState(0);
  const abortController = useRef<AbortController | null>(null);

  // --- Server-Side Proxy Execution ---
  const executeRequest = async (url: string, isSpoofed: boolean, hostHeader: string, targetIp: string, method: string = 'GET'): Promise<RequestResult> => {
    const start = performance.now();
    try {
      const headers: Record<string, string> = {
        'User-Agent': 'XC-BulkOps-Validator/1.0',
      };
      
      if (isSpoofed) {
        headers['Host'] = hostHeader;
        headers['X-F5-Test'] = 'sanity-check';
      } else {
        headers['Pragma'] = 'akamai-x-cache-on, akamai-x-get-cache-key, akamai-x-get-true-cache-key';
      }

      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('Frontend timeout after 20 seconds')), 20000);
      });

      const fetchPromise = fetch('/api/proxy/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          method,
          headers,
          targetIp: isSpoofed ? targetIp : undefined
        }),
        signal: abortController.current?.signal
      });

      const proxyResponse = await Promise.race([fetchPromise, timeoutPromise]);
      const data = await proxyResponse.json();
      const end = performance.now();

      if (!proxyResponse.ok) {
        throw new Error(data.error || `Proxy Error: ${proxyResponse.status}`);
      }

      const resHeaders: Record<string, string> = {};
      if (data.headers) {
        Object.entries(data.headers).forEach(([key, val]) => {
          resHeaders[key.toLowerCase()] = String(val);
        });
      }

      const text = data.body || '';
      const isBotChallenge = BOT_SIGNATURES.some(sig => text.includes(sig));
      const debugInfo = resHeaders['x-cache'] || resHeaders['x-akamai-session-info'] || undefined;

      return {
        status: data.status,
        statusText: data.statusText || '',
        size: text.length,
        headers: resHeaders,
        body: text,
        normalizedBody: normalizeHtml(text),
        duration: Math.round(end - start),
        isBotChallenge,
        debugInfo,
        connectedIp: data.connectedIp,
        tlsCert: data.tlsCert || null,
      };
    } catch (err: any) {
      const end = performance.now();
      console.error(`[Frontend] Request failed for ${url}:`, err.message);
      return {
        status: 'ERR',
        statusText: 'Network Error',
        size: 0,
        headers: {},
        body: '',
        normalizedBody: '',
        duration: Math.round(end - start),
        isBotChallenge: false,
        error: err.message
      };
    }
  };

  const addUrlEntry = () => {
    setUrlEntries(prev => [...prev, { id: `ue-${Date.now()}`, url: '' }]);
  };

  const removeUrlEntry = (id: string) => {
    setUrlEntries(prev => prev.length > 1 ? prev.filter(e => e.id !== id) : prev);
  };

  const updateUrlEntry = (id: string, value: string) => {
    setUrlEntries(prev => prev.map(e => e.id === id ? { ...e, url: value } : e));
  };

  const handleBulkAdd = () => {
    const lines = bulkText
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 0);

    if (lines.length === 0) return;

    const newEntries: UrlEntry[] = lines.map(url => ({
      id: `ue-${Date.now()}-${Math.random()}`,
      url,
    }));

    setUrlEntries(prev => {
      const hasOnlyBlank = prev.length === 1 && prev[0].url.trim() === '';
      return hasOnlyBlank ? newEntries : [...prev, ...newEntries];
    });

    setBulkText('');
    setShowBulkAdd(false);
    toast.success(`Added ${newEntries.length} URL${newEntries.length > 1 ? 's' : ''}`);
  };

  const isValidUrl = (raw: string): boolean => {
    const candidate = raw.startsWith('http://') || raw.startsWith('https://') ? raw : `https://${raw}`;
    try {
      const u = new URL(candidate);
      // Must have a real hostname with at least one dot (e.g. "localhost" is excluded)
      return u.hostname.includes('.');
    } catch {
      return false;
    }
  };

  const handleBulkFileImport = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result;
      if (typeof text === 'string') {
        const allLines = text.split('\n').map(l => l.trim()).filter(Boolean);
        const validUrls = allLines.filter(isValidUrl);
        const skipped = allLines.length - validUrls.length;

        if (validUrls.length === 0) {
          toast.error(`No valid URLs found in ${file.name}`);
          return;
        }

        setBulkText(prev => {
          const combined = prev.trim()
            ? `${prev.trim()}\n${validUrls.join('\n')}`
            : validUrls.join('\n');
          return combined;
        });

        const skippedNote = skipped > 0 ? ` (${skipped} invalid line${skipped !== 1 ? 's' : ''} skipped)` : '';
        toast.success(`Imported ${validUrls.length} URL${validUrls.length !== 1 ? 's' : ''} from ${file.name}${skippedNote}`);
      }
    };
    reader.readAsText(file);
    event.target.value = '';
  };

  const handleExportUrlsAsCsv = () => {
    const validEntries = urlEntries.filter(e => e.url.trim().length > 0);
    if (validEntries.length === 0) {
      toast.error("No URLs to export");
      return;
    }

    const validIps = spoofIps.map(ip => ip.trim()).filter(Boolean);
    const rows = validEntries.map(entry => {
      try {
        const parsed = new URL(
          entry.url.startsWith('http') ? entry.url : `https://${entry.url}`
        );
        const domain = parsed.hostname;
        const path = parsed.pathname + parsed.search || '/';
        return [domain, validIps.join(';'), path, 'GET'].join(',');
      } catch {
        return null;
      }
    }).filter(Boolean);

    const content = ['Live Domain, Spoof IPs (;-sep), Path, Method', ...rows].join('\n');
    const blob = new Blob([content], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `url-mode-export-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Exported ${rows.length} URL${rows.length !== 1 ? 's' : ''} as CSV`);
  };

  const runTest = async () => {
    let rows: TestRow[];

    if (inputMode === 'csv') {
      rows = parseCSV(csvText);
      if (rows.length === 0) {
        toast.error("No valid rows found in CSV");
        return;
      }
    } else {
      const validIps = spoofIps.filter(ip => ip.trim() !== '');
      if (validIps.length === 0) {
        toast.error("Please enter at least one Spoof IP address");
        return;
      }
      rows = parseUrlEntries(urlEntries, spoofIps);
      if (rows.length === 0) {
        toast.error("No valid URLs found. Check that URLs are properly formatted.");
        return;
      }
    }

    // Validate all IP addresses across all rows
    const invalidIps: string[] = [];
    for (const row of rows) {
      for (const ip of row.targetIps) {
        if (!isValidIp(ip)) invalidIps.push(ip);
      }
    }
    if (invalidIps.length > 0) {
      const unique = [...new Set(invalidIps)];
      toast.error(`Invalid IP address${unique.length > 1 ? 'es' : ''}: ${unique.join(', ')}`);
      return;
    }

    setIsRunning(true);
    setResults([]);
    setProgress(0);
    setCurrentResultIdx(0);
    abortController.current = new AbortController();

    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      const publicUrl = `https://${row.domain}${row.path}`;

      const [publicRes, ...spoofResArray] = await Promise.all([
        executeRequest(publicUrl, false, row.domain, '', row.method),
        ...row.targetIps.map(ip => executeRequest(publicUrl, true, row.domain, ip, row.method))
      ]);

      const overallReasons: string[] = [];
      let overallPassed = true;

      const spoofedResults: SpoofedResult[] = spoofResArray.map((spoofedRes, idx) => {
        const ip = row.targetIps[idx];
        const score = calculateSimilarity(publicRes.normalizedBody, spoofedRes.normalizedBody);
        const statusMatch = publicRes.status.toString() === spoofedRes.status.toString();

        const reasons: string[] = [];
        if (!statusMatch)               reasons.push(`Status Drift: Live ${publicRes.status} vs Spoof ${spoofedRes.status}`);
        if (score < 95)                 reasons.push(`Body Content Mismatch (${score}% similarity)`);
        if (spoofedRes.isBotChallenge)  reasons.push(`⚠️ F5 Bot Challenge Detected`);
        if (spoofedRes.status === 'ERR') reasons.push(`Connection Failed: ${spoofedRes.error}`);

        const passed = reasons.length === 0 || (reasons.length === 1 && spoofedRes.isBotChallenge);
        if (!passed) {
          overallPassed = false;
          reasons.forEach(r => overallReasons.push(`[${ip}] ${r}`));
        }

        return { ip, result: spoofedRes, score, statusMatch, passed };
      });

      const result: ComparisonResult = {
        row,
        public: publicRes,
        spoofedResults,
        overallPassed,
        reasons: overallReasons,
        timestamp: new Date().toISOString()
      };

      setResults(prev => [...prev, result]);
      setProgress(Math.round(((i + 1) / rows.length) * 100));
    }

    setIsRunning(false);
    toast.success("Validation Complete");
  };

  const handleExport = () => {
    if (results.length === 0) return;
    const header = [
      "Live Domain", "Path", "Method", "Overall Result",
      "Live Status", "Live ConnIP",
      ...results[0]?.spoofedResults.flatMap((_, i) => [
        `Spoof${i+1} IP`, `Spoof${i+1} Status`, `Spoof${i+1} StatusMatch`, `Spoof${i+1} Similarity`, `Spoof${i+1} Bot`
      ]) ?? [],
      "Drift Reasons"
    ];
    const csvRows = results.map(r => [
      r.row.domain, r.row.path, r.row.method,
      r.overallPassed ? "PASS" : "FAIL",
      r.public.status, r.public.connectedIp || '',
      ...r.spoofedResults.flatMap(s => [
        s.ip, s.result.status, s.statusMatch ? "YES" : "NO", `${s.score}%`, s.result.isBotChallenge ? "YES" : "NO"
      ]),
      r.reasons.join(' | ')
    ]);
    const content = [header.join(','), ...csvRows.map(r => r.join(','))].join('\n');
    const blob = new Blob([content], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `migration-sanity-check-${Date.now()}.csv`;
    a.click();
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result;
      if (typeof text === 'string') {
        setCsvText(text);
        toast.success(`Loaded ${file.name}`);
      }
    };
    reader.readAsText(file);
    event.target.value = '';
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <div className="flex items-center gap-4 mb-8">
          <Link to="/" className="p-2 hover:bg-slate-800 rounded-lg">
            <ArrowLeft className="w-5 h-5 text-slate-400" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Activity className="w-6 h-6 text-blue-400" />
              Live vs Spoof HTTP Sanity Checker
            </h1>
            <p className="text-slate-400">Smart comparison between Live (Public DNS) and Spoof (Direct IP to Origin)</p>
          </div>
          <Link to="/explainer/http-sanity" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
            <HelpCircle className="w-3.5 h-3.5" /> How does this work?
          </Link>
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 space-y-4">
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700 h-full flex flex-col">
              <h3 className="font-semibold text-lg mb-4">Configuration</h3>

              {/* Mode Toggle */}
              <div className="flex rounded-lg overflow-hidden border border-slate-700 mb-4">
                <button
                  onClick={() => setInputMode('csv')}
                  className={`flex-1 flex items-center justify-center gap-2 py-2 text-sm font-medium transition-colors ${
                    inputMode === 'csv'
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <FileText className="w-4 h-4" /> CSV Mode
                </button>
                <button
                  onClick={() => setInputMode('url')}
                  className={`flex-1 flex items-center justify-center gap-2 py-2 text-sm font-medium transition-colors ${
                    inputMode === 'url'
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Globe className="w-4 h-4" /> URL Mode
                </button>
              </div>

              <div className="flex-1 flex flex-col">
                {inputMode === 'csv' ? (
                  <>
                    <div className="flex justify-between items-center mb-2">
                      <label className="block text-xs font-mono text-slate-400">
                        CSV Input: Live Domain, Spoof IP, Path, Method (optional, default GET)
                      </label>
                      <div className="flex gap-2">
                        <button 
                          onClick={() => setCsvText('')}
                          className="text-xs flex items-center gap-1 text-slate-400 hover:text-white transition-colors"
                          title="Clear Input"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                        <button 
                          onClick={() => fileInputRef.current?.click()}
                          className="text-xs flex items-center gap-1 text-blue-400 hover:text-blue-300 transition-colors"
                        >
                          <Upload className="w-3 h-3" /> Upload CSV
                        </button>
                        <input 
                          ref={fileInputRef} 
                          type="file" 
                          onChange={handleFileUpload} 
                          accept=".csv,.txt" 
                          className="hidden" 
                        />
                      </div>
                    </div>
                    <textarea
                      value={csvText}
                      onChange={(e) => setCsvText(e.target.value)}
                      className="w-full h-64 bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs font-mono focus:ring-2 focus:ring-blue-500 outline-none resize-none"
                      placeholder="example.com, 1.2.3.4 (spoof IP), /api/status, GET"
                    />
                  </>
                ) : (
                  <>
                    {/* Spoof IP fields */}
                    <div className="mb-4 space-y-2">
                      <div className="flex items-center justify-between mb-1">
                        <label className="block text-xs font-mono text-slate-400 uppercase tracking-wider">
                          Spoof IP Addresses <span className="text-red-400">*</span>
                        </label>
                        <button onClick={addSpoofIp} className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors">
                          <Plus className="w-3 h-3"/> Add IP
                        </button>
                      </div>
                      {spoofIps.map((ip, index) => {
                        const c = getSpoofColor(index);
                        const trimmed = ip.trim();
                        const ipInvalid = trimmed.length > 0 && !isValidIp(trimmed);
                        return (
                          <div key={index} className={`flex gap-2 items-center p-2 rounded-lg border ${ipInvalid ? 'border-red-500/60 bg-red-500/10' : `${c.border} ${c.bg}`}`}>
                            <div className={`text-[10px] font-bold uppercase w-14 shrink-0 ${ipInvalid ? 'text-red-400' : c.label}`}>{getSpoofLabel(index)}</div>
                            <div className="flex-1 relative">
                              <input
                                type="text"
                                value={ip}
                                onChange={(e) => updateSpoofIp(index, e.target.value)}
                                placeholder="e.g. 10.0.0.1"
                                className={`w-full bg-slate-900/70 border rounded px-2 py-1.5 text-sm font-mono focus:ring-1 outline-none ${
                                  ipInvalid ? 'border-red-500/60 focus:ring-red-500' : 'border-slate-700 focus:ring-slate-500'}`}
                              />
                              {ipInvalid && (
                                <div className="flex items-center gap-1 mt-1 text-[10px] text-red-400">
                                  <AlertTriangle className="w-3 h-3" /> Invalid IP format
                                </div>
                              )}
                            </div>
                            <button
                              onClick={() => removeSpoofIp(index)}
                              disabled={spoofIps.length === 1}
                              className="p-1 text-slate-600 hover:text-red-400 disabled:opacity-20 transition-colors"
                            >
                              <X className="w-4 h-4"/>
                            </button>
                          </div>
                        );
                      })}
                      <p className="text-[10px] text-slate-500">Each URL will be tested against all spoof IPs in parallel.</p>
                    </div>

                    {/* URL list */}
                    <div className="flex items-center justify-between mb-2">
                      <label className="text-xs font-mono text-slate-400">URLs to Test</label>
                      <div className="flex items-center gap-3">
                        <button
                          onClick={handleExportUrlsAsCsv}
                          disabled={urlEntries.every(e => e.url.trim() === '')}
                          className="text-xs flex items-center gap-1 text-slate-400 hover:text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                          title="Export URLs as CSV for use in CSV mode"
                        >
                          <Download className="w-3 h-3" /> Export CSV
                        </button>
                        <button
                          onClick={() => { setShowBulkAdd(v => !v); setBulkText(''); }}
                          className="text-xs flex items-center gap-1 text-emerald-400 hover:text-emerald-300 transition-colors"
                        >
                          <ClipboardList className="w-3 h-3" /> Bulk Add
                        </button>
                        <button
                          onClick={addUrlEntry}
                          className="text-xs flex items-center gap-1 text-blue-400 hover:text-blue-300 transition-colors"
                        >
                          <Plus className="w-3 h-3" /> Add URL
                        </button>
                      </div>
                    </div>

                    {/* Bulk Add Panel */}
                    {showBulkAdd && (
                      <div className="mb-3 p-3 bg-slate-900 border border-emerald-500/30 rounded-lg space-y-2">
                        <div className="flex items-center justify-between">
                          <p className="text-xs text-emerald-300 font-medium">Paste URLs — one per line</p>
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => bulkFileInputRef.current?.click()}
                              className="text-xs flex items-center gap-1 text-blue-400 hover:text-blue-300 transition-colors"
                              title="Import URLs from a .txt or .csv file (one URL per line)"
                            >
                              <Upload className="w-3 h-3" /> Import from File
                            </button>
                            <input
                              ref={bulkFileInputRef}
                              type="file"
                              onChange={handleBulkFileImport}
                              accept=".txt,.csv"
                              className="hidden"
                            />
                            <button onClick={() => { setShowBulkAdd(false); setBulkText(''); }} className="text-slate-500 hover:text-slate-300">
                              <X className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                        <textarea
                          autoFocus
                          value={bulkText}
                          onChange={(e) => setBulkText(e.target.value)}
                          placeholder={`https://example.com/page1\nhttps://example.com/page2\nhttps://example.com/page3`}
                          className="w-full h-32 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-xs font-mono focus:ring-2 focus:ring-emerald-500 outline-none resize-none placeholder-slate-600"
                        />
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] text-slate-500">
                            {bulkText.split('\n').filter(l => l.trim()).length} URL{bulkText.split('\n').filter(l => l.trim()).length !== 1 ? 's' : ''} detected
                          </span>
                          <button
                            onClick={handleBulkAdd}
                            disabled={bulkText.trim().length === 0}
                            className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed rounded text-xs font-semibold transition-colors"
                          >
                            Add to List
                          </button>
                        </div>
                      </div>
                    )}

                    <div className="overflow-y-auto max-h-64 space-y-2 pr-0.5">
                      {urlEntries.map((entry) => (
                        <div key={entry.id} className="flex gap-2 items-center">
                          <input
                            type="text"
                            value={entry.url}
                            onChange={(e) => updateUrlEntry(entry.id, e.target.value)}
                            placeholder={`https://example.com/path`}
                            className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono focus:ring-2 focus:ring-blue-500 outline-none"
                          />
                          <button
                            onClick={() => removeUrlEntry(entry.id)}
                            disabled={urlEntries.length === 1}
                            className="p-2 text-slate-600 hover:text-red-400 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                            title="Remove URL"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </>
                )}

                <div className="mt-4 p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg text-xs space-y-2">
                  <div className="flex items-start gap-2">
                    <ShieldAlert className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                    <span className="text-blue-200">
                      <strong>Smart Features Active:</strong>
                      <ul className="list-disc pl-4 mt-1 space-y-0.5 text-blue-300/80">
                        <li>Pass/Fail based on Live vs Spoof status code match</li>
                        <li>Fuzzy HTML Matching (Scripts removed)</li>
                        <li>F5 Bot Defense Detection</li>
                        <li>Complete Header Analysis (All headers shown, noise marked)</li>
                        <li>Akamai Debug Headers Injected</li>
                      </ul>
                    </span>
                  </div>
                </div>
              </div>
              
              <button
                onClick={runTest}
                disabled={isRunning}
                className="mt-4 w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg font-semibold flex items-center justify-center gap-2 transition-colors"
              >
                {isRunning ? 'Running Analysis...' : 'Start Sanity Check'}
                <Play className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="lg:col-span-2 flex flex-col space-y-4">
            {isRunning && (
              <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-slate-300">Analyzing Requests...</span>
                  <span className="text-blue-400 font-mono">{progress}%</span>
                </div>
                <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                  <div className="h-full bg-blue-500 transition-all duration-300" style={{ width: `${progress}%` }} />
                </div>
              </div>
            )}

            <div className="bg-slate-800 rounded-xl border border-slate-700 flex-1 flex flex-col overflow-hidden min-h-[500px]">
              {/* Header bar with navigation */}
              <div className="p-4 border-b border-slate-700 flex justify-between items-center bg-slate-800/50">
                <h3 className="font-semibold text-slate-200">Analysis Report</h3>
                <div className="flex items-center gap-3">
                  {results.length > 0 && (
                    <>
                      <span className="text-xs text-slate-500">
                        {results.filter(r => r.overallPassed).length} passed · {results.filter(r => !r.overallPassed).length} failed · {results.length} total
                      </span>
                      <button
                        onClick={handleExport}
                        className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm flex items-center gap-2 transition-colors"
                      >
                        <Download className="w-4 h-4" /> CSV
                      </button>
                      <button
                        onClick={() => generateSanityCheckPdf(results)}
                        className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm flex items-center gap-2 transition-colors"
                      >
                        <FileText className="w-4 h-4" /> PDF
                      </button>
                    </>
                  )}
                </div>
              </div>

              {results.length === 0 ? (
                <div className="flex-1 flex flex-col items-center justify-center text-slate-500 p-8">
                  <Activity className="w-12 h-12 mb-4 opacity-20" />
                  <p>Ready to analyze. Upload CSV or enter URLs to begin.</p>
                </div>
              ) : (() => {
                const idx = Math.min(currentResultIdx, results.length - 1);
                const res = results[idx];
                const fullUrl = `https://${res.row.domain}${res.row.path}`;
                const displayedSpoofs = res.spoofedResults;
                const displayedReasons = res.reasons;

                return (
                  <div className="flex-1 flex flex-col overflow-hidden">
                    {/* Navigation bar */}
                    <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-700 bg-slate-900/40">
                      <button onClick={() => setCurrentResultIdx(Math.max(0, idx - 1))} disabled={idx === 0}
                        className="p-1.5 rounded-lg bg-slate-700 hover:bg-slate-600 disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
                        <ChevronLeft className="w-4 h-4" />
                      </button>
                      <button onClick={() => setCurrentResultIdx(Math.min(results.length - 1, idx + 1))} disabled={idx === results.length - 1}
                        className="p-1.5 rounded-lg bg-slate-700 hover:bg-slate-600 disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
                        <ChevronRight className="w-4 h-4" />
                      </button>
                      <span className="text-sm font-mono text-slate-400 ml-1">
                        {idx + 1} <span className="text-slate-600">of</span> {results.length}
                      </span>
                      <div className="flex-1" />
                      {/* Mini result list dropdown */}
                      <select value={idx} onChange={e => setCurrentResultIdx(Number(e.target.value))}
                        className="bg-slate-900 border border-slate-600 rounded-lg px-2 py-1.5 text-xs text-slate-300 max-w-xs truncate">
                        {results.map((r, i) => (
                          <option key={r.row.id} value={i}>
                            {r.overallPassed ? '\u2705' : '\u274C'} [{r.row.method}] {r.row.domain}{r.row.path}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Full detail view for the current result */}
                    <div className="flex-1 overflow-y-auto">
                      {/* Result header */}
                      <div className="px-5 pt-5 pb-4">
                        <div className="flex items-start gap-3">
                          <div className="shrink-0 mt-0.5">
                            {res.overallPassed
                              ? <CheckCircle className="w-6 h-6 text-emerald-500" />
                              : <XCircle className="w-6 h-6 text-red-500" />}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className={`text-xs font-bold uppercase px-2.5 py-0.5 rounded-full ${
                                res.overallPassed ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`}>
                                {res.overallPassed ? 'PASS' : 'FAIL'}
                              </span>
                              <Globe className="w-3.5 h-3.5 text-slate-500" />
                              <span className="text-sm font-semibold text-slate-200">{res.row.domain}</span>
                              <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30" title="Request method">{res.row.method}</span>
                            </div>
                            <div className="flex items-start gap-2 mt-1.5">
                              <span className="text-[10px] font-bold uppercase text-slate-500 mt-1.5 shrink-0">{res.row.method}</span>
                              <code className="flex-1 min-w-0 text-xs text-slate-300 bg-slate-900/60 border border-slate-700/60 rounded px-2 py-1 break-all" title={fullUrl}>
                                {fullUrl}
                              </code>
                              <a href={fullUrl} target="_blank" rel="noopener noreferrer"
                                className="shrink-0 text-slate-500 hover:text-blue-400 transition-colors mt-1.5">
                                <ExternalLink className="w-3.5 h-3.5" />
                              </a>
                            </div>
                          </div>
                        </div>

                        {/* Status chips */}
                        <div className="flex flex-wrap items-center gap-2 mt-4">
                          <div className="flex items-center gap-2 bg-blue-500/10 border border-blue-500/30 rounded-lg px-3 py-1.5">
                            <div className="flex items-center gap-1">
                              <div className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                              <span className="text-[10px] font-bold text-blue-400 uppercase tracking-wider">Live</span>
                            </div>
                            <span className={`text-sm font-mono font-bold ${res.public.status === 'ERR' ? 'text-red-400' : 'text-blue-300'}`}>
                              {res.public.status}
                            </span>
                            <span className="text-[10px] text-slate-500">{res.public.duration}ms</span>
                          </div>
                          {displayedSpoofs.map((spoof, si) => {
                            const c = getSpoofColor(si);
                            return (
                              <div key={si} className={`flex items-center gap-2 border rounded-lg px-3 py-1.5 ${c.border} ${c.bg}`}>
                                <div className="flex items-center gap-1">
                                  <div className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
                                  <span className={`text-[10px] font-bold uppercase tracking-wider ${c.label}`}>{getSpoofLabel(si)}</span>
                                </div>
                                <span className={`text-sm font-mono font-bold ${
                                  spoof.result.status === 'ERR' ? 'text-red-400' : !spoof.statusMatch ? 'text-amber-300' : 'text-slate-200'}`}>
                                  {spoof.result.status}
                                </span>
                                <span className={`text-[10px] font-semibold ${spoof.score >= 95 ? 'text-emerald-400' : 'text-red-400'}`}>
                                  {spoof.score}%
                                </span>
                                {spoof.result.isBotChallenge && <span className="text-[10px] text-amber-400 font-bold" title="Bot challenge detected">⚠</span>}
                              </div>
                            );
                          })}
                        </div>
                      </div>

                      {/* Drift reasons */}
                      {displayedReasons.length > 0 && (
                        <div className="mx-5 mb-4 p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg text-xs text-amber-200">
                          <strong className="block mb-1">Comparison Drift Detected:</strong>
                          <ul className="list-disc pl-4 space-y-0.5">
                            {displayedReasons.map((r, i) => <li key={i}>{r}</li>)}
                          </ul>
                        </div>
                      )}

                      {/* Comparison Table */}
                      <div className="px-5 pb-4">
                        <h4 className="text-xs font-bold text-slate-400 uppercase mb-2 flex items-center gap-2">
                          <Layers className="w-3 h-3" /> Side-by-Side Comparison
                        </h4>
                        <ComparisonTable publicRes={res.public} spoofedResults={displayedSpoofs} />
                      </div>

                      {/* Header Comparison */}
                      <div className="px-5 pb-4">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="text-xs font-bold text-slate-400 uppercase flex items-center gap-2">
                            <Layers className="w-3 h-3" /> Header Comparison
                          </h4>
                          <div className="flex items-center gap-3 text-[10px]">
                            <div className="flex items-center gap-1">
                              <div className="w-2 h-2 bg-amber-500 rounded" />
                              <span className="text-slate-500">Significant Diff</span>
                            </div>
                            <div className="flex items-center gap-1">
                              <div className="w-2 h-2 bg-slate-700 rounded" />
                              <span className="text-slate-500">Ignored</span>
                            </div>
                          </div>
                        </div>
                        <HeaderDiff publicRes={res.public} spoofedResults={displayedSpoofs} />
                      </div>

                      {/* TLS Certificate Comparison */}
                      {(res.public.tlsCert || displayedSpoofs.some(s => s.result.tlsCert)) && (
                        <div className="px-5 pb-4">
                          <h4 className="text-xs font-bold text-slate-400 uppercase mb-2 flex items-center gap-2">
                            <ShieldCheck className="w-3 h-3" /> TLS Certificate Comparison
                          </h4>
                          <TlsCertComparison
                            liveCert={res.public.tlsCert}
                            spoofCerts={displayedSpoofs.map((spoof, si) => ({
                              label: getSpoofLabel(si), ip: spoof.ip, cert: spoof.result.tlsCert,
                            }))}
                          />
                        </div>
                      )}

                      {/* Body Preview */}
                      {displayedSpoofs.length > 0 && (
                        <div className="px-5 pb-4">
                          <h4 className="text-xs font-bold text-slate-400 uppercase mb-2 flex items-center gap-2">
                            <Code className="w-3 h-3" /> Body Preview
                          </h4>
                          <div className="text-xs font-bold text-slate-500 mb-1">Normalized Body Preview (First 500 chars)</div>
                          <BodyCompare publicRes={res.public} spoofedResults={displayedSpoofs} />
                        </div>
                      )}

                      {/* Bottom navigation */}
                      <div className="px-5 pb-5 flex items-center justify-between">
                        <button onClick={() => setCurrentResultIdx(Math.max(0, idx - 1))} disabled={idx === 0}
                          className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 disabled:opacity-30 disabled:cursor-not-allowed rounded-lg text-sm transition-colors">
                          <ChevronLeft className="w-4 h-4" /> Previous
                        </button>
                        <span className="text-xs text-slate-500">{idx + 1} of {results.length}</span>
                        <button onClick={() => setCurrentResultIdx(Math.min(results.length - 1, idx + 1))} disabled={idx === results.length - 1}
                          className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 disabled:opacity-30 disabled:cursor-not-allowed rounded-lg text-sm transition-colors">
                          Next <ChevronRight className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}