import React, { useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  Download,
  Upload,
  Play,
  CheckCircle,
  AlertTriangle,
  Loader2,
  Hammer,
  Info,
  Server,
  Network,
  HelpCircle
} from 'lucide-react';
import { apiClient } from '../services/api';
import { useToast } from '../context/ToastContext';
import { Certificate } from '../types';

// --- Types ---

type LbType = 'HTTP' | 'HTTPS_AUTO' | 'HTTPS_CUSTOM';

interface CsvRow {
  name: string;
  namespace: string;
  domain: string; 
  origin: string;      // IP or Hostname
  port?: string;       // Origin Port
  type: string; 
  cert_name_override?: string;
  [key: string]: string | undefined;
}

interface ValidationResult {
  row: CsvRow;
  parsedDomains: string[];
  normalizedType: LbType | null;
  isValid: boolean;
  message: string;
  matchedCerts: Certificate[];
}

interface CreationResult {
  name: string;
  status: 'pending' | 'success' | 'error';
  step?: 'pool' | 'waf' | 'lb' | 'done';
  details?: string;
  vip?: string;
  cname?: string;
}

// --- Helpers ---

// Robust CSV Parser to handle quoted fields with commas
const parseCSV = (text: string): CsvRow[] => {
  const lines = text.trim().split('\n');
  if (lines.length < 2) return [];
  
  const headers = lines[0].split(',').map(h => h.trim());
  const result: CsvRow[] = [];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    // Manual parsing to handle quotes correctly
    const rowValues: string[] = [];
    let currentVal = '';
    let inQuotes = false;

    for (let j = 0; j < line.length; j++) {
      const char = line[j];
      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        rowValues.push(currentVal);
        currentVal = '';
      } else {
        currentVal += char;
      }
    }
    rowValues.push(currentVal);

    const obj: any = {};
    headers.forEach((h, idx) => {
      let val = rowValues[idx] || '';
      // Clean up quotes (e.g., "domain1,domain2" -> domain1,domain2)
      val = val.trim().replace(/^"|"$/g, '');
      obj[h] = val;
    });
    result.push(obj as CsvRow);
  }
  return result;
};

const isIpAddress = (val: string): boolean => {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^[a-fA-F0-9:]+$/; 
  return ipv4Regex.test(val) || (val.includes(':') && ipv6Regex.test(val));
};

export function HttpLbForge() {
  const toast = useToast();
  
  // State
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  
  // Data
  const [csvData, setCsvData] = useState<CsvRow[]>([]);
  const [validationResults, setValidationResults] = useState<ValidationResult[]>([]);
  const [creationResults, setCreationResults] = useState<CreationResult[]>([]);
  const [, setCertificates] = useState<Certificate[]>([]);
  
  // UI
  const [isLoading, setIsLoading] = useState(false);
  const [loadingText, setLoadingText] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  // --- Step 1: Template Generation ---

  const downloadTemplate = () => {
    const headers = ['name', 'namespace', 'domain', 'origin', 'port', 'type', 'cert_name_override (optional)'];
    
    const sampleRows = [
      'simple-app,demo-ns,app.example.com,192.168.1.50,443,HTTP,',
      'dns-origin-app,demo-ns,site.com,backend.internal.com,8080,HTTPS_AUTO,',
      'multi-domain-app,demo-ns,"site.com,www.site.com",10.0.0.5,443,HTTPS_CUSTOM,',
    ];

    const csvContent = headers.join(',') + '\n' + sampleRows.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lb_forge_template.csv`;
    a.click();
  };

  // --- Step 2: Upload & Analysis ---

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsLoading(true);
    setLoadingText('Reading file...');

    const reader = new FileReader();
    reader.onload = async (e) => {
      const text = e.target?.result as string;
      const rows = parseCSV(text);
      setCsvData(rows);

      const needsCertScan = rows.some(r => r.type?.toUpperCase().trim() === 'HTTPS_CUSTOM');
      
      let allCerts: Certificate[] = [];

      if (needsCertScan) {
        setLoadingText('Fetching certificates for auto-discovery...');
        try {
          const uniqueNamespaces = Array.from(new Set(rows.map(r => r.namespace).filter(Boolean)));
          
          for (const ns of uniqueNamespaces) {
             try {
               const resp = await apiClient.getCertificates(ns);
               allCerts = [...allCerts, ...resp.items];
             } catch (err) {
               console.warn(`Failed to fetch certs for namespace ${ns}`, err);
             }
          }
          setCertificates(allCerts);
        } catch (err) {
          toast.error('Failed to fetch certificates');
          console.error(err);
        }
      }
      
      validateRows(rows, allCerts);
      setIsLoading(false);
      setStep(2);
    };
    reader.readAsText(file);
  };

  const findMatchingCert = (domain: string, certs: Certificate[]): Certificate | undefined => {
    const cleanDomain = domain.toLowerCase().replace(/\.$/, '');

    for (const cert of certs) {
      if (!cert.spec.infos) continue;

      for (const info of cert.spec.infos) {
        const cn = info.common_name?.toLowerCase();
        const sans = info.subject_alternative_names?.map(s => s.toLowerCase()) || [];
        const allNames = [cn, ...sans].filter(Boolean) as string[];

        if (allNames.includes(cleanDomain)) return cert;

        for (const name of allNames) {
          if (name.startsWith('*.')) {
            const root = name.substring(2);
            if (cleanDomain.endsWith(root) && cleanDomain.split('.').length === root.split('.').length + 1) {
              return cert;
            }
          }
        }
      }
    }
    return undefined;
  };

  const normalizeType = (input: string): LbType | null => {
    const upper = input?.toUpperCase().trim();
    if (upper === 'HTTP') return 'HTTP';
    if (upper === 'HTTPS_AUTO' || upper === 'AUTO') return 'HTTPS_AUTO';
    if (upper === 'HTTPS_CUSTOM' || upper === 'CUSTOM') return 'HTTPS_CUSTOM';
    return null;
  };

  const validateRows = (rows: CsvRow[], certs: Certificate[]) => {
    const results: ValidationResult[] = rows.map(row => {
      let isValid = true;
      let message = 'Ready';
      let matchedCerts: Certificate[] = [];
      
      // Split by comma as well as semicolon and space
      const parsedDomains = row.domain
        ? row.domain.split(/[;, ]+/).map(d => d.trim()).filter(Boolean)
        : [];

      const normalizedType = normalizeType(row.type);

      // 1. Basic Field Validation
      if (!row.name || !row.namespace || parsedDomains.length === 0 || !row.origin || !row.type) {
        isValid = false;
        message = 'Missing name, namespace, domain, origin, or type';
      } 
      // 2. Type Validation
      else if (!normalizedType) {
        isValid = false;
        message = `Invalid Type: ${row.type}`;
      }
      // 3. Port Validation
      else if (row.port && isNaN(parseInt(row.port))) {
        isValid = false;
        message = `Invalid Port: ${row.port}`;
      }
      // 4. Certificate Validation (HTTPS_CUSTOM)
      else if (normalizedType === 'HTTPS_CUSTOM') {
        if (row.cert_name_override) {
            message = `Using manual cert: ${row.cert_name_override}`;
        } else {
          const foundCerts: Certificate[] = [];
          const missingDomains: string[] = [];

          parsedDomains.forEach(domain => {
            const match = findMatchingCert(domain, certs);
            if (match) {
                foundCerts.push(match);
            } else {
                missingDomains.push(domain);
            }
          });

          const uniqueCerts = Array.from(new Map(foundCerts.map(c => [c.metadata.name, c])).values());
          matchedCerts = uniqueCerts;

          if (missingDomains.length > 0) {
            isValid = false;
            message = `No cert found for: ${missingDomains.join(', ')}`;
          } else {
            message = `Matched ${uniqueCerts.length} cert(s)`;
          }
        }
      }

      return { row, parsedDomains, normalizedType, isValid, message, matchedCerts };
    });
    setValidationResults(results);
  };

  // --- Step 3: Execution ---

  const executeBulkCreation = async () => {
    setStep(3);
    const results: CreationResult[] = [];

    for (let i = 0; i < validationResults.length; i++) {
      const item = validationResults[i];
      
      setCreationResults(prev => [...prev, { name: item.row.name, status: 'pending', step: 'pool' }]);

      if (!item.isValid) {
        const result: CreationResult = { name: item.row.name, status: 'error', details: item.message };
        results.push(result);
        setCreationResults(prev => [...prev.filter(r => r.name !== item.row.name), result]);
        continue;
      }

      try {
        const poolName = `${item.row.name}-pool`;
        const wafName = `${item.row.name}-waf`;
        const originPort = item.row.port ? parseInt(item.row.port) : 443;
        
        // --- Phase 1: Create Origin Pool ---
        await createOriginPool(item, poolName, originPort);
        
        setCreationResults(prev => [
           ...prev.filter(r => r.name !== item.row.name),
           { name: item.row.name, status: 'pending', step: 'waf', details: 'Pool created, creating WAF...' }
        ]);

        // --- Phase 2: Create WAF ---
        await createWAF(item, wafName);

        setCreationResults(prev => [
           ...prev.filter(r => r.name !== item.row.name),
           { name: item.row.name, status: 'pending', step: 'lb', details: 'WAF created, creating LB...' }
        ]);

        // --- Phase 3: Create Load Balancer ---
        await createSingleLb(item, poolName, wafName);
        
        const result: CreationResult = { name: item.row.name, status: 'success', step: 'done', details: 'Created successfully' };
        results.push(result);
        setCreationResults(prev => [...prev.filter(r => r.name !== item.row.name), result]);
      } catch (error: any) {
        const result: CreationResult = { name: item.row.name, status: 'error', details: error.message || 'Unknown error' };
        results.push(result);
        setCreationResults(prev => [...prev.filter(r => r.name !== item.row.name), result]);
      }

      await new Promise(resolve => setTimeout(resolve, 500));
    }

    setStep(4);
    fetchFinalDetails(results);
  };

  const createOriginPool = async (item: ValidationResult, poolName: string, port: number) => {
    const { row } = item;
    const isIp = isIpAddress(row.origin);

    const payload = {
      metadata: {
        name: poolName,
        namespace: row.namespace
      },
      spec: {
        origin_servers: [
            {
                [isIp ? 'public_ip' : 'public_name']: isIp
                    ? { ip: row.origin }
                    : { dns_name: row.origin }
            }
        ],
        port: port,
        // Origin pools require an explicit TLS choice. Port 443 implies the
        // origin speaks TLS; otherwise connect in plaintext. (For a 443 origin
        // with a private/self-signed cert, switch to use_server_verification or
        // volterra_trusted_ca after creation.)
        ...(port === 443
          ? {
              use_tls: {
                use_host_header_as_sni: {},
                tls_config: { default_security: {} },
                skip_server_verification: {},
                no_mtls: {},
              },
            }
          : { no_tls: {} }),
        loadbalancer_algorithm: "LB_OVERRIDE",
        endpoint_selection: "DISTRIBUTED"
      }
    };

    return apiClient.createOriginPool(row.namespace, payload);
  };

  const createWAF = async (item: ValidationResult, wafName: string) => {
    const payload = {
        metadata: {
            name: wafName,
            namespace: item.row.namespace,
            disable: false
        },
        // app_firewall object spec: enforcement mode + settings live at the spec
        // root (not nested under `app_firewall`). `blocking`/`monitoring` are a
        // mutually-exclusive oneof — `use_loadbalancer_setting` is a route-level
        // WAF choice, not valid here, so it must not be set alongside `blocking`.
        spec: {
            blocking: {},
            default_detection_settings: {},
            default_bot_setting: {},
            default_anonymization: {}
        }
    };
    return apiClient.createAppFirewall(item.row.namespace, payload);
  };

  const createSingleLb = async (item: ValidationResult, poolName: string, wafName: string) => {
    const { row, parsedDomains, normalizedType, matchedCerts } = item;
    
    // UPDATED: Use simple_route wrapper correctly
    const routes = parsedDomains.map(domain => ({
        simple_route: {
            // XC RouteTypeSimple carries path/headers/origin_pools at the top
            // level — there is no `match` wrapper.
            path: {
                prefix: "/"
            },
            headers: [
                {
                    name: "Host",
                    exact: domain
                }
            ],
            origin_pools: [
                {
                    pool: {
                        name: poolName,
                        namespace: row.namespace
                    },
                    weight: 1,
                    priority: 1
                }
            ],
            // Use disable_host_rewrite to satisfy "auto_host_rewrite: false" requirement
            disable_host_rewrite: {}
        }
    }));

    const payload: any = {
      metadata: {
        name: row.name,
        namespace: row.namespace,
        disable: false
      },
      spec: {
        domains: parsedDomains,
        advertise_on_public_default_vip: {},
        routes: routes,
        app_firewall: {
            name: wafName,
            namespace: row.namespace
        },
        no_challenge: {},
        disable_rate_limit: {}
      }
    };

    if (normalizedType === 'HTTPS_AUTO') {
      payload.spec.https_auto_cert = {
        http_redirect: true,
        add_hsts: true,
        tls_config: { default_security: {} },
        no_mtls: {}
      };
    } else if (normalizedType === 'HTTPS_CUSTOM') {
      const certRefs = row.cert_name_override
        ? [{ name: row.cert_name_override, namespace: row.namespace }]
        : matchedCerts.map(c => ({ name: c.metadata.name, namespace: c.metadata.namespace }));

      payload.spec.https = {
        http_redirect: true,
        add_hsts: true,
        tls_cert_params: {
          tls_config: { default_security: {} },
          certificates: certRefs,
          no_mtls: {}
        }
      };
    }

    return apiClient.createHttpLoadBalancer(row.namespace, payload);
  };

  // --- Step 4: Reporting ---

  const fetchFinalDetails = async (baseResults: CreationResult[]) => {
    setIsLoading(true);
    setLoadingText('Fetching DNS & VIP details for report...');

    // Use the outcomes accumulated during creation, not `creationResults` from
    // the click-time closure (which is stale because the per-item updates used
    // the functional setState form and never rebind this variable).
    const enhancedResults = [...baseResults];

    for (let i = 0; i < enhancedResults.length; i++) {
      if (enhancedResults[i].status !== 'success') continue;

      try {
        const originalRow = csvData.find(c => c.name === enhancedResults[i].name);
        if (!originalRow) continue;

        const lb = await apiClient.getLoadBalancer(originalRow.namespace, originalRow.name);
        
        if (lb.dns_info && lb.dns_info.length > 0) {
          enhancedResults[i].cname = lb.dns_info[0].dns_name;
          enhancedResults[i].vip = lb.dns_info[0].ip_address;
        }
        
        if (!enhancedResults[i].vip && lb.internet_vip_info && lb.internet_vip_info.length > 0) {
            enhancedResults[i].vip = lb.internet_vip_info[0].ip_address;
        }

      } catch (e) {
        console.warn('Could not fetch final details for', enhancedResults[i].name);
      }
    }

    setCreationResults(enhancedResults);
    setIsLoading(false);
  };

  const downloadFinalReport = () => {
    const headers = ['Name', 'Namespace', 'Status', 'Domains', 'Type', 'Origin', 'WAF', 'LB CNAME', 'VIP IP', 'Details'];
    
    const rows = creationResults.map(res => {
        const original = csvData.find(c => c.name === res.name);
        const doms = original?.domain.replace(/[; ]+/g, ' | ') || '';

        return [
            res.name,
            original?.namespace || '',
            res.status,
            doms,
            original?.type || '',
            original?.origin || '',
            `${res.name}-waf`,
            res.cname || 'Pending/Unknown',
            res.vip || 'Pending/Unknown',
            res.details || ''
        ].join(',');
    });

    const csvContent = headers.join(',') + '\n' + rows.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lb_creation_report_${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  };

  // --- Render Helpers ---

  const renderStepIndicator = () => (
    <div className="flex items-center justify-between mb-8 px-12">
      {[
        { num: 1, label: 'Download Template' },
        { num: 2, label: 'Upload & Verify' },
        { num: 3, label: 'Execute' },
        { num: 4, label: 'Report' }
      ].map((s) => (
        <div key={s.num} className="flex flex-col items-center relative z-10">
          <div className={`w-10 h-10 rounded-full flex items-center justify-center font-bold transition-all duration-300 ${
            step >= s.num 
              ? 'bg-violet-600 text-white shadow-lg shadow-violet-500/30' 
              : 'bg-slate-800 text-slate-500 border border-slate-700'
          }`}>
            {step > s.num ? <CheckCircle className="w-6 h-6" /> : s.num}
          </div>
          <span className={`mt-2 text-sm font-medium ${step >= s.num ? 'text-slate-200' : 'text-slate-500'}`}>
            {s.label}
          </span>
        </div>
      ))}
      <div className="absolute top-5 left-0 w-full h-0.5 bg-slate-800 -z-0" />
      <div 
        className="absolute top-5 left-0 h-0.5 bg-violet-600 -z-0 transition-all duration-500" 
        style={{ width: `${((step - 1) / 3) * 100}%` }}
      />
    </div>
  );

  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="mb-8">
        <div className="flex items-center gap-4">
          <h1 className="text-3xl font-bold text-slate-100 flex items-center gap-3">
            <Hammer className="w-8 h-8 text-violet-400" />
            HTTP LB Forge
          </h1>
          <Link to="/explainer/http-lb-forge" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
            <HelpCircle className="w-3.5 h-3.5" /> How does this work?
          </Link>
        </div>
        <p className="text-slate-400 mt-2">
          Bulk create HTTP/HTTPS Load Balancers with automated Origin Pool, WAF, and Route configuration.
        </p>
      </div>

      {renderStepIndicator()}

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
        {/* STEP 1: CONFIGURATION */}
        {step === 1 && (
          <div className="space-y-8 max-w-3xl mx-auto">
            
            <div className="bg-slate-800/50 rounded-xl p-6 border border-slate-700 space-y-4">
              <h3 className="text-lg font-semibold text-slate-200 flex items-center gap-2">
                <Info className="w-5 h-5 text-violet-400" />
                CSV Guidelines
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                   <p className="text-sm text-slate-400 mb-2">Required Columns:</p>
                   <ul className="text-sm text-slate-300 space-y-1 list-disc list-inside font-mono bg-slate-900/50 p-3 rounded-lg border border-slate-800">
                      <li>name</li>
                      <li>namespace</li>
                      <li>domain <span className="text-slate-500 text-xs">(supports multiple)</span></li>
                      <li>origin <span className="text-emerald-400 text-xs">(IP or Hostname)</span></li>
                      <li>port <span className="text-slate-500 text-xs">(default 443)</span></li>
                      <li>type <span className="text-emerald-400 text-xs">(Required)</span></li>
                   </ul>
                </div>

                <div>
                   <p className="text-sm text-slate-400 mb-2">Supported Values for <b>type</b>:</p>
                   <ul className="space-y-2">
                      <li className="flex items-start gap-2 text-sm">
                        <span className="font-mono bg-blue-500/10 text-blue-400 px-1.5 py-0.5 rounded text-xs">HTTP</span>
                        <span className="text-slate-400">Standard HTTP Load Balancer</span>
                      </li>
                      <li className="flex items-start gap-2 text-sm">
                        <span className="font-mono bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded text-xs">HTTPS_AUTO</span>
                        <span className="text-slate-400">HTTPS with Auto Cert</span>
                      </li>
                      <li className="flex items-start gap-2 text-sm">
                        <span className="font-mono bg-amber-500/10 text-amber-400 px-1.5 py-0.5 rounded text-xs">HTTPS_CUSTOM</span>
                        <span className="text-slate-400">Auto-matched from existing certs</span>
                      </li>
                   </ul>
                </div>
              </div>

              <div className="pt-2 text-xs text-slate-500 italic space-y-1">
                <p>• <b>Automated Origin Pool:</b> A pool named <code>&lt;lb_name&gt;-pool</code> will be created.</p>
                <p>• <b>Automated WAF:</b> A WAF named <code>&lt;lb_name&gt;-waf</code> will be created and attached.</p>
                <p>• <b>Multiple Domains:</b> Use semicolons or wrap in quotes with commas (e.g. <code>"site.com,www.site.com"</code>).</p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <button 
                    onClick={downloadTemplate}
                    className="flex flex-col items-center justify-center gap-2 bg-slate-800 hover:bg-slate-750 text-slate-300 hover:text-white p-8 rounded-xl border border-slate-700 hover:border-violet-500/50 transition-all group"
                >
                    <Download className="w-8 h-8 text-violet-500 group-hover:scale-110 transition-transform" />
                    <span className="font-medium">1. Download Template</span>
                    <span className="text-xs text-slate-500">Get the sample CSV structure</span>
                </button>

                <div 
                    onClick={() => fileInputRef.current?.click()}
                    className="flex flex-col items-center justify-center gap-2 bg-slate-800 hover:bg-slate-750 text-slate-300 hover:text-white p-8 rounded-xl border border-slate-700 hover:border-violet-500/50 cursor-pointer transition-all group"
                >
                    <input 
                        type="file" 
                        accept=".csv" 
                        ref={fileInputRef} 
                        onChange={handleFileUpload} 
                        className="hidden" 
                    />
                    {isLoading ? (
                        <>
                           <Loader2 className="w-8 h-8 text-violet-500 animate-spin" />
                           <span className="font-medium">{loadingText}</span>
                        </>
                    ) : (
                        <>
                           <Upload className="w-8 h-8 text-violet-500 group-hover:scale-110 transition-transform" />
                           <span className="font-medium">2. Upload Filled CSV</span>
                           <span className="text-xs text-slate-500">Process and Validate file</span>
                        </>
                    )}
                </div>
            </div>

          </div>
        )}

        {/* STEP 2: PREVIEW & VALIDATE */}
        {step === 2 && (
          <div className="space-y-6">
             <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-slate-200">Validation Preview</h3>
                <div className="flex items-center gap-4">
                    <div className="text-sm text-slate-400">
                        {validationResults.filter(r => r.isValid).length} Valid / {validationResults.length} Total
                    </div>
                    <button
                        onClick={() => setStep(1)}
                        className="text-slate-400 hover:text-white text-sm"
                    >
                        Back
                    </button>
                </div>
             </div>

             <div className="overflow-x-auto rounded-lg border border-slate-700">
                <table className="w-full text-left text-sm text-slate-300">
                    <thead className="bg-slate-800 text-slate-400 uppercase font-medium">
                        <tr>
                            <th className="px-4 py-3">Status</th>
                            <th className="px-4 py-3">Namespace</th>
                            <th className="px-4 py-3">LB Name</th>
                            <th className="px-4 py-3">Domains</th>
                            <th className="px-4 py-3">Origin</th>
                            <th className="px-4 py-3">Type</th>
                            <th className="px-4 py-3">Config Details</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 bg-slate-900">
                        {validationResults.map((res, idx) => (
                            <tr key={idx} className="hover:bg-slate-800/50">
                                <td className="px-4 py-3">
                                    {res.isValid ? (
                                        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400">
                                            <CheckCircle className="w-3 h-3" /> Ready
                                        </span>
                                    ) : (
                                        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-500/10 text-red-400">
                                            <AlertTriangle className="w-3 h-3" /> Error
                                        </span>
                                    )}
                                </td>
                                <td className="px-4 py-3 text-slate-400">{res.row.namespace}</td>
                                <td className="px-4 py-3 font-mono text-slate-200">{res.row.name}</td>
                                <td className="px-4 py-3">
                                    <div className="flex flex-col gap-1">
                                        {res.parsedDomains.slice(0, 2).map(d => (
                                            <span key={d} className="bg-slate-800 px-1.5 py-0.5 rounded text-xs font-mono">{d}</span>
                                        ))}
                                        {res.parsedDomains.length > 2 && (
                                            <span className="text-xs text-slate-500">+{res.parsedDomains.length - 2} more</span>
                                        )}
                                    </div>
                                </td>
                                <td className="px-4 py-3 flex items-center gap-2">
                                  {isIpAddress(res.row.origin || '') ? (
                                    <Network className="w-4 h-4 text-slate-500" />
                                  ) : (
                                    <Server className="w-4 h-4 text-slate-500" />
                                  )}
                                  <span className="font-mono text-slate-300">{res.row.origin}</span>
                                  <span className="text-slate-500 text-xs">:{res.row.port || '443'}</span>
                                </td>
                                <td className="px-4 py-3 font-mono text-xs">
                                   {res.normalizedType || <span className="text-red-400">{res.row.type}</span>}
                                </td>
                                <td className="px-4 py-3">
                                    {res.normalizedType === 'HTTPS_CUSTOM' ? (
                                        <span className={`text-xs ${res.isValid ? 'text-blue-400' : 'text-red-400'}`}>
                                            {res.message}
                                        </span>
                                    ) : (
                                        <span className="text-xs text-slate-500">
                                            {res.isValid ? res.message : res.message}
                                        </span>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
             </div>

             <div className="flex justify-end pt-4">
                <button
                    onClick={executeBulkCreation}
                    disabled={validationResults.some(r => !r.isValid)}
                    className="flex items-center gap-2 bg-violet-600 hover:bg-violet-500 disabled:opacity-50 disabled:cursor-not-allowed text-white px-6 py-3 rounded-lg font-medium shadow-lg shadow-violet-600/20 transition-all"
                >
                    <Play className="w-5 h-5" />
                    Create {validationResults.length} Load Balancers
                </button>
             </div>
          </div>
        )}

        {/* STEP 3 & 4: EXECUTION & REPORT */}
        {(step === 3 || step === 4) && (
            <div className="space-y-6">
                 {isLoading && (
                     <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4 flex items-center gap-3 text-blue-400 animate-pulse mb-4">
                         <Loader2 className="w-5 h-5 animate-spin" />
                         {loadingText}
                     </div>
                 )}

                 <div className="overflow-hidden rounded-lg border border-slate-700">
                    <table className="w-full text-left text-sm text-slate-300">
                        <thead className="bg-slate-800 text-slate-400 uppercase font-medium">
                            <tr>
                                <th className="px-4 py-3">LB Name</th>
                                <th className="px-4 py-3">Status</th>
                                <th className="px-4 py-3">VIP / CNAME</th>
                                <th className="px-4 py-3">Details</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800 bg-slate-900">
                            {creationResults.map((res, idx) => (
                                <tr key={idx}>
                                    <td className="px-4 py-3 font-medium text-slate-200">{res.name}</td>
                                    <td className="px-4 py-3">
                                        {res.status === 'pending' && (
                                            <div className="flex items-center gap-2 text-violet-400">
                                                <Loader2 className="w-4 h-4 animate-spin" />
                                                <span className="text-xs">
                                                    {res.step === 'pool' && 'Pool'}
                                                    {res.step === 'waf' && 'WAF'}
                                                    {res.step === 'lb' && 'LB'}
                                                </span>
                                            </div>
                                        )}
                                        {res.status === 'success' && <CheckCircle className="w-4 h-4 text-emerald-400" />}
                                        {res.status === 'error' && <AlertTriangle className="w-4 h-4 text-red-400" />}
                                    </td>
                                    <td className="px-4 py-3 font-mono text-xs text-slate-400">
                                        {res.cname ? (
                                            <div>
                                                <span className="block text-slate-300">CNAME: {res.cname}</span>
                                                {res.vip && <span className="block text-slate-500">VIP: {res.vip}</span>}
                                            </div>
                                        ) : (
                                            '-'
                                        )}
                                    </td>
                                    <td className="px-4 py-3 text-slate-400 truncate max-w-xs" title={res.details}>
                                        {res.details}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                 </div>

                 {step === 4 && !isLoading && (
                    <div className="flex justify-center pt-6">
                        <button
                            onClick={downloadFinalReport}
                            className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white px-8 py-3 rounded-lg font-bold shadow-lg shadow-emerald-600/20 transition-all transform hover:-translate-y-0.5"
                        >
                            <Download className="w-5 h-5" />
                            Download Final Report
                        </button>
                    </div>
                 )}
            </div>
        )}

      </div>
    </div>
  );
}