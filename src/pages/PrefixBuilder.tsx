import { useState, useRef, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useToast } from '../context/ToastContext';
import { apiClient } from '../services/api';
import { 
  FileText, 
  Upload, 
  Plus, 
  Shield, 
  AlertCircle, 
  CheckCircle2, 
  Loader2,
  Trash2,
  List,
  Check,
  XCircle,
  ArrowLeft,
  Layers,
  Split,
  Tag,
  AlertTriangle,
  Lock,
  HelpCircle
} from 'lucide-react';
import type { ServicePolicy } from '../types';

interface ParsedIP {
  ip: string;
  isValid: boolean;
  type: 'v4' | 'v6' | 'invalid';
}

interface Label {
  key: string;
  value: string;
}

interface CreatedObjectDetail {
  name: string;
  count: number;
}

interface CreationResult {
  success: boolean;
  mode: 'SINGLE' | 'MULTI';
  createdObjects: CreatedObjectDetail[];
  namespace: string;
  totalIPs: number;
  policyName?: string;
  action?: 'ALLOW' | 'DENY';
}

type Mode = 'SINGLE' | 'MULTI';

const MAX_IPS_PER_SET = 1024;
const MANDATORY_LABEL_KEY = 'ips-list-name';

export function PrefixBuilder() {
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  
  // Progress & Result State
  const [progress, setProgress] = useState(0);
  const [currentAction, setCurrentAction] = useState('');
  const [result, setResult] = useState<CreationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Configuration State
  const [mode, setMode] = useState<Mode>('SINGLE');
  const [namespaces, setNamespaces] = useState<string[]>([]);
  
  // IP Prefix Set Config
  const [namespace, setNamespace] = useState('');
  const [baseName, setBaseName] = useState('');
  const [description, setDescription] = useState('');
  const [labels, setLabels] = useState<Label[]>([{ key: MANDATORY_LABEL_KEY, value: '' }]);
  
  // Input State
  const [rawInput, setRawInput] = useState('');
  const [parsedIPs, setParsedIPs] = useState<ParsedIP[]>([]);
  
  // Policy Attachment State
  const [attachToPolicy, setAttachToPolicy] = useState(false);
  const [policyNamespace, setPolicyNamespace] = useState(''); // Separate namespace for policy
  const [createPolicyMode, setCreatePolicyMode] = useState(false); // Toggle for create vs existing
  
  // Existing Policy State
  const [policies, setPolicies] = useState<any[]>([]); // Changed to any[] to handle list vs detail view differences
  const [isLoadingPolicies, setIsLoadingPolicies] = useState(false);
  const [selectedPolicyId, setSelectedPolicyId] = useState('');
  
  // New Policy State
  const [newPolicyName, setNewPolicyName] = useState('');
  const [ruleAction, setRuleAction] = useState<'ALLOW' | 'DENY'>('DENY');
  
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Regex Helpers
  const IPV4_CIDR_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:3[0-2]|[12]?[0-9]))?$/;
  const IPV6_REGEX = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/;

  // --- Effects ---

  // 1. Auto-Switch Mode based on IP Count
  useEffect(() => {
    const validCount = parsedIPs.filter(p => p.isValid).length;
    if (validCount > MAX_IPS_PER_SET && mode === 'SINGLE') {
      setMode('MULTI');
      toast.info(`Auto-switched to Auto-Split mode (${validCount} IPs > ${MAX_IPS_PER_SET})`);
    }
  }, [parsedIPs]);

  // 2. Load Namespaces
  useEffect(() => {
    const loadNamespaces = async () => {
      try {
        const res = await apiClient.getNamespaces();
        const items = res.items?.map(n => n.name).sort() || [];
        setNamespaces(items);
      } catch (err) {
        console.error('Failed to load namespaces', err);
        toast.error('Failed to fetch namespaces. Check connection.');
      }
    };
    loadNamespaces();
  }, []);

  // 3. Load Policies when Policy Namespace changes
  useEffect(() => {
    const fetchPolicies = async () => {
      if (!policyNamespace || createPolicyMode) {
        setPolicies([]);
        return;
      }
      
      setIsLoadingPolicies(true);
      try {
        const res = await apiClient.getServicePolicies(policyNamespace);
        setPolicies(res.items || []);
        setSelectedPolicyId('');
      } catch (err) {
        console.error('Failed to fetch policies', err);
        setPolicies([]);
        toast.error(`Failed to fetch policies for ${policyNamespace}: ${(err as Error).message}`);
      } finally {
        setIsLoadingPolicies(false);
      }
    };
    fetchPolicies();
  }, [policyNamespace, createPolicyMode]);

  // --- Handlers ---

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setRawInput(text);
      parseIPs(text);
    };
    reader.readAsText(file);
  };

  const parseIPs = (input: string) => {
    const tokens = input.split(/[\s,]+/).filter(t => t.trim().length > 0);
    const parsed = tokens.map(token => {
      const clean = token.trim();
      let type: ParsedIP['type'] = 'invalid';
      if (IPV4_CIDR_REGEX.test(clean)) type = 'v4';
      else if (IPV6_REGEX.test(clean)) type = 'v6';
      return { ip: clean, isValid: type !== 'invalid', type };
    });
    setParsedIPs(parsed);
  };

  const handleInputChange = (val: string) => {
    setRawInput(val);
    parseIPs(val);
  };

  const clearInput = () => {
    setRawInput('');
    setParsedIPs([]);
    if (fileInputRef.current) fileInputRef.current.value = '';
    setResult(null);
    setError(null);
  };

  const resetForm = () => {
    setBaseName('');
    setDescription('');
    setLabels([{ key: MANDATORY_LABEL_KEY, value: '' }]); 
    setResult(null);
    setError(null);
    clearInput();
    setProgress(0);
    setCurrentAction('');
    setNewPolicyName('');
  };

  const addLabel = () => setLabels([...labels, { key: '', value: '' }]);
  const removeLabel = (idx: number) => {
    if (labels[idx].key === MANDATORY_LABEL_KEY) return;
    setLabels(labels.filter((_, i) => i !== idx));
  };
  const updateLabel = (idx: number, field: 'key' | 'value', val: string) => {
    if (labels[idx].key === MANDATORY_LABEL_KEY && field === 'key') return;
    const newLabels = [...labels];
    newLabels[idx][field] = val;
    setLabels(newLabels);
  };

  const handleSubmit = async () => {
    if (!baseName) {
      toast.error('Object Name/Prefix is required');
      return;
    }
    
    if (!namespace) {
      toast.error('Please select a Namespace for the IP Prefix Set');
      return;
    }

    if (attachToPolicy) {
      if (!policyNamespace) {
        toast.error('Please select a Namespace for the Service Policy');
        return;
      }
      if (createPolicyMode && !newPolicyName) {
         toast.error('New Policy Name is required');
         return;
      }
      if (!createPolicyMode && !selectedPolicyId) {
        toast.error('Please select a Service Policy to attach to');
        return;
      }
    }

    const missingLabel = labels.some(l => !l.key.trim() || !l.value.trim());
    if (missingLabel) {
      toast.error('All labels must have both a key and a value');
      return;
    }

    const validIPs = parsedIPs.filter(p => p.isValid);
    if (validIPs.length === 0) {
      toast.error('No valid IPs found to process');
      return;
    }

    if (mode === 'SINGLE' && validIPs.length > MAX_IPS_PER_SET) {
      if (!confirm(`Warning: You have ${validIPs.length} IPs, but the limit for a single object is ${MAX_IPS_PER_SET}. This operation might fail. Proceed?`)) {
        return;
      }
    }

    setLoading(true);
    setProgress(0);
    setResult(null);
    setError(null);
    setCurrentAction('Initializing...');

    const createdObjectDetails: CreatedObjectDetail[] = [];
    const createdObjectNames: string[] = [];

    try {
      // 1. Create IP Prefix Sets
      let chunks: ParsedIP[][] = [];
      if (mode === 'SINGLE') {
        chunks = [validIPs];
      } else {
        for (let i = 0; i < validIPs.length; i += MAX_IPS_PER_SET) {
          chunks.push(validIPs.slice(i, i + MAX_IPS_PER_SET));
        }
      }

      const totalChunks = chunks.length;
      const labelMap = labels.reduce((acc, l) => ({ ...acc, [l.key]: l.value }), {});

      for (let i = 0; i < totalChunks; i++) {
        const chunk = chunks[i];
        const suffix = mode === 'MULTI' ? `-${i + 1}` : '';
        const objectName = `${baseName}${suffix}`;
        
        setCurrentAction(`Creating ${objectName} (${i + 1}/${totalChunks})...`);
        const percent = Math.round(((i + 1) / totalChunks) * 80); 
        setProgress(percent);

        const payload = {
          metadata: {
            name: objectName,
            namespace,
            description: mode === 'MULTI' ? `${description} [Part ${i+1}/${totalChunks}]` : description,
            labels: labelMap,
            disable: false
          },
          spec: {
            ipv4_prefixes: chunk.filter(p => p.type === 'v4').map(p => ({ ipv4_prefix: p.ip })),
            ipv6_prefixes: chunk.filter(p => p.type === 'v6').map(p => ({ ipv6_prefix: p.ip }))
          }
        };

        try {
          await apiClient.createIpPrefixSet(namespace, payload);
          createdObjectNames.push(objectName);
          createdObjectDetails.push({ name: objectName, count: chunk.length });
        } catch (objError) {
          throw new Error(`Failed to create object '${objectName}': ${(objError as Error).message}`);
        }
      }

      toast.success(`${createdObjectNames.length} IP Prefix Set(s) created.`);

      // 2. Handle Service Policy (Attach Existing or Create New)
      let finalPolicyName = undefined;
      
      if (attachToPolicy) {
        setProgress(90);
        
        if (createPolicyMode) {
          setCurrentAction(`Creating new Service Policy "${newPolicyName}"...`);
          try {
            await createNewServicePolicy(createdObjectNames);
            finalPolicyName = newPolicyName;
          } catch (polError) {
             throw new Error(`Failed to create policy '${newPolicyName}': ${(polError as Error).message}`);
          }
        } else {
          // Check policies array to find the full name in metadata if it exists there, 
          // OR fallback to the list view property 'name'
          const policy = policies.find(p => (p.metadata?.name || p.name) === selectedPolicyId);
          
          if (policy) {
            // Need the full name which might be in metadata.name or name property
            const policyRealName = policy.metadata?.name || policy.name;
            
            setCurrentAction(`Attaching to Service Policy "${policyRealName}"...`);
            
            try {
              // We pass policyRealName because the helper function will re-fetch the full object
              await attachToExistingServicePolicy(policyRealName, createdObjectNames);
              finalPolicyName = policyRealName;
            } catch (attError) {
               throw new Error(`Failed to update policy '${policyRealName}': ${(attError as Error).message}`);
            }
          }
        }
      }

      setProgress(100);
      setCurrentAction('Completed successfully!');
      
      setResult({
        success: true,
        mode,
        createdObjects: createdObjectDetails,
        namespace,
        totalIPs: validIPs.length,
        policyName: finalPolicyName,
        action: ruleAction
      });

    } catch (err) {
      setError((err as Error).message || 'An unknown error occurred.');
      setCurrentAction('Failed.');
      setProgress(0);
    } finally {
      setLoading(false);
    }
  };

  const createNewServicePolicy = async (prefixSetNames: string[]) => {
    const prefixSetRefs = prefixSetNames.map(name => ({
      name: name,
      namespace: namespace
    }));

    const newRule = {
      metadata: {
        name: `rule-${baseName}-initial`,
        description: `Initial rule for ${baseName}`
      },
      spec: {
        action: ruleAction,
        waf_action: { none: {} },
        ip_matcher: {
          prefix_sets: prefixSetRefs
        }
      }
    };

    const payload = {
      metadata: {
        name: newPolicyName,
        namespace: policyNamespace,
        description: `Created via Prefix Builder for ${baseName}`,
        disable: false
      },
      spec: {
        algo: "FIRST_MATCH",
        rule_list: {
          rules: [newRule]
        }
      }
    };

    await apiClient.createServicePolicy(policyNamespace, payload);
  };

  const attachToExistingServicePolicy = async (policyName: string, prefixSetNames: string[]) => {
    // Fetch FULL policy details since list view doesn't have 'spec'
    const fullPolicy = await apiClient.getServicePolicy(policyNamespace, policyName) as ServicePolicy;
    
    const prefixSetRefs = prefixSetNames.map(name => ({
      name: name,
      namespace: namespace
    }));

    const newRule = {
      metadata: {
        name: `rule-${baseName}-${Date.now()}`,
        description: `Auto-generated rule for ${baseName} (${prefixSetNames.length} sets)`
      },
      spec: {
        action: ruleAction,
        waf_action: { none: {} },
        ip_matcher: {
          prefix_sets: prefixSetRefs 
        }
      }
    };

    const spec: any = { ...fullPolicy.spec };
    
    // Extract existing rules safely
    let existingRules: any[] = [];
    if (spec.rule_list && spec.rule_list.rules) {
      existingRules = spec.rule_list.rules;
    } else if (Array.isArray(spec.rules)) {
      existingRules = spec.rules;
    }

    if (spec.legacy_rule_list && existingRules.length === 0) {
       toast.warning('Warning: Policy uses legacy rules. Cannot append inline rule.');
       return;
    }

    const finalRules = [newRule, ...existingRules];

    // Clean up spec to enforce rule_list OneOf choice
    // This removes conflicting fields like 'deny_list' if they exist
    delete spec.rules;
    delete spec.deny_all_requests;
    delete spec.allow_all_requests;
    delete spec.simple_rules; 
    delete spec.deny_list; 
    delete spec.allow_list;
    delete spec.legacy_rule_list;

    spec.rule_list = {
      rules: finalRules
    };

    await apiClient.updateServicePolicy(policyNamespace, fullPolicy.metadata!.name, {
      metadata: fullPolicy.metadata,
      spec: spec
    });
  };

  const validCount = parsedIPs.filter(p => p.isValid).length;
  const invalidCount = parsedIPs.length - validCount;
  const isAutoSwitched = validCount > MAX_IPS_PER_SET && mode === 'MULTI';

  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="mb-6">
        <Link to="/" className="inline-flex items-center text-slate-400 hover:text-white transition-colors group">
          <ArrowLeft className="w-4 h-4 mr-2 group-hover:-translate-x-1 transition-transform" />
          Back to Home
        </Link>
      </div>

      <div className="mb-8">
        <div className="flex items-center gap-4">
          <h1 className="text-3xl font-bold text-slate-100 flex items-center gap-3">
            <Layers className="w-8 h-8 text-blue-400" />
            Prefix Builder
          </h1>
          <Link to="/explainer/prefix-builder" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
            <HelpCircle className="w-3.5 h-3.5" /> How does this work?
          </Link>
        </div>
        <p className="text-slate-400 mt-2">
          Create IP Prefix Sets and optionally create or update Service Policies.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* LEFT COLUMN: Controls */}
        <div className="lg:col-span-5 space-y-6">
          
          {/* Result Card */}
          {result && (
            <div className="bg-emerald-900/20 border border-emerald-500/50 rounded-xl p-6 animate-slide-in">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-full bg-emerald-500/20 flex items-center justify-center">
                  <Check className="w-6 h-6 text-emerald-400" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-emerald-400">Creation Successful</h3>
                  <p className="text-xs text-emerald-300/70">
                    {result.createdObjects.length} object(s) pushed to F5 XC
                  </p>
                </div>
              </div>
              
              <div className="space-y-3 text-sm text-slate-300">
                <div className="flex justify-between border-b border-emerald-500/20 pb-2">
                  <span className="text-slate-400">Total IPs:</span>
                  <span className="font-mono text-white">{result.totalIPs}</span>
                </div>
                <div className="flex justify-between border-b border-emerald-500/20 pb-2">
                  <span className="text-slate-400">Object Namespace:</span>
                  <span className="font-mono text-white">{result.namespace}</span>
                </div>
                <div className="border-b border-emerald-500/20 pb-2">
                  <span className="text-slate-400 block mb-2">Created Objects:</span>
                  <div className="max-h-32 overflow-y-auto space-y-1 pr-1 custom-scrollbar">
                    {result.createdObjects.map(obj => (
                       <div key={obj.name} className="flex justify-between items-center font-mono text-xs text-emerald-300 bg-emerald-950/40 px-3 py-2 rounded border border-emerald-500/10">
                         <span>{obj.name}</span>
                         <span className="text-emerald-400/60 bg-emerald-900/30 px-1.5 py-0.5 rounded text-[10px]">{obj.count} IPs</span>
                       </div>
                    ))}
                  </div>
                </div>
                {result.policyName && (
                   <div className="flex justify-between pt-1">
                    <span className="text-slate-400">Attached To:</span>
                    <span className="font-mono text-white truncate max-w-[180px]" title={result.policyName}>
                      {result.policyName}
                    </span>
                  </div>
                )}
              </div>

              <button 
                onClick={resetForm}
                className="mt-6 w-full flex items-center justify-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white py-2 rounded-lg transition-colors text-sm font-medium"
              >
                <Plus className="w-4 h-4" /> Start Over
              </button>
            </div>
          )}

          {/* Error Card */}
          {error && (
            <div className="bg-red-900/20 border border-red-500/50 rounded-xl p-6 animate-slide-in">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-full bg-red-500/20 flex items-center justify-center">
                  <XCircle className="w-6 h-6 text-red-400" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-red-400">Creation Failed</h3>
                  <p className="text-xs text-red-300/70">The operation could not be completed</p>
                </div>
              </div>
              
              <div className="p-4 bg-red-950/30 rounded-lg border border-red-900/50 mb-6">
                <p className="font-mono text-sm text-red-200 break-all">{error}</p>
              </div>

              <button 
                onClick={() => setError(null)}
                className="w-full flex items-center justify-center gap-2 bg-red-600 hover:bg-red-500 text-white py-2 rounded-lg transition-colors text-sm font-medium"
              >
                <ArrowLeft className="w-4 h-4" /> Go Back & Fix
              </button>
            </div>
          )}

          {/* MAIN FORM */}
          {!result && !error && (
          <>
            <div className="grid grid-cols-2 gap-4">
              <button
                onClick={() => setMode('SINGLE')}
                className={`p-4 rounded-xl border flex flex-col items-center gap-2 transition-all ${
                  mode === 'SINGLE' 
                    ? 'bg-blue-600/10 border-blue-500 text-blue-400' 
                    : 'bg-slate-800/50 border-slate-700 text-slate-400 hover:bg-slate-800'
                }`}
              >
                <FileText className="w-6 h-6" />
                <span className="text-sm font-medium">Single Object</span>
              </button>
              <button
                onClick={() => setMode('MULTI')}
                className={`p-4 rounded-xl border flex flex-col items-center gap-2 transition-all ${
                  mode === 'MULTI' 
                    ? 'bg-blue-600/10 border-blue-500 text-blue-400' 
                    : 'bg-slate-800/50 border-slate-700 text-slate-400 hover:bg-slate-800'
                }`}
              >
                <Split className="w-6 h-6" />
                <span className="text-sm font-medium">Auto-Split List</span>
              </button>
            </div>

            {isAutoSwitched && (
              <div className="bg-blue-900/20 border border-blue-500/30 p-3 rounded-lg flex items-start gap-3 animate-slide-in">
                <AlertTriangle className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
                <div className="text-xs text-blue-200">
                  <span className="font-bold">Mode Auto-Switched:</span> You have {validCount} IPs. 
                  Since this exceeds the 1024 limit, we automatically enabled Auto-Split mode for you.
                </div>
              </div>
            )}

            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <h2 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
                <List className="w-5 h-5 text-blue-400" />
                Input IPs
              </h2>
              
              <div className="space-y-4">
                <div className="relative">
                  <textarea
                    value={rawInput}
                    onChange={(e) => handleInputChange(e.target.value)}
                    className="w-full h-32 bg-slate-900 border border-slate-700 rounded-lg p-3 text-slate-300 font-mono text-xs focus:ring-2 focus:ring-blue-500 outline-none resize-none"
                    placeholder="192.168.1.0/24&#10;10.0.0.1"
                  />
                  {rawInput && (
                     <button onClick={clearInput} className="absolute top-2 right-2 p-1 text-slate-500 hover:text-slate-300 bg-slate-800 rounded">
                       <Trash2 className="w-4 h-4" />
                     </button>
                   )}
                </div>

                <div 
                  onClick={() => fileInputRef.current?.click()}
                  className="border-2 border-dashed border-slate-700 rounded-lg p-3 flex flex-col items-center justify-center cursor-pointer hover:border-blue-500 hover:bg-slate-800/50 transition-all group"
                >
                  <div className="flex items-center gap-2 text-slate-500 group-hover:text-blue-400">
                    <Upload className="w-4 h-4" />
                    <span className="text-sm">Upload .txt or .csv</span>
                  </div>
                  <input 
                    ref={fileInputRef}
                    type="file" 
                    accept=".txt,.csv"
                    className="hidden"
                    onChange={handleFileUpload}
                  />
                </div>
              </div>
            </div>

            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <h2 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
                <Shield className="w-5 h-5 text-blue-400" />
                Configuration
              </h2>
              
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">Prefix Set Namespace</label>
                    <select
                      value={namespace}
                      onChange={(e) => setNamespace(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-200 text-sm"
                    >
                      <option value="">-- Select Namespace --</option>
                      {namespaces.map((ns) => (
                        <option key={ns} value={ns}>{ns}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">
                      {mode === 'MULTI' ? 'Base Name Prefix' : 'Object Name'}
                    </label>
                    <input
                      type="text"
                      value={baseName}
                      onChange={(e) => setBaseName(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-200 text-sm"
                      placeholder={mode === 'MULTI' ? "e.g. blocklist" : "e.g. my-list"}
                    />
                  </div>
                </div>

                <div className="border-t border-slate-700 pt-4">
                  <label className="block text-xs font-medium text-slate-400 mb-2 flex items-center gap-2">
                    <Tag className="w-3 h-3" /> Labels (Required)
                  </label>
                  
                  <div className="space-y-2 mb-2">
                    {labels.map((label, idx) => (
                      <div key={idx} className="flex gap-2">
                        <div className="flex-1 relative">
                          <input
                            placeholder="Key"
                            value={label.key}
                            onChange={(e) => updateLabel(idx, 'key', e.target.value)}
                            readOnly={label.key === MANDATORY_LABEL_KEY}
                            className={`w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 ${label.key === MANDATORY_LABEL_KEY ? 'opacity-70 cursor-not-allowed pl-8' : ''}`}
                          />
                          {label.key === MANDATORY_LABEL_KEY && (
                            <Lock className="w-3 h-3 text-slate-500 absolute left-2 top-2.5" />
                          )}
                        </div>
                        <input
                          placeholder="Value"
                          value={label.value}
                          onChange={(e) => updateLabel(idx, 'value', e.target.value)}
                          className="flex-1 bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-slate-200"
                        />
                        <button 
                          onClick={() => removeLabel(idx)} 
                          disabled={label.key === MANDATORY_LABEL_KEY}
                          className={`text-slate-500 ${label.key === MANDATORY_LABEL_KEY ? 'opacity-30 cursor-not-allowed' : 'hover:text-red-400'}`}
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                  <button onClick={addLabel} className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1">
                    <Plus className="w-3 h-3" /> Add Label
                  </button>
                </div>

                <div className="border-t border-slate-700 pt-4">
                  <label className="flex items-center gap-2 cursor-pointer mb-4">
                    <input 
                      type="checkbox" 
                      checked={attachToPolicy} 
                      onChange={(e) => setAttachToPolicy(e.target.checked)}
                      className="rounded border-slate-700 bg-slate-900 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-sm font-medium text-slate-200">Configure Service Policy</span>
                  </label>

                  {attachToPolicy && (
                    <div className="bg-slate-900/50 rounded-lg p-4 space-y-4 border border-slate-700">
                      
                      <div>
                        <label className="block text-xs font-medium text-slate-400 mb-1">Policy Namespace</label>
                        <select
                          value={policyNamespace}
                          onChange={(e) => setPolicyNamespace(e.target.value)}
                          className="w-full bg-slate-800 border border-slate-600 rounded-lg p-2 text-slate-200 text-sm"
                        >
                          <option value="">-- Select Namespace --</option>
                          {namespaces.map((ns) => (
                            <option key={ns} value={ns}>{ns}</option>
                          ))}
                        </select>
                      </div>

                      <div className="flex bg-slate-800 p-1 rounded-lg">
                        <button
                          onClick={() => setCreatePolicyMode(false)}
                          className={`flex-1 py-1.5 px-3 rounded text-xs font-medium transition-all ${!createPolicyMode ? 'bg-blue-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'}`}
                        >
                          Attach to Existing
                        </button>
                        <button
                          onClick={() => setCreatePolicyMode(true)}
                          className={`flex-1 py-1.5 px-3 rounded text-xs font-medium transition-all ${createPolicyMode ? 'bg-blue-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'}`}
                        >
                          Create New Policy
                        </button>
                      </div>

                      {createPolicyMode ? (
                        <div className="space-y-3 animate-fade-in">
                          <div>
                            <label className="block text-xs font-medium text-slate-400 mb-1">New Policy Name</label>
                            <input
                              type="text"
                              value={newPolicyName}
                              onChange={(e) => setNewPolicyName(e.target.value)}
                              className="w-full bg-slate-800 border border-slate-600 rounded-lg p-2 text-slate-200 text-sm"
                              placeholder="e.g. block-bad-actors"
                            />
                          </div>
                          
                          <div>
                            <label className="block text-xs font-medium text-slate-400 mb-1">Add Created IPs To:</label>
                            <div className="grid grid-cols-2 gap-3">
                              <label className={`cursor-pointer border rounded-lg p-3 flex flex-col items-center gap-1 transition-all ${ruleAction === 'ALLOW' ? 'bg-green-900/20 border-green-500/50 text-green-400' : 'bg-slate-800 border-slate-600 text-slate-400 opacity-60 hover:opacity-100'}`}>
                                <input type="radio" name="newPolicyType" value="ALLOW" checked={ruleAction === 'ALLOW'} onChange={() => setRuleAction('ALLOW')} className="hidden" />
                                <CheckCircle2 className="w-5 h-5" />
                                <span className="text-xs font-bold">Allowed Sources</span>
                              </label>
                              <label className={`cursor-pointer border rounded-lg p-3 flex flex-col items-center gap-1 transition-all ${ruleAction === 'DENY' ? 'bg-red-900/20 border-red-500/50 text-red-400' : 'bg-slate-800 border-slate-600 text-slate-400 opacity-60 hover:opacity-100'}`}>
                                <input type="radio" name="newPolicyType" value="DENY" checked={ruleAction === 'DENY'} onChange={() => setRuleAction('DENY')} className="hidden" />
                                <XCircle className="w-5 h-5" />
                                <span className="text-xs font-bold">Denied Sources</span>
                              </label>
                            </div>
                          </div>
                        </div>
                      ) : (
                        <div className="space-y-3 animate-fade-in">
                          <div>
                            <label className="block text-xs font-medium text-slate-400 mb-1 flex justify-between">
                              Select Policy
                              {isLoadingPolicies && <span className="flex items-center gap-1 text-blue-400"><Loader2 className="w-3 h-3 animate-spin"/> Loading...</span>}
                            </label>
                            <select
                              value={selectedPolicyId}
                              onChange={(e) => setSelectedPolicyId(e.target.value)}
                              disabled={!policyNamespace || isLoadingPolicies}
                              className="w-full bg-slate-800 border border-slate-600 rounded-lg p-2 text-slate-200 text-sm disabled:opacity-50"
                            >
                              <option value="">{isLoadingPolicies ? 'Loading policies...' : '-- Select Policy --'}</option>
                              {policies.map(p => {
                                // Use name from list root, falling back to metadata.name
                                const name = p.name || p.metadata?.name;
                                return (
                                  <option key={name} value={name}>{name}</option>
                                );
                              })}
                            </select>
                            {!policyNamespace && <p className="text-[10px] text-yellow-500/80 mt-1">Select policy namespace first</p>}
                          </div>
                          <div className="flex gap-4">
                            <label className="flex items-center gap-2 cursor-pointer">
                              <input 
                                type="radio" name="action" value="DENY"
                                checked={ruleAction === 'DENY'} onChange={() => setRuleAction('DENY')}
                                className="text-red-500 bg-slate-800 border-slate-600"
                              />
                              <span className="text-sm text-red-400">Deny</span>
                            </label>
                            <label className="flex items-center gap-2 cursor-pointer">
                              <input 
                                type="radio" name="action" value="ALLOW"
                                checked={ruleAction === 'ALLOW'} onChange={() => setRuleAction('ALLOW')}
                                className="text-green-500 bg-slate-800 border-slate-600"
                              />
                              <span className="text-sm text-green-400">Allow</span>
                            </label>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
                
                <div className="mt-6 space-y-3">
                  {loading && (
                    <div className="space-y-1">
                      <div className="flex justify-between text-xs text-slate-400">
                         <span>{currentAction}</span>
                         <span>{progress}%</span>
                      </div>
                      <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-blue-500 transition-all duration-300 ease-out"
                          style={{ width: `${progress}%` }}
                        />
                      </div>
                    </div>
                  )}

                  <button
                    onClick={handleSubmit}
                    disabled={loading || parsedIPs.filter(p => p.isValid).length === 0}
                    className="w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-500 text-white font-medium py-3 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Plus className="w-5 h-5" />}
                    {loading ? 'Processing...' : `Create ${mode === 'MULTI' ? 'Objects' : 'Object'}`}
                  </button>
                </div>
              </div>
            </div>
          </>
          )}
        </div>

        {/* RIGHT COLUMN: Preview */}
        <div className="lg:col-span-7 h-full">
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 h-full flex flex-col max-h-[calc(100vh-120px)]">
            <h2 className="text-xl font-semibold text-slate-100 mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <List className="w-5 h-5 text-blue-400" />
                <span>Preview</span>
              </div>
              <div className="flex gap-2">
                {invalidCount > 0 && (
                   <span className="text-xs font-medium px-2 py-1 bg-red-900/30 text-red-400 border border-red-900/50 rounded-full">
                    {invalidCount} Invalid
                  </span>
                )}
                <span className="text-xs font-medium px-2 py-1 bg-green-900/30 text-green-400 border border-green-900/50 rounded-full">
                  {validCount} Valid IPs
                </span>
              </div>
            </h2>
            
            {mode === 'MULTI' && validCount > MAX_IPS_PER_SET && (
              <div className="mb-4 p-3 bg-blue-900/20 border border-blue-500/30 rounded-lg flex items-start gap-3">
                <Split className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm text-blue-200">Auto-Split Active</p>
                  <p className="text-xs text-blue-300/70 mt-1">
                    Your {validCount} IPs will be split into <strong>{Math.ceil(validCount / MAX_IPS_PER_SET)}</strong> objects (Prefix Sets), named 
                    <span className="font-mono bg-blue-950 px-1 mx-1 rounded">{baseName || 'name'}-1</span> through 
                    <span className="font-mono bg-blue-950 px-1 mx-1 rounded">{baseName || 'name'}-{Math.ceil(validCount / MAX_IPS_PER_SET)}</span>.
                  </p>
                </div>
              </div>
            )}

            <div className="flex-1 overflow-y-auto bg-slate-900 rounded-lg p-3 border border-slate-700">
               {parsedIPs.length === 0 ? (
                 <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-3">
                   <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center">
                     <List className="w-6 h-6 opacity-50" />
                   </div>
                   <p className="text-sm">Waiting for input...</p>
                 </div>
               ) : (
                 <div className="grid grid-cols-1 xl:grid-cols-2 gap-2">
                   {parsedIPs.map((item, idx) => (
                     <div 
                       key={idx} 
                       className={`flex items-center justify-between p-2 rounded text-xs font-mono border ${
                         item.isValid 
                           ? 'bg-slate-800 text-slate-300 border-slate-700' 
                           : 'bg-red-900/10 text-red-400 border-red-900/30'
                       }`}
                     >
                       <div className="flex items-center gap-2 overflow-hidden">
                         {item.isValid ? (
                           <CheckCircle2 className="w-3 h-3 text-green-500 flex-shrink-0" />
                         ) : (
                           <AlertCircle className="w-3 h-3 text-red-500 flex-shrink-0" />
                         )}
                         <span className="truncate">{item.ip}</span>
                       </div>
                       <div className="flex items-center gap-2">
                         {mode === 'MULTI' && item.isValid && (
                           <span className="text-[9px] px-1 py-0.5 rounded bg-slate-700 text-slate-400">
                             Set {Math.floor(idx / MAX_IPS_PER_SET) + 1}
                           </span>
                         )}
                         <span className={`text-[9px] uppercase px-1.5 py-0.5 rounded ${
                           item.isValid ? 'bg-slate-700 text-slate-400' : 'bg-red-900/20 text-red-400'
                         }`}>
                           {item.type}
                         </span>
                       </div>
                     </div>
                   ))}
                 </div>
               )}
            </div>
            
            <p className="text-xs text-slate-500 mt-3 text-right">
              Showing {parsedIPs.length} entries
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}