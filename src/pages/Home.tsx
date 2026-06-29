import { useState, useCallback } from 'react';
import {
  Globe,
  Grid3X3,
  RefreshCcw,
  Shield,
  User,
  AlertTriangle,
  Search,
  Download,
  Save,
  Layout,
  Clock,
  Eye,
  Activity,
  Lock,
  ChevronRight,
  Copy,
  Layers,
  Split,
  Hammer,
  Gauge,
  ShieldAlert,
  Database,
  GitBranch,
  BarChart2,
  Zap,
  Pin,
  EyeOff,
  GitCompare,
  Swords,
} from 'lucide-react';
import { ConnectionPanel } from '../components/ConnectionPanel';
import { ToolCard } from '../components/ToolCard';
import { useApp } from '../context/AppContext';

const PINNED_STORAGE_KEY = 'xc-app-store:pinned-tools';

const tools = [
  {
    name: 'API Shield Advisor',
    description: 'Guided API security assessment. Scans your F5 XC config, discovers APIs, profiles traffic, and walks you through enabling 90+ security controls with data-driven recommendations.',
    icon: Shield,
    to: '/api-shield',
    tags: [
      { label: 'Analyze', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'Live SOC Room',
    description: 'Real-time security operations center. Continuously monitors F5 XC with 23 anomaly detectors, 12 auto-investigation workflows, and live dashboards.',
    icon: Activity,
    to: '/soc-lobby',
    tags: [
      { label: 'Live Monitor', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'FP Analyzer',
    description: 'Analyze WAF security events to detect false positives. Reviews signatures, violations, and threat intel with 7-signal scoring.',
    icon: ShieldAlert,
    to: '/fp-analyzer',
    tags: [
      { label: 'Analyze', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'Config Dump',
    description: 'Export full configuration for any object type with all child objects. Download as JSON or PDF.',
    icon: Database,
    to: '/config-dump',
    tags: [
      { label: 'Export', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'API Discovery Report Dashboard',
    description: 'High-level API Discovery overview, raw schema downloads, and per-LB schema detail with Excel & PDF export across multiple load balancers.',
    icon: BarChart2,
    to: '/api-report',
    tags: [
      { label: 'Analyze', type: 'report' as const },
      { label: 'Export', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'DDoS Settings Advisor',
    description: 'Analyze traffic patterns to find peak RPS and recommend tuned L7 DDoS protection settings for optimal security hardening.',
    icon: Shield,
    to: '/ddos-advisor',
    tags: [
      { label: 'Analyze', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'Rate Limit Advisor',
    description: 'Analyze 7 days of traffic to find safe rate limits. Combines access logs with security events for data-driven recommendations.',
    icon: Gauge,
    to: '/rate-limit-advisor',
    tags: [
      { label: 'Analyze', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'Config Viewer',
    description: 'Interactive map of Load Balancer dependencies and configuration settings.',
    icon: Grid3X3,
    to: '/config-visualizer',
    tags: [
      { label: 'Visualize', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'Dependency Map',
    description: 'Interactive relationship map of all config objects. Graph, table, tree, and matrix views.',
    icon: GitBranch,
    to: '/config-explorer',
    tags: [
      { label: 'Visualize', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'Config Comparator',
    description: 'Compare configurations across namespaces or tenants. Detect drift and validate migrations.',
    icon: Split,
    to: '/config-comparator',
    tags: [
      { label: 'Audit', type: 'report' as const },
      { label: 'Cross-Tenant', type: 'update' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'HTTP Sanity Checker',
    description: 'Smart comparison (headers, fuzzy body match) between Live (Akamai) vs Spoof (F5).',
    icon: Activity,
    to: '/http-sanity-checker',
    tags: [
      { label: 'Audit', type: 'report' as const },
      { label: 'Standalone', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
    standalone: true,
  },
  {
    name: 'Prefix Builder',
    description: 'Build IP prefix sets in bulk for firewall and routing rules.',
    icon: Grid3X3,
    to: '/prefix-builder',
    tags: [{ label: 'Create', type: 'create' as const }],
    disabled: false,
    badge: 'New',
  },
  {
    name: 'WAF Status Scanner',
    description: 'Audit WAF modes, exclusion rules, and security status across all load balancers.',
    icon: Search,
    to: '/waf-scanner',
    tags: [
      { label: 'Report', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'Start Here',
    featured: true,
  },
  {
    name: 'Copy Config',
    description: 'Copy configuration objects across tenants or namespaces. Supports Alert Receivers and Policies.',
    icon: Copy,
    to: '/copy-config',
    tags: [
      { label: 'Create', type: 'create' as const },
      { label: 'Cross-Tenant', type: 'update' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'Security Auditor',
    description: 'Comprehensive security posture assessment against 30+ best practice rules.',
    icon: Shield,
    to: '/security-auditor',
    tags: [
      { label: 'Audit', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'WAF Attack Simulator',
    description: 'Fire OWASP WAF & API Top 10 attack signatures at an endpoint, then reconcile XC logs to see what was blocked vs. reached origin.',
    icon: Swords,
    to: '/waf-attack-simulator',
    tags: [
      { label: 'Active Test', type: 'update' as const },
      { label: 'WAF', type: 'report' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'Property Viewer',
    description: 'View any property across all config objects — compare domains, WAF modes, timeouts & more at a glance.',
    icon: Layers,
    to: '/property-viewer',
    tags: [
      { label: 'Report', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'HTTP LB Forge',
    description: 'Create multiple HTTP Load Balancers at scale from CSV input.',
    icon: Hammer,
    to: '/http-lb-forge',
    tags: [{ label: 'Create', type: 'create' as const }],
    disabled: false,
    badge: 'New',
    featured: true,
  },
  {
    name: 'Log Analyzer',
    description: 'Analyze access logs with flexible filters. View metrics, distributions, and top values for any field.',
    icon: BarChart2,
    to: '/log-analyzer',
    tags: [
      { label: 'Analyze', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'Load Tester',
    description: 'Stress test any endpoint with configurable RPS, concurrency, and real-time response time metrics.',
    icon: Zap,
    to: '/load-tester',
    tags: [
      { label: 'Testing', type: 'update' as const },
      { label: 'Standalone', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
    standalone: true,
  },
  {
    name: 'Diff Checker',
    description: 'Side-by-side and unified text diff with char-level highlighting, semantic JSON/YAML/XML diff, 3-way merge, ignore patterns, and GitHub PR import. Runs entirely in your browser.',
    icon: GitCompare,
    to: '/diff-checker',
    tags: [
      { label: 'Compare', type: 'report' as const },
      { label: 'Standalone', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
    standalone: true,
  },
  {
    name: 'Anonymizer',
    description: 'Reversible find-and-replace for txt/docx/pptx/xlsx files. Redact customer-identifying content before sharing, restore real values before delivery. Runs entirely in your browser.',
    icon: EyeOff,
    to: '/anonymizer',
    tags: [
      { label: 'Redact', type: 'report' as const },
      { label: 'Standalone', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
    standalone: true,
  },
  {
    name: 'CDN Factory',
    description: 'Spin up CDN distributions en masse with bulk configuration.',
    icon: Globe,
    tags: [{ label: 'Create', type: 'create' as const }],
    disabled: true,
  },
  {
    name: 'Config Sync',
    description: 'Mass update settings across HTTP Load Balancers (HSTS, API Discovery, etc.)',
    icon: RefreshCcw,
    tags: [{ label: 'Update', type: 'update' as const }],
    disabled: true,
  },
  {
    name: 'Policy Pusher',
    description: 'Deploy service policies fleet-wide across load balancers.',
    icon: Shield,
    tags: [{ label: 'Update', type: 'update' as const }],
    disabled: true,
  },
  {
    name: 'Identity Roller',
    description: 'Roll out user identification policies everywhere.',
    icon: User,
    tags: [{ label: 'Update', type: 'update' as const }],
    disabled: true,
  },
  {
    name: 'Threat Toggle',
    description: 'Enable/disable Malicious User Detection across all apps.',
    icon: AlertTriangle,
    tags: [{ label: 'Update', type: 'update' as const }],
    disabled: true,
  },
  {
    name: 'Log Harvester',
    description: 'Extract logs for a given duration for offline analysis.',
    icon: Download,
    tags: [{ label: 'Export', type: 'report' as const }],
    disabled: true,
  },
];

const features = [
  {
    icon: Save,
    title: 'Auto-Backup',
    description: 'Every operation creates a restore point. Roll back with one click if needed.',
  },
  {
    icon: Layout,
    title: 'Before/After Diff',
    description: 'See exactly what changed with side-by-side configuration comparison.',
  },
  {
    icon: Clock,
    title: 'Rate Limiting',
    description: "Smart queue with configurable rate limits. Never hit API throttling.",
  },
  {
    icon: Eye,
    title: 'Dry Run Preview',
    description: 'Preview all changes before execution. Nothing happens until you confirm.',
  },
  {
    icon: Activity,
    title: 'Live Progress',
    description: 'Real-time progress tracking with ETA. Pause and resume anytime.',
  },
  {
    icon: Lock,
    title: 'Secure Proxy',
    description: 'Server-side proxy ensures secure API communication. No CORS issues.',
  },
];

function loadPinned(): Set<string> {
  try {
    const raw = localStorage.getItem(PINNED_STORAGE_KEY);
    return raw ? new Set(JSON.parse(raw) as string[]) : new Set();
  } catch {
    return new Set();
  }
}

export function Home() {
  const { isConnected } = useApp();
  const [pinned, setPinned] = useState<Set<string>>(loadPinned);

  const togglePin = useCallback((name: string) => {
    setPinned(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      try { localStorage.setItem(PINNED_STORAGE_KEY, JSON.stringify([...next])); } catch { /* ignore */ }
      return next;
    });
  }, []);

  const pinnedTools = tools.filter(t => pinned.has(t.name));
  const unpinnedTools = tools.filter(t => !pinned.has(t.name));

  return (
    <main className="max-w-7xl mx-auto px-6 py-8">
      <ConnectionPanel />

      <section className="mb-8">
        <div className="flex items-center gap-4 p-4 bg-slate-800/50 border border-slate-700 rounded-xl hover:border-slate-600 transition-colors cursor-pointer">
          <div className="w-12 h-12 bg-violet-500/15 rounded-xl flex items-center justify-center text-violet-400">
            <Save className="w-6 h-6" />
          </div>
          <div className="flex-1">
            <h3 className="font-semibold text-slate-100 mb-0.5">Backup Vault</h3>
            <p className="text-sm text-slate-400">
              <span className="font-semibold text-violet-400">0</span> restore points available
            </p>
          </div>
          <button className="flex items-center gap-1 px-4 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors text-sm font-medium">
            View All
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </section>

      <section id="tools" className="mb-12">
        {pinnedTools.length > 0 && (
          <div className="mb-8">
            <div className="flex items-center gap-2 mb-4">
              <Pin className="w-4 h-4 fill-amber-400 text-amber-400" />
              <h2 className="text-sm font-semibold text-amber-400 uppercase tracking-wider">Pinned</h2>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {pinnedTools.map(tool => (
                <ToolCard
                  key={tool.name}
                  {...tool}
                  disabled={tool.disabled || (!tool.standalone && !isConnected)}
                  isPinned={true}
                  onTogglePin={() => togglePin(tool.name)}
                />
              ))}
            </div>
            <div className="mt-8 border-t border-slate-700/50" />
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {unpinnedTools.map(tool => (
            <ToolCard
              key={tool.name}
              {...tool}
              disabled={tool.disabled || (!tool.standalone && !isConnected)}
              isPinned={false}
              onTogglePin={tool.disabled ? undefined : () => togglePin(tool.name)}
            />
          ))}
        </div>
      </section>

      <section className="mb-12">
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-slate-100 mb-2">Built for Safety & Scale</h2>
          <p className="text-slate-400">Enterprise-grade features for production environments</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map(feature => (
            <div
              key={feature.title}
              className="p-6 bg-slate-800/50 border border-slate-700 rounded-xl hover:border-slate-600 transition-colors"
            >
              <div className="w-10 h-10 bg-slate-700 rounded-lg flex items-center justify-center text-blue-400 mb-4">
                <feature.icon className="w-5 h-5" />
              </div>
              <h3 className="font-semibold text-slate-100 mb-2">{feature.title}</h3>
              <p className="text-sm text-slate-400 leading-relaxed">{feature.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Footer moved to shared component */}
    </main>
  );
}