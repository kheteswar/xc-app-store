import { Link, useNavigate } from 'react-router-dom';
import { ExternalLink, Clock, ChevronDown, LogOut, Moon, Sun, Sunrise, Briefcase } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useTheme, THEME_MODES, VARIANT_NAMES, type Variant } from '../context/ThemeContext';

export function Header() {
  const navigate = useNavigate();
  const { isConnected, tenant, disconnect } = useApp();
  const { theme, variant, applyTheme } = useTheme();

  const handleDisconnect = () => {
    disconnect();
    navigate('/');
  };

  // We are putting the other links here
  const otherLinks = [
    { to: '/', label: 'Backup Vault', hash: '#backup-vault' },
    { to: '/', label: 'Settings', hash: '#settings' },
  ];

  // Here is our new hidden drawer full of tools!
  const toolsList = [
    { to: '/waf-scanner', label: 'WAF Scanner' },
    { to: '/config-visualizer', label: 'Config Viewer' },
    { to: '/copy-config', label: 'Copy Config' },
    { to: '/security-auditor', label: 'Security Auditor' },
    { to: '/property-viewer', label: 'Property Viewer' },
    { to: '/config-comparator', label: 'Config Comparator' },
    { to: '/http-sanity-checker', label: 'HTTP Sanity Checker' },
    { to: '/prefix-builder', label: 'Prefix Builder' },
    { to: '/http-lb-forge', label: 'HTTP LB Forge' },
    { to: '/config-dump', label: 'Config Dump' },
    { to: '/config-explorer', label: 'Dependency Map' },
    { to: '/ddos-advisor', label: 'DDoS Advisor' },
    { to: '/log-analyzer', label: 'Log Analyzer' },
    { to: '/load-tester', label: 'Load Tester' },
    { to: '/soc-lobby', label: 'SOC Room' },
    { to: '/api-shield', label: 'API Shield Advisor' },
    { to: '/work-mgr', label: 'Work Manager' },
  ];

  return (
    <header className="sticky top-0 z-50 bg-slate-900/90 backdrop-blur-md border-b border-slate-800 h-16">
      <div className="max-w-7xl mx-auto px-6 h-full flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link to="/" className="flex items-center gap-3">
            <div className="w-10 h-10 text-blue-500">
              <svg viewBox="0 0 40 40" className="w-full h-full">
                <rect x="2" y="2" width="36" height="36" rx="8" stroke="currentColor" strokeWidth="2.5" fill="none" />
                <path d="M12 20h16M20 12v16" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
              </svg>
            </div>
            <div className="flex flex-col">
              <span className="text-lg font-bold text-slate-100 tracking-tight">XC App Store</span>
              <span className="text-xs text-slate-500 font-medium">F5 XC Apps & Scripts</span>
            </div>
          </Link>

          {isConnected && tenant && (
            <div className="flex items-center gap-3 ml-2 pl-4 border-l border-slate-700">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_6px] shadow-emerald-500" />
                <span className="text-sm font-medium text-slate-200">{tenant}</span>
                <span className="text-xs text-slate-500 hidden lg:inline">.console.ves.volterra.io</span>
              </div>
              <button
                onClick={handleDisconnect}
                className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-md transition-colors"
                title="Disconnect from tenant"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Disconnect</span>
              </button>
            </div>
          )}
        </div>

        <nav className="flex items-center gap-1">
          <Link to="/work-mgr" className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-slate-400 hover:text-white transition-colors">
            <Briefcase className="w-4 h-4" />
            Work Manager
          </Link>
          <Link to="/time-tracker" className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-slate-400 hover:text-white transition-colors">
            <Clock className="w-4 h-4" />
            Time Tracker
          </Link>

          {/* This is the magic Tools dropdown container! */}
          <div className="relative group">
            <button className="flex items-center gap-1 px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-md transition-colors">
              Tools
              <ChevronDown className="w-4 h-4" />
            </button>

            {/* This is the hidden box that appears when you hover */}
            <div className="absolute left-0 mt-2 w-48 bg-slate-800 border border-slate-700 rounded-md shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50">
              <div className="py-1">
                {toolsList.map(tool => (
                  <Link
                    key={tool.label}
                    to={tool.to}
                    className="block px-4 py-2 text-sm text-slate-300 hover:bg-slate-700 hover:text-white"
                  >
                    {tool.label}
                  </Link>
                ))}
              </div>
            </div>
          </div>

          {/* Generating the rest of the standard links */}
          {otherLinks.map(link => (
            <Link
              key={link.label}
              to={link.to + (link.hash || '')}
              className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-md transition-colors"
            >
              {link.label}
            </Link>
          ))}

          <a
            href="https://docs.cloud.f5.com/docs-v2/api"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-md transition-colors"
          >
            API Docs
            <ExternalLink className="w-3 h-3 opacity-50" />
          </a>

          <div className="relative group">
            <button
              className="p-2 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-md transition-colors flex items-center gap-1"
              title={`Theme: ${theme} · ${VARIANT_NAMES[theme][variant - 1]}`}
            >
              {theme === 'dark' ? <Moon className="w-4 h-4" /> : theme === 'light' ? <Sun className="w-4 h-4" /> : <Sunrise className="w-4 h-4" />}
              <ChevronDown className="w-3 h-3 opacity-60" />
            </button>
            <div className="absolute right-0 mt-2 w-60 bg-slate-800 border border-slate-700 rounded-lg shadow-xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-150 z-50 p-2">
              <div className="px-2 pb-1.5 mb-1 text-[10px] uppercase tracking-wider text-slate-500 border-b border-slate-700/60">Theme · pick a variant</div>
              {THEME_MODES.map(m => {
                const Icon = m.key === 'dark' ? Moon : m.key === 'light' ? Sun : Sunrise;
                return (
                  <div key={m.key} className="mt-2 first:mt-1">
                    <div className="flex items-center gap-1.5 px-2 mb-1 text-[11px] font-semibold text-slate-300">
                      <Icon className="w-3.5 h-3.5" /> {m.label}
                    </div>
                    <div className="grid grid-cols-3 gap-1">
                      {VARIANT_NAMES[m.key].map((name, i) => {
                        const active = theme === m.key && variant === (i + 1);
                        return (
                          <button
                            key={i}
                            onClick={() => applyTheme(m.key, (i + 1) as Variant)}
                            className={`px-1.5 py-1.5 rounded-md text-[11px] leading-tight border text-center transition-colors ${active ? 'bg-blue-500/20 border-blue-500/50 text-blue-300' : 'border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500'}`}
                          >
                            {name}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </nav>
      </div>
    </header>
  );
}