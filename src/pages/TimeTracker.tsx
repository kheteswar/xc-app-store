import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
  Save, Download, Upload, Plus, Trash2, Send, Clock,
  Settings, AlertCircle, ChevronLeft, ChevronRight, KeyRound, Loader2,
  ChevronDown, Search, Globe, RefreshCw, RotateCcw, BarChart2,
  TrendingUp, Users, Building2, Calendar, Copy, ClipboardPaste
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, PieChart, Pie, Cell
} from 'recharts';
import { useToast } from '../context/ToastContext';

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS & TYPES
// ═══════════════════════════════════════════════════════════════════════════

const API_BASE_DOMAIN = 'time-tracker.mgdsvc-ai.f5sdclabs.com';

const DEFAULT_PRODUCTS = [
  'AI Guardrails / AI Red Team', 'BIG-IP', 'Bot Standard', 'Bot Web & Mobile', 
  'Not Apply', 'Other', 'Shape - Bot Defense (IBD)', 'XC API Security', 
  'XC CDN', 'XC Data Intelligence', 'XC DDoS', 'XC DNS', 'XC General', 
  'XC MCN', 'XC Mobile App Shield', 'XC WAF', 'XC Web App Scanning'
];

const DEFAULT_WORK_TYPES = [
  'Business as Usual', 'Customer Escalation', 'Customer Onboarding', 
  'Customer Training', 'Exception', 'F5 Wellness Day', 'Free of Charge', 
  'Holiday', 'Internal Meetings', 'Internal Training', 'On-call', 
  'Proof of Concept', 'PTO', 'Self-Development', 'XC Expert Hours'
];

const DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] as const;
type Day = typeof DAYS[number];

const INTERNAL_CUSTOMER = 'F5 Networks, Inc. - Headquarters';

const CHART_COLORS = [
  '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
  '#06b6d4', '#f97316', '#ec4899', '#84cc16', '#14b8a6',
  '#a78bfa', '#fb923c', '#34d399', '#f472b6', '#60a5fa'
];

type Duration = 'this_week' | 'last_week' | 'last_month' | 'last_quarter' | 'this_year';

interface DailyBreakdownItem { id: string; label: string; hours: number; }
interface DailyTotal {
  date: string;
  totalHours: number;
  byCustomer: DailyBreakdownItem[];
  byProduct: DailyBreakdownItem[];
  byWorkType: DailyBreakdownItem[];
}
interface SummaryResponse {
  range: { startDate: string; endDate: string };
  dailyTotals: DailyTotal[];
  monthlyTotals: { month: string; totalHours: number }[];
}

// Compute date range from duration preset (client-side, no server needed)
const getDateRangeForDuration = (d: Duration): { startDate: string; endDate: string } => {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const fmt = (dt: Date) => {
    const y = dt.getFullYear();
    const m = String(dt.getMonth() + 1).padStart(2, '0');
    const day = String(dt.getDate()).padStart(2, '0');
    return `${y}-${m}-${day}`;
  };
  switch (d) {
    case 'this_week': {
      const start = getStartOfWeek(today);
      return { startDate: fmt(start), endDate: fmt(today) };
    }
    case 'last_week': {
      // Get previous week's Monday to Sunday
      const end = new Date(getStartOfWeek(today));
      end.setDate(end.getDate() - 1); // Last week's Sunday
      const start = new Date(end);
      start.setDate(start.getDate() - 6); // Last week's Monday
      return { startDate: fmt(start), endDate: fmt(end) };
    }
    case 'last_month': {
      const start = new Date(today.getFullYear(), today.getMonth() - 1, 1);
      const end   = new Date(today.getFullYear(), today.getMonth(), 0);
      return { startDate: fmt(start), endDate: fmt(end) };
    }
    case 'last_quarter': {
      // Rolling last 90 days (more useful than strict calendar quarter)
      const start = new Date(today);
      start.setDate(start.getDate() - 89);
      return { startDate: fmt(start), endDate: fmt(today) };
    }
    case 'this_year': {
      const start = new Date(today.getFullYear(), 0, 1);
      return { startDate: fmt(start), endDate: fmt(today) };
    }
  }
};

interface TimeRow {
  id: string;
  customerName: string;
  productName: string;
  workTypeName: string;
  hours: Record<Day, string>;
}

interface ReferenceItem {
  id: string;
  name: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

const generateId = () => {
  return typeof crypto !== 'undefined' && crypto.randomUUID 
    ? crypto.randomUUID() 
    : Math.random().toString(36).substring(2, 15);
};

const getStartOfWeek = (date: Date) => {
  const d = new Date(date);
  d.setHours(0, 0, 0, 0); // Strictly reset to midnight to prevent timezone boundary bugs
  const day = d.getDay() || 7; 
  d.setDate(d.getDate() - (day - 1));
  return d;
};

const getDatesForWeekOffset = (offsetWeeks: number) => {
  const start = getStartOfWeek(new Date());
  start.setDate(start.getDate() + (offsetWeeks * 7));
  
  const dates: Record<string, { label: string, dayLabel: string, dateLabel: string, fullDate: string }> = {};
  DAYS.forEach((day, index) => {
    const d = new Date(start);
    d.setDate(d.getDate() + index);
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    
    dates[day] = {
      label: `${day.charAt(0).toUpperCase() + day.slice(1)} ${d.getMonth() + 1}/${d.getDate()}`,
      dayLabel: day.charAt(0).toUpperCase() + day.slice(1),
      dateLabel: `${d.getMonth() + 1}/${d.getDate()}`,
      fullDate: `${yyyy}-${mm}-${dd}` 
    };
  });
  return dates;
};

// ═══════════════════════════════════════════════════════════════════════════
// UI COMPONENTS
// ═══════════════════════════════════════════════════════════════════════════

interface SearchableDropdownProps {
  value: string;
  onChange: (value: string) => void;
  options: { label: string; value: string }[];
  placeholder: string;
  isLoading?: boolean;
  disabled?: boolean;
}

function SearchableDropdown({ value, onChange, options, placeholder, isLoading, disabled }: SearchableDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [dropdownStyle, setDropdownStyle] = useState<React.CSSProperties>({});
  const wrapperRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target as Node)) {
        setIsOpen(false);
        setSearch('');
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  // Recalculate position on scroll/resize so fixed dropdown tracks the trigger
  useEffect(() => {
    if (!isOpen) return;
    function updatePosition() {
      if (!wrapperRef.current) return;
      const rect = wrapperRef.current.getBoundingClientRect();
      setDropdownStyle({
        position: 'fixed',
        top: rect.bottom + 4,
        left: rect.left,
        width: rect.width,
        zIndex: 9999,
      });
    }
    updatePosition();
    window.addEventListener('scroll', updatePosition, true);
    window.addEventListener('resize', updatePosition);
    return () => {
      window.removeEventListener('scroll', updatePosition, true);
      window.removeEventListener('resize', updatePosition);
    };
  }, [isOpen]);

  const openDropdown = () => {
    if (disabled || isLoading) return;
    if (!isOpen && wrapperRef.current) {
      const rect = wrapperRef.current.getBoundingClientRect();
      setDropdownStyle({
        position: 'fixed',
        top: rect.bottom + 4,
        left: rect.left,
        width: rect.width,
        zIndex: 9999,
      });
    }
    setIsOpen(!isOpen);
    setSearch('');
  };

  const filteredOptions = options.filter(opt => 
    opt.label.toLowerCase().includes(search.toLowerCase())
  );

  const displayLabel = options.find(opt => opt.value === value)?.label || value || '';

  return (
    <div ref={wrapperRef} className="relative w-full">
      <div 
        onClick={openDropdown}
        className={`flex items-center justify-between w-full bg-slate-900/50 border rounded p-2 text-sm transition-all select-none
          ${disabled || isLoading ? 'border-slate-700/50 text-slate-500 cursor-not-allowed' : 'border-slate-600 hover:border-blue-500 cursor-pointer text-slate-200'}
          ${isOpen ? 'border-blue-500 ring-1 ring-blue-500/50' : ''}
        `}
      >
        <span className={`truncate mr-2 ${!displayLabel ? 'text-slate-500' : ''}`}>
          {isLoading ? 'Loading...' : (displayLabel || placeholder)}
        </span>
        <ChevronDown className={`w-4 h-4 transition-transform duration-200 flex-shrink-0 ${isOpen ? 'rotate-180 text-blue-400' : 'text-slate-500'}`} />
      </div>

      {isOpen && (
        <div style={dropdownStyle} className="bg-slate-800 border border-slate-600 rounded-lg shadow-2xl overflow-hidden animate-in fade-in slide-in-from-top-2 duration-150">
          <div className="p-2 border-b border-slate-700 bg-slate-800/50">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input 
                ref={inputRef}
                type="text" 
                className="w-full bg-slate-900 border border-slate-700 rounded px-9 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500 placeholder-slate-500"
                placeholder="Search..."
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
          </div>
          <ul className="max-h-56 overflow-y-auto py-1 custom-scrollbar">
            {filteredOptions.length === 0 ? (
              <li className="p-3 text-sm text-slate-500 text-center italic">No results found</li>
            ) : (
              filteredOptions.map(opt => (
                <li 
                  key={opt.value}
                  onClick={() => {
                    onChange(opt.value);
                    setIsOpen(false);
                    setSearch('');
                  }}
                  className={`px-3 py-2 text-sm cursor-pointer transition-colors flex items-center justify-between
                    ${value === opt.value ? 'bg-blue-500/20 text-blue-400 font-medium' : 'text-slate-300 hover:bg-slate-700 hover:text-white'}
                  `}
                >
                  <span className="truncate">{opt.label}</span>
                </li>
              ))
            )}
          </ul>
        </div>
      )}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════
// REPORTS PANEL COMPONENT  (uses GET /api/time-entries/summary — user-scoped)
// ═══════════════════════════════════════════════════════════════════════════

interface ReportsPanelProps { token: string; }

function ReportsPanel({ token }: ReportsPanelProps) {
  const [duration, setDuration]         = useState<Duration>('last_month');
  const [summary, setSummary]           = useState<SummaryResponse | null>(null);
  const [isLoading, setIsLoading]       = useState(false);
  const [hasFetched, setHasFetched]     = useState(false);
  const [error, setError]               = useState<string | null>(null);
  const [selectedCustomer, setSelectedCustomer] = useState<string | null>(null);
  const [trendChartType, setTrendChartType]     = useState<'bar' | 'line'>('bar');

  const { startDate, endDate } = useMemo(() => getDateRangeForDuration(duration), [duration]);

  const fetchReportData = useCallback(async () => {
    if (!token) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          isExternal: true,
          targetUrl: `https://${API_BASE_DOMAIN}/api/time-entries/summary?startDate=${startDate}&endDate=${endDate}`,
          token,
          method: 'GET'
        })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err?.message || `HTTP ${res.status}`);
      }
      const data: SummaryResponse = await res.json();
      setSummary(data);
      setHasFetched(true);
    } catch (e: any) {
      setError(e.message || 'Failed to load report data');
    } finally {
      setIsLoading(false);
    }
  }, [token, startDate, endDate]);

  useEffect(() => { fetchReportData(); }, [fetchReportData]);

  // ── All aggregations derived from dailyTotals ────────────────────────────

  const totalHours = useMemo(() =>
    (summary?.dailyTotals ?? []).reduce((s, d) => s + d.totalHours, 0), [summary]);

  const internalHours = useMemo(() =>
    (summary?.dailyTotals ?? []).reduce((s, d) =>
      s + (d.byCustomer.find(c => c.label === INTERNAL_CUSTOMER)?.hours ?? 0), 0), [summary]);

  const externalHours = totalHours - internalHours;

  // Extra KPIs
  const avgDailyHours = useMemo(() => {
    const activeDays = (summary?.dailyTotals ?? []).filter(d => d.totalHours > 0).length;
    return activeDays > 0 ? Math.round((totalHours / activeDays) * 10) / 10 : 0;
  }, [summary, totalHours]);

  const activeDaysCount = useMemo(() =>
    (summary?.dailyTotals ?? []).filter(d => d.totalHours > 0).length, [summary]);

  const peakWeekHours = useMemo(() => {
    const weekMap: Record<string, number> = {};
    (summary?.dailyTotals ?? []).forEach(d => {
      const dt = new Date(d.date + 'T00:00:00');
      const ws = getStartOfWeek(dt);
      const key = `${ws.getMonth() + 1}/${ws.getDate()}`;
      weekMap[key] = (weekMap[key] ?? 0) + d.totalHours;
    });
    const max = Math.max(0, ...Object.values(weekMap));
    return Math.round(max * 10) / 10;
  }, [summary]);

  const externalPct = totalHours > 0 ? Math.round((externalHours / totalHours) * 100) : 0;
  const customerData = useMemo(() => {
    const map: Record<string, number> = {};
    (summary?.dailyTotals ?? []).forEach(d =>
      d.byCustomer.filter(c => c.label !== INTERNAL_CUSTOMER).forEach(c => {
        map[c.label] = (map[c.label] ?? 0) + c.hours;
      })
    );
    return Object.entries(map)
      .map(([label, hours]) => ({ label, hours: Math.round(hours * 10) / 10 }))
      .sort((a, b) => b.hours - a.hours);
  }, [summary]);

  // Hours per work type across all days
  const workTypeData = useMemo(() => {
    const map: Record<string, number> = {};
    (summary?.dailyTotals ?? []).forEach(d =>
      d.byWorkType.forEach(w => { map[w.label] = (map[w.label] ?? 0) + w.hours; })
    );
    return Object.entries(map)
      .map(([name, hours]) => ({ name, hours: Math.round(hours * 10) / 10 }))
      .sort((a, b) => b.hours - a.hours)
      .slice(0, 10);
  }, [summary]);

  // Weekly trend — group dailyTotals by week start, sum totalHours
  const weeklyTrendData = useMemo(() => {
    const weekMap: Record<string, { week: string; hours: number; _sort: number }> = {};
    (summary?.dailyTotals ?? []).forEach(d => {
      const dt = new Date(d.date + 'T00:00:00');
      const ws = getStartOfWeek(dt);
      const key = `${ws.getMonth() + 1}/${ws.getDate()}`;
      if (!weekMap[key]) weekMap[key] = { week: key, hours: 0, _sort: ws.getTime() };
      weekMap[key].hours = Math.round((weekMap[key].hours + d.totalHours) * 100) / 100;
    });
    return Object.values(weekMap).sort((a, b) => a._sort - b._sort);
  }, [summary]);

  // Per-customer per-week stacked chart
  const customerWeeklyData = useMemo(() => {
    const weekMap: Record<string, Record<string, number> & { _sort: number }> = {};
    (summary?.dailyTotals ?? []).forEach(d => {
      const dt = new Date(d.date + 'T00:00:00');
      const ws = getStartOfWeek(dt);
      const key = `${ws.getMonth() + 1}/${ws.getDate()}`;
      if (!weekMap[key]) weekMap[key] = { _sort: ws.getTime() } as any;
      d.byCustomer.forEach(c => {
        // Exclude Internal account from the weekly customer breakdown
        if (c.label === INTERNAL_CUSTOMER || c.label === 'Internal') return;
        const name = c.label;
        weekMap[key][name] = Math.round(((weekMap[key][name] ?? 0) + c.hours) * 100) / 100;
      });
    });
    return Object.entries(weekMap)
      .sort((a, b) => a[1]._sort - b[1]._sort)
      .map(([week, vals]) => { const { _sort, ...rest } = vals; return { week, ...rest }; });
  }, [summary]);

  const customerKeys = useMemo(() => {
    const keys = new Set<string>();
    customerWeeklyData.forEach(row =>
      Object.keys(row).filter(k => k !== 'week' && k !== 'Internal').forEach(k => keys.add(k))
    );
    return Array.from(keys);
  }, [customerWeeklyData]);

  // Internal vs External per week — for the new trend tracker
  const internalVsExternalWeekly = useMemo(() => {
    const weekMap: Record<string, { week: string; External: number; Internal: number; _sort: number }> = {};
    (summary?.dailyTotals ?? []).forEach(d => {
      const dt = new Date(d.date + 'T00:00:00');
      const ws = getStartOfWeek(dt);
      const key = `${ws.getMonth() + 1}/${ws.getDate()}`;
      if (!weekMap[key]) weekMap[key] = { week: key, External: 0, Internal: 0, _sort: ws.getTime() };
      d.byCustomer.forEach(c => {
        const h = c.hours ?? 0;
        if (c.label === INTERNAL_CUSTOMER) weekMap[key].Internal = Math.round((weekMap[key].Internal + h) * 100) / 100;
        else weekMap[key].External = Math.round((weekMap[key].External + h) * 100) / 100;
      });
    });
    return Object.values(weekMap).sort((a, b) => a._sort - b._sort);
  }, [summary]);

  // Filtered view when a customer is selected
  const filteredCustomerWeeklyData = useMemo(() => {
    if (!selectedCustomer) return customerWeeklyData;
    return customerWeeklyData.map(row => {
      const { week, ...rest } = row as Record<string, number | string>;
      const filtered: Record<string, any> = { week };
      if (selectedCustomer === 'Internal') {
        if (rest['Internal'] !== undefined) filtered['Internal'] = rest['Internal'];
      } else {
        if (rest[selectedCustomer] !== undefined) filtered[selectedCustomer] = rest[selectedCustomer];
      }
      return filtered;
    });
  }, [customerWeeklyData, selectedCustomer]);

  const filteredCustomerKeys = useMemo(() =>
    selectedCustomer && selectedCustomer !== 'Internal' ? [selectedCustomer] : customerKeys,
    [customerKeys, selectedCustomer]);

  // Day-of-week pattern
  const dowData = useMemo(() => {
    const dayNames = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const map: Record<string, number> = {};
    (summary?.dailyTotals ?? []).forEach(d => {
      const dt = new Date(d.date + 'T00:00:00');
      const dow = dayNames[(dt.getDay() + 6) % 7];
      map[dow] = (map[dow] ?? 0) + d.totalHours;
    });
    return dayNames.map(day => ({ day, hours: Math.round((map[day] ?? 0) * 10) / 10 }));
  }, [summary]);

  const splitPieData = [
    { name: 'External',      value: Math.round(externalHours * 10) / 10 },
    { name: 'Internal (F5)', value: Math.round(internalHours * 10) / 10 },
  ];

  const DURATION_OPTIONS: { value: Duration; label: string }[] = [
    { value: 'this_week',    label: 'This Week'    },
    { value: 'last_week',    label: 'Last Week'    },
    { value: 'last_month',   label: 'Last Month'   },
    { value: 'last_quarter', label: 'Last 90 Days' },
    { value: 'this_year',    label: 'This Year'    },
  ];
  const PIE_COLORS   = ['#3b82f6', '#f59e0b'];
  const tooltipStyle = { backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', color: '#e2e8f0', fontSize: '12px' };

  return (
    <div className="space-y-6">
      {/* Duration Selector Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/30 p-4 rounded-xl border border-slate-700/50">
        <div>
          <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-blue-400" /> Time Analytics
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">{startDate} → {endDate}</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex bg-slate-900 border border-slate-700 rounded-lg p-1 gap-1">
            {DURATION_OPTIONS.map(opt => (
              <button key={opt.value} onClick={() => setDuration(opt.value)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                  duration === opt.value
                    ? 'bg-blue-600 text-white shadow-sm shadow-blue-900/50'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700'
                }`}>{opt.label}
              </button>
            ))}
          </div>
          <button onClick={fetchReportData} disabled={isLoading}
            className="p-2 text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 rounded-lg transition-colors" title="Refresh">
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* States */}
      {isLoading ? (
        <div className="flex items-center justify-center py-24">
          <Loader2 className="w-8 h-8 animate-spin text-blue-400" />
          <span className="ml-3 text-sm text-slate-400">Loading analytics...</span>
        </div>
      ) : error ? (
        <div className="flex flex-col items-center justify-center py-16 text-red-400 gap-3">
          <AlertCircle className="w-10 h-10 opacity-60" />
          <p className="text-sm font-medium">{error}</p>
          <button onClick={fetchReportData} className="text-xs text-blue-400 hover:underline">Try again</button>
        </div>
      ) : !hasFetched ? null : totalHours === 0 ? (
        <div className="flex flex-col items-center justify-center py-24 text-slate-500">
          <BarChart2 className="w-12 h-12 mb-3 opacity-30" />
          <p className="text-sm">No time entries found for this period.</p>
        </div>
      ) : (
        <>
          {/* Summary Cards — 8 KPIs */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: 'Total Hours',      value: `${Math.round(totalHours * 10) / 10}h`,    icon: Clock,      color: 'text-blue-400',    bg: 'bg-blue-500/10 border-blue-500/20',      sub: 'across all entries'              },
              { label: 'External Hours',   value: `${Math.round(externalHours * 10) / 10}h`, icon: Users,      color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/20', sub: `${externalPct}% of total`        },
              { label: 'Internal Hours',   value: `${Math.round(internalHours * 10) / 10}h`, icon: Building2,  color: 'text-amber-400',   bg: 'bg-amber-500/10 border-amber-500/20',    sub: `${100 - externalPct}% of total`  },
              { label: 'Customers Served', value: customerData.length,                       icon: Globe,      color: 'text-purple-400',  bg: 'bg-purple-500/10 border-purple-500/20',  sub: 'external accounts'               },
              { label: 'Avg Daily Hours',  value: `${avgDailyHours}h`,                       icon: TrendingUp, color: 'text-cyan-400',    bg: 'bg-cyan-500/10 border-cyan-500/20',      sub: 'on active days'                  },
              { label: 'Active Days',      value: activeDaysCount,                           icon: Calendar,   color: 'text-pink-400',    bg: 'bg-pink-500/10 border-pink-500/20',      sub: 'days with logged hours'          },
              { label: 'Peak Week',        value: `${peakWeekHours}h`,                       icon: BarChart2,  color: 'text-orange-400',  bg: 'bg-orange-500/10 border-orange-500/20',  sub: 'highest single week'             },
              { label: 'Ext/Int Ratio',    value: `${externalPct}/${100 - externalPct}`,     icon: RefreshCw,  color: 'text-violet-400',  bg: 'bg-violet-500/10 border-violet-500/20',  sub: 'customer vs internal %'          },
            ].map(card => (
              <div key={card.label} className={`${card.bg} border rounded-xl p-3.5 flex items-start gap-3`}>
                <card.icon className={`w-4 h-4 ${card.color} mt-1 flex-shrink-0`} />
                <div className="min-w-0">
                  <p className="text-xl font-bold text-slate-100 leading-tight">{card.value}</p>
                  <p className="text-xs font-medium text-slate-300 mt-0.5">{card.label}</p>
                  <p className="text-xs text-slate-500 mt-0.5 truncate">{card.sub}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Row 1: Weekly trend */}
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-blue-400" /> Weekly Hours Trend
            </h3>
            <ResponsiveContainer width="100%" height={240}>
              <AreaChart data={weeklyTrendData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
                <defs>
                  <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}   />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="week" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={{ stroke: '#334155' }} tickLine={false} />
                <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={tooltipStyle} formatter={(v: any) => [`${v}h`, 'Total Hours']} />
                <Area type="monotone" dataKey="hours" stroke="#3b82f6" fill="url(#trendGrad)" strokeWidth={2} dot={false} activeDot={{ r: 4, strokeWidth: 0 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Row 2: Internal vs External Weekly Trend — with bar/line toggle */}
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
            <div className="flex items-start justify-between mb-1">
              <div>
                <h3 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                  <Building2 className="w-4 h-4 text-amber-400" /> Internal vs External — Weekly Breakdown
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">Week-by-week split of customer-facing vs internal (F5) hours</p>
              </div>
              {/* Bar / Line toggle */}
              <div className="flex bg-slate-900 border border-slate-700 rounded-lg p-0.5 gap-0.5 flex-shrink-0">
                <button onClick={() => setTrendChartType('bar')}
                  className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md transition-all ${
                    trendChartType === 'bar' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
                  }`}>
                  <BarChart2 className="w-3 h-3" /> Bar
                </button>
                <button onClick={() => setTrendChartType('line')}
                  className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md transition-all ${
                    trendChartType === 'line' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
                  }`}>
                  <TrendingUp className="w-3 h-3" /> Line
                </button>
              </div>
            </div>

            <ResponsiveContainer width="100%" height={260}>
              {trendChartType === 'bar' ? (
                <BarChart data={internalVsExternalWeekly} margin={{ top: 10, right: 10, left: 0, bottom: 5 }} barGap={2}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="week" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={{ stroke: '#334155' }} tickLine={false} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={tooltipStyle} formatter={(v: any, name: any) => [`${v}h`, name]} labelFormatter={(l) => `Week of ${l}`} />
                  <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                  <Bar dataKey="External" stackId="a" fill="#3b82f6" maxBarSize={40} radius={[0, 0, 0, 0]} />
                  <Bar dataKey="Internal" stackId="a" fill="#f59e0b" maxBarSize={40} radius={[3, 3, 0, 0]} />
                </BarChart>
              ) : (
                <LineChart data={internalVsExternalWeekly} margin={{ top: 10, right: 10, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="week" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={{ stroke: '#334155' }} tickLine={false} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={tooltipStyle} formatter={(v: any, name: any) => [`${v}h`, name]} labelFormatter={(l) => `Week of ${l}`} />
                  <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                  <Line type="monotone" dataKey="External" stroke="#3b82f6" strokeWidth={2} dot={{ r: 3, fill: '#3b82f6', strokeWidth: 0 }} activeDot={{ r: 5, strokeWidth: 0 }} />
                  <Line type="monotone" dataKey="Internal" stroke="#f59e0b" strokeWidth={2} dot={{ r: 3, fill: '#f59e0b', strokeWidth: 0 }} activeDot={{ r: 5, strokeWidth: 0 }} />
                </LineChart>
              )}
            </ResponsiveContainer>

            {/* Summary ratio row */}
            <div className="mt-4 pt-4 border-t border-slate-700/50 grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-lg font-bold text-blue-400">{Math.round(externalHours * 10) / 10}h</p>
                <p className="text-xs text-slate-500 mt-0.5">Total External</p>
              </div>
              <div>
                <p className="text-lg font-bold text-slate-200">
                  {totalHours > 0 ? `${externalPct}% / ${100 - externalPct}%` : '—'}
                </p>
                <p className="text-xs text-slate-500 mt-0.5">Ext / Int Ratio</p>
              </div>
              <div>
                <p className="text-lg font-bold text-amber-400">{Math.round(internalHours * 10) / 10}h</p>
                <p className="text-xs text-slate-500 mt-0.5">Total Internal</p>
              </div>
            </div>
          </div>

          {/* Row 3: Internal vs External donut + Hours by Customer */}
          <div className="grid md:grid-cols-2 gap-4">
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                <Building2 className="w-4 h-4 text-amber-400" /> Internal vs External Split
              </h3>
              <div className="flex items-center gap-6">
                <ResponsiveContainer width="50%" height={180}>
                  <PieChart>
                    <Pie data={splitPieData} cx="50%" cy="50%" innerRadius={50} outerRadius={78} paddingAngle={3} dataKey="value">
                      {splitPieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i]} stroke="transparent" />)}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} formatter={(v: any) => [`${v}h`, '']} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex-1 space-y-3">
                  {splitPieData.map((item, i) => (
                    <div key={item.name}>
                      <div className="flex justify-between items-center mb-1">
                        <div className="flex items-center gap-2">
                          <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: PIE_COLORS[i] }} />
                          <span className="text-xs text-slate-400">{item.name}</span>
                        </div>
                        <span className="text-sm font-bold text-slate-200">{item.value}h</span>
                      </div>
                      <div className="w-full bg-slate-700 rounded-full h-1.5">
                        <div className="h-1.5 rounded-full transition-all" style={{
                          width: `${totalHours > 0 ? (item.value / totalHours) * 100 : 0}%`,
                          backgroundColor: PIE_COLORS[i]
                        }} />
                      </div>
                      <p className="text-xs text-slate-600 mt-0.5">
                        {totalHours > 0 ? ((item.value / totalHours) * 100).toFixed(1) : 0}%
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                <Users className="w-4 h-4 text-emerald-400" /> Hours by Customer (External)
              </h3>
              {customerData.length === 0 ? (
                <p className="text-xs text-slate-500 italic">No external customer hours found.</p>
              ) : (
                <div className="space-y-2.5 max-h-52 overflow-y-auto pr-1 custom-scrollbar">
                  {customerData.map((item, i) => (
                    <div key={item.label}>
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-xs text-slate-400 truncate max-w-[65%]" title={item.label}>{item.label}</span>
                        <span className="text-xs font-bold text-slate-200 ml-2 flex-shrink-0">{item.hours}h</span>
                      </div>
                      <div className="w-full bg-slate-700 rounded-full h-2">
                        <div className="h-2 rounded-full transition-all" style={{
                          width: `${customerData[0].hours > 0 ? (item.hours / customerData[0].hours) * 100 : 0}%`,
                          backgroundColor: CHART_COLORS[i % CHART_COLORS.length]
                        }} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Row 4: Work Type + Day of Week */}
          <div className="grid md:grid-cols-2 gap-4">
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                <Calendar className="w-4 h-4 text-purple-400" /> Hours by Work Type
              </h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={workTypeData} layout="vertical" margin={{ top: 0, right: 20, left: 10, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={false} tickLine={false} width={130}
                    tickFormatter={(v: string) => v.length > 18 ? v.slice(0, 17) + '…' : v} />
                  <Tooltip contentStyle={tooltipStyle} formatter={(v: any) => [`${v}h`, 'Hours']} />
                  <Bar dataKey="hours" radius={[0, 4, 4, 0]} maxBarSize={18}>
                    {workTypeData.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                <BarChart2 className="w-4 h-4 text-cyan-400" /> Hours by Day of Week
              </h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={dowData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="day" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={tooltipStyle} formatter={(v: any) => [`${v}h`, 'Hours']} />
                  <Bar dataKey="hours" radius={[4, 4, 0, 0]} maxBarSize={40}>
                    {dowData.map((entry, i) => (
                      <Cell key={i}
                        fill={entry.day === 'Sat' || entry.day === 'Sun' ? '#475569' : '#3b82f6'}
                        opacity={entry.hours === 0 ? 0.3 : 1} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Row 5: Weekly Customer Breakdown — click to filter */}
          {customerWeeklyData.length > 0 && customerKeys.length > 0 && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                    <BarChart2 className="w-4 h-4 text-blue-400" /> Weekly Customer Hours Breakdown
                  </h3>
                  {selectedCustomer && (
                    <p className="text-xs text-blue-400 mt-0.5">
                      Filtered: <span className="font-medium">{selectedCustomer}</span>
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  {selectedCustomer && (
                    <button
                      onClick={() => setSelectedCustomer(null)}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-700 hover:bg-slate-600 border border-slate-600 rounded-lg transition-colors"
                    >
                      <RotateCcw className="w-3 h-3" /> Reset Filter
                    </button>
                  )}
                  {!selectedCustomer && (
                    <p className="text-xs text-slate-500 italic">Click a legend item to filter</p>
                  )}
                </div>
              </div>

              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={filteredCustomerWeeklyData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="week" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={{ stroke: '#334155' }} tickLine={false} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Legend
                    wrapperStyle={{ fontSize: '11px', paddingTop: '10px', cursor: 'pointer' }}
                    onClick={(e) => {
                      const name = e.dataKey as string;
                      setSelectedCustomer(prev => prev === name ? null : name);
                    }}
                    formatter={(value: string) => (
                      <span style={{
                        color: selectedCustomer && selectedCustomer !== value ? '#475569' : '#cbd5e1',
                        fontWeight: selectedCustomer === value ? '600' : '400',
                        textDecoration: selectedCustomer === value ? 'underline' : 'none'
                      }}>{value}</span>
                    )}
                  />
                  {filteredCustomerKeys.slice(0, 10).map((customer, i) => (
                    <Bar
                      key={customer}
                      dataKey={customer}
                      stackId="a"
                      fill={CHART_COLORS[(customerKeys.indexOf(customer) + 1) % CHART_COLORS.length]}
                      maxBarSize={40}
                      radius={i === filteredCustomerKeys.length - 1 && (internalHours === 0 || selectedCustomer !== null) ? [3, 3, 0, 0] : [0, 0, 0, 0]}
                      style={{ cursor: 'pointer' }}
                    />
                  ))}
                  {internalHours > 0 && (!selectedCustomer || selectedCustomer === 'Internal') && (
                    <Bar dataKey="Internal" stackId="a" fill="#f59e0b" radius={[3, 3, 0, 0]} maxBarSize={40} style={{ cursor: 'pointer' }} />
                  )}
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════════════════════════

export function TimeTracker() {
  const toast = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const theadRef = useRef<HTMLTableSectionElement>(null);
  const [showStickyHeader, setShowStickyHeader] = useState(false);

  // App Initialization State
  const [isInitialized, setIsInitialized] = useState(false);
  const [isConfigured, setIsConfigured] = useState(false);
  const [activeTab, setActiveTab] = useState<'timesheet' | 'reports'>('timesheet');

  // API State
  const [token, setToken] = useState('');
  const [rememberToken, setRememberToken] = useState(true);
  const [showSettings, setShowSettings] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoadingWeek, setIsLoadingWeek] = useState(false);
  const [isCopyingPrevWeek, setIsCopyingPrevWeek] = useState(false);
  const [copiedSetup, setCopiedSetup] = useState<{ customerName: string; productName: string; workTypeName: string }[] | null>(() => {
    try {
      const saved = localStorage.getItem('tt_copied_setup');
      return saved ? JSON.parse(saved) : null;
    } catch { return null; }
  });

  // Data State
  const [customers, setCustomers] = useState<ReferenceItem[]>([]);
  const [products, setProducts] = useState<ReferenceItem[]>(DEFAULT_PRODUCTS.map(p => ({ id: p, name: p })));
  const [workTypes, setWorkTypes] = useState<ReferenceItem[]>(DEFAULT_WORK_TYPES.map(w => ({ id: w, name: w })));
  const [isLoadingReferences, setIsLoadingReferences] = useState(false);
  
  // Grid State
  const [weekOffset, setWeekOffset] = useState(0);
  const weekDates = useMemo(() => getDatesForWeekOffset(weekOffset), [weekOffset]);
  const [rows, setRows] = useState<TimeRow[]>([]);

  // 1. Load saved settings & state on mount
  useEffect(() => {
    const savedToken = localStorage.getItem('tt_token');
    
    if (savedToken) {
      setToken(savedToken);
      setRememberToken(true);
      setIsConfigured(true);
    } else {
      setRememberToken(false);
      setIsConfigured(false);
      setRows([{ id: generateId(), customerName: '', productName: '', workTypeName: '', hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' } }]);
    }
    
    setIsInitialized(true);
  }, []);

  // 2. Fetch Reference Data automatically when configured
  useEffect(() => {
    if (isInitialized && isConfigured && token) {
      fetchReferenceData(token);
    }
  }, [isInitialized, isConfigured, token]);

  const fetchReferenceData = async (authToken: string) => {
    setIsLoadingReferences(true);
    try {
      // Fetch Customers (Paginated)
      let allCustomers: ReferenceItem[] = [];
      let page = 1;
      let hasMore = true;

      while (hasMore) {
        const res = await fetch('/api/proxy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            isExternal: true,
            targetUrl: `https://${API_BASE_DOMAIN}/api/customers?status=active&pageSize=500&page=${page}`,
            token: authToken,
            method: 'GET'
          })
        });

        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          if (res.status === 401 || res.status === 403 || data?.message?.includes('Unauthorized')) {
            toast.error('API Token is invalid or expired. Please update settings.');
            setIsConfigured(false); 
            return;
          } else {
            toast.error(`Failed to fetch customers: ${data?.message || res.statusText}`);
          }
          hasMore = false;
          break;
        }

        const data = await res.json();
        const customerList = Array.isArray(data) ? data : (data?.items || []);
        allCustomers = [...allCustomers, ...customerList];

        if (customerList.length < 500) {
          hasMore = false;
        } else {
          page++;
        }
      }

      if (allCustomers.length > 0) {
        const uniqueCustomers = Array.from(new Map(allCustomers.map(c => [c.id, c])).values());
        setCustomers(uniqueCustomers.sort((a, b) => a.name.localeCompare(b.name)));
      }

      // Fetch Products
      try {
        const prodRes = await fetch('/api/proxy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            isExternal: true,
            targetUrl: `https://${API_BASE_DOMAIN}/api/products`,
            token: authToken,
            method: 'GET'
          })
        });
        if (prodRes.ok) {
          const pData = await prodRes.json();
          const pList = Array.isArray(pData) ? pData : (pData?.items || []);
          if (pList.length > 0) setProducts(pList.sort((a: ReferenceItem, b: ReferenceItem) => a.name.localeCompare(b.name)));
        }
      } catch (e) {
        console.warn("Failed to fetch products dynamically", e);
      }

      // Fetch Work Types
      try {
        const wtRes = await fetch('/api/proxy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            isExternal: true,
            targetUrl: `https://${API_BASE_DOMAIN}/api/work-types`,
            token: authToken,
            method: 'GET'
          })
        });
        if (wtRes.ok) {
          const wData = await wtRes.json();
          const wList = Array.isArray(wData) ? wData : (wData?.items || []);
          if (wList.length > 0) setWorkTypes(wList.sort((a: ReferenceItem, b: ReferenceItem) => a.name.localeCompare(b.name)));
        }
      } catch (e) {
        console.warn("Failed to fetch work types dynamically", e);
      }

    } catch (e) {
      console.error("Failed to fetch reference data", e);
      toast.error('Network error while fetching reference data.');
    } finally {
      setIsLoadingReferences(false);
    }
  };

  // Helper to fetch ALL time entries robustly (handling pagination up to 100 entries per page)
  const fetchAllWeekEntries = useCallback(async (start: string, end: string, authToken: string) => {
    let allEntries: any[] = [];
    let page = 1;
    let hasMore = true;

    while (hasMore) {
      const res = await fetch('/api/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          isExternal: true,
          targetUrl: `https://${API_BASE_DOMAIN}/api/time-entries?startDate=${start}&endDate=${end}&pageSize=100&page=${page}`,
          token: authToken,
          method: 'GET'
        })
      });

      if (!res.ok) {
        if (res.status === 401 || res.status === 403) throw new Error('Unauthorized');
        break;
      }

      const data = await res.json();
      const entries = Array.isArray(data) ? data : (data?.items || data?.data || data?.entries || []);
      allEntries = [...allEntries, ...entries];

      if (entries.length < 100) {
        hasMore = false;
      } else {
        page++;
      }
    }
    return allEntries;
  }, []);

  // 3. Fetch Existing Time Entries for the currently selected week
  const fetchWeekData = useCallback(async () => {
    if (!token || !isConfigured) return;
    
    setIsLoadingWeek(true);
    try {
      const startDate = weekDates.mon.fullDate;
      const endDate = weekDates.sun.fullDate;
      
      const entries = await fetchAllWeekEntries(startDate, endDate, token);
      
      // Group entries into matrix rows
      const grouped: Record<string, TimeRow> = {};
      
      entries.forEach((e: any) => {
        const key = `${e.customerName}|${e.productName}|${e.workTypeName}`;
        
        if (!grouped[key]) {
          grouped[key] = {
            id: generateId(),
            customerName: e.customerName || '',
            productName: e.productName || '',
            workTypeName: e.workTypeName || '',
            hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' }
          };
        }
        
        // Match the specific day of the week accurately
        const entryDate = e.workDate?.split('T')[0];
        const dayMatch = DAYS.find(d => weekDates[d].fullDate === entryDate);
        if (dayMatch) {
          grouped[key].hours[dayMatch] = String(e.effortHours || '');
        }
      });

      const newRows = Object.values(grouped);
      
      // Ensure there's always at least one empty row to type into
      if (newRows.length === 0) {
        newRows.push({ id: generateId(), customerName: '', productName: '', workTypeName: '', hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' } });
      }
      
      setRows(newRows);
    } catch (error: any) {
      console.error("Failed to load weekly entries", error);
      if (error.message === 'Unauthorized') {
         setIsConfigured(false);
         toast.error('API Token expired. Please update settings.');
      } else {
         toast.error('Failed to load existing timesheet data for this week.');
      }
    } finally {
      setIsLoadingWeek(false);
    }
  }, [token, isConfigured, weekDates, toast, fetchAllWeekEntries]);

  // Fetch week data when the selected week changes or on first load
  useEffect(() => {
    if (isInitialized && isConfigured) {
      fetchWeekData();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [weekOffset, isInitialized, isConfigured]);

  // Show a fixed sticky header when the real thead scrolls above the site header
  useEffect(() => {
    const el = theadRef.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      ([entry]) => setShowStickyHeader(!entry.isIntersecting),
      { rootMargin: '-64px 0px 0px 0px', threshold: 0 }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [activeTab, isConfigured]);

  const copyFromPreviousWeek = useCallback(async () => {
    if (!token || !isConfigured) return;
    setIsCopyingPrevWeek(true);
    try {
      const prevWeekDates = getDatesForWeekOffset(weekOffset - 1);
      const entries = await fetchAllWeekEntries(prevWeekDates.mon.fullDate, prevWeekDates.sun.fullDate, token);
      if (entries.length === 0) { toast.info('No time entries found in the previous week to copy.'); return; }
      const seen = new Set<string>();
      const newRows: TimeRow[] = [];
      entries.forEach((e: any) => {
        const key = `${e.customerName}|${e.productName}|${e.workTypeName}`;
        if (!seen.has(key)) {
          seen.add(key);
          newRows.push({ id: generateId(), customerName: e.customerName || '', productName: e.productName || '', workTypeName: e.workTypeName || '', hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' } });
        }
      });
      newRows.sort((a, b) => a.customerName.localeCompare(b.customerName) || a.productName.localeCompare(b.productName) || a.workTypeName.localeCompare(b.workTypeName));
      setRows(newRows);
      toast.success(`Copied ${newRows.length} row(s) from the previous week.`);
    } catch (error: any) {
      if (error.message === 'Unauthorized') { setIsConfigured(false); toast.error('API Token expired. Please update settings.'); }
      else { toast.error('Failed to load previous week data.'); }
    } finally { setIsCopyingPrevWeek(false); }
  }, [token, isConfigured, weekOffset, fetchAllWeekEntries, toast]);

  const copySetup = useCallback(() => {
    const setup = rows
      .filter(r => r.customerName || r.productName || r.workTypeName)
      .map(({ customerName, productName, workTypeName }) => ({ customerName, productName, workTypeName }));
    if (setup.length === 0) {
      toast.warning('No rows with setup to copy. Fill in Customer, Product, or Work Type first.');
      return;
    }
    setCopiedSetup(setup);
    localStorage.setItem('tt_copied_setup', JSON.stringify(setup));
    toast.success(`Copied setup from ${setup.length} row(s) to clipboard.`);
  }, [rows, toast]);

  const pasteSetup = useCallback(() => {
    if (!copiedSetup || copiedSetup.length === 0) {
      toast.warning('No setup in clipboard. Copy a setup from any week first.');
      return;
    }
    const newRows: TimeRow[] = copiedSetup.map(s => ({
      id: generateId(),
      customerName: s.customerName,
      productName: s.productName,
      workTypeName: s.workTypeName,
      hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' }
    }));
    setRows(newRows);
    toast.success(`Pasted setup with ${newRows.length} row(s). Hours are blank — fill them in.`);
  }, [copiedSetup, toast]);

  const saveSettings = () => {
    if (!token) {
      toast.warning('API Token is required.');
      return;
    }

    if (rememberToken) localStorage.setItem('tt_token', token);
    else localStorage.removeItem('tt_token');

    setIsConfigured(true);
    setShowSettings(false);
    toast.success('API Configuration saved');
    fetchReferenceData(token); 
  };

  // Row Management
  const addRow = () => setRows([...rows, { id: generateId(), customerName: '', productName: '', workTypeName: '', hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' } }]);
  const removeRow = (id: string) => setRows(rows.filter(r => r.id !== id));
  const updateRow = (id: string, field: keyof TimeRow, value: any) => setRows(rows.map(r => r.id === id ? { ...r, [field]: value } : r));
  const updateHours = (id: string, day: Day, value: string) => setRows(rows.map(r => r.id === id ? { ...r, hours: { ...r.hours, [day]: value } } : r));

  const resetHours = () => {
    setRows(rows.map(row => ({
      ...row,
      hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' }
    })));
    toast.success('Hours reset to blank');
  };

  // Totals Calculations
  const getRowTotal = (row: TimeRow) => {
    return DAYS.reduce((sum, day) => sum + (parseFloat(row.hours[day]) || 0), 0);
  };

  const getDayTotal = (day: Day) => {
    return rows.reduce((sum, row) => sum + (parseFloat(row.hours[day]) || 0), 0);
  };

  const getWeeklyTotal = () => {
    return DAYS.reduce((sum, day) => sum + getDayTotal(day), 0);
  };

  // Import / Export
  const exportTemplate = () => {
    const dataToExport = rows.map(({ customerName, productName, workTypeName }) => ({
      customerName, productName, workTypeName, hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' }
    })); 
    const blob = new Blob([JSON.stringify(dataToExport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'weekly-timesheet-template.json';
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Template exported');
  };

  const importTemplate = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const importedData = JSON.parse(event.target?.result as string);
        if (Array.isArray(importedData)) {
          const newRows = importedData.map(r => ({
            id: generateId(),
            customerName: r.customerName || r.customer || '', 
            productName: r.productName || r.product || '',
            workTypeName: r.workTypeName || r.workType || '',
            hours: r.hours || { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' }
          }));
          // Merge imported template rows below existing ones, filtering out entirely empty existing rows
          const filteredExisting = rows.filter(r => r.customerName || r.productName || r.workTypeName || getRowTotal(r) > 0);
          setRows([...filteredExisting, ...newRows]);
          toast.success('Template imported successfully');
        }
      } catch (err) {
        toast.error('Invalid JSON file format');
      }
      if (fileInputRef.current) fileInputRef.current.value = ''; 
    };
    reader.readAsText(file);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // SUBMISSION LOGIC (With UPSERT support)
  // ═══════════════════════════════════════════════════════════════════════════
  const submitTimesheet = async () => {
    if (!token) {
      toast.error('API Token is required.');
      setIsConfigured(false);
      return;
    }

    // 1. Gather all entries the user has inputted on the screen
    const entriesToProcess: any[] = [];
    let hasValidationErrors = false;

    rows.forEach(row => {
      DAYS.forEach(day => {
        const rawVal = row.hours[day];
        const val = parseFloat(rawVal);
        const hasInput = rawVal !== '' && rawVal !== null && rawVal !== undefined;
        
        if (hasInput) {
          if (!row.customerName || !row.productName || !row.workTypeName) {
            hasValidationErrors = true;
          } else {
            entriesToProcess.push({
              customerName: row.customerName,
              productName: row.productName,
              workTypeName: row.workTypeName,
              workDate: weekDates[day].fullDate,
              effortHours: isNaN(val) ? 0 : val
            });
          }
        }
      });
    });

    if (hasValidationErrors) {
      toast.error('Some entries have hours but are missing Customer, Product, or Work Type.');
      return;
    }

    if (entriesToProcess.length === 0) {
      toast.warning('No hours found to submit.');
      return;
    }

    setIsSubmitting(true);

    // 2. Fetch Existing Entries for the Week to determine POST vs PUT vs DELETE
    let existingEntries: any[] = [];
    try {
      const startDate = weekDates.mon.fullDate;
      const endDate = weekDates.sun.fullDate;
      existingEntries = await fetchAllWeekEntries(startDate, endDate, token);
    } catch (e) {
      console.warn("Could not fetch existing entries, proceeding with POST only.", e);
    }

    // Helper to find ID of existing exact match
    const getExistingEntryId = (cName: string, pName: string, wName: string, date: string) => {
      const found = existingEntries.find(e => 
        e.customerName === cName && 
        e.productName === pName && 
        e.workTypeName === wName && 
        e.workDate && e.workDate.startsWith(date)
      );
      return found?.id || found?._id; 
    };

    let successCount = 0;
    let failCount = 0;

    // 3. Process each entry (Create, Update, or Delete)
    try {
      const requests = entriesToProcess.map(entry => {
        const existingId = getExistingEntryId(entry.customerName, entry.productName, entry.workTypeName, entry.workDate);
        
        let method = 'POST';
        let targetUrl = `https://${API_BASE_DOMAIN}/api/time-entries`;
        let bodyPayload: any = entry;

        if (existingId) {
          if (entry.effortHours > 0) {
            // Update existing entry
            method = 'PUT';
            targetUrl = `https://${API_BASE_DOMAIN}/api/time-entries/${existingId}`;
          } else {
            // Delete existing entry if user cleared the field to 0
            method = 'DELETE';
            targetUrl = `https://${API_BASE_DOMAIN}/api/time-entries/${existingId}`;
            bodyPayload = undefined; 
          }
        } else {
          if (entry.effortHours <= 0) {
            // Field is empty/0 and doesn't exist remotely; skip it safely
            return Promise.resolve({ ok: true, skipped: true });
          }
        }

        return fetch('/api/proxy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            isExternal: true,
            targetUrl,
            token: token,
            method,
            body: bodyPayload
          })
        });
      });

      const responses = await Promise.all(requests);
      
      for (const res of responses) {
        if ((res as any).skipped) continue; 
        if (res.ok) successCount++;
        else failCount++;
      }

      if (failCount === 0 && successCount > 0) {
        toast.success(`Successfully processed ${successCount} time entries!`);
        fetchWeekData(); // Refresh table to match DB state perfectly
      } else if (failCount > 0) {
        toast.warning(`Processed ${successCount} entries, but ${failCount} failed.`);
      } else {
        toast.info(`No changes needed to be submitted.`);
      }

    } catch (error: any) {
      toast.error(error.message || 'Failed to submit timesheet');
    } finally {
      setIsSubmitting(false);
    }
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER: LOADING STATE
  // ═══════════════════════════════════════════════════════════════════════════
  if (!isInitialized) {
    return <div className="min-h-screen bg-slate-900 flex items-center justify-center text-blue-400"><Loader2 className="w-8 h-8 animate-spin" /></div>;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER: SETUP REQUIRED SCREEN
  // ═══════════════════════════════════════════════════════════════════════════
  if (!isConfigured) {
    return (
      <div className="min-h-screen bg-slate-900 text-slate-200 flex items-center justify-center p-6">
        <div className="w-full max-w-lg bg-slate-800 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden">
          <div className="p-8 text-center border-b border-slate-700/50 bg-slate-800/80">
            <div className="w-16 h-16 bg-blue-500/10 text-blue-400 rounded-2xl flex items-center justify-center mx-auto mb-4 border border-blue-500/20">
              <Clock className="w-8 h-8" />
            </div>
            <h1 className="text-2xl font-bold text-slate-100">Setup Time Tracker</h1>
            <p className="text-slate-400 mt-2 text-sm">Please provide your secure Bearer Token to access your customers and submit timesheets.</p>
          </div>
          
          <div className="p-8 space-y-6">
            <div className="space-y-3">
              <label className="text-sm font-medium text-slate-300 flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-slate-500" /> Bearer Token
              </label>
              <input 
                type="password" 
                value={token} 
                onChange={e => setToken(e.target.value)} 
                className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-all" 
                placeholder="Paste your timetracker API token..." 
              />
              
              <label className="flex items-center gap-2.5 cursor-pointer mt-2 pl-1 w-max group">
                <input 
                  type="checkbox" 
                  checked={rememberToken}
                  onChange={e => setRememberToken(e.target.checked)}
                  className="w-4 h-4 rounded border-slate-600 bg-slate-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-slate-800 cursor-pointer"
                />
                <span className="text-sm text-slate-400 group-hover:text-slate-300 transition-colors select-none">Remember token for future sessions</span>
              </label>
            </div>

            <button 
              onClick={saveSettings} 
              disabled={!token}
              className="w-full flex justify-center items-center gap-2 py-3.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl font-semibold transition-all active:scale-[0.98]"
            >
              Save Token & Continue
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER: MAIN APP GRID
  // ═══════════════════════════════════════════════════════════════════════════

  const customerOptions = customers.map(c => ({ label: c.name, value: c.name })).sort((a, b) => a.label.localeCompare(b.label));
  const productOptions = products.map(p => ({ label: p.name, value: p.name })).sort((a, b) => a.label.localeCompare(b.label));
  const workTypeOptions = workTypes.map(w => ({ label: w.name, value: w.name })).sort((a, b) => a.label.localeCompare(b.label));

  return (
    <div className="min-h-screen bg-slate-900 text-slate-200 p-4">
      <style>{`
        /* Minimal scrollbar for dropdowns */
        .custom-scrollbar::-webkit-scrollbar { width: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #475569; }
        
        /* Remove arrows from number inputs */
        input[type="number"].no-spinners::-webkit-inner-spin-button,
        input[type="number"].no-spinners::-webkit-outer-spin-button {
          -webkit-appearance: none;
          margin: 0;
        }
        input[type="number"].no-spinners {
          -moz-appearance: textfield;
        }
      `}</style>
      
      <div className="max-w-[1600px] mx-auto space-y-6 pb-40">
        
        {/* Header Section */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-800/50 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-blue-500/20 text-blue-400 rounded-xl flex items-center justify-center">
              <Clock className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100">Weekly Time Tracker</h1>
              <p className="text-sm text-slate-400">Fill your entire week in a single go</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Tab Switcher */}
            <div className="flex bg-slate-900 border border-slate-700 rounded-lg p-1 gap-1">
              <button
                onClick={() => setActiveTab('timesheet')}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                  activeTab === 'timesheet'
                    ? 'bg-blue-600 text-white shadow-sm shadow-blue-900/50'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700'
                }`}
              >
                <Clock className="w-3.5 h-3.5" /> Timesheet
              </button>
              <button
                onClick={() => setActiveTab('reports')}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                  activeTab === 'reports'
                    ? 'bg-blue-600 text-white shadow-sm shadow-blue-900/50'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700'
                }`}
              >
                <BarChart2 className="w-3.5 h-3.5" /> Reports
              </button>
            </div>

            {activeTab === 'timesheet' && (
              <>
                <input type="file" accept=".json" className="hidden" ref={fileInputRef} onChange={importTemplate} />
                <button onClick={() => fileInputRef.current?.click()} className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm transition-colors">
                  <Upload className="w-4 h-4" /> Import Setup
                </button>
                <button onClick={exportTemplate} className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm transition-colors">
                  <Download className="w-4 h-4" /> Export Setup
                </button>
              </>
            )}
            <button onClick={() => setShowSettings(!showSettings)} className={`p-2 rounded-lg transition-colors border ${showSettings ? 'bg-blue-500/20 border-blue-500/50 text-blue-400' : 'bg-slate-700 border-slate-600 hover:bg-slate-600'}`}>
              <Settings className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* API Settings Panel (Collapsible) */}
        {showSettings && (
          <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 animate-in slide-in-from-top-2">
            <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-amber-400" /> Update Configuration
            </h3>
            <div className="flex flex-col md:flex-row gap-4 items-start">
              <div className="flex-1 w-full space-y-2">
                <label className="text-xs text-slate-400 font-medium">Bearer Token</label>
                <input type="password" value={token} onChange={e => setToken(e.target.value)} className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2 text-sm focus:border-blue-500 outline-none" placeholder="Paste your timetracker API token..." />
                
                <label className="flex items-center gap-2 cursor-pointer mt-2 pl-1 w-max group">
                  <input 
                    type="checkbox" 
                    checked={rememberToken}
                    onChange={e => setRememberToken(e.target.checked)}
                    className="w-3.5 h-3.5 rounded border-slate-600 bg-slate-900 text-blue-500 focus:ring-blue-500 cursor-pointer"
                  />
                  <span className="text-xs text-slate-400 group-hover:text-slate-300 transition-colors select-none">Remember token</span>
                </label>
              </div>
              <button onClick={saveSettings} className="flex items-center gap-2 px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors mt-6">
                <Save className="w-4 h-4" /> Save Configuration
              </button>
            </div>
          </div>
        )}

        {/* Reports Tab */}
        {activeTab === 'reports' && <ReportsPanel token={token} />}

        {/* Timesheet Tab Content */}
        {activeTab === 'timesheet' && <>

        {/* Week Navigator */}
        <div className="flex items-center justify-between bg-slate-800/30 p-4 rounded-xl border border-slate-700/50 relative">
          <button onClick={() => setWeekOffset(w => w - 1)} className="p-2 hover:bg-slate-700 rounded-lg transition-colors"><ChevronLeft className="w-5 h-5" /></button>
          
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-300">
              Week of {weekDates.mon.label} – {weekDates.sun.label}
            </span>
            <button onClick={fetchWeekData} disabled={isLoadingWeek || isCopyingPrevWeek} className="p-1.5 text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 rounded-lg transition-colors ml-2" title="Refresh from Server">
              <RefreshCw className={`w-4 h-4 ${isLoadingWeek ? 'animate-spin' : ''}`} />
            </button>
            <button onClick={copyFromPreviousWeek} disabled={isLoadingWeek || isCopyingPrevWeek} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-amber-400 hover:text-amber-300 hover:bg-amber-500/10 border border-amber-500/30 hover:border-amber-400/50 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed" title="Pre-fill rows from previous week (without hours)">
              {isCopyingPrevWeek ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ChevronLeft className="w-3.5 h-3.5" />}
              Copy Previous Week
            </button>
            <div className="w-px h-6 bg-slate-700" />
            <button onClick={copySetup} disabled={isLoadingWeek} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300 hover:bg-cyan-500/10 border border-cyan-500/30 hover:border-cyan-400/50 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed" title="Copy this week's row setup (Customer, Product, Work Type) to clipboard">
              <Copy className="w-3.5 h-3.5" />
              Copy Setup
            </button>
            <button onClick={pasteSetup} disabled={isLoadingWeek || !copiedSetup} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-emerald-400 hover:text-emerald-300 hover:bg-emerald-500/10 border border-emerald-500/30 hover:border-emerald-400/50 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed" title={copiedSetup ? `Paste ${copiedSetup.length} row(s) from clipboard` : 'No setup copied yet'}>
              <ClipboardPaste className="w-3.5 h-3.5" />
              Paste Setup{copiedSetup ? ` (${copiedSetup.length})` : ''}
            </button>
          </div>
          
          <button onClick={() => setWeekOffset(w => w + 1)} className="p-2 hover:bg-slate-700 rounded-lg transition-colors"><ChevronRight className="w-5 h-5" /></button>
        </div>

        {/* Sticky Column Header — shown when the real header scrolls out of view */}
        {showStickyHeader && (
          <div className="fixed top-16 left-0 right-0 z-40 bg-slate-800 border-b border-slate-700 shadow-lg shadow-black/30">
            <div className="max-w-[1600px] mx-auto px-4">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr>
                    <th className="p-2 text-xs font-semibold text-slate-400 uppercase tracking-wider w-[200px]">Customer</th>
                    <th className="p-2 text-xs font-semibold text-slate-400 uppercase tracking-wider w-[160px]">Product</th>
                    <th className="p-2 text-xs font-semibold text-slate-400 uppercase tracking-wider w-[155px]">Work Type</th>
                    {DAYS.map(day => (
                      <th key={day} className="p-2 text-xs font-semibold text-center text-slate-400 uppercase tracking-wider w-16">
                        <span>{weekDates[day].dayLabel}</span>{' '}
                        <span>{weekDates[day].dateLabel}</span>
                      </th>
                    ))}
                    <th className="p-2 text-xs font-semibold text-center text-slate-400 uppercase tracking-wider w-14">Total</th>
                    <th className="p-2 w-10"></th>
                  </tr>
                </thead>
              </table>
            </div>
          </div>
        )}

        {/* Matrix Grid */}
        <div className={`bg-slate-800/50 rounded-xl border border-slate-700 overflow-hidden transition-opacity duration-300 ${isLoadingWeek ? 'opacity-50 pointer-events-none' : 'opacity-100'}`}>
          <div className="overflow-x-auto">
            <div className="w-full">
              <table className="w-full text-left border-collapse">
                <thead ref={theadRef}>
                  <tr className="bg-slate-800/80 border-b border-slate-700">
                    <th className="p-2 text-xs font-semibold text-slate-400 uppercase tracking-wider w-[200px]">Customer</th>
                    <th className="p-2 text-xs font-semibold text-slate-400 uppercase tracking-wider w-[160px]">Product</th>
                    <th className="p-2 text-xs font-semibold text-slate-400 uppercase tracking-wider w-[155px]">Work Type</th>
                    {DAYS.map(day => (
                      <th key={day} className="p-2 text-xs font-semibold text-center text-slate-400 uppercase tracking-wider w-16">
                        <div>{weekDates[day].dayLabel}</div>
                        <div>{weekDates[day].dateLabel}</div>
                      </th>
                    ))}
                    <th className="p-2 text-xs font-semibold text-center text-slate-400 uppercase tracking-wider w-14 bg-slate-800">Total</th>
                    <th className="p-2 w-10 sticky right-0 bg-slate-800/80"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/50">
                  {rows.map((row) => {
                    const rowTotal = getRowTotal(row);
                    return (
                      <tr key={row.id} className="hover:bg-slate-700/10 transition-colors">
                        <td className="p-2 align-top">
                          <SearchableDropdown 
                            value={row.customerName}
                            onChange={(val) => updateRow(row.id, 'customerName', val)}
                            options={customerOptions}
                            placeholder="Select Customer..."
                            isLoading={isLoadingReferences}
                          />
                        </td>
                        <td className="p-2 align-top">
                          <SearchableDropdown 
                            value={row.productName}
                            onChange={(val) => updateRow(row.id, 'productName', val)}
                            options={productOptions}
                            placeholder="Select Product..."
                            isLoading={isLoadingReferences}
                          />
                        </td>
                        <td className="p-2 align-top">
                          <SearchableDropdown 
                            value={row.workTypeName}
                            onChange={(val) => updateRow(row.id, 'workTypeName', val)}
                            options={workTypeOptions}
                            placeholder="Select Type..."
                            isLoading={isLoadingReferences}
                          />
                        </td>
                        {DAYS.map(day => (
                          <td key={day} className="p-2 align-top">
                            <input 
                              type="number" 
                              min="0" max="24" step="0.25"
                              value={row.hours[day]}
                              onChange={e => updateHours(row.id, day, e.target.value)}
                              className="no-spinners w-full bg-slate-900/50 border border-slate-600 rounded p-1.5 text-sm text-center focus:border-blue-500 focus:bg-slate-900 outline-none transition-all placeholder-slate-600"
                              placeholder="-"
                            />
                          </td>
                        ))}
                        <td className="p-2 text-center align-middle bg-slate-800/30">
                          <span className={`font-mono text-sm font-semibold ${rowTotal > 0 ? 'text-blue-400' : 'text-slate-600'}`}>
                            {rowTotal > 0 ? rowTotal.toFixed(2) : '-'}
                          </span>
                        </td>
                        <td className="p-2 text-center align-middle sticky right-0 bg-slate-900/80 border-l border-slate-700/50">
                          <button onClick={() => removeRow(row.id)} className="text-slate-400 hover:text-red-400 hover:bg-red-400/10 p-1.5 rounded-lg transition-colors" title="Remove Row">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
                <tfoot className="bg-slate-800/80 border-t-2 border-slate-700">
                  <tr>
                    <td colSpan={3} className="p-3 text-right text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      Daily Totals
                    </td>
                    {DAYS.map(day => {
                      const dayTotal = getDayTotal(day);
                      return (
                        <td key={day} className="p-3 text-center align-middle">
                          <span className={`font-mono text-sm font-bold ${dayTotal > 0 ? 'text-slate-200' : 'text-slate-600'}`}>
                            {dayTotal > 0 ? dayTotal.toFixed(2) : '-'}
                          </span>
                        </td>
                      );
                    })}
                    <td className="p-3 text-center align-middle bg-blue-500/10 border-l border-r border-slate-700">
                      <span className="font-mono text-sm font-bold text-blue-400">
                        {getWeeklyTotal() > 0 ? getWeeklyTotal().toFixed(2) : '-'}
                      </span>
                    </td>
                    <td></td>
                  </tr>
                  <tr className="border-t border-slate-700/50">
                    <td colSpan={12} className="p-2">
                      <button onClick={addRow} className="flex items-center gap-2 px-4 py-2 text-sm text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 rounded-lg transition-colors">
                        <Plus className="w-4 h-4" /> Add Row
                      </button>
                    </td>
                  </tr>
                </tfoot>
              </table>
            </div>
          </div>
        </div>

        {/* Submit Actions */}
        <div className="flex justify-between items-center pt-4">
          <button 
            onClick={resetHours} 
            disabled={isSubmitting || isLoadingWeek}
            className="flex items-center gap-2 px-6 py-3 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-medium transition-all"
          >
            <RotateCcw className="w-4 h-4" />
            Reset Hours
          </button>
          
          <button 
            onClick={submitTimesheet} 
            disabled={isSubmitting || isLoadingWeek}
            className="flex items-center gap-2 px-8 py-3 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl font-semibold shadow-lg shadow-emerald-900/20 transition-all active:scale-95"
          >
            {isSubmitting ? <Loader2 className="w-5 h-5 animate-spin" /> : <Send className="w-5 h-5" />}
            Submit Timesheet for Week
          </button>
        </div>

        </> /* end timesheet tab */}

      </div>
    </div>
  );
}