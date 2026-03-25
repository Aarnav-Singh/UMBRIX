"use client";

import React, { useState } from 'react';
import { Target, ExternalLink, Database, Clock, ShieldAlert, Users, Server, UserPlus, Zap, Filter, Radio } from 'lucide-react';
import useSWR from 'swr';

const fetcher = (url: string) => fetch(url).then(r => r.json());

// ─── Types ───────────────────────────────────────────────

interface Finding {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source?: string;
  status: 'open' | 'approved' | 'dismissed' | 'escalated' | 'new';
  created_at?: string;
  ip?: string;
  domain?: string;
  linked_techniques?: string[];
}

interface FindingsResponse {
  findings?: Finding[];
}

// ─── Helpers ─────────────────────────────────────────────

function timeAgo(iso?: string): string {
  if (!iso) return '';
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  return `${Math.round(diff / 3600)}h ago`;
}

const SEVERITY_MAP = {
  critical: { label: 'CRITICAL', border: '#ef4444', text: 'text-[#ef4444]', bg: 'bg-[#ef4444]/10 border-[#ef4444]/30' },
  high: { label: 'HIGH', border: '#f59e0b', text: 'text-[#f59e0b]', bg: 'bg-[#f59e0b]/10 border-[#f59e0b]/30' },
  medium: { label: 'MEDIUM', border: '#8b5cf6', text: 'text-[#8b5cf6]', bg: 'bg-[#8b5cf6]/10 border-[#8b5cf6]/30' },
  low: { label: 'LOW', border: '#64748b', text: 'text-slate-400', bg: 'bg-slate-500/10 border-slate-500/30' },
};

const STATUS_MAP = {
  open: 'text-[#f59e0b]',
  new: 'text-[#06b6d4]',
  approved: 'text-[#10b981]',
  dismissed: 'text-slate-500 line-through',
  escalated: 'text-[#ef4444]',
};

function SkeletonCard() {
  return (
    <div className="glass-card rounded-xl p-4 border border-slate-700/50 animate-pulse space-y-3">
      <div className="h-4 bg-slate-800 rounded w-3/4" />
      <div className="h-3 bg-slate-800/80 rounded w-full" />
      <div className="flex gap-4">
        <div className="h-3 bg-slate-800/80 rounded w-24" />
        <div className="h-3 bg-slate-800/80 rounded w-16" />
      </div>
    </div>
  );
}

// ─── Action POST ─────────────────────────────────────────

async function postAction(id: string, action: 'approve' | 'dismiss' | 'escalate', feedback?: string) {
  const res = await fetch(`/api/proxy/api/v1/findings/${id}/action`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, feedback }),
  });
  if (!res.ok) throw new Error(`Action failed: ${res.status}`);
  return res.json();
}

export default function FindingsPage() {
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [verdictPending, setVerdictPending] = useState<Record<string, string>>({});
  const [localStatuses, setLocalStatuses] = useState<Record<string, Finding['status']>>({});

  const { data, isLoading, mutate } = useSWR<FindingsResponse | Finding[]>(
    '/api/proxy/api/v1/findings',
    fetcher,
    { refreshInterval: 10000 }
  );

  // Normalise: API may return array or { findings: [] }
  let findings: Finding[] = [];
  if (data) {
    if (Array.isArray(data)) {
      findings = data;
    } else if ((data as FindingsResponse).findings) {
      findings = (data as FindingsResponse).findings!;
    }
  }

  // Apply local status overrides (from verdict actions)
  findings = findings.map(f => localStatuses[f.id] ? { ...f, status: localStatuses[f.id] } : f);

  // Apply filters
  const filtered = findings.filter(f => {
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
    if (statusFilter !== 'all' && f.status !== statusFilter) return false;
    return true;
  });

  const newCount = findings.filter(f => f.status === 'open' || f.status === 'new').length;
  const criticalCount = findings.filter(f => f.severity === 'critical').length;

  const handleAction = async (id: string, action: 'approve' | 'dismiss' | 'escalate') => {
    setVerdictPending(p => ({ ...p, [id]: action }));
    try {
      await postAction(id, action);
      const newStatus: Finding['status'] = action === 'approve' ? 'approved' : action === 'dismiss' ? 'dismissed' : 'escalated';
      setLocalStatuses(p => ({ ...p, [id]: newStatus }));
      mutate();
    } catch {
      // silently keep local state
    } finally {
      setVerdictPending(p => { const n = { ...p }; delete n[id]; return n; });
    }
  };

  const sourceIconMap: Record<string, React.ElementType> = {
    endpoint: Database,
    network: ShieldAlert,
    identity: Users,
    cloud: Server,
  };

  return (
    <div className="flex-1 overflow-auto custom-scrollbar p-6 relative bg-transparent">
      <div className="flex flex-col lg:flex-row gap-6 max-w-7xl mx-auto relative z-10">
        {/* Left Column: Threat Status & Triage */}
        <div className="flex-1 space-y-6">
          <header className="flex justify-between items-end mb-2">
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
                  <Target className="w-6 h-6 text-[#ef4444] animate-pulse" />
                  Threat Vectors
              </h1>
              <p className="text-sm text-slate-400 mt-1">Review and triage incoming security events</p>
            </div>
            <span className="text-[#06b6d4] text-[10px] uppercase font-bold tracking-widest bg-[#06b6d4]/10 px-3 py-1.5 rounded-full border border-[#06b6d4]/30 animate-pulse hidden md:inline-flex items-center gap-2 shadow-[0_0_15px_rgba(6,182,212,0.2)]">
              <span className="flex size-1.5 bg-[#06b6d4] rounded-full" />
              LIVE_FEED.SYS
            </span>
          </header>

          {/* Hologram Card for Global Status */}
          <div className="glass-panel p-6 border border-[#ef4444]/30 shadow-[0_8px_32px_0_rgba(239,68,68,0.15)] relative overflow-hidden group">
            <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(239,68,68,0.05)_0%,rgba(239,68,68,0)_100%)] pointer-events-none" />
            <div className="absolute inset-0 opacity-20 pointer-events-none scan-line" />

            <div className="flex justify-between items-start mb-6 relative z-10">
              <div>
                <p className="text-slate-400 text-xs font-bold uppercase tracking-widest">Global Status</p>
                <p className="text-3xl font-display font-bold text-white mt-1">
                  {criticalCount > 0 ? 'Elevated Risk' : 'Nominal'}
                </p>
              </div>
              {criticalCount > 0 && (
                <div className="bg-[#ef4444]/20 text-[#ef4444] px-3 py-1 rounded text-xs font-bold border border-[#ef4444]/40 animate-pulse shadow-[0_0_10px_#ef4444]">
                  {criticalCount} CRITICAL
                </div>
              )}
            </div>

            {/* Abstract 3D Radar/Target View */}
            <div className="relative h-48 w-full flex items-center justify-center">
              <div className="absolute inset-0 opacity-30 flex items-center justify-center">
                <svg className="w-48 h-48 animate-[spin_20s_linear_infinite]" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="45" fill="none" stroke="#ef4444" strokeWidth="0.5" />
                  <circle cx="50" cy="50" r="30" fill="none" stroke="#ef4444" strokeWidth="0.5" />
                  <circle cx="50" cy="50" r="15" fill="none" stroke="#ef4444" strokeWidth="0.5" />
                  <line x1="50" y1="5" x2="50" y2="95" stroke="#ef4444" strokeWidth="0.5" />
                  <line x1="5" y1="50" x2="95" y2="50" stroke="#ef4444" strokeWidth="0.5" />
                </svg>
              </div>

              <svg className="relative z-10 w-40 h-40 animate-[pulse_4s_ease-in-out_infinite]" fill="none" viewBox="0 0 100 100">
                <polygon points="50,10 85,30 85,70 50,90 15,70 15,30" fill="rgba(239, 68, 68, 0.1)" stroke="#ef4444" strokeWidth="1" />
                <path d="M50 10 L50 90 M15 30 L85 70 M15 70 L85 30" stroke="#ef4444" strokeDasharray="2 2" strokeWidth="0.5" />
                <circle cx="50" cy="30" r="3" fill="#ef4444" className="shadow-[0_0_10px_#ef4444] animate-ping" />
                {criticalCount > 0 && <circle cx="35" cy="65" r="4" fill="#ef4444" className="shadow-[0_0_15px_#ef4444]" />}
              </svg>

              <div className="absolute bottom-0 left-4 right-4 flex justify-between">
                <div className="text-[10px] font-mono font-bold text-[#ef4444]">NODE_ALPHA: ACTIVE</div>
                <div className="text-[10px] font-mono font-bold text-[#ef4444]">FINDINGS: {findings.length}</div>
              </div>
            </div>
          </div>

          {/* Filters + Triage */}
          <section className="space-y-4 pt-6 mt-6 border-t border-slate-700/50">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-white text-lg font-bold">Findings Triage</h3>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[10px] bg-[#06b6d4]/10 text-[#06b6d4] px-2 py-1 rounded border border-[#06b6d4]/30 font-bold tracking-widest">
                  NEW ({newCount})
                </span>
                {/* Severity filter */}
                <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-700 shadow-inner rounded-lg px-3 py-1.5">
                  <Filter className="w-3.5 h-3.5 text-slate-400" />
                  <select
                    value={severityFilter}
                    onChange={e => setSeverityFilter(e.target.value)}
                    className="bg-transparent text-[11px] font-bold uppercase tracking-wider text-slate-300 outline-none cursor-pointer"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                {/* Status filter */}
                <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-700 shadow-inner rounded-lg px-3 py-1.5">
                  <select
                    value={statusFilter}
                    onChange={e => setStatusFilter(e.target.value)}
                    className="bg-transparent text-[11px] font-bold uppercase tracking-wider text-slate-300 outline-none cursor-pointer"
                  >
                    <option value="all">All Statuses</option>
                    <option value="open">Open</option>
                    <option value="new">New</option>
                    <option value="approved">Approved</option>
                    <option value="dismissed">Dismissed</option>
                    <option value="escalated">Escalated</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              {isLoading && (
                <>
                  <SkeletonCard />
                  <SkeletonCard />
                </>
              )}

              {!isLoading && filtered.length === 0 && (
                <div className="glass-card rounded-xl p-8 text-center border border-slate-700/50">
                  <Target className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                  <p className="text-slate-400 text-sm font-medium">No findings detected</p>
                  <p className="text-slate-500 text-xs mt-1">All threat vectors nominal</p>
                </div>
              )}

              {!isLoading && filtered.map((finding) => {
                const sev = SEVERITY_MAP[finding.severity] ?? SEVERITY_MAP.low;
                const Icon = sourceIconMap[finding.source ?? ''] ?? Database;
                const isPending = !!verdictPending[finding.id];
                const currentStatus = localStatuses[finding.id] ?? finding.status;
                const isResolved = currentStatus === 'approved' || currentStatus === 'dismissed';

                return (
                  <div
                    key={finding.id}
                    className={`glass-card p-5 relative overflow-hidden group border border-slate-700/50 hover:border-slate-600 transition-all cursor-pointer shadow-lg ${isResolved ? 'opacity-60 grayscale-[0.3]' : ''}`}
                    style={{ borderLeftWidth: 4, borderLeftColor: sev.border }}
                  >
                    <div className="flex justify-between items-start mb-2">
                      <h4 className="text-white font-bold text-sm pr-2">{finding.title}</h4>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${sev.bg} ${sev.text}`}>
                          {sev.label}
                        </span>
                        <ExternalLink className="w-4 h-4 text-slate-500 group-hover:text-white transition-colors" />
                      </div>
                    </div>
                    <p className="text-slate-400 text-xs mb-4">{finding.description}</p>

                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center gap-4">
                        {finding.ip && (
                          <div className="flex items-center gap-1.5 px-2 py-1 bg-slate-900/50 rounded border border-slate-800">
                            <Icon className="w-3.5 h-3.5 text-slate-400" />
                            <span className="text-[10px] text-slate-300 font-mono font-bold">{finding.ip}</span>
                          </div>
                        )}
                        {finding.created_at && (
                          <div className="flex items-center gap-1.5">
                            <Clock className="w-3.5 h-3.5 text-slate-500" />
                            <span className="text-[10px] text-slate-400 font-mono">{timeAgo(finding.created_at).toUpperCase()}</span>
                          </div>
                        )}
                        <span className={`text-[10px] font-bold uppercase tracking-widest ${STATUS_MAP[currentStatus] ?? 'text-slate-400'}`}>
                          {currentStatus}
                        </span>
                      </div>

                      {/* Verdict buttons */}
                      {!isResolved && (
                        <div className="flex items-center gap-2">
                          <button
                            disabled={isPending}
                            onClick={() => handleAction(finding.id, 'approve')}
                            className="text-[10px] uppercase tracking-wider font-bold px-3 py-1.5 rounded bg-[#10b981]/10 text-[#10b981] border border-[#10b981]/30 hover:bg-[#10b981]/20 transition-all disabled:opacity-50"
                          >
                            {verdictPending[finding.id] === 'approve' ? '...' : 'Approve'}
                          </button>
                          <button
                            disabled={isPending}
                            onClick={() => handleAction(finding.id, 'dismiss')}
                            className="text-[10px] uppercase tracking-wider font-bold px-3 py-1.5 rounded bg-slate-500/10 text-slate-400 border border-slate-500/30 hover:bg-slate-500/20 transition-all disabled:opacity-50"
                          >
                            {verdictPending[finding.id] === 'dismiss' ? '...' : 'Dismiss'}
                          </button>
                          <button
                            disabled={isPending}
                            onClick={() => handleAction(finding.id, 'escalate')}
                            className="text-[10px] uppercase tracking-wider font-bold px-3 py-1.5 rounded bg-[#ef4444]/10 text-[#ef4444] border border-[#ef4444]/30 hover:bg-[#ef4444]/20 transition-all shadow-[0_0_10px_rgba(239,68,68,0.2)] disabled:opacity-50"
                          >
                            {verdictPending[finding.id] === 'escalate' ? '...' : 'Escalate'}
                          </button>
                        </div>
                      )}
                    </div>

                    {/* Background large icon */}
                    <div className="absolute -right-4 -bottom-4 opacity-5 group-hover:opacity-10 transition-opacity">
                      <Target className="w-24 h-24" style={{ color: sev.border }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </section>
        </div>

        {/* Right Column: Node Analysis */}
        <div className="lg:w-1/3 flex flex-col pt-[60px]">
          <div className="glass-panel p-6 border border-slate-700/50 sticky top-6 relative overflow-hidden">
            <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(6,182,212,0.03)_0%,rgba(6,182,212,0)_100%)] pointer-events-none" />

            <div className="flex items-center gap-4 mb-6 relative z-10">
              <div className="w-12 h-12 rounded-lg bg-[#06b6d4]/10 flex items-center justify-center border border-[#06b6d4]/30 shadow-[0_0_15px_rgba(6,182,212,0.2)]">
                <Radio className="w-6 h-6 text-[#06b6d4]" />
              </div>
              <div>
                <h4 className="text-white font-bold text-lg">Node Analysis</h4>
                <p className="text-[10px] text-slate-400 font-mono uppercase tracking-widest mt-1">
                  {findings.length} FINDINGS TOTAL
                </p>
              </div>
            </div>

            {/* 3D Wireframe Server Visualization */}
            <div className="w-full h-56 bg-slate-900 rounded-xl border border-slate-700/50 relative overflow-hidden flex items-center justify-center mb-6 group shadow-inner">
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-[#06b6d4]/10 via-transparent to-transparent" />

              <div className="relative w-32 h-32 flex flex-col items-center justify-center -mt-4 transition-transform duration-700 group-hover:scale-110">
                <div className="w-24 h-24 border-2 border-[#06b6d4]/40 rotate-45 flex items-center justify-center relative shadow-[inset_0_0_20px_rgba(6,182,212,0.2)]">
                  <div className="w-16 h-16 border border-[#06b6d4]/60 absolute animate-pulse" />
                  <div className="w-full h-0.5 bg-[#06b6d4]/20 absolute top-1/2 -translate-y-1/2" />
                  <div className="w-0.5 h-full bg-[#06b6d4]/20 absolute left-1/2 -translate-x-1/2" />
                  <Server className="w-10 h-10 text-[#06b6d4] -rotate-45 relative z-10 drop-shadow-[0_0_10px_rgba(6,182,212,0.8)]" />
                </div>
                <div className="absolute -bottom-8 text-[10px] font-mono font-bold text-[#06b6d4] animate-pulse">WIRE_FRAME: RENDERED</div>
              </div>

              {/* Corner brackets */}
              <div className="absolute w-6 h-6 border-l-2 border-t-2 border-[#06b6d4]/40 top-3 left-3 rounded-tl" />
              <div className="absolute w-6 h-6 border-r-2 border-t-2 border-[#06b6d4]/40 top-3 right-3 rounded-tr" />
              <div className="absolute w-6 h-6 border-l-2 border-b-2 border-[#06b6d4]/40 bottom-3 left-3 rounded-bl" />
              <div className="absolute w-6 h-6 border-r-2 border-b-2 border-[#06b6d4]/40 bottom-3 right-3 rounded-br" />
            </div>

            {/* Summary stats */}
            <div className="mb-6 grid grid-cols-2 gap-3 relative z-10">
              {(['critical', 'high', 'medium', 'low'] as const).map(s => {
                const cnt = findings.filter(f => f.severity === s).length;
                const sev = SEVERITY_MAP[s];
                return (
                  <div key={s} className="rounded-xl p-3 bg-slate-900 border border-slate-700/50 flex flex-col items-center justify-center shadow-inner">
                    <p className={`text-2xl font-display font-bold ${sev.text}`}>{cnt}</p>
                    <p className="text-[9px] uppercase font-bold tracking-widest text-slate-500 mt-1">{s}</p>
                  </div>
                );
              })}
            </div>

            <div className="flex flex-col gap-3 relative z-10">
              <button className="w-full flex items-center justify-center gap-2 py-3.5 rounded-xl bg-slate-800 border border-slate-600 font-bold text-xs uppercase tracking-wider hover:bg-slate-700 transition-colors text-white">
                <UserPlus className="w-4 h-4 text-slate-400" />
                Assign Incident
              </button>
              <button className="w-full flex items-center justify-center gap-2 py-3.5 rounded-xl bg-[#06b6d4] text-slate-950 font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(6,182,212,0.4)] hover:shadow-[0_0_30px_rgba(6,182,212,0.7)] hover:bg-[#0891b2] transition-all">
                <Zap className="w-4 h-4" />
                Start Mitigation
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
