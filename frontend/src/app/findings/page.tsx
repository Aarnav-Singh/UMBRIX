"use client";

import React, { useState } from 'react';
import { Target, ExternalLink, Database, Clock, ShieldAlert, Users, Server, UserPlus, Zap, Filter, Radio, Brain, Bug } from 'lucide-react';
import useSWR from 'swr';

const fetcher = (url: string) => fetch(url).then(r => r.json());

// ─── Types ───────────────────────────────────────────────

interface CveContext {
  cve_id: string;
  cvss_score?: number;
  severity?: string;
  description?: string;
  patch_available?: boolean;
}

interface TriageResult {
  severity: string;
  confidence: number;
  summary: string;
  recommended_action: string;
  tools_used: string[];
}

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
  cve_context?: CveContext[];
  triage_result?: TriageResult;
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
  critical: { label: 'CRITICAL', border: 'var(--sf-critical)', text: 'text-sf-critical', bg: 'bg-sf-critical/10 border-sf-critical/30' },
  high: { label: 'HIGH', border: 'var(--sf-warning)', text: 'text-sf-warning', bg: 'bg-sf-warning/10 border-sf-warning/30' },
  medium: { label: 'MEDIUM', border: 'var(--sf-accent-2)', text: 'text-sf-accent-2', bg: 'bg-sf-accent-2/10 border-sf-accent-2/30' },
  low: { label: 'LOW', border: 'var(--sf-muted)', text: 'text-sf-muted', bg: 'bg-sf-surface border-sf-border' },
};

const STATUS_MAP = {
  open: 'text-sf-warning',
  new: 'text-sf-accent',
  approved: 'text-sf-safe',
  dismissed: 'text-sf-muted line-through',
  escalated: 'text-sf-critical',
};

function SkeletonCard() {
  return (
    <div className="py-4 border-b border-white/5 animate-pulse space-y-3">
      <div className="h-4 bg-sf-surface rounded w-3/4" />
      <div className="h-3 bg-sf-surface/80 rounded w-full" />
      <div className="flex gap-4">
        <div className="h-3 bg-sf-surface/80 rounded w-24" />
        <div className="h-3 bg-sf-surface/80 rounded w-16" />
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

async function triggerAiTriage(id: string): Promise<TriageResult | null> {
  try {
    const res = await fetch('/api/proxy/api/v1/agents/triage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_id: id }),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export default function FindingsPage() {
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [verdictPending, setVerdictPending] = useState<Record<string, string>>({});
  const [localStatuses, setLocalStatuses] = useState<Record<string, Finding['status']>>({});
  const [triageResults, setTriageResults] = useState<Record<string, TriageResult>>({});
  const [triagePending, setTriagePending] = useState<Record<string, boolean>>({});

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
              <h1 className="text-2xl font-bold text-sf-text tracking-tight flex items-center gap-3">
                  <Target className="w-6 h-6 text-sf-critical motion-safe:animate-pulse" />
                  Threat Vectors
              </h1>
              <p className="text-sm text-sf-muted mt-1">Review and triage incoming security events</p>
            </div>
            <span className="text-sf-accent-2 text-[10px] uppercase font-bold tracking-widest bg-sf-accent-2/10 px-3 py-1.5 rounded-full border border-sf-accent-2/30 motion-safe:animate-pulse hidden md:inline-flex items-center gap-2 shadow-[0_0_15px_var(--sf-accent-2)]">
              <span className="flex size-1.5 bg-sf-accent-2 rounded-full" />
              LIVE_FEED.SYS
            </span>
          </header>

          {/* Hologram Section for Global Status (Borderless) */}
          <div className="py-6 border-b border-sf-accent/20 relative group">
            <div className="flex justify-between items-start mb-6 relative z-10">
              <div>
                <p className="text-sf-muted text-[10px] font-medium uppercase tracking-widest">Global Status</p>
                <p className="text-4xl font-display font-light text-sf-text mt-1">
                  {criticalCount > 0 ? 'Elevated Risk' : 'Nominal'}
                </p>
              </div>
              {criticalCount > 0 && (
                <div className="text-sf-critical text-2xl font-display font-light motion-safe:animate-pulse">
                  {criticalCount} <span className="text-[10px] uppercase font-bold tracking-widest text-sf-muted ml-1">CRITICAL</span>
                </div>
              )}
            </div>

            {/* Dynamic 3D Radar Threat Plot View */}
             <div className="relative h-28 w-full flex items-center mb-6 overflow-hidden bg-sf-surface/30 rounded-xl border border-sf-border shadow-inner">
                 <svg className="w-full h-full text-sf-accent/30 stroke-current text-opacity-10" fill="none">
                    {/* Grid lines */}
                    <line x1="0" y1="25%" x2="100%" y2="25%" strokeWidth="1" strokeDasharray="2 4" opacity="0.5" />
                    <line x1="0" y1="50%" x2="100%" y2="50%" strokeWidth="1" strokeDasharray="4 4" />
                    <line x1="0" y1="75%" x2="100%" y2="75%" strokeWidth="1" strokeDasharray="2 4" opacity="0.5" />

                    <line x1="25%" y1="0" x2="25%" y2="100%" strokeWidth="1" strokeDasharray="2 4" opacity="0.5" />
                    <line x1="50%" y1="0" x2="50%" y2="100%" strokeWidth="1" strokeDasharray="4 4" />
                    <line x1="75%" y1="0" x2="75%" y2="100%" strokeWidth="1" strokeDasharray="2 4" opacity="0.5" />

                    {/* Threat Nodes */}
                    {findings.map((f, i) => {
                      // Pseudo-random deterministic placement based on ID
                      const seed1 = f.id.charCodeAt(0) || 0;
                      const seed2 = f.id.charCodeAt(f.id.length - 1) || 0;
                      const x = `${10 + (Math.abs(Math.sin(seed1 * i)) * 80)}%`;
                      const y = `${10 + (Math.abs(Math.cos(seed2 * i)) * 80)}%`;
                      
                      const color = SEVERITY_MAP[f.severity]?.border || 'var(--sf-accent)';

                      return (
                         <circle 
                            key={f.id} 
                            cx={x} 
                            cy={y} 
                            r={f.severity === 'critical' ? '4' : '2'} 
                            fill={color} 
                            className="animate-pulse"
                            style={{ filter: `drop-shadow(0 0 6px ${color})` }}
                          />
                      );
                    })}
                 </svg>
                 <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,transparent_20%,var(--sf-bg)_100%)] pointer-events-none" />
                 
                 <div className="absolute left-4 bottom-2 flex gap-6 z-10 bg-sf-bg/80 px-3 py-1 rounded border border-sf-accent/20 backdrop-blur-sm">
                    <div className="text-[10px] font-mono font-medium text-sf-accent">NODE_ALPHA: ACTIVE</div>
                    <div className="text-[10px] font-mono font-medium text-sf-accent">THREAT_NODES: {findings.length}</div>
                 </div>
            </div>
          </div>

          {/* Filters + Triage */}
          <section className="space-y-4 pt-6 mt-6 border-t border-sf-border">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sf-text text-lg font-bold">Findings Triage</h3>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[10px] bg-sf-accent-2/10 text-sf-accent-2 px-2 py-1 rounded border border-sf-accent-2/30 font-bold tracking-widest">
                  NEW ({newCount})
                </span>
                {/* Severity filter */}
                <div className="flex items-center gap-1.5 bg-sf-surface border border-sf-border shadow-inner rounded-lg px-3 py-1.5">
                  <Filter className="w-3.5 h-3.5 text-sf-muted" />
                  <select
                    value={severityFilter}
                    onChange={e => setSeverityFilter(e.target.value)}
                    className="bg-transparent text-[11px] font-bold uppercase tracking-wider text-sf-text outline-none cursor-pointer"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                {/* Status filter */}
                <div className="flex items-center gap-1.5 bg-sf-surface border border-sf-border shadow-inner rounded-lg px-3 py-1.5">
                  <select
                    value={statusFilter}
                    onChange={e => setStatusFilter(e.target.value)}
                    className="bg-transparent text-[11px] font-bold uppercase tracking-wider text-sf-text outline-none cursor-pointer"
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
                <div className="py-8 text-center">
                  <Target className="w-10 h-10 text-sf-muted mx-auto mb-3" />
                  <p className="text-sf-muted text-sm font-medium">No findings detected</p>
                  <p className="text-sf-muted text-[10px] mt-1 uppercase tracking-widest">All threat vectors nominal</p>
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
                    className={`py-4 border-b border-white/5 relative group hover:bg-white/5 transition-all cursor-pointer ${isResolved ? 'opacity-60 grayscale-[0.3]' : ''}`}
                  >
                    <div className="flex justify-between items-start mb-2">
                      <h4 className="text-sf-text font-bold text-sm pr-2">{finding.title}</h4>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${sev.bg} ${sev.text}`}>
                          {sev.label}
                        </span>
                        <ExternalLink className="w-4 h-4 text-sf-muted group-hover:text-sf-text transition-colors" />
                      </div>
                    </div>
                    <p className="text-sf-muted text-xs mb-3">{finding.description}</p>

                    {/* CVE Enrichment Badges (Phase 34B) */}
                    {finding.cve_context && finding.cve_context.length > 0 && (
                      <div className="flex flex-wrap gap-2 mb-3">
                        {finding.cve_context.map((cve) => (
                          <div key={cve.cve_id} className="flex items-center gap-1.5 px-2 py-1 bg-sf-accent-2/10 border border-sf-accent-2/30 rounded text-[10px]">
                            <Bug className="w-3 h-3 text-sf-accent-2" />
                            <span className="font-mono font-bold text-sf-accent-2">{cve.cve_id}</span>
                            {cve.cvss_score && (
                              <span className={`px-1.5 py-0.5 rounded font-bold ${
                                cve.cvss_score >= 9 ? 'bg-sf-critical/20 text-sf-critical' : 
                                cve.cvss_score >= 7 ? 'bg-sf-warning/20 text-sf-warning' : 
                                'bg-sf-accent/20 text-sf-accent'
                              }`}>CVSS {cve.cvss_score}</span>
                            )}
                            {cve.patch_available !== undefined && (
                              <span className={`uppercase font-bold ${cve.patch_available ? 'text-sf-safe' : 'text-sf-critical'}`}>
                                {cve.patch_available ? 'PATCHED' : 'UNPATCHED'}
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    )}

                    {/* AI Triage Result (Phase 34A) */}
                    {(triageResults[finding.id] || finding.triage_result) && (
                      <div className="mb-3 p-3 bg-sf-surface border-l-2 border-l-sf-accent border-y border-r border-sf-border rounded-r-lg">
                        <div className="flex items-center gap-2 mb-1">
                          <Brain className="w-3.5 h-3.5 text-sf-accent" />
                          <span className="text-[10px] uppercase font-bold tracking-widest text-sf-accent font-mono z-10">AI TRIAGE</span>
                          <span className="text-[10px] font-mono text-sf-muted">
                            {Math.round(((triageResults[finding.id] || finding.triage_result)?.confidence ?? 0) * 100)}% confidence
                          </span>
                        </div>
                        <p className="text-xs text-sf-text font-mono">{(triageResults[finding.id] || finding.triage_result)?.summary}</p>
                        <p className="text-[10px] text-sf-accent/80 mt-1 font-mono font-medium">
                          → {(triageResults[finding.id] || finding.triage_result)?.recommended_action}
                        </p>
                      </div>
                    )}

                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center gap-4">
                        {finding.ip && (
                          <div className="flex items-center gap-1.5 px-2 py-1 bg-sf-surface rounded border border-sf-border">
                            <Icon className="w-3.5 h-3.5 text-sf-muted" />
                            <span className="text-[10px] text-sf-text font-mono font-bold">{finding.ip}</span>
                          </div>
                        )}
                        {finding.created_at && (
                          <div className="flex items-center gap-1.5">
                            <Clock className="w-3.5 h-3.5 text-sf-muted" />
                            <span className="text-[10px] text-sf-muted font-mono">{timeAgo(finding.created_at).toUpperCase()}</span>
                          </div>
                        )}
                        <span className={`text-[10px] font-bold uppercase tracking-widest ${STATUS_MAP[currentStatus] ?? 'text-sf-muted'}`}>
                          {currentStatus}
                        </span>
                      </div>

                      {/* Verdict buttons */}
                      {!isResolved && (
                        <div className="flex items-center gap-2">
                          {/* AI Triage trigger */}
                          {!triageResults[finding.id] && !finding.triage_result && (
                            <button
                              disabled={!!triagePending[finding.id]}
                              onClick={async () => {
                                setTriagePending(p => ({ ...p, [finding.id]: true }));
                                const result = await triggerAiTriage(finding.id);
                                if (result) setTriageResults(p => ({ ...p, [finding.id]: result }));
                                setTriagePending(p => { const n = { ...p }; delete n[finding.id]; return n; });
                              }}
                              className="text-[10px] uppercase tracking-wider font-bold px-3 py-1.5 rounded bg-sf-accent/10 text-sf-accent border border-sf-accent/30 hover:bg-sf-accent/20 transition-all disabled:opacity-50 flex items-center gap-1.5"
                            >
                              <Brain className="w-3 h-3" />
                              {triagePending[finding.id] ? 'Analyzing...' : 'AI Triage'}
                            </button>
                          )}
                          <button
                            disabled={isPending}
                            onClick={() => handleAction(finding.id, 'approve')}
                            className="text-[10px] uppercase tracking-wider font-bold px-3 py-1.5 rounded bg-sf-safe/10 text-sf-safe border border-sf-safe/30 hover:bg-sf-safe/20 transition-all disabled:opacity-50"
                          >
                            {verdictPending[finding.id] === 'approve' ? '...' : 'Approve'}
                          </button>
                          <button
                            disabled={isPending}
                            onClick={() => handleAction(finding.id, 'dismiss')}
                            className="text-[10px] uppercase tracking-wider font-bold px-3 py-1.5 rounded bg-sf-muted/10 text-sf-muted border border-sf-muted/30 hover:bg-sf-surface transition-all disabled:opacity-50"
                          >
                            {verdictPending[finding.id] === 'dismiss' ? '...' : 'Dismiss'}
                          </button>
                          <button
                            disabled={isPending}
                            onClick={() => handleAction(finding.id, 'escalate')}
                            className="text-[10px] uppercase tracking-wider font-bold px-3 py-1.5 rounded bg-sf-critical/10 text-sf-critical border border-sf-critical/30 hover:bg-sf-critical/20 transition-all shadow-[0_0_10px_var(--sf-critical)] disabled:opacity-50"
                          >
                            {verdictPending[finding.id] === 'escalate' ? '...' : 'Escalate'}
                          </button>
                        </div>
                      )}
                    </div>

                    {/* Background large icon */}
                    <div className="absolute -right-4 -bottom-4 opacity-5 group-hover:opacity-10 transition-opacity pointer-events-none z-0">
                      <Target className="w-24 h-24" style={{ color: sev.border }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </section>
        </div>

        <div className="lg:w-1/3 flex flex-col pt-[60px]">
          <div className="sticky top-6 relative overflow-hidden pl-8 border-l border-white/5">

            <div className="flex items-center gap-4 mb-6 relative z-10">
              <div className="w-12 h-12 rounded-lg bg-sf-accent/10 flex items-center justify-center border border-sf-accent/30 shadow-[0_0_15px_var(--sf-accent)]">
                <Radio className="w-6 h-6 text-sf-accent" />
              </div>
              <div>
                <h4 className="text-sf-text font-bold text-lg">Node Analysis</h4>
                <p className="text-[10px] text-sf-muted font-mono uppercase tracking-widest mt-1">
                  {findings.length} FINDINGS TOTAL
                </p>
              </div>
            </div>

            {/* 3D Wireframe Server Visualization */}
            <div className="w-full h-56 relative overflow-hidden flex items-center justify-center mb-6 group">
              <div className="absolute inset-0 bg-gradient-radial from-sf-accent-2/5 via-transparent to-transparent" />

              <div className="relative w-32 h-32 flex flex-col items-center justify-center -mt-4 transition-transform duration-700 group-hover:scale-110">
                <div className="w-24 h-24 border border-sf-accent-2/40 rotate-45 flex items-center justify-center relative shadow-[inset_0_0_20px_rgba(6,182,212,0.1)]">
                  <div className="w-16 h-16 border border-sf-accent-2/60 
                                  absolute motion-safe:animate-pulse" />
                  <div className="w-full h-[1px] bg-sf-accent-2/20 absolute top-1/2 -translate-y-1/2" />
                  <div className="w-[1px] h-full bg-sf-accent-2/20 absolute left-1/2 -translate-x-1/2" />
                  <Server className="w-8 h-8 text-sf-accent-2 -rotate-45 relative z-10 drop-shadow-[0_0_10px_var(--sf-accent-2)]" />
                </div>
                <div className="absolute -bottom-8 text-[10px] font-mono font-medium text-sf-accent-2 motion-safe:animate-pulse">WIRE_FRAME: RENDERED</div>
              </div>
            </div>

            {/* Summary stats */}
            <div className="mb-6 grid grid-cols-2 gap-x-8 gap-y-4 relative z-10">
              {(['critical', 'high', 'medium', 'low'] as const).map(s => {
                const cnt = findings.filter(f => f.severity === s).length;
                const sev = SEVERITY_MAP[s];
                return (
                  <div key={s} className="flex flex-col border-b border-white/5 pb-2">
                    <p className={`text-2xl font-display font-light ${sev.text}`}>{cnt}</p>
                    <p className="text-[9px] uppercase font-medium tracking-widest text-sf-muted mt-0.5">{s}</p>
                  </div>
                );
              })}
            </div>

            <div className="flex flex-col gap-3 relative z-10">
              <button className="w-full flex items-center justify-center gap-2 py-3.5 rounded-xl bg-sf-surface-raised border border-sf-border font-bold text-xs uppercase tracking-wider hover:bg-sf-surface transition-colors text-sf-text">
                <UserPlus className="w-4 h-4 text-sf-muted" />
                Assign Incident
              </button>
              <button className="w-full flex items-center justify-center gap-2 py-3.5 rounded-xl bg-sf-accent text-sf-bg font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_var(--sf-accent)] hover:shadow-[0_0_30px_var(--sf-accent)] hover:bg-sf-accent-2 transition-all">
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
