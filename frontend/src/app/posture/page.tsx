"use client";

import React, { useState } from 'react';
import { TrendingUp, TrendingDown, Minus, ChevronUp, ChevronDown } from 'lucide-react';
import useSWR from 'swr';

const fetcher = (url: string) => fetch(url).then(r => r.json());

// ─── Types ───────────────────────────────────────────────

interface PostureScore {
  composite: number;
  domains: Record<string, number>;
  last_evaluated: number;
}

interface PostureDomain {
  id: string;
  name: string;
  weight: number;
  score: number;
  description: string;
  top_findings: string[];
  trend: 'up' | 'down' | 'stable';
}

interface PostureDomainsResponse {
  domains: PostureDomain[];
}

interface MitreTechnique {
  id: string;
  name: string;
  coverage: 'covered' | 'partial' | 'blind';
  tools?: string[];
  fix?: string;
  campaign_linked?: boolean;
}

interface MitreTactic {
  tactic: string;
  techniques: MitreTechnique[];
}

interface PostureCoverageResponse {
  tactics: MitreTactic[];
}

interface RemediationFinding {
  id: string;
  domain: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  effort: 'low' | 'medium' | 'high';
  priority: number;
  linked_campaigns: string[];
  linked_techniques: string[];
  status: string;
}

interface RemediationResponse {
  findings: RemediationFinding[];
}

interface HistoryPoint {
  date: string;
  score: number;
}

interface HistoryResponse {
  data_points: HistoryPoint[];
}

// ─── Sub-components ──────────────────────────────────────

function ScoreGauge({ score }: { score: number }) {
  const color = score > 80 ? '#10b981' : score > 60 ? '#fbbf24' : '#f43f5e';
  const shadow = score > 80 ? 'rgba(16,185,129,0.5)' : score > 60 ? 'rgba(251,191,36,0.5)' : 'rgba(244,63,94,0.5)';
  const circumference = 2 * Math.PI * 40;
  const offset = circumference * (1 - score / 100);

  return (
    <div className="flex flex-col items-end">
      <div className="relative inline-flex items-center justify-center">
        <svg width="80" height="80" className="-rotate-90">
          <circle cx="40" cy="40" r="34" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="6" />
          <circle
            cx="40" cy="40" r="34" fill="none"
            stroke={color}
            strokeWidth="6"
            strokeDasharray={`${2 * Math.PI * 34}`}
            strokeDashoffset={`${(2 * Math.PI * 34) * (1 - score / 100)}`}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 1s ease-out', filter: `drop-shadow(0 0 6px ${shadow})` }}
          />
        </svg>
        <span
          className="absolute text-2xl font-bold"
          style={{ color }}
        >
          {Math.round(score)}
        </span>
      </div>
    </div>
  );
}

function TrendIcon({ trend }: { trend: 'up' | 'down' | 'stable' }) {
  if (trend === 'up') return <TrendingUp className="w-3.5 h-3.5 text-emerald-400" />;
  if (trend === 'down') return <TrendingDown className="w-3.5 h-3.5 text-red-400" />;
  return <Minus className="w-3.5 h-3.5 text-slate-400" />;
}

function SeverityBadge({ severity }: { severity: RemediationFinding['severity'] }) {
  const map: Record<string, string> = {
    critical: 'bg-red-500/15 text-red-400 border-red-500/30',
    high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    low: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
  };
  return (
    <span className={`px-2 py-0.5 rounded border text-[10px] font-bold uppercase ${map[severity] ?? map.low}`}>
      {severity}
    </span>
  );
}

function EffortTag({ effort }: { effort: RemediationFinding['effort'] }) {
  const map: Record<string, string> = {
    low: 'text-emerald-400',
    medium: 'text-yellow-400',
    high: 'text-red-400',
  };
  return <span className={`text-[10px] font-mono ${map[effort] ?? 'text-slate-400'}`}>{effort} effort</span>;
}

function CoverageDot({ coverage }: { coverage: MitreTechnique['coverage'] }) {
  const colors: Record<string, string> = {
    covered: 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.6)]',
    partial: 'bg-yellow-400 shadow-[0_0_6px_rgba(251,191,36,0.5)]',
    blind: 'bg-red-500 shadow-[0_0_6px_rgba(244,63,94,0.5)]',
  };
  return <span className={`inline-block w-2.5 h-2.5 rounded-sm ${colors[coverage]}`} title={coverage} />;
}

// ─── Sparkline from history data ─────────────────────────

function Sparkline({ data }: { data: HistoryPoint[] }) {
  if (!data.length) return null;
  const scores = data.map(d => d.score);
  const min = Math.min(...scores);
  const max = Math.max(...scores);
  const range = max - min || 1;
  const w = 400;
  const h = 120;
  const pad = 10;

  const points = scores.map((s, i) => {
    const x = pad + (i / (scores.length - 1)) * (w - pad * 2);
    const y = h - pad - ((s - min) / range) * (h - pad * 2);
    return `${x},${y}`;
  }).join(' ');

  const areaPoints = `${pad},${h - pad} ${points} ${w - pad},${h - pad}`;

  return (
    <svg className="w-full h-full" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <defs>
        <linearGradient id="sparkGrad" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="#00f2ff" stopOpacity="0.35" />
          <stop offset="100%" stopColor="#00f2ff" stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={areaPoints} fill="url(#sparkGrad)" />
      <polyline points={points} fill="none" stroke="#00f2ff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
      {/* Current score dot */}
      <circle
        cx={w - pad}
        cy={h - pad - ((scores[scores.length - 1] - min) / range) * (h - pad * 2)}
        r="4"
        fill="#00f2ff"
        className="animate-ping"
        style={{ filter: 'drop-shadow(0 0 5px #00f2ff)' }}
      />
    </svg>
  );
}

// ─── Skeleton ────────────────────────────────────────────

function SkeletonBlock({ className }: { className?: string }) {
  return <div className={`animate-pulse bg-slate-800/60 rounded ${className}`} />;
}

// ─── Sort state for remediation ──────────────────────────

type SortKey = 'priority' | 'severity' | 'effort';

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const EFFORT_ORDER: Record<string, number> = { low: 0, medium: 1, high: 2 };

export default function PosturePage() {
  const [sortKey, setSortKey] = useState<SortKey>('priority');
  const [sortAsc, setSortAsc] = useState(true);

  const { data: scoreData, isLoading: scoreLoading } = useSWR<PostureScore>(
    '/api/proxy/api/v1/posture/score', fetcher, { refreshInterval: 10000 }
  );
  const { data: domainsData, isLoading: domainsLoading } = useSWR<PostureDomainsResponse>(
    '/api/proxy/api/v1/posture/domains', fetcher, { refreshInterval: 10000 }
  );
  const { data: coverageData, isLoading: coverageLoading } = useSWR<PostureCoverageResponse>(
    '/api/proxy/api/v1/posture/coverage', fetcher, { refreshInterval: 30000 }
  );
  const { data: remediationData, isLoading: remediationLoading } = useSWR<RemediationResponse>(
    '/api/proxy/api/v1/posture/remediation', fetcher, { refreshInterval: 10000 }
  );
  const { data: historyData, isLoading: historyLoading } = useSWR<HistoryResponse>(
    '/api/proxy/api/v1/posture/history', fetcher, { refreshInterval: 60000 }
  );

  const score = scoreData ?? { composite: 0, domains: {}, last_evaluated: 0 };
  const domains = domainsData?.domains ?? [];
  const tactics = coverageData?.tactics ?? [];
  const findings = remediationData?.findings ?? [];
  const historyPoints = historyData?.data_points ?? [];

  const compositeScore = score.composite ?? 0;
  const scoreColor = compositeScore > 80 ? 'text-emerald-400' : compositeScore > 60 ? 'text-yellow-400' : 'text-red-400';

  // Sort remediation findings
  const sortedFindings = [...findings].sort((a, b) => {
    let cmp = 0;
    if (sortKey === 'priority') cmp = a.priority - b.priority;
    else if (sortKey === 'severity') cmp = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    else if (sortKey === 'effort') cmp = EFFORT_ORDER[a.effort] - EFFORT_ORDER[b.effort];
    return sortAsc ? cmp : -cmp;
  });

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc(p => !p);
    else { setSortKey(key); setSortAsc(true); }
  };

  const SortIcon = ({ k }: { k: SortKey }) =>
    sortKey === k
      ? (sortAsc ? <ChevronUp className="w-3 h-3 inline ml-1" /> : <ChevronDown className="w-3 h-3 inline ml-1" />)
      : null;

  return (
    <div className="flex-1 overflow-auto custom-scrollbar p-6">
      <div className="max-w-7xl mx-auto space-y-8">

        {/* ── Hero: Composite Score + 30-day Sparkline ── */}
        <section className="space-y-4">
          <div className="flex justify-between items-end">
            <div>
              <h2 className="text-2xl font-bold text-white drop-shadow-[0_0_10px_rgba(0,242,255,0.6)]">
                Network Posture
              </h2>
              <p className="text-slate-400 text-sm">Real-time integrity mesh</p>
            </div>
            <div className="text-right flex items-center gap-4">
              {scoreLoading ? (
                <SkeletonBlock className="w-24 h-10" />
              ) : (
                <>
                  <span className={`text-5xl font-bold drop-shadow-[0_0_10px_rgba(0,242,255,0.6)] ${scoreColor}`}>
                    {Math.round(compositeScore)}
                  </span>
                  <ScoreGauge score={compositeScore} />
                </>
              )}
            </div>
          </div>

          {/* 30-day Sparkline */}
          <div className="bg-brand-card/70 backdrop-blur-md rounded-2xl p-4 min-h-[180px] relative overflow-hidden border border-brand-accent/20 shadow-[0_4px_30px_rgba(0,0,0,0.5),inset_0_0_10px_rgba(0,242,255,0.05)]">
            <div className="absolute inset-0 opacity-10 bg-[linear-gradient(rgba(0,242,255,0.2)_1px,transparent_1px),linear-gradient(90deg,rgba(0,242,255,0.2)_1px,transparent_1px)] bg-[size:20px_20px]" />
            <div className="relative z-10 w-full h-36">
              {historyLoading
                ? <SkeletonBlock className="w-full h-full" />
                : <Sparkline data={historyPoints} />
              }
            </div>
            <div className="flex justify-between mt-2">
              {historyPoints.length > 0 && [0, Math.floor(historyPoints.length / 4), Math.floor(historyPoints.length / 2), Math.floor(3 * historyPoints.length / 4), historyPoints.length - 1].map(i => (
                <span key={i} className="text-[10px] text-slate-500 font-bold uppercase tracking-tighter">
                  {historyPoints[i]?.date?.slice(5) ?? ''}
                </span>
              ))}
            </div>
          </div>
        </section>

        {/* ── Domain Cards ── */}
        <section className="space-y-4">
          <h3 className="text-xs font-black uppercase tracking-[0.2em] text-brand-accent/80">Security Domains</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
            {domainsLoading
              ? Array.from({ length: 5 }).map((_, i) => (
                  <SkeletonBlock key={i} className="h-40 rounded-xl" />
                ))
              : domains.map((domain) => {
                  const domainScore = domain.score ?? 0;
                  const ringColor = domainScore > 80 ? '#10b981' : domainScore > 60 ? '#fbbf24' : '#f43f5e';
                  const dashOffset = 100 - domainScore;
                  return (
                    <div key={domain.id} className="bg-brand-card/70 backdrop-blur-md border border-brand-accent/20 shadow-[0_0_15px_rgba(0,242,255,0.08)] rounded-xl p-4 flex flex-col gap-3 hover:-translate-y-1 transition-transform">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-bold uppercase text-slate-400 tracking-wider">{domain.name}</span>
                        <TrendIcon trend={domain.trend} />
                      </div>
                      {/* Score ring */}
                      <div className="relative w-16 h-16 mx-auto">
                        <svg className="w-16 h-16 -rotate-90" viewBox="0 0 36 36">
                          <circle cx="18" cy="18" r="16" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="3" />
                          <circle
                            cx="18" cy="18" r="16" fill="none"
                            stroke={ringColor}
                            strokeWidth="3"
                            strokeDasharray="100"
                            strokeDashoffset={dashOffset}
                            style={{ transition: 'stroke-dashoffset 1s ease-out' }}
                          />
                        </svg>
                        <div className="absolute inset-0 flex items-center justify-center font-bold text-lg text-white">
                          {Math.round(domainScore)}
                        </div>
                      </div>
                      {/* Score bar */}
                      <div className="h-1.5 bg-brand-accent/10 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-1000"
                          style={{ width: `${domainScore}%`, backgroundColor: ringColor }}
                        />
                      </div>
                      {/* Top finding */}
                      {domain.top_findings?.[0] && (
                        <p className="text-[9px] text-slate-500 leading-tight line-clamp-2">{domain.top_findings[0]}</p>
                      )}
                    </div>
                  );
                })
            }
          </div>
        </section>

        {/* ── MITRE ATT&CK Coverage Heatmap ── */}
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-black uppercase tracking-[0.2em] text-brand-accent/80">MITRE ATT&amp;CK Coverage</h3>
            <div className="flex items-center gap-4 text-[10px] font-mono">
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-sm bg-emerald-500 inline-block" /> Covered</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-sm bg-yellow-400 inline-block" /> Partial</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-sm bg-red-500 inline-block" /> Blind</span>
            </div>
          </div>
          <div className="bg-brand-card/70 backdrop-blur-md rounded-xl border border-brand-accent/20 p-5 overflow-x-auto">
            {coverageLoading ? (
              <SkeletonBlock className="w-full h-40 rounded" />
            ) : tactics.length === 0 ? (
              <p className="text-slate-500 text-sm text-center py-8">Coverage data unavailable — connect data sources to populate.</p>
            ) : (
              <div className="space-y-4 min-w-[600px]">
                {tactics.map((tactic) => (
                  <div key={tactic.tactic}>
                    <p className="text-[10px] font-bold uppercase text-slate-400 mb-2 tracking-wider">{tactic.tactic}</p>
                    <div className="flex flex-wrap gap-2">
                      {tactic.techniques.map((tech) => (
                        <div
                          key={tech.id}
                          className="flex items-center gap-1.5 bg-brand-dark/60 border border-brand-accent/10 rounded px-2 py-1 hover:border-brand-accent/40 transition-colors cursor-default group relative"
                          title={tech.fix ?? tech.name}
                        >
                          <CoverageDot coverage={tech.coverage} />
                          <span className="text-[9px] font-mono text-slate-300">{tech.id}</span>
                          {tech.campaign_linked && (
                            <span className="text-[8px] text-brand-accent">&#x2605;</span>
                          )}
                          {/* Tooltip */}
                          <div className="absolute bottom-full left-0 mb-1 hidden group-hover:block z-20 bg-brand-dark border border-brand-accent/30 rounded px-2 py-1.5 text-[9px] text-slate-200 whitespace-nowrap shadow-xl">
                            <p className="font-bold">{tech.name}</p>
                            {tech.tools && <p className="text-slate-400">{tech.tools.join(', ')}</p>}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>

        {/* ── Remediation Queue ── */}
        <section className="space-y-4">
          <h3 className="text-xs font-black uppercase tracking-[0.2em] text-brand-accent/80">Remediation Queue</h3>
          <div className="bg-brand-card/70 backdrop-blur-md rounded-xl border border-brand-accent/20 overflow-x-auto">
            <table className="w-full text-left text-[11px] min-w-[600px]">
              <thead>
                <tr className="text-slate-500 border-b border-brand-accent/10 bg-brand-surface/20">
                  <th className="px-4 py-3 font-semibold uppercase tracking-wider cursor-pointer hover:text-slate-300" onClick={() => handleSort('priority')}>
                    # <SortIcon k="priority" />
                  </th>
                  <th className="px-4 py-3 font-semibold uppercase tracking-wider">Finding</th>
                  <th className="px-4 py-3 font-semibold uppercase tracking-wider cursor-pointer hover:text-slate-300" onClick={() => handleSort('severity')}>
                    Severity <SortIcon k="severity" />
                  </th>
                  <th className="px-4 py-3 font-semibold uppercase tracking-wider cursor-pointer hover:text-slate-300" onClick={() => handleSort('effort')}>
                    Effort <SortIcon k="effort" />
                  </th>
                  <th className="px-4 py-3 font-semibold uppercase tracking-wider">Linked</th>
                  <th className="px-4 py-3 font-semibold uppercase tracking-wider">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-brand-accent/5">
                {remediationLoading
                  ? Array.from({ length: 4 }).map((_, i) => (
                      <tr key={i}>
                        {Array.from({ length: 6 }).map((_, j) => (
                          <td key={j} className="px-4 py-3"><SkeletonBlock className="h-4 w-full" /></td>
                        ))}
                      </tr>
                    ))
                  : sortedFindings.map((f) => (
                      <tr key={f.id} className="hover:bg-brand-accent/5 transition-colors">
                        <td className="px-4 py-3 font-mono text-slate-500">{f.priority}</td>
                        <td className="px-4 py-3">
                          <p className="text-white font-medium">{f.title}</p>
                          <p className="text-slate-500 text-[10px] mt-0.5 line-clamp-1">{f.description}</p>
                        </td>
                        <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                        <td className="px-4 py-3"><EffortTag effort={f.effort} /></td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {f.linked_campaigns.slice(0, 2).map(c => (
                              <span key={c} className="text-[9px] bg-brand-accent/10 text-brand-accent border border-brand-accent/20 px-1.5 py-0.5 rounded font-mono">{c}</span>
                            ))}
                            {f.linked_techniques.slice(0, 1).map(t => (
                              <span key={t} className="text-[9px] bg-slate-700/60 text-slate-300 border border-slate-600/40 px-1.5 py-0.5 rounded font-mono">{t}</span>
                            ))}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-[10px] font-bold uppercase ${
                            f.status === 'open' ? 'text-red-400' :
                            f.status === 'in_progress' ? 'text-yellow-400' :
                            'text-emerald-400'
                          }`}>
                            {f.status.replace('_', ' ')}
                          </span>
                        </td>
                      </tr>
                    ))
                }
              </tbody>
            </table>
            {!remediationLoading && sortedFindings.length === 0 && (
              <p className="text-slate-500 text-sm text-center py-8">No remediation items — posture is clean.</p>
            )}
          </div>
        </section>

      </div>
    </div>
  );
}
