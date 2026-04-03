"use client";

import React, { useState, useEffect } from "react";
import { User, ShieldAlert, Activity, CheckCircle2, XCircle, Terminal } from "lucide-react";
import { api } from "@/lib/api/client";
import { useLiveEvents } from "@/hooks/useLiveEvents";
import useSWR from "swr";
import { ThreatGlobe } from "@/components/features/dashboard/ThreatGlobe";
import { BarChart, Bar, ResponsiveContainer } from "recharts";

// ─── Types & Demos ───────────────────────────────────────────────

interface RemediationFinding { id: string; title: string; severity: 'critical' | 'high' | 'medium' | 'low'; }
interface HistoryPoint { date: string; score: number; }

const DEMO_METRICS = { posture_score: 71, posture_delta: 0, active_campaigns: 24, critical_campaigns: 7, events_per_second: 240, connectors_total: 18, connectors_online: 16, analyst_accuracy: 94.5 };
const DEMO_REMEDIATION: RemediationFinding[] = [
    { id: '1', title: 'Suspicious Execution (cmd.exe)', severity: 'critical' },
    { id: '2', title: 'Unauthorized IAM Role Assigned', severity: 'high' },
    { id: '3', title: 'Geographic Anomaly (Unknown ASN)', severity: 'medium' },
    { id: '4', title: 'Unusual Volume of Outbound Traffic', severity: 'critical' },
];
const DEMO_HISTORY: HistoryPoint[] = Array.from({ length: 30 }, (_, i) => ({
    date: new Date(Date.now() - (29 - i) * 86400000).toISOString().split('T')[0],
    score: 62 + Math.round(Math.sin(i * 0.4) * 7 + i * 0.3) + Math.random() * 5,
}));

const DEMO_LIVE_FEED = [
    { e: 'Authentication Failed', s: 'IDP', d: 'Blocked', icon: User, c: 'text-sf-warning', timeOffset: 5000 },
    { e: 'Firewall Rule Triggered', s: 'WAN', d: 'Logged', icon: ShieldAlert, c: 'text-sf-safe', timeOffset: 12000 },
    { e: 'Suspicious DLL Loaded', s: 'WS-WIN-04', d: 'Alert', icon: XCircle, c: 'text-sf-critical', timeOffset: 25000 },
    { e: 'Network Scan Detected', s: 'DMZ', d: 'Blocked', icon: Activity, c: 'text-sf-warning', timeOffset: 45000 },
];

// ─── Page ─────────────────────────────────────────────────
export default function DashboardPage() {

    // ─── REAL TIME DATA PIPELINE ───────────────────────────────────────────────
    
    // 1. Polled REST Metrics
    const { data: apiMetrics } = useSWR("metrics", api.getMetrics, { refreshInterval: 5000 });
    const { data: apiTimeline } = useSWR("timeline", () => api.getPostureTimeline(24), { refreshInterval: 60000 });
    const { data: apiCampaigns } = useSWR("campaigns", api.getCampaigns, { refreshInterval: 30000 });

    // 2. Local State fallbacks & Live Array
    const [localMetrics, setLocalMetrics] = useState(DEMO_METRICS);
    const [liveFeed, setLiveFeed] = useState<any[]>([]);

    // 3. Seed Live Feed on mount
    useEffect(() => {
        api.getRecentEvents(20)
           .then(data => { if(Array.isArray(data) && data.length > 0) setLiveFeed(data) })
           .catch(() => {}); // silently fail to demo data if backend offline
    }, []);

    // 4. SSE WebSockets for live events
    useLiveEvents({ 
        onEvent: (event: any) => {
            // Update live metrics organically
            if (event.ml_scores && typeof event.ml_scores === "object" && (event.ml_scores as any).meta_score > 0) {
                setLocalMetrics(prev => ({ 
                    ...prev, 
                    posture_score: Math.max(0, Math.min(100, prev.posture_score - (event.posture_delta as number || 0))),
                    events_per_second: prev.events_per_second + 1
                }));
            }
            // Update live terminal array
            if (event.message || event.event_type) {
                setLiveFeed(prev => [event, ...prev].slice(0, 30));
            }
        }
    });

    // 5. Data Resolution (API priority -> Local SSE -> Demo Fallback)
    const metrics = apiMetrics || localMetrics;
    const historyPoints = apiTimeline?.snapshots?.length 
        ? apiTimeline.snapshots.map(s => ({ date: s.timestamp, score: s.score })) 
        : DEMO_HISTORY;
    const findings: RemediationFinding[] = apiCampaigns?.length 
        ? apiCampaigns.map(c => ({ id: c.id, title: c.name, severity: c.severity as 'critical'|'high'|'medium'|'low' })) 
        : DEMO_REMEDIATION;


    return (
        <div className="relative w-full h-screen overflow-hidden bg-sf-bg text-sf-text font-sans">
            {/* BACKGROUND GLOBE MAP (OPEN CANVAS) */}
            <div className="absolute inset-0 z-0">
                <ThreatGlobe />
                {/* Radial fade to seamlessly blend globe into the dark background */}
                <div className="absolute inset-0 z-10 pointer-events-none bg-[radial-gradient(ellipse_at_center,transparent_30%,var(--sf-bg)_100%)] opacity-90" />
            </div>

            <div className="absolute inset-0 z-20 pointer-events-none p-6">
                
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-4">
                    <div className="bg-sf-surface/40 backdrop-blur-md border border-white/5 rounded-xl p-4 flex flex-col justify-center pointer-events-auto transition-transform hover:-translate-y-1 relative overflow-hidden group">
                        <div className="flex items-center gap-2 text-sf-muted text-xs font-medium mb-2 uppercase tracking-widest z-10 relative">
                            <ShieldAlert className="w-4 h-4 text-sf-safe group-hover:text-sf-accent transition-colors" /> Posture Score
                        </div>
                        <div className="text-3xl font-display font-light text-white z-10 relative">
                            {Math.round(metrics.posture_score)}<span className="text-sf-muted text-lg">/100</span>
                        </div>
                        <div className="absolute inset-x-0 bottom-0 h-10 opacity-20 pointer-events-none">
                            <ResponsiveContainer width="100%" height={40}>
                                <BarChart data={historyPoints.slice(-15)}>
                                    <Bar dataKey="score" fill="#14b8a6" radius={[2, 2, 0, 0]} />
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    <div className="bg-sf-surface/40 backdrop-blur-md border border-white/5 rounded-xl p-4 flex flex-col justify-center pointer-events-auto transition-transform hover:-translate-y-1 relative overflow-hidden group">
                        <div className="flex items-center gap-2 text-sf-muted text-xs font-medium mb-2 uppercase tracking-widest z-10 relative">
                            <Activity className="w-4 h-4 text-sf-warning group-hover:text-sf-accent transition-colors" /> Active Campaigns
                        </div>
                        <div className="text-3xl font-display font-light text-white z-10 relative">
                            {metrics.active_campaigns}
                        </div>
                        <div className="absolute right-4 top-1/2 -translate-y-1/2 text-sf-warning/20 pointer-events-none h-12 w-16">
                            <svg viewBox="0 0 100 50" className="w-full h-full fill-none stroke-current" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M0,25 Q10,25 15,10 T30,40 T45,5 T60,25 T100,25" />
                            </svg>
                        </div>
                    </div>

                    <div className="bg-sf-surface/40 backdrop-blur-md border border-white/5 rounded-xl p-4 flex flex-col justify-center pointer-events-auto transition-transform hover:-translate-y-1 relative overflow-hidden group">
                        <div className="flex items-center gap-2 text-sf-muted text-xs font-medium mb-2 uppercase tracking-widest z-10 relative">
                            <XCircle className="w-4 h-4 text-sf-critical group-hover:text-red-400 transition-colors" /> Critical Findings
                        </div>
                        <div className="text-3xl font-display font-light text-sf-critical z-10 relative">
                            {metrics.critical_campaigns}
                        </div>
                        <div className="absolute inset-x-0 bottom-0 h-1 opacity-20 bg-gradient-to-r from-sf-critical/0 via-sf-critical to-sf-critical/0 group-hover:opacity-50 transition-opacity" />
                    </div>

                    <div className="bg-sf-surface/40 backdrop-blur-md border border-white/5 rounded-xl p-4 flex flex-col justify-center pointer-events-auto transition-transform hover:-translate-y-1 relative overflow-hidden group">
                        <div className="flex items-center gap-2 text-sf-muted text-xs font-medium mb-2 uppercase tracking-widest z-10 relative">
                            <Terminal className="w-4 h-4 text-sf-accent group-hover:text-white transition-colors" /> Events/Sec
                        </div>
                        <div className="text-3xl font-display font-light text-white z-10 relative">
                            {metrics.events_per_second || 240}
                        </div>
                        <div className="absolute right-4 top-1/2 -translate-y-1/2 text-sf-accent/10 pointer-events-none h-12 w-16">
                            <div className="w-full h-full border-b border-t border-sf-accent/30 flex items-center justify-center gap-1">
                                <div className="w-1 bg-sf-accent h-[40%] animate-[bounce_1s_infinite]" />
                                <div className="w-1 bg-sf-accent h-[80%] animate-[bounce_1.2s_infinite]" />
                                <div className="w-1 bg-sf-accent h-[50%] animate-[bounce_0.8s_infinite]" />
                                <div className="w-1 bg-sf-accent h-[100%] animate-[bounce_1.1s_infinite]" />
                            </div>
                        </div>
                    </div>

                    <div className="bg-sf-surface/40 backdrop-blur-md border border-white/5 rounded-xl p-4 flex flex-col justify-center pointer-events-auto transition-transform hover:-translate-y-1 relative overflow-hidden group">
                        <div className="flex items-center gap-2 text-sf-muted text-xs font-medium mb-2 uppercase tracking-widest z-10 relative">
                            <CheckCircle2 className="w-4 h-4 text-sf-safe group-hover:text-white transition-colors" /> Integrations
                        </div>
                        <div className="text-3xl font-display font-light text-white z-10 relative">
                            {metrics.connectors_online}<span className="text-sf-muted text-lg">/{metrics.connectors_total}</span>
                        </div>
                        <div className="absolute bottom-0 left-0 w-full h-1 bg-white/5">
                             <div className="h-full bg-sf-safe" style={{ width: `${(metrics.connectors_online / metrics.connectors_total) * 100}%` }} />
                        </div>
                    </div>
                </div>

                {/* BOTTOM FLOATING FINDINGS (Clean Triage List) */}
                <div className="absolute bottom-6 left-6 w-[420px] max-w-[calc(100vw-3rem)] pointer-events-auto">
                    <div className="bg-sf-surface/40 backdrop-blur-md border border-white/5 rounded-xl p-5 shadow-2xl">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-xs font-bold text-white uppercase tracking-widest">Recent Triage Findings</h3>
                            <button className="text-[10px] text-sf-accent hover:text-white transition-colors bg-sf-accent/10 px-2 py-0.5 rounded border border-sf-accent/20">View All</button>
                        </div>
                        <div className="space-y-4">
                            {findings.slice(0,3).map((f, i) => (
                                <div key={i} className="flex flex-col gap-1.5 group cursor-pointer p-2 -mx-2 rounded hover:bg-white/5 transition-colors">
                                    <div className="flex items-start gap-3">
                                        <div className={`mt-0.5 w-2 h-2 rounded-full shadow-[0_0_8px_currentColor] shrink-0 ${f.severity === 'critical' ? 'bg-sf-critical text-sf-critical' : f.severity === 'high' ? 'bg-sf-warning text-sf-warning' : 'bg-sf-safe text-sf-safe'}`} />
                                        <div className="flex-1 min-w-0">
                                            <p className="text-sm text-white/90 font-medium leading-tight truncate group-hover:text-sf-accent transition-colors">{f.title}</p>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-3 pl-5 text-[10px] font-mono text-sf-muted">
                                        <span suppressHydrationWarning>{new Date(Date.now() - (i*1000*60*15)).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
                                        <span className="w-1 h-1 rounded-full bg-sf-muted/50" />
                                        <span className="uppercase">{f.severity}</span>
                                        <span className="w-1 h-1 rounded-full bg-sf-muted/50" />
                                        <span>SRC: 198.51.100.{14 + i}</span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* RIGHT SIDEBAR LIVE TELEMETRY FEED */}
                <div className="absolute right-6 top-28 bottom-6 w-80 pointer-events-auto flex flex-col gap-4 hidden xl:flex">
                    <div className="bg-sf-surface/40 backdrop-blur-md border border-white/5 rounded-xl p-5 flex-1 flex flex-col overflow-hidden shadow-2xl">
                        <h3 className="text-xs font-bold text-white mb-4 uppercase tracking-widest flex items-center justify-between border-b border-white/10 pb-3">
                            Live Telemetry Feed
                            <span className="flex items-center gap-2 text-[10px] text-sf-accent bg-sf-accent/10 px-2 py-0.5 rounded border border-sf-accent/20">
                                <span className="relative flex h-1.5 w-1.5">
                                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sf-accent opacity-75"></span>
                                  <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-sf-accent"></span>
                                </span>
                                STREAMING
                            </span>
                        </h3>
                        
                        <div className="flex-1 overflow-y-auto space-y-3 pr-2 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
                            {liveFeed.length > 0 ? (
                                liveFeed.map((item, i) => (
                                    <div key={i} className="flex gap-3 text-[11px] font-mono leading-tight hover:bg-white/5 p-2 rounded -mx-2 transition-colors cursor-pointer group">
                                        <div className="mt-0.5 shrink-0">
                                            {item.severity?.toLowerCase() === 'critical' ? <XCircle className="w-3.5 h-3.5 text-sf-critical" /> : 
                                             item.severity?.toLowerCase() === 'high' ? <ShieldAlert className="w-3.5 h-3.5 text-sf-warning" /> :
                                             <Activity className="w-3.5 h-3.5 text-sf-safe" />}
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <div className="flex justify-between items-start mb-1">
                                                <span className="text-white truncate group-hover:text-sf-accent transition-colors">{item.message || item.event_type || 'Unknown Event'}</span>
                                                <span suppressHydrationWarning className="text-sf-muted/50 text-[9px] shrink-0">
                                                    {new Date(item.timestamp || Date.now()).toISOString().split('T')[1].slice(0, 8)}
                                                </span>
                                            </div>
                                            <div className="text-sf-muted/70 flex gap-4">
                                                <span className="truncate">S: <span className="text-sf-muted">{item.source_type || 'Network'}</span></span>
                                                <span className="truncate">ACT: <span className="text-sf-muted">{item.action || 'Logged'}</span></span>
                                            </div>
                                        </div>
                                    </div>
                                ))
                            ) : (
                                DEMO_LIVE_FEED.map((item, i) => (
                                    <div key={i} className="flex gap-3 text-[11px] font-mono leading-tight hover:bg-white/5 p-2 rounded -mx-2 transition-colors cursor-pointer group">
                                        <div className="mt-0.5 shrink-0">
                                            <item.icon className={`w-3.5 h-3.5 ${item.c}`} />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <div className="flex justify-between items-start mb-1">
                                                <span className="text-white truncate group-hover:text-sf-accent transition-colors">{item.e}</span>
                                                <span suppressHydrationWarning className="text-sf-muted/50 text-[9px] shrink-0">
                                                    {new Date(Date.now() - item.timeOffset).toISOString().split('T')[1].slice(0, 8)}
                                                </span>
                                            </div>
                                            <div className="text-sf-muted/70 flex gap-4">
                                                <span className="truncate">S: <span className="text-sf-muted">{item.s}</span></span>
                                                <span className="truncate">ACT: <span className="text-sf-muted">{item.d}</span></span>
                                            </div>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
