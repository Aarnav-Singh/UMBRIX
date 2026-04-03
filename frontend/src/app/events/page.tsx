"use client";

import React, { useState, useCallback, useEffect } from 'react';
import { Terminal, X, Share2, ShieldAlert, Activity } from 'lucide-react';
import { useLiveEvents } from "@/hooks/useLiveEvents";

interface LogEvent {
    id: string;
    timestamp: string;
    level: "INFO" | "CRITICAL" | "WARN";
    message: string;
    meta: { key: string, value: string }[];
    rawJson: any;
}

const DEMO_LOGS: LogEvent[] = [
    {
        id: "EV-001",
        timestamp: "14:02:44.921",
        level: "INFO",
        message: "POST /api/v2/auth/validate HTTP/1.1 - Origin: 192.168.1.44 - UserAgent: Mozilla/5.0...",
        meta: [{ key: "source", value: "external" }, { key: "cluster", value: "node-04" }],
        rawJson: { "timestamp": "2023-10-27T14:02:44Z", "event_id": 488218, "source": { "ip": "192.168.1.44", "port": 443 }, "payload": "Auth request validated." }
    },
];

function canonicalToLogEvent(event: Record<string, unknown>): LogEvent {
    const severity = (event.severity as string || "info").toLowerCase();
    const metaScore = event.ml_scores && typeof event.ml_scores === "object"
        ? (event.ml_scores as Record<string, number>).meta_score ?? 0
        : 0;
    const level: "INFO" | "CRITICAL" | "WARN" =
        severity === "critical" || metaScore > 0.8 ? "CRITICAL" :
            severity === "high" || metaScore > 0.5 ? "WARN" : "INFO";

    const ts = event.timestamp ? new Date(event.timestamp as string) : new Date();
    const timeStr = ts.toLocaleTimeString("en-US", { hour12: false, fractionalSecondDigits: 3 });

    const meta: { key: string; value: string }[] = [];
    if (event.source_type) meta.push({ key: "source", value: String(event.source_type) });
    if (metaScore > 0) meta.push({ key: "threat_score", value: metaScore.toFixed(2) });
    if (event.campaign_id) meta.push({ key: "campaign", value: String(event.campaign_id) });
    const label = event.ml_scores && typeof event.ml_scores === "object"
        ? (event.ml_scores as Record<string, string>).ensemble_label : undefined;
    if (label && label !== "benign") meta.push({ key: "label", value: String(label) });

    return {
        id: String(event.event_id || `EV-${Date.now()}`),
        timestamp: timeStr,
        level,
        message: String(event.message || `${event.action || "unknown"} from ${event.source_type || "unknown"}`),
        meta,
        rawJson: event,
    };
}

const EventRow = ({ log, setSelectedLog }: { log: LogEvent, setSelectedLog: (log: LogEvent) => void }) => {
    const isCritical = log.level === 'CRITICAL';
    const isWarn = log.level === 'WARN';
    const colorHex = isCritical ? 'var(--sf-critical)' : isWarn ? 'var(--sf-warning)' : 'var(--sf-accent)';

    return (
        <div className="mb-3">
            <div
                onClick={() => setSelectedLog(log)}
                className={`h-[114px] bg-sf-surface/80 backdrop-blur-md p-4 rounded-xl border-l-[4px] flex flex-col gap-2 cursor-pointer transition-all hover:-translate-y-1 hover:shadow-lg ${isCritical ? 'border-l-[var(--sf-critical)] shadow-[0_0_20px_rgba(244,63,94,0.15)] border border-sf-critical/20' : isWarn ? 'border-l-[var(--sf-warning)] border border-sf-warning/20' : 'border-l-[var(--sf-accent)] border border-sf-accent/10 hover:border-sf-accent/40'}`}
            >
                <div className="flex justify-between items-start">
                    <span className="font-mono text-[10px]" style={{ color: colorHex }}>T: {log.timestamp}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded-sm font-bold tracking-widest" style={{ color: colorHex, backgroundColor: `${colorHex}15`, border: `1px solid ${colorHex}30` }}>
                        {log.level}
                    </span>
                </div>
                <p className="text-slate-200 text-xs font-mono line-clamp-2 leading-relaxed">{log.message}</p>

                {log.meta.length > 0 && (
                    <div className="flex gap-2 mt-1 flex-wrap">
                        {log.meta.map((m: any, i: number) => (
                            <span key={i} className={`text-[10px] uppercase font-mono ${isCritical ? 'bg-sf-critical/10 text-sf-critical border-sf-critical/30' : 'bg-sf-bg text-sf-muted border-sf-border'} px-1.5 py-0.5 rounded border`}>
                                {m.key}: {m.value}
                            </span>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default function RawEventsPage() {
    const [selectedLog, setSelectedLog] = useState<LogEvent | null>(null);
    const [liveEvents, setLiveEvents] = useState<LogEvent[]>([]);
    const [eps, setEps] = useState(0);

    useEffect(() => {
        fetch('/api/proxy/api/v1/events/recent?limit=50')
            .then(r => r.json())
            .then(data => {
                if (data.events && Array.isArray(data.events)) {
                    const logs = data.events.map((e: any) => canonicalToLogEvent(e));
                    setLiveEvents(logs);
                }
            })
            .catch(err => console.error("Failed to load recent events", err));
    }, []);

    const handleLiveEvent = useCallback((event: Record<string, unknown>) => {
        const logEvent = canonicalToLogEvent(event);
        setLiveEvents(prev => [logEvent, ...prev].slice(0, 100));
        setEps(prev => prev + 1);
    }, []);

    useLiveEvents({ onEvent: handleLiveEvent });

    const allLogs = liveEvents.length > 0 ? liveEvents : DEMO_LOGS;


    return (
        <div className="flex-1 overflow-hidden flex flex-col relative bg-[linear-gradient(rgba(0,242,255,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,242,255,0.03)_1px,transparent_1px)] bg-[size:30px_30px]">
            {/* Header / Stats Overlay */}
            <div className="flex flex-col md:flex-row gap-3 p-6 pb-2 z-10">
                <div className="flex-1 bg-sf-bg/70 backdrop-blur-md border border-sf-accent/50 rounded-xl p-4 shadow-[0_0_15px_rgba(0,242,255,0.15)] relative overflow-hidden">
                    <div className="absolute inset-0 bg-gradient-to-br from-sf-accent/5 to-transparent"></div>
                    <p className="text-sf-muted text-xs font-medium uppercase tracking-wider relative">Events/Sec</p>
                    <div className="flex items-end gap-2 mt-1 relative">
                        <span className="text-white text-3xl font-bold leading-none tracking-tight">{eps > 0 ? eps.toLocaleString() : '0'}</span>
                        {eps > 0 && <span className="text-sf-accent text-xs font-bold mb-1">LIVE</span>}
                    </div>
                </div>
                <div className="flex-1 bg-sf-bg/70 backdrop-blur-md border border-sf-accent/50 rounded-xl p-4 shadow-[0_0_15px_rgba(0,242,255,0.15)] relative overflow-hidden">
                    <div className="absolute inset-0 bg-gradient-to-br from-sf-accent/5 to-transparent"></div>
                    <p className="text-sf-muted text-xs font-medium uppercase tracking-wider relative">Total Events</p>
                    <div className="flex items-end gap-2 mt-1 relative">
                        <span className="text-white text-3xl font-bold leading-none tracking-tight">{liveEvents.length || '0'}</span>
                        {liveEvents.length > 0 && <span className="text-sf-accent text-xs font-bold mb-1">streamed</span>}
                    </div>
                </div>
            </div>

            {/* Stream Label */}
            <div className="px-6 py-4 flex items-center justify-between z-10 border-b border-sf-accent/10 mb-2 bg-sf-bg/50 backdrop-blur-sm">
                <div className="flex items-center gap-2">
                    <span className={`flex size-2.5 rounded-full ${liveEvents.length > 0 ? 'bg-sf-accent animate-pulse shadow-[0_0_8px_var(--sf-accent)]' : 'bg-slate-600'}`}></span>
                    <h3 className="text-white text-sm font-bold uppercase tracking-widest flex items-center gap-2">
                        <Activity className="w-4 h-4 text-sf-accent" />
                        {liveEvents.length > 0 ? 'Real-time Stream' : 'Awaiting Events'}
                    </h3>
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${liveEvents.length > 0 ? 'text-sf-accent bg-sf-accent/10 border-sf-accent/30 animate-pulse' : 'text-sf-muted bg-sf-surface border-sf-border'}`}>
                    {liveEvents.length > 0 ? 'LIVE_FEED' : 'WAITING'}
                </span>
            </div>

            {/* Event Log Stream */}
            <div className="flex-1 px-6 py-2 pb-10 overflow-y-auto overflow-x-hidden custom-scrollbar relative z-10 perspective-[1000px]">
                {allLogs.map(log => (
                    <EventRow key={log.id} log={log} setSelectedLog={setSelectedLog} />
                ))}
            </div>

            {/* Modal */}
            {selectedLog && (
                <div className="absolute inset-x-4 md:inset-x-20 lg:inset-x-32 top-20 z-50 bg-sf-surface/95 backdrop-blur-xl rounded-xl p-6 shadow-[0_0_30px_rgba(0,242,255,0.2)] border border-sf-accent/50 animate-[slideDown_0.2s_ease-out]">
                    <div className="flex justify-between items-center mb-4">
                        <div className="flex items-center gap-2">
                            <Terminal className="w-5 h-5 text-sf-accent" />
                            <h4 className="text-white text-base font-bold uppercase tracking-wider">Event Inspector</h4>
                            <span className="text-[10px] font-mono text-sf-muted ml-2">{selectedLog.id}</span>
                        </div>
                        <button onClick={() => setSelectedLog(null)} className="text-sf-muted hover:text-white transition-colors">
                            <X className="w-5 h-5" />
                        </button>
                    </div>

                    <div className="bg-black/80 rounded-lg p-5 font-mono text-[12px] leading-loose border border-sf-accent/20 overflow-x-auto max-h-[400px] overflow-y-auto">
                        <pre className="text-slate-300 whitespace-pre-wrap">
                            {JSON.stringify(selectedLog.rawJson, null, 2)}
                        </pre>
                    </div>

                    <div className="mt-5 flex gap-3">
                        <button className="flex-1 bg-sf-accent text-sf-bg font-bold text-xs py-3 rounded-lg flex items-center justify-center gap-2 hover:bg-sf-accent hover:shadow-[0_0_15px_var(--sf-accent)] transition-all">
                            <Share2 className="w-4 h-4" /> EXPORT JSON
                        </button>
                        <button className="flex-1 bg-sf-accent/10 border border-sf-accent/40 text-sf-accent hover:bg-sf-accent/20 font-bold text-xs py-3 rounded-lg flex items-center justify-center gap-2 transition-all">
                            <ShieldAlert className="w-4 h-4" /> TRACE SOURCE
                        </button>
                    </div>
                </div>
            )}

            {selectedLog && (
                <div
                    className="absolute inset-0 bg-sf-bg/60 backdrop-blur-sm z-40"
                    onClick={() => setSelectedLog(null)}
                />
            )}
        </div>
    );
}
