"use client";

import { useEffect, useState, useCallback } from "react";
import { AlertCircle, Target, ShieldCheck, Activity } from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type LiveEvent } from "@/lib/api/client";
import { useLiveEvents } from "@/hooks/useLiveEvents";



function severityToType(severity: string): string {
    switch (severity) {
        case "critical": return "critical";
        case "high": return "high";
        case "medium": return "high";
        case "info": return "info";
        default: return "info";
    }
}

function timeAgo(timestamp: string): string {
    const diff = Date.now() - new Date(timestamp).getTime();
    const minutes = Math.floor(diff / 60000);
    if (minutes < 1) return "Just now";
    if (minutes < 60) return `${minutes} min ago`;
    const hours = Math.floor(minutes / 60);
    return `${hours} hour${hours > 1 ? "s" : ""} ago`;
}

export function ActivityFeed() {
    const queryClient = useQueryClient();

    const { data: events } = useQuery({
        queryKey: ["recentEvents"],
        queryFn: () => api.getRecentEvents(20),
        placeholderData: [],
    });

    // Prepend new SSE events to the list
    const handleLiveEvent = useCallback(
        (event: Record<string, unknown>) => {
            queryClient.setQueryData<LiveEvent[]>(["recentEvents"], (old) => {
                const liveEvent = event as unknown as LiveEvent;
                return [liveEvent, ...(old ?? [])].slice(0, 50);
            });
        },
        [queryClient]
    );

    useLiveEvents({ onEvent: handleLiveEvent });

    const displayEvents = events ?? [];

    const getIcon = (type: string) => {
        switch (type) {
            case 'critical': return <AlertCircle className="w-4 h-4 text-brand-orange" />;
            case 'high': return <Target className="w-4 h-4 text-orange-400" />;
            case 'success': return <ShieldCheck className="w-4 h-4 text-green-500" />;
            default: return <Activity className="w-4 h-4 text-text-muted" />;
        }
    };

    return (
        <div className="flex-1 overflow-y-auto hidden-scrollbar space-y-3">
            {displayEvents.map((evt) => {
                const type = severityToType(evt.severity);
                return (
                    <div key={evt.event_id} className="p-3 bg-surface-elevated/50 rounded-lg border border-surface-border/50 flex gap-3 text-sm transition-colors hover:bg-surface-elevated group">
                        <div className="pt-0.5 opacity-80 group-hover:opacity-100 transition-opacity">
                            {getIcon(type)}
                        </div>
                        <div className="flex-1">
                            <p className={`font-medium ${['critical', 'high'].includes(type) ? 'text-text-primary' : 'text-text-secondary'}`}>
                                {evt.message}
                            </p>
                            <div className="flex gap-3 items-center mt-1.5">
                                <span className="text-xs text-text-muted font-mono">{timeAgo(evt.timestamp)}</span>
                                {evt.meta_score > 0.5 && (
                                    <span className="text-[9px] font-bold uppercase tracking-wider text-brand-orange bg-brand-orange/10 px-1.5 py-0.5 rounded">
                                        {(evt.meta_score * 100).toFixed(0)}%
                                    </span>
                                )}
                            </div>
                        </div>
                    </div>
                );
            })}
        </div>
    );
}
