"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import useSWR from "swr";

export type ThreatState = "nominal" | "elevated" | "incident";

interface ThreatStateContextType {
 threatState: ThreatState;
 criticalCount: number;
 highCount: number;
 maxScore: number;
}

const ThreatStateContext = createContext<ThreatStateContextType>({
 threatState: "nominal",
 criticalCount: 0,
 highCount: 0,
 maxScore: 0,
});

const fetcher = (url: string) => fetch(url).then(r => r.json());

function computeState(criticalCount: number, highCount: number, maxScore: number): ThreatState {
 if (criticalCount > 0 && maxScore > 0.85) return "incident";
 if (criticalCount > 0 || highCount > 2) return "elevated";
 return "nominal";
}

export function ThreatStateProvider({ children }: { children: React.ReactNode }) {
 const { data } = useSWR("/api/proxy/api/v1/findings?limit=100", fetcher, {
 refreshInterval: 15000,
 keepPreviousData: true,
 });

 const findings: any[] = Array.isArray(data?.findings) ? data.findings : (Array.isArray(data) ? data : []);
 const criticalCount = findings.filter((f: any) => f.severity === "critical" && f.status !== "resolved").length;
 const highCount = findings.filter((f: any) => f.severity === "high" && f.status !== "resolved").length;
 const maxScore = findings.reduce((m: number, f: any) => Math.max(m, f.ml_score ?? 0), 0);
 const threatState = computeState(criticalCount, highCount, maxScore);

 useEffect(() => {
 document.documentElement.setAttribute("data-threat",
 threatState === "nominal" ? "" : threatState
 );
 // Drive pulse speed from maxScore proxy
 const pulseRate = Math.max(0.5, 3 - (maxScore * 2));
 document.documentElement.style.setProperty("--pulse-rate", `${pulseRate}s`);
 }, [threatState, maxScore]);

 return (
 <ThreatStateContext.Provider value={{ threatState, criticalCount, highCount, maxScore }}>
 {children}
 </ThreatStateContext.Provider>
 );
}

export function useThreatState() {
 return useContext(ThreatStateContext);
}
