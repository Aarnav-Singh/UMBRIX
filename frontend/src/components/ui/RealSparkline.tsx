"use client";

import React, { useState, useEffect, useRef } from "react";
import useSWR from "swr";
import { Sparkline } from "@/components/ui/Sparkline";
import { useEventStream } from "@/contexts/EventStreamContext";

interface RealSparklineProps {
 source: "eps" | "posture" | "campaigns";
 width?: number;
 height?: number;
 className?: string;
}

const fetcher = (url: string) => fetch(url).then(r => r.json());

export function RealSparkline({ source, width = 80, height = 20, className = "" }: RealSparklineProps) {
 const { epsHistory } = useEventStream();

 // Campaigns buffer — counts over SWR refreshes
 const [campaignBuffer, setCampaignBuffer] = useState<number[]>(Array(30).fill(0));
 const { data: campaignsData } = useSWR(
 source === "campaigns" ? "/api/proxy/api/v1/campaigns" : null,
 fetcher,
 { refreshInterval: 30000 }
 );

 useEffect(() => {
 if (source === "campaigns" && campaignsData) {
 const count = Array.isArray(campaignsData) ? campaignsData.length
 : campaignsData?.campaigns?.length ?? 0;
 setCampaignBuffer(prev => [...prev.slice(-29), count]);
 }
 }, [campaignsData, source]);

 // Posture history from API
 const { data: postureData } = useSWR(
 source === "posture" ? "/api/proxy/api/v1/posture/history" : null,
 fetcher,
 { refreshInterval: 60000 }
 );

 function getData(): number[] {
 if (source === "eps") return epsHistory.length > 1 ? epsHistory : Array(30).fill(0);
  if (source === "posture") {
    const pts = Array.isArray(postureData?.data_points) ? postureData.data_points : (Array.isArray(postureData) ? postureData : []);
    return pts.length > 1 ? pts.map((p: any) => (typeof p === 'number' ? p : (p?.score ?? 0))) : Array(30).fill(0);
  }
 if (source === "campaigns") return campaignBuffer;
 return Array(30).fill(0);
 }

 return (
 <Sparkline
 data={getData()}
 color="var(--ng-cyan-bright)"
 width={width}
 height={height}
 className={className}
 />
 );
}
