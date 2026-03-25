"use client";

import { useMemo } from "react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { useQuery } from "@tanstack/react-query";
import { api, type PostureSnapshot } from "@/lib/api/client";



export function PostureChart() {
    const { data: postureData } = useQuery({
        queryKey: ["posture"],
        queryFn: () => api.getPostureTimeline(24),
    });

    const chartData = useMemo(() => {
        if (postureData?.snapshots?.length) {
            return postureData.snapshots.map((s) => ({
                time: new Date(s.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
                score: s.score,
            }));
        }
        return [];
    }, [postureData]);

    return (
        <div className="w-full h-full relative">
            <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
                    <defs>
                        <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#F97316" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="#F97316" stopOpacity={0} />
                        </linearGradient>
                    </defs>
                    <XAxis
                        dataKey="time"
                        stroke="#475569"
                        fontSize={12}
                        tickLine={false}
                        axisLine={false}
                        minTickGap={30}
                    />
                    <YAxis
                        stroke="#475569"
                        fontSize={12}
                        tickLine={false}
                        axisLine={false}
                        domain={[60, 100]}
                    />
                    <Tooltip
                        contentStyle={{ backgroundColor: '#121A24', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px' }}
                        itemStyle={{ color: '#F8FAFC' }}
                        cursor={{ stroke: 'rgba(249, 115, 22, 0.4)', strokeWidth: 2, strokeDasharray: '4 4' }}
                        formatter={(value: any) => [`${value}`, 'Posture']}
                    />
                    <Area
                        type="monotone"
                        dataKey="score"
                        stroke="#F97316"
                        strokeWidth={2}
                        fillOpacity={1}
                        fill="url(#colorScore)"
                    />
                </AreaChart>
            </ResponsiveContainer>
        </div>
    );
}
