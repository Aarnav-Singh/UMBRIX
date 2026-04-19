import React from "react";

interface SparklineProps {
 data: number[];
 color?: string; // accepts CSS var strings like 'var(--ng-cyan-bright)'
 width?: number;
 height?: number;
 className?: string;
 showDot?: boolean;
 showArea?: boolean;
}

export function Sparkline({
 data,
 color = "var(--ng-cyan-bright)",
 width = 100,
 height = 30,
 className = "",
 showDot = true,
 showArea = true,
}: SparklineProps) {
 if (!Array.isArray(data) || data.length < 2) return null;

 const min = Math.min(...data);
 const max = Math.max(...data);
 const range = max - min || 1;
 const paddingY = 3;
 const effectiveH = height - paddingY * 2;
 const dx = width / (data.length - 1);

 const pts = data.map((val, i) => {
 const x = i * dx;
 const y = height - paddingY - ((val - min) / range) * effectiveH;
 return { x, y };
 });

 const linePath = pts.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x},${p.y}`).join(" ");
 const areaPath = `${linePath} L ${pts[pts.length - 1].x},${height} L 0,${height} Z`;
 const lastPt = pts[pts.length - 1];
 const gradId = `sg-${Math.random().toString(36).slice(2)}`;

 return (
 <svg
 width={width}
 height={height}
 viewBox={`0 0 ${width} ${height}`}
 preserveAspectRatio="none"
 className={`overflow-visible ${className}`}
 >
 <defs>
 <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
 <stop offset="0%" stopColor={color} stopOpacity="0.25" />
 <stop offset="100%" stopColor={color} stopOpacity="0" />
 </linearGradient>
 </defs>
 {showArea && (
 <path d={areaPath} fill={`url(#${gradId})`} />
 )}
 <path
 d={linePath}
 fill="none"
 stroke={color}
 strokeWidth={1.5}
 strokeLinecap="round"
 strokeLinejoin="round"
 vectorEffect="non-scaling-stroke"
 />
 {showDot && (
 <circle
 cx={lastPt.x}
 cy={lastPt.y}
 r={2.5}
 fill={color}
 vectorEffect="non-scaling-stroke"
 />
 )}
 </svg>
 );
}
