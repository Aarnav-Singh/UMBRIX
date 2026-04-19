"use client";

import React, { useCallback } from "react";
import { FixedSizeList as List } from "react-window";
// eslint-disable-next-line
const AutoSizer = require("react-virtualized-auto-sizer").AutoSizer as any;

interface Column<T> {
 key: keyof T;
 header: string;
 render?: (value: any, item: T) => React.ReactNode;
 align?: "left" | "right" | "center";
 width?: string; // CSS width e.g. "100px" or "20%"
}

interface VirtualDataGridProps<T> {
 data: T[];
 columns: Column<T>[];
 className?: string;
 rowKey: keyof T;
 onRowClick?: (row: T) => void;
 itemSize?: number;
 severityKey?: keyof T;
 sortable?: boolean;
}

export function VirtualDataGrid<T>({ data, columns, className = "", rowKey, onRowClick, itemSize = 40, severityKey, sortable }: VirtualDataGridProps<T>) {
 
 const [sortKey, setSortKey] = React.useState<keyof T | null>(null);
 const [sortDir, setSortDir] = React.useState<"asc" | "desc">("asc");

 const sortedData = sortable && sortKey
 ? [...data].sort((a, b) => {
 const av = a[sortKey], bv = b[sortKey];
 const cmp = String(av).localeCompare(String(bv));
 return sortDir === "asc" ? cmp : -cmp;
 })
 : data;

 function getSeverityClass(severity: string): string {
 if (severity === "critical") return "border-l-[3px] border-ng-error bg-[rgba(220,38,38,0.03)]";
 if (severity === "high") return "border-l-[3px] border-ng-magenta bg-[rgba(215,119,6,0.02)]";
 return "border-l-[3px] border-transparent";
 }

 const Row = useCallback(({ index, style }: { index: number; style: React.CSSProperties }) => {
 const item = sortedData[index];
 const severityVal = severityKey ? String(item[severityKey]) : "";
 const severityClass = severityKey ? getSeverityClass(severityVal) : "";

 return (
 <div 
 style={style} 
 className={`flex items-center border-b border-ng-outline-dim/40/50 group hover:bg-ng-mid/50 transition-colors ${onRowClick ? 'cursor-pointer' : ''} ${severityClass}`}
 onClick={() => onRowClick?.(item)}
 >
 {columns.map((col) => {
 const val = item[col.key];
 const flexStyle = col.width ? { width: col.width, flexShrink: 0 } : { flex: 1, minWidth: 0 };
 return (
 <div 
 key={`${String(item[rowKey])}-${String(col.key)}`} 
 className={`py-2 px-3 whitespace-nowrap text-[11px] font-mono text-ng-on overflow-hidden ${col.align === "right" ? "text-right" : col.align === "center" ? "text-center" : "text-left"}`}
 style={flexStyle}
 >
 {col.render ? col.render(val, item) : String(val)}
 </div>
 );
 })}
 </div>
 );
 }, [sortedData, columns, onRowClick, rowKey, severityKey]);

 return (
 <div className={`w-full h-full flex flex-col ${className}`}>
 {/* Header */}
 <div className="flex w-full items-center border-b border-ng-outline-dim/40 bg-ng-mid pr-[15px]">
 {columns.map((col) => {
 const flexStyle = col.width ? { width: col.width, flexShrink: 0 } : { flex: 1, minWidth: 0 };
 return (
 <div 
 key={String(col.key)} 
 onClick={sortable ? () => {
 if (sortKey === col.key) setSortDir(d => d === "asc" ? "desc" : "asc");
 else { setSortKey(col.key); setSortDir("asc"); }
 } : undefined}
 className={`py-2 px-3 tracking-widest text-[11px] text-ng-muted uppercase font-normal ${col.align === "right" ? "text-right" : col.align === "center" ? "text-center" : "text-left"} ${sortable ? "cursor-pointer hover:text-ng-on select-none" : ""}`}
 style={flexStyle}
 >
 {col.header}{sortable && sortKey === col.key ? (sortDir === "asc" ? " ↑" : " ↓") : ""}
 </div>
 );
 })}
 </div>

 {/* Virtualized Body */}
 <div className="flex-1 w-full relative min-h-0">
 {data.length === 0 ? (
 <div className="absolute inset-0 flex flex-col items-center justify-center border-t border-ng-outline-dim/40 border-dashed bg-ng-mid/20">
 <div className="w-1.5 h-1.5 bg-ng-muted/50 mb-3 rotate-45" />
 <span className="text-ng-muted tracking-widest text-[10px] font-mono">DATASET EMPTY</span>
 </div>
 ) : (
 <AutoSizer>
 {({ height, width }: { height: number; width: number }) => (
 <List
 height={height}
 itemCount={sortedData.length}
 itemSize={itemSize}
 width={width}
 overscanCount={5}
 >
 {Row}
 </List>
 )}
 </AutoSizer>
 )}
 </div>
 </div>
 );
}
