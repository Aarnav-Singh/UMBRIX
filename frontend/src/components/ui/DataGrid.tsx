"use client";

import React from "react";

interface Column<T> {
 key: keyof T;
 header: string;
 render?: (value: any, item: T) => React.ReactNode;
 align?: "left" | "right" | "center";
}

interface DataGridProps<T> {
 data: T[];
 columns: Column<T>[];
 className?: string;
 rowKey: keyof T;
 onRowClick?: (row: T) => void;
 severityKey?: keyof T;
 sortable?: boolean;
}

export function DataGrid<T>({ data, columns, className = "", rowKey, onRowClick, severityKey, sortable }: DataGridProps<T>) {
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

 return (
 <div className={`w-full overflow-x-auto ${className}`}>
 <table className="w-full text-[11px] font-mono text-left border-collapse">
 <thead>
 <tr className="border-b border-ng-outline-dim/40 bg-ng-mid">
 {columns.map((col) => (
 <th 
 key={String(col.key)} 
 onClick={sortable ? () => {
 if (sortKey === col.key) setSortDir(d => d === "asc" ? "desc" : "asc");
 else { setSortKey(col.key); setSortDir("asc"); }
 } : undefined}
 className={`py-2 px-3 tracking-widest text-ng-muted uppercase font-normal ${col.align === "right" ? "text-right" : col.align === "center" ? "text-center" : "text-left"} ${sortable ? "cursor-pointer hover:text-ng-on select-none" : ""}`}
 >
 {col.header}{sortable && sortKey === col.key ? (sortDir === "asc" ? " ↑" : " ↓") : ""}
 </th>
 ))}
 </tr>
 </thead>
 <tbody className="divide-y divide-ng-outline-dim/30/50">
  {(Array.isArray(sortedData) ? sortedData : []).map((item) => (
 <tr 
 key={String(item[rowKey])} 
 className={`group hover:bg-ng-mid/50 transition-colors ${onRowClick ? 'cursor-pointer' : ''} ${severityKey ? getSeverityClass(String(item[severityKey])) : ''}`}
 onClick={() => onRowClick?.(item)}
 >
 {columns.map((col) => {
 const val = item[col.key];
 return (
 <td 
 key={`${String(item[rowKey])}-${String(col.key)}`} 
 className={`py-2.5 px-3 whitespace-nowrap text-ng-on ${col.align === "right" ? "text-right" : col.align === "center" ? "text-center" : "text-left"}`}
 >
 {col.render ? col.render(val, item) : (val as React.ReactNode)}
 </td>
 );
 })}
 </tr>
 ))}
 </tbody>
 </table>
 {data.length === 0 && (
 <div className="p-8 text-center flex flex-col items-center justify-center border-t border-ng-outline-dim/40 border-dashed bg-ng-mid/20">
 <div className="w-1.5 h-1.5 bg-ng-muted/50 mb-3 rotate-45" />
 <span className="text-ng-muted tracking-widest text-[10px] font-mono">DATASET EMPTY</span>
 </div>
 )}
 </div>
 );
}
