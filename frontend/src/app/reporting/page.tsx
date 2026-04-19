"use client";

import React, { useState, useEffect, useCallback } from "react";
import { FileText, Download, Filter, Calendar, Loader2, FileSpreadsheet, FileType } from "lucide-react";

interface ReportMeta {
 id: string;
 report_name: string;
 report_type: string;
 generated_by: string;
 file_size_bytes: number;
 created_at: string;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

function getToken() {
 return typeof window !== "undefined" ? localStorage.getItem("sentinel_token") : null;
}

async function apiFetch(path: string, opts: RequestInit = {}) {
 const token = getToken();
 return fetch(`/api/proxy/api/v1${path}`, {
 ...opts,
 headers: {
 ...(token ? { Authorization: `Bearer ${token}` } : {}),
 ...(opts.headers || {}),
 },
 });
}

const TYPE_LABELS: Record<string, { label: string; color: string }> = {
 executive_pdf: { label: "Executive", color: "text-[var(--ng-cyan)] bg-[var(--ng-cyan)]/10" },
 soc2_pdf: { label: "SOC 2", color: "text-[var(--ng-cyan-bright)] bg-[var(--ng-cyan-bright)]/10" },
 excel_extract: { label: "Excel", color: "text-[var(--ng-lime)] bg-[var(--ng-lime)]/10" },
 scheduled_pdf: { label: "Compliance", color: "text-[var(--ng-magenta)] bg-[var(--ng-magenta)]/10" },
 scheduled_csv: { label: "Compliance CSV", color: "text-[var(--ng-magenta)] bg-[var(--ng-magenta)]/10" },
};

function formatBytes(bytes: number) {
 if (bytes < 1024) return `${bytes} B`;
 if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
 return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function ReportingPage() {
 const [reports, setReports] = useState<ReportMeta[]>([]);
 const [loading, setLoading] = useState(true);
 const [generating, setGenerating] = useState<string | null>(null);
 const [filter, setFilter] = useState("all");

 const fetchReports = useCallback(async () => {
 try {
 setLoading(true);
 const res = await apiFetch("/reports/history");
 if (res.ok) {
 const data = await res.json();
 setReports(data.reports || []);
 }
 } catch {
 // graceful fallback
 } finally {
 setLoading(false);
 }
 }, []);

 useEffect(() => { fetchReports(); }, [fetchReports]);

 const downloadReport = async (format: "csv" | "excel" | "pdf" | "soc2") => {
 setGenerating(format);
 try {
 const path = format === "soc2" ? "/reports/soc2" : `/reports/${format}`;
 const res = await apiFetch(path);
 if (!res.ok) throw new Error("Failed to generate report");
 
 const blob = await res.blob();
 const url = URL.createObjectURL(blob);
 const a = document.createElement("a");
 a.href = url;
 const ext = format === "excel" ? "xlsx" : format === "soc2" ? "pdf" : format;
 a.download = `sentinel_report_${new Date().toISOString().split("T")[0]}.${ext}`;
 a.click();
 URL.revokeObjectURL(url);

 // Refresh the report history
 setTimeout(fetchReports, 1000);
 } catch {
 // handle error
 } finally {
 setGenerating(null);
 }
 };

 const filtered = filter === "all"
 ? reports
 : reports.filter(r => r.report_type === filter);

 return (
 <div className="flex-1 flex flex-col h-full overflow-y-auto custom-scrollbar p-8">
 <header className="mb-8 flex justify-between items-end">
 <div>
 <h1 className="font-headline tracking-widest uppercase text-3xl font-bold text-ng-on tracking-tight flex items-center gap-3">
 <FileText className="w-8 h-8 text-ng-cyan" />
 Reporting
 </h1>
 <p className="text-ng-muted mt-2">Generate and export security compliance and incident reports.</p>
 </div>
 <div className="flex items-center gap-2">
 <button
 onClick={() => downloadReport("csv")}
 disabled={!!generating}
 className="px-3 py-2 bg-ng-mid border border-ng-outline-dim/40 text-ng-on font-semibold rounded-none hover:bg-ng-mid/80 transition-colors flex items-center gap-2 text-xs disabled:opacity-40"
 >
 {generating === "csv" ? <Loader2 className="w-3 h-3 animate-spin" /> : <FileText className="w-3 h-3" />}
 CSV
 </button>
 <button
 onClick={() => downloadReport("excel")}
 disabled={!!generating}
 className="px-3 py-2 bg-ng-mid border border-ng-outline-dim/40 text-ng-on font-semibold rounded-none hover:bg-ng-mid/80 transition-colors flex items-center gap-2 text-xs disabled:opacity-40"
 >
 {generating === "excel" ? <Loader2 className="w-3 h-3 animate-spin" /> : <FileSpreadsheet className="w-3 h-3" />}
 Excel
 </button>
 <button
 onClick={() => downloadReport("pdf")}
 disabled={!!generating}
 className="px-3 py-2 bg-ng-mid border border-ng-outline-dim/40 text-ng-on font-semibold rounded-none hover:bg-ng-mid/80 transition-colors flex items-center gap-2 text-xs disabled:opacity-40"
 >
 {generating === "pdf" ? <Loader2 className="w-3 h-3 animate-spin" /> : <FileType className="w-3 h-3" />}
 PDF
 </button>
 <button
 onClick={() => downloadReport("soc2")}
 disabled={!!generating}
 className="px-4 py-2 bg-ng-cyan-bright text-ng-base font-bold rounded-none hover:bg-ng-cyan-bright/90 transition-colors flex items-center gap-2 text-xs disabled:opacity-40"
 >
 {generating === "soc2" ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
 SOC 2 Report
 </button>
 </div>
 </header>

 <div className="ng-surface border border-ng-outline-dim/40 rounded-none mb-6">
 <div className="p-4 border-b border-ng-outline-dim/40 flex gap-4">
 <select
 value={filter}
 onChange={e => setFilter(e.target.value)}
 className="flex items-center gap-2 text-sm text-ng-on bg-ng-mid px-3 py-1.5 rounded-none border border-ng-outline-dim/40 focus:outline-none focus:border-ng-cyan/50 cursor-pointer"
 >
 <option value="all">All Types</option>
 <option value="executive_pdf">Executive</option>
 <option value="soc2_pdf">SOC 2</option>
 <option value="excel_extract">Excel</option>
 <option value="scheduled_pdf">Compliance</option>
 </select>
 <div className="flex items-center gap-2 text-sm text-ng-muted bg-ng-mid px-3 py-1.5 rounded-none border border-ng-outline-dim/40">
 <Calendar className="w-4 h-4" />
 {reports.length} reports generated
 </div>
 </div>
 
 <table className="w-full text-left text-sm">
 <thead className="bg-ng-mid/50 text-ng-muted uppercase text-[10px] tracking-wider">
 <tr>
 <th className="px-6 py-4 font-medium">Report Name</th>
 <th className="px-6 py-4 font-medium">Type</th>
 <th className="px-6 py-4 font-medium">Generated By</th>
 <th className="px-6 py-4 font-medium">Size</th>
 <th className="px-6 py-4 font-medium">Date</th>
 </tr>
 </thead>
 <tbody className="divide-y divide-ng-outline-dim/30 text-ng-on">
 {loading ? (
 <tr><td colSpan={5} className="px-6 py-12 text-center text-ng-muted">
 <Loader2 className="w-5 h-5 animate-spin inline mr-2" /> Loading reports...
 </td></tr>
 ) : filtered.length === 0 ? (
 <tr><td colSpan={5} className="px-6 py-12 text-center text-ng-muted">
 No reports generated yet. Use the buttons above to create one.
 </td></tr>
 ) : filtered.map((report) => {
 const typeInfo = TYPE_LABELS[report.report_type] || { label: report.report_type, color: "text-ng-muted bg-ng-muted/10" };
 return (
 <tr key={report.id} className="hover:bg-ng-mid/30 transition-colors">
 <td className="px-6 py-4 text-ng-on font-medium flex items-center gap-3">
 <FileText className="w-4 h-4 text-ng-muted" />
 {report.report_name}
 </td>
 <td className="px-6 py-4">
 <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${typeInfo.color}`}>
 {typeInfo.label}
 </span>
 </td>
 <td className="px-6 py-4 text-xs">{report.generated_by}</td>
 <td className="px-6 py-4 font-mono text-xs text-ng-muted">
 {formatBytes(report.file_size_bytes)}
 </td>
 <td className="px-6 py-4 font-mono text-xs text-ng-muted">
 {new Date(report.created_at).toLocaleDateString()}
 </td>
 </tr>
 );
 })}
 </tbody>
 </table>
 </div>
 </div>
 );
}
