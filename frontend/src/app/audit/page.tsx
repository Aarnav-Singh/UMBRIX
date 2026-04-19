"use client";

import React, { useState, useEffect, useCallback } from "react";
import { ScrollText, Search, ChevronLeft, ChevronRight, Clock, User, Activity } from "lucide-react";

interface AuditEntry {
 id: string;
 timestamp: string;
 action: string;
 user: string;
 client_ip: string;
 detail: string | null;
 path: string | null;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

function getToken() {
 return typeof window !== "undefined" ? localStorage.getItem("sentinel_token") : null;
}

async function apiFetch(path: string) {
 const token = getToken();
 const res = await fetch(`/api/proxy/api/v1${path}`, {
 headers: {
 ...(token ? { Authorization: `Bearer ${token}` } : {}),
 },
 });
 if (!res.ok) throw new Error(`Request failed: ${res.status}`);
 return res.json();
}

const ACTION_COLORS: Record<string, string> = {
 login_success: "text-[var(--ng-lime)]",
 login_failed: "text-[var(--ng-error)]",
 logout_success: "text-ng-muted",
 mfa_enabled_with_backup_codes: "text-[var(--ng-cyan-bright)]",
 admin_user_created: "text-[var(--ng-cyan)]",
 admin_user_deactivated: "text-[var(--ng-magenta)]",
 report_csv_generated: "text-[var(--ng-cyan)]",
 report_pdf_generated: "text-[var(--ng-cyan)]",
};

export default function AuditPage() {
 const [entries, setEntries] = useState<AuditEntry[]>([]);
 const [loading, setLoading] = useState(true);
 const [page, setPage] = useState(1);
 const [total, setTotal] = useState(0);
 const [search, setSearch] = useState("");
 const pageSize = 25;

 const fetchAudit = useCallback(async () => {
 try {
 setLoading(true);
 const offset = (page - 1) * pageSize;
 const params = new URLSearchParams({ limit: String(pageSize), offset: String(offset) });
 if (search) params.set("q", search);
 const data = await apiFetch(`/compliance/audit-trail?${params}`);
 setEntries(data.entries || []);
 setTotal(data.total || 0);
 } catch {
 setEntries([]);
 } finally {
 setLoading(false);
 }
 }, [page, search]);

 useEffect(() => { fetchAudit(); }, [fetchAudit]);

 const totalPages = Math.max(1, Math.ceil(total / pageSize));

 return (
 <div className="flex-1 flex flex-col h-full overflow-y-auto custom-scrollbar p-8">
 <header className="mb-8">
 <h1 className="font-headline tracking-widest uppercase text-3xl font-bold text-ng-on tracking-tight flex items-center gap-3">
 <ScrollText className="w-8 h-8 text-ng-cyan" />
 Audit Trail
 </h1>
 <p className="text-ng-muted mt-2">Platform-wide audit log for compliance and security review.</p>
 </header>

 {/* Search & Pagination Controls */}
 <div className="flex items-center justify-between mb-4 gap-4">
 <div className="relative flex-1 max-w-md">
 <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ng-muted" />
 <input
 placeholder="Filter by action or user..."
 value={search}
 onChange={e => { setSearch(e.target.value); setPage(1); }}
 className="w-full pl-10 pr-4 py-2 bg-ng-mid border border-ng-outline-dim/40 rounded-none text-ng-on text-[10px] font-mono focus:outline-none focus:border-ng-cyan/50 uppercase tracking-widest"
 />
 </div>
 <div className="flex items-center gap-2 text-sm text-ng-muted">
 <span>{total} entries</span>
 <button
 onClick={() => setPage(p => Math.max(1, p - 1))}
 disabled={page <= 1}
 className="p-1 rounded-none hover:bg-ng-mid disabled:opacity-30"
 >
 <ChevronLeft className="w-4 h-4" />
 </button>
 <span className="font-mono text-xs">{page}/{totalPages}</span>
 <button
 onClick={() => setPage(p => Math.min(totalPages, p + 1))}
 disabled={page >= totalPages}
 className="p-1 rounded-none hover:bg-ng-mid disabled:opacity-30"
 >
 <ChevronRight className="w-4 h-4" />
 </button>
 </div>
 </div>

 {/* Audit Table */}
 <div className="ng-surface border border-ng-outline-dim/40 rounded-none overflow-hidden">
 <table className="w-full text-left text-sm">
 <thead className="bg-ng-mid/50 text-ng-muted uppercase text-[10px] tracking-wider">
 <tr>
 <th className="px-6 py-4 font-medium">Timestamp</th>
 <th className="px-6 py-4 font-medium">Action</th>
 <th className="px-6 py-4 font-medium">User</th>
 <th className="px-6 py-4 font-medium">IP Address</th>
 <th className="px-6 py-4 font-medium">Detail</th>
 </tr>
 </thead>
 <tbody className="divide-y divide-ng-outline-dim/30 text-ng-on">
 {loading ? (
 <tr><td colSpan={5} className="px-6 py-12 text-center text-ng-muted">Loading audit trail...</td></tr>
 ) : entries.length === 0 ? (
 <tr><td colSpan={5} className="px-6 py-12 text-center text-ng-muted">No audit entries found.</td></tr>
 ) : entries.map((entry, i) => (
 <tr key={entry.id || i} className="hover:bg-ng-mid/30 transition-colors">
 <td className="px-6 py-3 font-mono text-xs text-ng-muted whitespace-nowrap">
 <Clock className="inline w-3 h-3 mr-1.5 -mt-0.5" />
 {new Date(entry.timestamp).toLocaleString()}
 </td>
 <td className="px-6 py-3">
 <span className={`font-mono text-xs font-bold ${ACTION_COLORS[entry.action] || "text-ng-on"}`}>
 {entry.action}
 </span>
 </td>
 <td className="px-6 py-3">
 <span className="flex items-center gap-1.5 text-xs">
 <User className="w-3 h-3 text-ng-muted" />
 {entry.user}
 </span>
 </td>
 <td className="px-6 py-3 font-mono text-xs text-ng-muted">{entry.client_ip || "â€”"}</td>
 <td className="px-6 py-3 text-xs text-ng-muted max-w-xs truncate">{entry.detail || "â€”"}</td>
 </tr>
 ))}
 </tbody>
 </table>
 </div>
 </div>
 );
}

