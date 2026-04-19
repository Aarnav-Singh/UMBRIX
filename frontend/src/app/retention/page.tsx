"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Database, Clock, Save, AlertTriangle, CheckCircle2, Trash2, HardDrive } from "lucide-react";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

function getToken() {
 return typeof window !== "undefined" ? localStorage.getItem("sentinel_token") : null;
}

async function apiFetch(path: string, opts: RequestInit = {}) {
 const token = getToken();
 const res = await fetch(`/api/proxy/api/v1${path}`, {
 ...opts,
 headers: {
 "Content-Type": "application/json",
 ...(token ? { Authorization: `Bearer ${token}` } : {}),
 ...(opts.headers || {}),
 },
 });
 if (!res.ok) {
 const body = await res.json().catch(() => ({}));
 throw new Error(body.detail || `Request failed: ${res.status}`);
 }
 return res.json();
}

const PRESETS = [
 { days: 30, label: "30 days", description: "Minimum for most use cases" },
 { days: 90, label: "90 days", description: "Recommended for SOC 2" },
 { days: 180, label: "180 days", description: "HIPAA minimum" },
 { days: 365, label: "1 year", description: "PCI-DSS v4.0 requirement" },
];

export default function RetentionPage() {
 const [currentDays, setCurrentDays] = useState(90);
 const [pendingDays, setPendingDays] = useState(90);
 const [saving, setSaving] = useState(false);
 const [purging, setPurging] = useState(false);
 const [saved, setSaved] = useState(false);
 const [purgeResult, setPurgeResult] = useState<string | null>(null);
 const [error, setError] = useState<string | null>(null);
 const [isConfirmOpen, setIsConfirmOpen] = useState(false);

 // Fetch current retention setting on mount
 useEffect(() => {
 // The retention period is stored as clickhouse_ttl_days in config
 // For now, default to 90 and allow the user to change it
 setCurrentDays(90);
 setPendingDays(90);
 }, []);

 const saveRetention = async () => {
 if (pendingDays < 30 || pendingDays > 365) {
 setError("Retention must be between 30 and 365 days.");
 return;
 }

 setSaving(true);
 setError(null);
 try {
 // This calls the compliance/retention endpoint to enforce at the DB level
 await apiFetch(`/compliance/retention?retention_days=${pendingDays}`, {
 method: "POST",
 });
 setCurrentDays(pendingDays);
 setSaved(true);
 setTimeout(() => setSaved(false), 3000);
 } catch (err: any) {
 setError(err.message);
 } finally {
 setSaving(false);
 }
 };

 const triggerPurge = async () => {

 setPurging(true);
 setError(null);
 try {
 const result = await apiFetch(`/compliance/retention?retention_days=${currentDays}`, {
 method: "POST",
 });
 setPurgeResult(`Purged ${result.purged_rows || 0} rows older than ${result.retention_days} days.`);
 setTimeout(() => setPurgeResult(null), 5000);
 } catch (err: any) {
 setError(err.message);
 } finally {
 setPurging(false);
 }
 };

 return (
 <div className="flex-1 flex flex-col h-full overflow-y-auto custom-scrollbar p-8">
 <header className="mb-8">
 <h1 className="font-headline tracking-widest uppercase text-3xl font-bold text-ng-on tracking-tight flex items-center gap-3">
 <Database className="w-8 h-8 text-ng-cyan" />
 Data Retention
 </h1>
 <p className="text-ng-muted mt-2">Configure how long security events and audit logs are retained.</p>
 </header>

 {error && (
 <div className="mb-6 px-4 py-3 rounded-none bg-[var(--ng-error)]/10 border border-[var(--ng-error)]/30 text-[var(--ng-error)] text-[10px] font-mono tracking-widest uppercase flex items-center gap-2">
 <AlertTriangle className="w-4 h-4 flex-shrink-0" /> {error}
 <button onClick={() => setError(null)} className="ml-auto underline">Dismiss</button>
 </div>
 )}

 {saved && (
 <div className="mb-6 px-4 py-3 rounded-none bg-[var(--ng-lime)]/10 border border-[var(--ng-lime)]/30 text-[var(--ng-lime)] text-[10px] font-mono tracking-widest uppercase flex items-center gap-2">
 <CheckCircle2 className="w-4 h-4" /> Retention policy updated successfully.
 </div>
 )}

 {purgeResult && (
 <div className="mb-6 px-4 py-3 rounded-none bg-[var(--ng-cyan-bright)]/10 border border-[var(--ng-cyan-bright)]/30 text-[var(--ng-cyan-bright)] text-[10px] font-mono tracking-widest uppercase flex items-center gap-2">
 <HardDrive className="w-4 h-4" /> {purgeResult}
 </div>
 )}

 <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
 {/* Current Setting */}
 <div className="ng-surface border border-ng-outline-dim/40 rounded-none p-6 space-y-6">
 <h2 className="font-headline tracking-widest uppercase text-sm font-bold uppercase tracking-widest text-ng-cyan/80 flex items-center gap-2">
 <Clock className="w-4 h-4" /> Retention Period
 </h2>

 <div className="text-center py-6">
 <div className="text-6xl font-bold text-ng-on tabular-nums">{pendingDays}</div>
 <p className="text-ng-muted text-sm mt-2">days</p>
 </div>

 <input
 type="range"
 min={30}
 max={365}
 step={1}
 value={pendingDays}
 onChange={e => setPendingDays(Number(e.target.value))}
 className="w-full accent-ng-cyan-bright"
 />

 <div className="flex justify-between text-[10px] text-ng-muted font-mono">
 <span>30d</span>
 <span>90d</span>
 <span>180d</span>
 <span>365d</span>
 </div>

 {/* Presets */}
 <div className="grid grid-cols-2 gap-2">
 {PRESETS.map(preset => (
 <button
 key={preset.days}
 onClick={() => setPendingDays(preset.days)}
 className={`px-3 py-2 rounded-none border text-xs text-left transition-all ${
 pendingDays === preset.days
 ? "border-ng-cyan/50 bg-ng-cyan-bright/10 text-ng-cyan"
 : "border-ng-outline-dim/40 bg-ng-base text-ng-muted hover:border-ng-on"
 }`}
 >
 <span className="font-bold">{preset.label}</span>
 <p className="text-[9px] mt-0.5 opacity-70">{preset.description}</p>
 </button>
 ))}
 </div>

 <button
 onClick={saveRetention}
 disabled={saving || pendingDays === currentDays}
 className="w-full px-4 py-2.5 bg-ng-cyan-bright text-ng-base font-bold rounded-none hover:bg-ng-cyan-bright/90 transition-colors flex items-center justify-center gap-2 text-sm disabled:opacity-40"
 >
 <Save className="w-4 h-4" />
 {saving ? "Saving..." : "Save Retention Policy"}
 </button>
 </div>

 {/* Info & Purge */}
 <div className="space-y-6">
 <div className="ng-surface border border-ng-outline-dim/40 rounded-none p-6 space-y-4">
 <h2 className="font-headline tracking-widest uppercase text-sm font-bold uppercase tracking-widest text-ng-cyan/80">
 Compliance Requirements
 </h2>
 <div className="space-y-3">
 {[
 { framework: "SOC 2 Type II", minimum: "90 days", color: "text-[var(--ng-cyan-bright)]" },
 { framework: "HIPAA", minimum: "180 days (6 years for records)", color: "text-[var(--ng-cyan)]" },
 { framework: "PCI-DSS v4.0", minimum: "365 days", color: "text-[var(--ng-magenta)]" },
 { framework: "GDPR", minimum: "As long as needed (Art. 5)", color: "text-[var(--ng-cyan)]" },
 { framework: "NIST CSF 2.0", minimum: "Organization-defined", color: "text-[var(--ng-lime)]" },
 ].map(item => (
 <div key={item.framework} className="flex justify-between items-center py-2 border-b border-ng-outline-dim/40 last:border-0">
 <span className={`text-sm font-medium ${item.color}`}>{item.framework}</span>
 <span className="text-xs text-ng-muted font-mono">{item.minimum}</span>
 </div>
 ))}
 </div>
 </div>

 <div className="ng-surface border border-[var(--ng-error)]/30 rounded-none p-6 space-y-4">
 <h2 className="font-headline tracking-widest uppercase text-sm font-bold uppercase tracking-widest text-[var(--ng-error)]/80 flex items-center gap-2">
 <Trash2 className="w-4 h-4" /> Manual Data Purge
 </h2>
 <p className="text-xs text-ng-muted leading-relaxed">
 Manually trigger a data purge to remove events and audit data older than
 the current retention period ({currentDays} days). This operation is
 <strong className="text-[var(--ng-error)]"> irreversible</strong>.
 </p>
 <button
 onClick={() => setIsConfirmOpen(true)}
 disabled={purging}
 className="w-full px-4 py-2.5 bg-[var(--ng-error)]/10 border border-[var(--ng-error)]/30 text-[var(--ng-error)] font-bold rounded-none hover:bg-[var(--ng-error)]/20 transition-colors flex items-center justify-center gap-2 text-sm disabled:opacity-40"
 >
 <Trash2 className="w-4 h-4" />
 {purging ? "Purging..." : "Purge Expired Data"}
 </button>
 </div>
 </div>
 </div>

 <ConfirmDialog 
 isOpen={isConfirmOpen}
 title="Purge Data"
 message={`Are you sure you want to purge data older than the retention period (${currentDays} days)? This action is irreversible.`}
 confirmLabel="Purge Data"
 dangerous={true}
 onConfirm={triggerPurge}
 onCancel={() => setIsConfirmOpen(false)}
 />
 </div>
 );
}
