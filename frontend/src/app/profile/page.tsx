"use client";

import { User, Shield, Building2, Mail, Moon, Sun, Key, Copy, CheckCircle2, AlertTriangle } from "lucide-react";
import { useState, useEffect } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

function parseJwt(token: string): Record<string, any> | null {
 try {
 const payload = token.split('.')[1];
 return JSON.parse(atob(payload));
 } catch {
 return null;
 }
}

function getToken() {
 return typeof window !== "undefined" ? localStorage.getItem("sentinel_token") : null;
}

async function apiFetch(path: string, opts: RequestInit = {}) {
 const token = getToken();
 const res = await fetch(`/api/proxy${path}`, {
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

export default function ProfilePage() {
 const [darkMode, setDarkMode] = useState(true);
 const [claims, setClaims] = useState<Record<string, any>>({});

 // MFA state
 const [mfaStep, setMfaStep] = useState<"idle" | "setup" | "verify" | "done">("idle");
 const [mfaSecret, setMfaSecret] = useState("");
 const [mfaUri, setMfaUri] = useState("");
 const [mfaCode, setMfaCode] = useState("");
 const [backupCodes, setBackupCodes] = useState<string[]>([]);
 const [mfaError, setMfaError] = useState<string | null>(null);
 const [copied, setCopied] = useState(false);

 useEffect(() => {
 const token = typeof window !== 'undefined' ? localStorage.getItem('sentinel_token') : null;
 if (token) {
 const parsed = parseJwt(token);
 if (parsed) setClaims(parsed);
 }
 }, []);

 const name = claims.display_name || claims.sub || "Analyst";
 const email = claims.email || claims.sub || "—";
 const role = claims.role || "analyst";
 const tenant = claims.tenant_id || "default";
 const mfaEnabled = !!claims.mfa_enabled;

 const roleColors: Record<string, string> = {
 admin: "text-[var(--ng-error)] bg-[var(--ng-error)]/10 border-[var(--ng-error)]/30",
 analyst: "text-[var(--ng-cyan-bright)] bg-[var(--ng-cyan-bright)]/10 border-[var(--ng-cyan-bright)]/30",
 viewer: "text-ng-muted bg-ng-muted/10 border-ng-outline-dim/40/30",
 };

 const startMfaSetup = async () => {
 try {
 setMfaError(null);
 const data = await apiFetch("/api/v1/auth/enable-mfa", { method: "POST" });
 setMfaSecret(data.secret);
 setMfaUri(data.provisioning_uri);
 setMfaStep("setup");
 } catch (err: any) {
 setMfaError(err.message);
 }
 };

 const verifyMfa = async () => {
 try {
 setMfaError(null);
 const data = await apiFetch("/api/v1/auth/verify-mfa-setup", {
 method: "POST", body: JSON.stringify({ mfa_code: mfaCode }),
 });
 setBackupCodes(data.backup_codes || []);
 setMfaStep("done");
 } catch (err: any) {
 setMfaError(err.message);
 }
 };

 const copyBackupCodes = () => {
 navigator.clipboard.writeText(backupCodes.join("\n"));
 setCopied(true);
 setTimeout(() => setCopied(false), 2000);
 };

 return (
 <div className="flex-1 overflow-auto custom-scrollbar p-8">
 <div className="max-w-2xl mx-auto space-y-8">
 <header>
 <h1 className="font-headline tracking-widest uppercase text-2xl font-bold text-ng-on tracking-tight flex items-center gap-3">
 <User className="w-6 h-6 text-ng-cyan" />
 Analyst Profile
 </h1>
 <p className="text-ng-muted text-sm mt-1">Account details and preferences</p>
 </header>

 {/* Identity Card */}
 <div className="bg-ng-mid border border-ng-outline-dim/40 rounded-none p-6 space-y-5">
 <div className="flex items-center gap-4">
 <div className="w-16 h-16 rounded-none bg-gradient-to-br from-ng-cyan-bright/30 to-ng-cyan-bright/10 border border-ng-cyan/50/40 flex items-center justify-center">
 <span className="text-2xl font-bold text-ng-cyan">{name.charAt(0).toUpperCase()}</span>
 </div>
 <div>
 <h2 className="font-headline tracking-widest uppercase text-lg font-bold text-ng-on">{name}</h2>
 <span className={`inline-block mt-1 px-2 py-0.5 rounded-none text-[10px] uppercase font-bold border ${roleColors[role] ?? roleColors.viewer}`}>
 {role}
 </span>
 </div>
 </div>

 <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 border-t border-ng-outline-dim/40">
 <div className="flex items-center gap-3">
 <Mail className="w-4 h-4 text-ng-muted" />
 <div>
 <p className="text-[10px] text-ng-muted uppercase tracking-wider font-bold">Email</p>
 <p className={`text-sm font-mono ${email === "—" ? "text-ng-muted" : "text-ng-on"}`}>
 {email === "—" ? "Email not set — contact your administrator" : email}
 </p>
 </div>
 </div>
 <div className="flex items-center gap-3">
 <Building2 className="w-4 h-4 text-ng-muted" />
 <div>
 <p className="text-[10px] text-ng-muted uppercase tracking-wider font-bold">Tenant</p>
 <p className="text-sm text-ng-on font-mono">{tenant}</p>
 </div>
 </div>
 <div className="flex items-center gap-3">
 <Shield className="w-4 h-4 text-ng-muted" />
 <div>
 <p className="text-[10px] text-ng-muted uppercase tracking-wider font-bold">Role</p>
 <p className="text-sm text-ng-on capitalize">{role}</p>
 </div>
 </div>
 </div>
 </div>

 {/* MFA Management */}
 <div className="bg-ng-mid border border-ng-outline-dim/40 rounded-none p-6">
 <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-ng-cyan/80 mb-4 flex items-center gap-2">
 <Key className="w-3.5 h-3.5" />
 Multi-Factor Authentication
 </h3>

 {mfaError && (
 <div className="mb-4 px-3 py-2 rounded-none bg-[var(--ng-error)]/10 border border-[var(--ng-error)]/30 text-[var(--ng-error)] text-xs flex items-center gap-2">
 <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" /> {mfaError}
 </div>
 )}

 {mfaStep === "idle" && (
 <div className="flex items-center justify-between">
 <div>
 <p className="text-sm text-ng-on font-medium">
 {mfaEnabled ? "MFA is enabled" : "MFA is not enabled"}
 </p>
 <p className="text-[10px] text-ng-muted">
 {mfaEnabled
 ? "Your account is protected with two-factor authentication."
 : "Enable TOTP-based two-factor authentication for added security."}
 </p>
 </div>
 {!mfaEnabled && (
 <button
 onClick={startMfaSetup}
 className="px-4 py-2 bg-ng-cyan-bright text-ng-base font-bold rounded-none text-xs hover:bg-ng-cyan-bright/90"
 >
 Enable MFA
 </button>
 )}
 {mfaEnabled && (
 <span className="px-2 py-1 rounded-none text-[10px] font-bold text-[var(--ng-lime)] bg-[var(--ng-lime)]/10 border border-[var(--ng-lime)]/30">
 ✓ Active
 </span>
 )}
 </div>
 )}

 {mfaStep === "setup" && (
 <div className="space-y-4">
 <p className="text-sm text-ng-on">
 Enter this secret key in your authenticator app:
 </p>
 <div className="bg-ng-mid border border-ng-outline-dim/40 rounded-none p-4 text-center space-y-2">
 <code className="block text-base text-ng-cyan font-mono tracking-[0.25em] break-all select-all">
 {mfaSecret}
 </code>
 <p className="text-[10px] text-ng-muted">Google Authenticator · Authy · 1Password → Add account → Enter key manually</p>
 </div>
 <div className="flex gap-3">
 <input
 placeholder="Enter 6-digit code"
 value={mfaCode}
 onChange={e => setMfaCode(e.target.value)}
 maxLength={6}
 className="flex-1 px-3 py-2 bg-ng-mid border border-ng-outline-dim/40 rounded-none text-ng-on text-sm text-center tracking-[0.3em] focus:outline-none focus:border-ng-cyan/50"
 />
 <button
 onClick={verifyMfa}
 disabled={mfaCode.length < 6}
 className="px-4 py-2 bg-ng-cyan-bright text-ng-base font-bold rounded-none text-xs hover:bg-ng-cyan-bright/90 disabled:opacity-40"
 >
 Verify
 </button>
 </div>
 </div>
 )}

 {mfaStep === "done" && (
 <div className="space-y-4">
 <div className="flex items-center gap-2 text-[var(--ng-lime)]">
 <CheckCircle2 className="w-5 h-5" />
 <p className="font-bold text-sm">MFA enabled successfully!</p>
 </div>
 <p className="text-xs text-ng-muted">
 Save these backup codes in a safe place. Each code can only be used once.
 </p>
 <div className="bg-ng-mid border border-ng-outline-dim/40 rounded-none p-4">
 <div className="grid grid-cols-2 gap-2">
 {backupCodes.map((code, i) => (
 <code key={i} className="text-xs text-ng-on font-mono">{code}</code>
 ))}
 </div>
 </div>
 <button
 onClick={copyBackupCodes}
 className="px-3 py-1.5 text-xs text-ng-muted hover:text-ng-on flex items-center gap-1.5 bg-ng-mid border border-ng-outline-dim/40 rounded-none"
 >
 {copied ? <CheckCircle2 className="w-3 h-3 text-[var(--ng-lime)]" /> : <Copy className="w-3 h-3" />}
 {copied ? "Copied!" : "Copy All"}
 </button>
 </div>
 )}
 </div>

 {/* Preferences */}
 <div className="bg-ng-mid border border-ng-outline-dim/40 rounded-none p-6">
 <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-ng-cyan/80 mb-4">Preferences</h3>
 <div className="flex items-center justify-between">
 <div className="flex items-center gap-3">
 {darkMode ? <Moon className="w-4 h-4 text-ng-muted" /> : <Sun className="w-4 h-4 text-ng-magenta" />}
 <div>
 <p className="text-sm text-ng-on font-medium">Dark Mode</p>
 <p className="text-[10px] text-ng-muted">Toggle interface theme</p>
 </div>
 </div>
 <button
 onClick={() => setDarkMode(!darkMode)}
 className={`w-10 h-5 rounded-full transition-colors relative ${darkMode ? 'bg-ng-cyan-bright' : 'bg-ng-mid'}`}
 >
 <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${darkMode ? 'left-5' : 'left-0.5'}`} />
 </button>
 </div>
 </div>
 </div>
 </div>
 );
}

