"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Users, Plus, Shield, ChevronDown, UserX, UserCheck, Search, AlertCircle } from "lucide-react";

interface User {
 id: string;
 email: string;
 role: string;
 display_name: string | null;
 tenant_id: string;
 is_active: boolean;
 mfa_enabled: boolean;
}

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
 if (res.status === 500) throw new Error("Admin service unavailable. Please check backend logs.");
 const body = await res.json().catch(() => ({}));
 throw new Error(body.detail || `Request failed: ${res.status}`);
 }
 return res.json();
}

const ROLE_BADGE: Record<string, string> = {
 admin: "text-[var(--ng-error)] bg-[var(--ng-error)]/10 border-[var(--ng-error)]/30",
 analyst: "text-[var(--ng-cyan-bright)] bg-[var(--ng-cyan-bright)]/10 border-[var(--ng-cyan-bright)]/30",
 viewer: "text-ng-muted bg-ng-muted/10 border-ng-outline-dim/40/30",
};

export default function AdminPage() {
 const [users, setUsers] = useState<User[]>([]);
 const [loading, setLoading] = useState(true);
 const [error, setError] = useState<string | null>(null);
 const [search, setSearch] = useState("");
 const [showCreate, setShowCreate] = useState(false);
 const [form, setForm] = useState({ email: "", password: "", role: "viewer", display_name: "" });

 const fetchUsers = useCallback(async () => {
 try {
 setLoading(true);
 const data = await apiFetch("/admin/users");
 setUsers(data);
 } catch (err: any) {
 setError(err.message);
 } finally {
 setLoading(false);
 }
 }, []);

 useEffect(() => { fetchUsers(); }, [fetchUsers]);

 const createUser = async () => {
 try {
 await apiFetch("/admin/users", { method: "POST", body: JSON.stringify(form) });
 setShowCreate(false);
 setForm({ email: "", password: "", role: "viewer", display_name: "" });
 fetchUsers();
 } catch (err: any) {
 setError(err.message);
 }
 };

 const updateRole = async (email: string, role: string) => {
 try {
 await apiFetch(`/admin/users/${encodeURIComponent(email)}/role`, {
 method: "PATCH", body: JSON.stringify({ role }),
 });
 fetchUsers();
 } catch (err: any) {
 setError(err.message);
 }
 };

 const toggleActive = async (email: string, isActive: boolean) => {
 const action = isActive ? "deactivate" : "activate";
 try {
 await apiFetch(`/admin/users/${encodeURIComponent(email)}/${action}`, { method: "PATCH" });
 fetchUsers();
 } catch (err: any) {
 setError(err.message);
 }
 };

 const filtered = users.filter(u =>
 u.email.toLowerCase().includes(search.toLowerCase()) ||
 (u.display_name || "").toLowerCase().includes(search.toLowerCase())
 );

 return (
 <div className="flex-1 flex flex-col h-full overflow-y-auto custom-scrollbar p-8">
 <header className="mb-8 flex justify-between items-end">
 <div>
 <h1 className="font-headline tracking-widest uppercase text-3xl font-bold text-ng-on tracking-tight flex items-center gap-3">
 <Users className="w-8 h-8 text-ng-cyan" />
 User Management
 </h1>
 <p className="text-ng-muted mt-2">Manage platform users, roles, and access controls.</p>
 </div>
 <button
 onClick={() => setShowCreate(true)}
 className="px-4 py-2 bg-ng-cyan-bright text-ng-base font-bold rounded-none hover:bg-ng-cyan-bright/90 transition-colors flex items-center gap-2 text-[10px] font-mono tracking-widest uppercase"
 >
 <Plus className="w-4 h-4" /> Create User
 </button>
 </header>

 {error && (
 <div className="mb-4 px-4 py-3 rounded-none bg-ng-error/10 border border-ng-error/30 flex items-center justify-between">
 <div className="flex items-center gap-3">
 <AlertCircle className="w-4 h-4 text-ng-error" />
 <span className="text-[11px] font-mono uppercase tracking-wide text-ng-error font-bold">
 {error}
 </span>
 </div>
 <button 
 onClick={() => setError(null)} 
 className="text-[10px] font-mono uppercase tracking-widest text-ng-muted hover:text-ng-on transition-colors border border-ng-outline-dim/40 bg-ng-mid px-2 py-1 rounded-none"
 >
 Dismiss
 </button>
 </div>
 )}

 {/* Create User Modal */}
 {showCreate && (
 <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
 <div className="ng-surface border border-ng-outline-dim/40 p-6 w-full max-w-md space-y-4">
 <h2 className="font-headline tracking-widest uppercase text-lg font-bold text-ng-on">Create New User</h2>
 <input
 placeholder="Email" value={form.email}
 onChange={e => setForm({ ...form, email: e.target.value })}
 className="w-full px-3 py-2 bg-ng-mid border border-ng-outline-dim/40 rounded-none text-ng-on text-sm focus:outline-none focus:border-ng-cyan/50"
 />
 <input
 placeholder="Display Name" value={form.display_name}
 onChange={e => setForm({ ...form, display_name: e.target.value })}
 className="w-full px-3 py-2 bg-ng-mid border border-ng-outline-dim/40 rounded-none text-ng-on text-sm focus:outline-none focus:border-ng-cyan/50"
 />
 <input
 type="password" placeholder="Password" value={form.password}
 onChange={e => setForm({ ...form, password: e.target.value })}
 className="w-full px-3 py-2 bg-ng-mid border border-ng-outline-dim/40 rounded-none text-ng-on text-sm focus:outline-none focus:border-ng-cyan/50"
 />
 <select
 value={form.role}
 onChange={e => setForm({ ...form, role: e.target.value })}
 className="w-full px-3 py-2 bg-ng-mid border border-ng-outline-dim/40 rounded-none text-ng-on text-sm focus:outline-none focus:border-ng-cyan/50"
 >
 <option value="viewer">Viewer</option>
 <option value="analyst">Analyst</option>
 <option value="admin">Admin</option>
 </select>
 <div className="flex gap-3 pt-2">
 <button
 onClick={createUser}
 className="flex-1 px-4 py-2 bg-ng-cyan-bright text-ng-base font-bold rounded-none text-[10px] font-mono tracking-widest uppercase hover:bg-ng-cyan-bright/90 transition-colors"
 >
 Create
 </button>
 <button
 onClick={() => setShowCreate(false)}
 className="flex-1 px-4 py-2 bg-ng-mid border border-ng-outline-dim/40 text-ng-on rounded-none text-[10px] font-mono tracking-widest uppercase hover:bg-ng-mid/80 transition-colors"
 >
 Cancel
 </button>
 </div>
 </div>
 </div>
 )}

 {/* Search */}
 <div className="mb-4 relative">
 <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ng-muted" />
 <input
 placeholder="Search users..."
 value={search}
 onChange={e => setSearch(e.target.value)}
 className="w-full pl-10 pr-4 py-2 bg-ng-mid border border-ng-outline-dim/40 rounded-none text-ng-on text-[10px] font-mono focus:outline-none focus:border-ng-cyan/50 uppercase tracking-widest"
 />
 </div>

 {/* Users Table */}
 <div className="ng-surface border border-ng-outline-dim/40">
 <table className="w-full text-left text-sm">
 <thead className="bg-ng-mid/50 text-ng-muted uppercase text-[10px] tracking-wider">
 <tr>
 <th className="px-6 py-4 font-medium">User</th>
 <th className="px-6 py-4 font-medium">Role</th>
 <th className="px-6 py-4 font-medium">MFA</th>
 <th className="px-6 py-4 font-medium">Status</th>
 <th className="px-6 py-4 font-medium">Actions</th>
 </tr>
 </thead>
 <tbody className="divide-y divide-ng-outline-dim/30 text-ng-on">
 {loading ? (
 <tr><td colSpan={5} className="px-6 py-12 text-center text-ng-muted">Loading users...</td></tr>
 ) : filtered.length === 0 ? (
 <tr><td colSpan={5} className="px-6 py-12 text-center text-ng-muted">No users found.</td></tr>
 ) : filtered.map(user => (
 <tr key={user.id} className="hover:bg-ng-mid/30 transition-colors">
 <td className="px-6 py-4">
 <div className="flex items-center gap-3">
 <div className="w-8 h-8 rounded-none bg-gradient-to-br from-ng-cyan-bright/30 to-ng-cyan-bright/10 border border-ng-cyan/50/30 flex items-center justify-center">
 <span className="text-xs font-bold text-ng-cyan">
 {(user.display_name || user.email).charAt(0).toUpperCase()}
 </span>
 </div>
 <div>
 <p className="text-ng-on font-medium">{user.display_name || user.email}</p>
 <p className="text-[10px] text-ng-muted font-mono">{user.email}</p>
 </div>
 </div>
 </td>
 <td className="px-6 py-4">
 <select
 value={user.role}
 onChange={e => updateRole(user.email, e.target.value)}
 className={`px-2 py-0.5 rounded-none text-[10px] uppercase font-bold border bg-transparent cursor-pointer ${ROLE_BADGE[user.role] || ROLE_BADGE.viewer}`}
 >
 <option value="viewer">Viewer</option>
 <option value="analyst">Analyst</option>
 <option value="admin">Admin</option>
 </select>
 </td>
 <td className="px-6 py-4">
 <span className={`text-[10px] font-bold uppercase ${user.mfa_enabled ? "text-[var(--ng-lime)]" : "text-ng-muted"}`}>
 {user.mfa_enabled ? "âœ“ Enabled" : "Disabled"}
 </span>
 </td>
 <td className="px-6 py-4">
 <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-none text-[10px] font-bold ${
 user.is_active
 ? "text-[var(--ng-lime)] bg-[var(--ng-lime)]/10"
 : "text-[var(--ng-error)] bg-[var(--ng-error)]/10"
 }`}>
 <span className={`w-1.5 h-1.5 rounded-none ${user.is_active ? "bg-[var(--ng-lime)]" : "bg-[var(--ng-error)]"}`} />
 {user.is_active ? "Active" : "Disabled"}
 </span>
 </td>
 <td className="px-6 py-4">
 <button
 onClick={() => toggleActive(user.email, user.is_active)}
 className={`text-xs font-semibold flex items-center gap-1 ${
 user.is_active
 ? "text-[var(--ng-error)] hover:opacity-80"
 : "text-[var(--ng-lime)] hover:opacity-80"
 }`}
 >
 {user.is_active ? <UserX className="w-3 h-3" /> : <UserCheck className="w-3 h-3" />}
 {user.is_active ? "Deactivate" : "Activate"}
 </button>
 </td>
 </tr>
 ))}
 </tbody>
 </table>
 </div>
 </div>
 );
}

