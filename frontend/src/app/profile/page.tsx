"use client";

import { User, Shield, Building2, Mail, Moon, Sun } from "lucide-react";
import { useState, useEffect } from "react";

function parseJwt(token: string): Record<string, any> | null {
    try {
        const payload = token.split('.')[1];
        return JSON.parse(atob(payload));
    } catch {
        return null;
    }
}

export default function ProfilePage() {
    const [darkMode, setDarkMode] = useState(true);
    const [claims, setClaims] = useState<Record<string, any>>({});

    useEffect(() => {
        const token = typeof window !== 'undefined' ? localStorage.getItem('sf_token') : null;
        if (token) {
            const parsed = parseJwt(token);
            if (parsed) setClaims(parsed);
        }
    }, []);

    const name = claims.display_name || claims.sub || "Analyst";
    const email = claims.email || claims.sub || "—";
    const role = claims.role || "analyst";
    const tenant = claims.tenant_id || "default";

    const roleColors: Record<string, string> = {
        admin: "text-red-400 bg-red-400/10 border-red-400/30",
        analyst: "text-cyan-400 bg-cyan-400/10 border-cyan-400/30",
        viewer: "text-slate-400 bg-slate-400/10 border-slate-400/30",
    };

    return (
        <div className="flex-1 overflow-auto custom-scrollbar p-8">
            <div className="max-w-2xl mx-auto space-y-8">
                <header>
                    <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
                        <User className="w-6 h-6 text-brand-accent" />
                        Analyst Profile
                    </h1>
                    <p className="text-slate-400 text-sm mt-1">Account details and preferences</p>
                </header>

                {/* Identity Card */}
                <div className="bg-brand-card border border-brand-border rounded-xl p-6 space-y-5">
                    <div className="flex items-center gap-4">
                        <div className="w-16 h-16 rounded-full bg-gradient-to-br from-brand-accent/30 to-brand-accent/10 border border-brand-accent/40 flex items-center justify-center">
                            <span className="text-2xl font-bold text-brand-accent">{name.charAt(0).toUpperCase()}</span>
                        </div>
                        <div>
                            <h2 className="text-lg font-bold text-white">{name}</h2>
                            <span className={`inline-block mt-1 px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${roleColors[role] ?? roleColors.viewer}`}>
                                {role}
                            </span>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 border-t border-brand-border">
                        <div className="flex items-center gap-3">
                            <Mail className="w-4 h-4 text-slate-500" />
                            <div>
                                <p className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">Email</p>
                                <p className="text-sm text-white font-mono">{email}</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-3">
                            <Building2 className="w-4 h-4 text-slate-500" />
                            <div>
                                <p className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">Tenant</p>
                                <p className="text-sm text-white font-mono">{tenant}</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-3">
                            <Shield className="w-4 h-4 text-slate-500" />
                            <div>
                                <p className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">Role</p>
                                <p className="text-sm text-white capitalize">{role}</p>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Preferences */}
                <div className="bg-brand-card border border-brand-border rounded-xl p-6">
                    <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-brand-accent/80 mb-4">Preferences</h3>
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            {darkMode ? <Moon className="w-4 h-4 text-slate-400" /> : <Sun className="w-4 h-4 text-yellow-400" />}
                            <div>
                                <p className="text-sm text-white font-medium">Dark Mode</p>
                                <p className="text-[10px] text-slate-500">Toggle interface theme</p>
                            </div>
                        </div>
                        <button
                            onClick={() => setDarkMode(!darkMode)}
                            className={`w-10 h-5 rounded-full transition-colors relative ${darkMode ? 'bg-brand-accent' : 'bg-slate-600'}`}
                        >
                            <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${darkMode ? 'left-5' : 'left-0.5'}`} />
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
