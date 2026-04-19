"use client";

import React, { useState } from "react";
import { 
 Settings as SettingsIcon, Shield, Key, Bell, Globe, 
 Monitor, Clock, Zap, Save, RefreshCcw, Eye, EyeOff
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { PanelCard, StaggerChildren } from "@/components/ui/MotionWrappers";

type Tab = "general" | "api" | "security" | "notifications";

export default function SettingsPage() {
 const [activeTab, setActiveTab] = useState<Tab>("general");
 const [saved, setSaved] = useState(false);
 const [showApiKey, setShowApiKey] = useState(false);

 const handleSave = () => {
 setSaved(true);
 setTimeout(() => setSaved(false), 2000);
 };

 return (
 <div className="flex flex-col h-full bg-ng-base p-6 gap-6 relative overflow-hidden">
 {/* Header */}
 <div className="flex items-center justify-between shrink-0">
 <div className="flex items-center gap-3">
 <div className="w-10 h-10 bg-ng-cyan-bright/10 border border-ng-cyan/50/30 flex items-center justify-center text-ng-cyan">
 <SettingsIcon className="w-5 h-5" />
 </div>
 <div>
 <h1 className="font-headline tracking-widest uppercase text-sm font-mono font-bold tracking-[0.2em] uppercase text-ng-on">Platform Settings</h1>
 <p className="text-[10px] font-mono text-ng-muted uppercase tracking-widest mt-0.5">Configure UMBRIX nodes and interface</p>
 </div>
 </div>
 <button 
 onClick={handleSave}
 className="flex items-center gap-2 px-6 py-2 bg-ng-cyan-bright text-ng-base text-[10px] font-mono font-bold uppercase tracking-widest hover:bg-ng-cyan-bright-active transition-colors rounded-none"
 >
 {saved ? <CheckCircle className="w-3.5 h-3.5" /> : <Save className="w-3.5 h-3.5" />}
 {saved ? "Config Saved" : "Apply Changes"}
 </button>
 </div>

 <div className="flex-1 flex gap-6 min-h-0">
 {/* Internal Nav */}
 <div className="w-48 shrink-0 flex flex-col gap-1">
 {[
 { id: "general", label: "General", icon: <Globe className="w-4 h-4" /> },
 { id: "api", label: "API & Keys", icon: <Key className="w-4 h-4" /> },
 { id: "security", label: "Security", icon: <Shield className="w-4 h-4" /> },
 { id: "notifications", label: "Alerting", icon: <Bell className="w-4 h-4" /> },
 ].map(tab => (
 <button
 key={tab.id}
 onClick={() => setActiveTab(tab.id as Tab)}
 className={`flex items-center gap-3 px-4 py-3 text-[11px] font-mono uppercase tracking-widest transition-all border-l-2
 ${activeTab === tab.id 
 ? "bg-ng-mid border-ng-cyan/50 text-ng-cyan" 
 : "border-transparent text-ng-muted hover:bg-ng-mid/50 hover:text-ng-on"}`}
 >
 {tab.icon}
 {tab.label}
 </button>
 ))}
 </div>

 {/* Content Area */}
 <div className="flex-1 min-w-0">
 <AnimatePresence mode="wait">
 <motion.div
 key={activeTab}
 initial={{ opacity: 0, x: 10 }}
 animate={{ opacity: 1, x: 0 }}
 exit={{ opacity: 0, x: -10 }}
 transition={{ duration: 0.2 }}
 className="h-full"
 >
 <PanelCard className="h-full flex flex-col p-8 overflow-y-auto custom-scrollbar bg-ng-mid/30">
 {activeTab === "general" && (
 <div className="space-y-8">
 <section>
 <h3 className="text-[10px] font-mono text-ng-cyan uppercase tracking-[0.2em] mb-4 border-b border-ng-outline-dim/40 pb-2">Interface Configuration</h3>
 <div className="grid grid-cols-2 gap-8">
 <div className="space-y-2">
 <label className="text-[11px] font-mono text-ng-on uppercase">Preferred Theme</label>
 <select className="w-full bg-ng-base border border-ng-outline-dim/40 p-2 text-[11px] font-mono text-ng-on focus:outline-none focus:border-ng-cyan/50 rounded-none">
 <option>DEEP_SPACE_DARK (DEFAULT)</option>
 <option>INDUSTRIAL_LIGHT</option>
 <option>SYSTEM_FOLLOW</option>
 </select>
 </div>
 <div className="space-y-2">
 <label className="text-[11px] font-mono text-ng-on uppercase">Data Refresh Rate</label>
 <select className="w-full bg-ng-base border border-ng-outline-dim/40 p-2 text-[11px] font-mono text-ng-on focus:outline-none focus:border-ng-cyan/50 rounded-none">
 <option>REAL_TIME (3s)</option>
 <option>TIGHT (10s)</option>
 <option>LAX (30s)</option>
 </select>
 </div>
 </div>
 </section>

 <section>
 <h3 className="text-[10px] font-mono text-ng-cyan uppercase tracking-[0.2em] mb-4 border-b border-ng-outline-dim/40 pb-2">Node Environment</h3>
 <div className="grid grid-cols-2 gap-8">
 <div className="space-y-2">
 <label className="text-[11px] font-mono text-ng-on uppercase">Timezone (Global)</label>
 <select className="w-full bg-ng-base border border-ng-outline-dim/40 p-2 text-[11px] font-mono text-ng-on focus:outline-none focus:border-ng-cyan/50 rounded-none">
 <option>UTC+00:00 (Greenwich)</option>
 <option>UTC-05:00 (New York)</option>
 <option>UTC+05:30 (Mumbai)</option>
 </select>
 </div>
 <div className="space-y-2 flex items-end">
 <button className="flex items-center gap-2 px-4 py-2 border border-ng-error/30 text-ng-error text-[10px] font-mono uppercase hover:bg-ng-error/10 transition-colors w-full justify-center">
 <RefreshCcw className="w-3.5 h-3.5" /> Purge Local Cache
 </button>
 </div>
 </div>
 </section>
 </div>
 )}

 {activeTab === "api" && (
 <div className="space-y-8">
 <section>
 <h3 className="text-[10px] font-mono text-ng-cyan uppercase tracking-[0.2em] mb-4 border-b border-ng-outline-dim/40 pb-2">UQL API Access</h3>
 <div className="space-y-4">
 <div className="space-y-2">
 <label className="text-[11px] font-mono text-ng-on uppercase">Primary Access Token</label>
 <div className="flex gap-2">
 <div className="flex-1 bg-ng-base border border-ng-outline-dim/40 p-2 text-[11px] font-mono text-ng-on flex items-center justify-between overflow-hidden">
  <span className="truncate">{showApiKey ? "sf_key_••••_••••_••••_active" : "••••••••••••••••••••••••••••••••"}</span>
 <button onClick={() => setShowApiKey(!showApiKey)} className="text-ng-muted hover:text-ng-on ml-2">
 {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
 </button>
 </div>
 <button className="px-4 border border-ng-outline-dim/40 text-[10px] font-mono uppercase hover:bg-ng-mid transition-colors">Rotate</button>
 </div>
 </div>
 </div>
 </section>

 <section>
 <h3 className="text-[10px] font-mono text-ng-cyan uppercase tracking-[0.2em] mb-4 border-b border-ng-outline-dim/40 pb-2">Webhook Relay</h3>
 <div className="space-y-2">
 <label className="text-[11px] font-mono text-ng-on uppercase">Destination Endpoint</label>
 <input 
 type="text" 
 placeholder="https://hooks.slack.com/services/..."
 className="w-full bg-ng-base border border-ng-outline-dim/40 p-2 text-[11px] font-mono text-ng-on focus:outline-none focus:border-ng-cyan/50 rounded-none"
 />
 </div>
 </section>
 </div>
 )}

 {activeTab === "security" && (
 <div className="space-y-8">
 <section>
 <h3 className="text-[10px] font-mono text-ng-cyan uppercase tracking-[0.2em] mb-4 border-b border-ng-outline-dim/40 pb-2">Authentication</h3>
 <div className="space-y-6">
 <div className="flex items-center justify-between border-b border-ng-outline-dim/40/50 pb-4">
 <div>
 <div className="text-[11px] font-mono text-ng-on uppercase">Multi-Factor Auth</div>
 <div className="text-[9px] font-mono text-ng-muted uppercase mt-1">Requires biometric or TOTP for critical actions</div>
 </div>
 <div className="w-12 h-6 bg-ng-base border border-ng-outline-dim/40 p-1 cursor-pointer">
 <div className="w-4 h-4 bg-ng-cyan-bright" />
 </div>
 </div>
 <div className="flex items-center justify-between border-b border-ng-outline-dim/40/50 pb-4">
 <div>
 <div className="text-[11px] font-mono text-ng-on uppercase">Strict Session Mode</div>
 <div className="text-[9px] font-mono text-ng-muted uppercase mt-1">Automated logout after 15 minutes of inactivity</div>
 </div>
 <div className="w-12 h-6 bg-ng-base border border-ng-outline-dim/40 p-1 cursor-pointer">
 <div className="w-4 h-4 bg-ng-muted translate-x-0" />
 </div>
 </div>
 </div>
 </section>

 <section>
 <div className="p-4 border border-ng-magenta/20 bg-ng-magenta/5">
 <h4 className="text-[10px] font-mono text-ng-magenta uppercase flex items-center gap-2 mb-2">
 <Shield className="w-3.5 h-3.5" /> High Entropy Note
 </h4>
 <p className="text-[9px] font-mono text-ng-muted uppercase leading-relaxed">
 Passwords are encrypted using Argon2id. Changes will invalidate all active sessions globally.
 </p>
 </div>
 </section>
 </div>
 )}

 {activeTab === "notifications" && (
 <div className="space-y-8">
 <section>
 <h3 className="text-[10px] font-mono text-ng-cyan uppercase tracking-[0.2em] mb-4 border-b border-ng-outline-dim/40 pb-2">Critical Alert Channels</h3>
 <div className="grid grid-cols-2 gap-4">
 {[
 { label: "Browser Push", active: true },
 { label: "Email Digest", active: false },
 { label: "Telegram Bot", active: true },
 { label: "Slack Sync", active: false },
 ].map(channel => (
 <div key={channel.label} className="flex items-center justify-between p-3 border border-ng-outline-dim/40 bg-ng-base">
 <span className="text-[10px] font-mono text-ng-on uppercase">{channel.label}</span>
 <div className={`w-2 h-2 ${channel.active ? 'bg-ng-lime' : 'bg-ng-muted'}`} />
 </div>
 ))}
 </div>
 </section>
 </div>
 )}
 </PanelCard>
 </motion.div>
 </AnimatePresence>
 </div>
 </div>
 </div>
 );
}

function CheckCircle(props: any) {
 return (
 <svg
 {...props}
 xmlns="http://www.w3.org/2000/svg"
 width="24"
 height="24"
 viewBox="0 0 24 24"
 fill="none"
 stroke="currentColor"
 strokeWidth="2"
 strokeLinecap="round"
 strokeLinejoin="round"
 >
 <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
 <polyline points="22 4 12 14.01 9 11.01" />
 </svg>
 );
}
