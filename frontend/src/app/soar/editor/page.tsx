"use client";

import React, { useState } from "react";
import Link from "next/link";
import { ArrowLeft, Save, Plus, GripVertical, Trash2, ShieldAlert, UserCheck, Play, Send } from "lucide-react";

type ActionType = "isolate_host" | "block_ip" | "wait_for_approval" | "send_email" | "create_ticket";

interface PlaybookStep {
    id: string;
    type: ActionType;
    params: Record<string, string>;
}

const AVAILABLE_ACTIONS: { type: ActionType; icon: React.ReactNode; label: string; desc: string }[] = [
    { type: "isolate_host", icon: <ShieldAlert className="w-4 h-4 text-[#ef4444]" />, label: "Isolate Host", desc: "Block network access via EDR" },
    { type: "block_ip", icon: <ShieldAlert className="w-4 h-4 text-[#f59e0b]" />, label: "Block IP", desc: "Add IP to firewall deny list" },
    { type: "wait_for_approval", icon: <UserCheck className="w-4 h-4 text-[#06b6d4]" />, label: "Wait for Approval", desc: "Pause until analyst approves" },
    { type: "send_email", icon: <Send className="w-4 h-4 text-[#10b981]" />, label: "Send Notification", desc: "Email or webhook alert" },
    { type: "create_ticket", icon: <Plus className="w-4 h-4 text-[#8b5cf6]" />, label: "Create Ticket", desc: "Jira / ServiceNow incident" },
];

export default function PlaybookEditorPage() {
    const [name, setName] = useState("New Security Playbook");
    const [description, setDescription] = useState("Description of the automated response sequence.");
    const [steps, setSteps] = useState<PlaybookStep[]>([]);
    const [saveStatus, setSaveStatus] = useState<string | null>(null);
    const [saving, setSaving] = useState(false);

    const addStep = (type: ActionType) => {
        setSteps([...steps, { id: Math.random().toString(36).substring(7), type, params: {} }]);
    };

    const removeStep = (id: string) => {
        setSteps(steps.filter(s => s.id !== id));
    };

    const handleSave = async () => {
        setSaving(true);
        setSaveStatus(null);
        try {
            const res = await fetch('/api/proxy/api/v1/soar/playbooks', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name,
                    description,
                    nodes: steps.map(s => ({
                        id: s.id,
                        action_type: s.type,
                        provider: s.type === 'isolate_host' ? 'crowdstrike' : s.type === 'block_ip' ? 'paloalto' : 'system',
                        params: s.params,
                    })),
                }),
            });
            if (!res.ok) throw new Error(`Save failed: ${res.status}`);
            setSaveStatus('Saved!');
        } catch (e) {
            setSaveStatus('Save failed');
        } finally {
            setSaving(false);
        }
    };

    return (
        <div className="flex-1 flex flex-col h-full bg-slate-950">
            {/* Header */}
            <header className="h-16 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between px-6 shrink-0">
                <div className="flex items-center gap-4">
                    <Link href="/soar" className="text-slate-400 hover:text-white transition-colors">
                        <ArrowLeft className="w-5 h-5" />
                    </Link>
                    <div className="w-px h-6 bg-slate-700" />
                    <input 
                        type="text" 
                        value={name} 
                        onChange={e => setName(e.target.value)} 
                        className="bg-transparent border-none text-lg font-bold text-white focus:ring-0 p-0 w-[400px]"
                    />
                </div>
                <button 
                    onClick={handleSave}
                    className="flex items-center gap-2 bg-[#06b6d4] hover:bg-[#0891b2] text-slate-950 px-4 py-2 rounded-lg font-bold text-xs transition-colors"
                >
                    <Save className="w-4 h-4" />
                    {saving ? "Saving..." : "Save Playbook"}
                </button>
            </header>

            <div className="flex flex-1 overflow-hidden">
                {/* Editor Canvas */}
                <div className="flex-1 overflow-y-auto p-8 relative">
                    <div className="max-w-3xl mx-auto">
                        <div className="mb-8">
                            <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2 block">Description</label>
                            <input 
                                type="text"
                                value={description}
                                onChange={e => setDescription(e.target.value)}
                                className="w-full bg-slate-900/50 border border-slate-800 rounded-lg p-3 text-sm text-slate-300 focus:outline-none focus:border-[#06b6d4]/50 transition-colors"
                            />
                        </div>

                        <div className="space-y-4 relative">
                            {/* Start Node */}
                            <div className="w-48 mx-auto bg-slate-800 border border-slate-700 rounded-full py-2 px-4 flex items-center justify-center gap-2 shadow-lg z-10 relative">
                                <Play className="w-4 h-4 text-[#10b981]" />
                                <span className="text-sm font-bold text-white uppercase tracking-wider">Trigger Event</span>
                            </div>

                            {steps.length === 0 && (
                                <div className="text-center py-12 border-2 border-dashed border-slate-800 rounded-xl bg-slate-900/20">
                                    <p className="text-slate-500 text-sm">Add actions from the right panel to build your playbook.</p>
                                </div>
                            )}

                            {steps.map((step, index) => {
                                const actionDef = AVAILABLE_ACTIONS.find(a => a.type === step.type);
                                return (
                                    <div key={step.id} className="relative group">
                                        {/* Connector Line */}
                                        <div className="absolute left-1/2 -top-4 w-px h-4 bg-slate-700 -translate-x-1/2" />
                                        
                                        <div className="bg-slate-900 border border-slate-700 group-hover:border-[#06b6d4]/50 rounded-xl p-4 flex items-center gap-4 transition-all shadow-md">
                                            <div className="cursor-grab active:cursor-grabbing p-1 text-slate-600 hover:text-slate-400">
                                                <GripVertical className="w-5 h-5" />
                                            </div>
                                            <div className="w-10 h-10 rounded-lg bg-slate-800 flex items-center justify-center border border-slate-700">
                                                {actionDef?.icon}
                                            </div>
                                            <div className="flex-1">
                                                <p className="text-sm font-bold text-white">{actionDef?.label}</p>
                                                <div className="text-[11px] text-slate-500 mt-1 font-mono">
                                                    Action ID: {step.type}
                                                </div>
                                            </div>
                                            <button 
                                                onClick={() => removeStep(step.id)}
                                                className="p-2 text-slate-500 hover:text-[#ef4444] hover:bg-[#ef4444]/10 rounded-lg transition-colors"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                </div>

                {/* Right Action Palette */}
                <div className="w-80 bg-slate-900 border-l border-slate-800 flex flex-col items-stretch overflow-y-auto">
                    <div className="p-4 border-b border-slate-800 bg-slate-900/80 sticky top-0 z-10 backdrop-blur-sm">
                        <h2 className="text-sm font-bold text-white uppercase tracking-wider">Available Actions</h2>
                        <p className="text-[10px] text-slate-400 mt-1 uppercase tracking-widest">Click to append to sequence</p>
                    </div>
                    <div className="p-4 space-y-3">
                        {AVAILABLE_ACTIONS.map(action => (
                            <button
                                key={action.type}
                                onClick={() => addStep(action.type)}
                                className="w-full text-left bg-slate-800/50 hover:bg-slate-800 border border-slate-700 hover:border-slate-600 p-3 rounded-lg flex items-start gap-3 transition-all group"
                            >
                                <div className="mt-0.5 w-8 h-8 rounded shrink-0 bg-slate-900 border border-slate-700 flex items-center justify-center group-hover:scale-110 transition-transform">
                                    {action.icon}
                                </div>
                                <div>
                                    <p className="text-xs font-bold text-white mb-1">{action.label}</p>
                                    <p className="text-[10px] text-slate-400 leading-tight">{action.desc}</p>
                                </div>
                            </button>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}
