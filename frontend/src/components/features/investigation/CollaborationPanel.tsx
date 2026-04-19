"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
 Users,
 MessageSquare,
 Tag,
 Send,
 Hash,
 Circle,
 Clock,
 Wifi,
 WifiOff,
 ChevronDown,
  Pencil,
} from "lucide-react";
import { getToken } from "@/lib/auth";

// ─── Types ────────────────────────────────────────────────────────────────────

interface PresenceUser {
 name: string;
 avatar?: string;
 status: "active" | "idle" | "away";
 joined_at?: number;
}

interface Annotation {
 id?: number;
 user_id: string;
 content: string;
 annotation_type: "note" | "tag" | "crdt_note";
 created_at?: string;
 ts?: number;
}

interface CollaborationPanelProps {
 incidentId: string;
 currentUserId: string;
 currentUserName?: string;
 wsBaseUrl?: string;
 className?: string;
}

// ─── Avatar ───────────────────────────────────────────────────────────────────

const AVATAR_COLORS = [
 "bg-[var(--ng-cyan-bright)]",
 "bg-[var(--ng-lime)]",
 "bg-[var(--ng-cyan)]",
 "bg-[var(--ng-magenta)]",
 "bg-[var(--ng-error)]",
 "bg-[var(--ng-cyan)]",
];

function getAvatarColor(userId: string) {
 let hash = 0;
 for (let i = 0; i < userId.length; i++) hash = userId.charCodeAt(i) + ((hash << 5) - hash);
 return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length];
}

function Avatar({ userId, name, size = "sm" }: { userId: string; name: string; size?: "sm" | "md" }) {
 const initials = name
 .split(" ")
 .map((n) => n[0])
 .join("")
 .toUpperCase()
 .slice(0, 2);
 const dim = size === "sm" ? "w-6 h-6 text-[9px]" : "w-8 h-8 text-xs";
 return (
 <div className={`${dim} ${getAvatarColor(userId)} rounded-none flex items-center justify-center font-bold text-white flex-shrink-0`}>
 {initials}
 </div>
 );
}

// ─── Status dot ───────────────────────────────────────────────────────────────

function StatusDot({ status }: { status: string }) {
 const color = status === "active" ? "bg-[var(--ng-lime)]" : status === "idle" ? "bg-[var(--ng-magenta)]" : "bg-ng-muted";
 return (
 <span className={`w-2 h-2 rounded-none inline-block flex-shrink-0 ${color} ${status === "active" ? "animate-pulse" : ""}`} />
 );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export const CollaborationPanel: React.FC<CollaborationPanelProps> = ({
 incidentId,
 currentUserId,
 currentUserName = currentUserId,
 wsBaseUrl,
 className = "",
}) => {
 const [connected, setConnected] = useState(false);
 const [users, setUsers] = useState<Record<string, PresenceUser>>({});
 const [annotations, setAnnotations] = useState<Annotation[]>([]);
 const [inputValue, setInputValue] = useState("");
 const [inputMode, setInputMode] = useState<"note" | "tag">("note");
 const [typingUsers, setTypingUsers] = useState<Set<string>>(new Set());
 const [collapsed, setCollapsed] = useState(false);
 const [loadingHistory, setLoadingHistory] = useState(true);

 const wsRef = useRef<WebSocket | null>(null);
 const typingTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
 const bottomRef = useRef<HTMLDivElement | null>(null);

 // ── Fetch annotation history ───────────────────────────────────────────────
 useEffect(() => {
 const fetchHistory = async () => {
 try {
 const res = await fetch(`/api/v1/collaboration/${incidentId}/annotations`);
 if (res.ok) {
 const data = await res.json();
 setAnnotations((data.annotations || []).reverse());
 }
 } catch {
 // silently degrade
 } finally {
 setLoadingHistory(false);
 }
 };
 fetchHistory();
 }, [incidentId]);

 // ── WebSocket connection ───────────────────────────────────────────────────
 useEffect(() => {
 const base = wsBaseUrl || (typeof window !== "undefined"
 ? (window.location.protocol === "https:" ? "wss://" : "ws://") + window.location.host
 : "ws://localhost:8000");
 const url = `${base}/api/v1/ws/collaborate/${incidentId}`;

 let ws: WebSocket;
 let reconnectTimer: ReturnType<typeof setTimeout>;
 let unmounted = false;

 const connect = () => {
 ws = new WebSocket(url);
 wsRef.current = ws;

 ws.onopen = () => {
 setConnected(true);
 ws.send(JSON.stringify({ type: "join", user_id: currentUserId, name: currentUserName }));
 };

 ws.onclose = () => {
 setConnected(false);
 wsRef.current = null;
 if (!unmounted) reconnectTimer = setTimeout(connect, 3000);
 };

 ws.onerror = () => ws.close();

 ws.onmessage = (evt) => {
 try {
 const msg = JSON.parse(evt.data);
 if (msg.type === "presence_update") {
 setUsers(msg.users || {});
 } else if (msg.type === "note_updated") {
 const ann: Annotation = {
 user_id: msg.user_id,
 content: msg.content,
 annotation_type: "note",
 ts: Date.now(),
 };
 setAnnotations((prev) => [...prev, ann]);
 } else if (msg.type === "tag_added") {
 const ann: Annotation = {
 user_id: msg.user_id,
 content: msg.tag,
 annotation_type: "tag",
 ts: Date.now(),
 };
 setAnnotations((prev) => [...prev, ann]);
 } else if (msg.type === "typing") {
 if (msg.user_id !== currentUserId) {
 setTypingUsers((prev) => new Set([...Array.from(prev), msg.user_id]));
 setTimeout(() => {
 setTypingUsers((prev) => { const n = new Set(prev); n.delete(msg.user_id); return n; });
 }, 2500);
 }
 }
 } catch { /* ignore parse errors */ }
 };
 };

 connect();
 return () => {
 unmounted = true;
 clearTimeout(reconnectTimer);
 if (wsRef.current) {
 wsRef.current.send(JSON.stringify({ type: "leave", user_id: currentUserId }));
 wsRef.current.close();
 }
 };
 }, [incidentId, currentUserId, currentUserName, wsBaseUrl]);

 // ── Auto-scroll ────────────────────────────────────────────────────────────
 useEffect(() => {
 bottomRef.current?.scrollIntoView({ behavior: "smooth" });
 }, [annotations]);

 // ── Send message ───────────────────────────────────────────────────────────
 const send = useCallback(() => {
 const val = inputValue.trim();
 if (!val || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;

 if (inputMode === "tag") {
 wsRef.current.send(JSON.stringify({ type: "tag_added", user_id: currentUserId, tag: val }));
 } else {
 wsRef.current.send(JSON.stringify({ type: "note_updated", user_id: currentUserId, content: val }));
 }
 setInputValue("");
 }, [inputValue, inputMode, currentUserId]);

 // ── Typing indicator ───────────────────────────────────────────────────────
 const notifyTyping = useCallback(() => {
 if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
 wsRef.current.send(JSON.stringify({ type: "typing", user_id: currentUserId, field: "notes" }));
 if (typingTimer.current) clearTimeout(typingTimer.current);
 }, [currentUserId]);

 const handleKeyDown = (e: React.KeyboardEvent) => {
 if (e.key === "Enter" && !e.shiftKey) {
 e.preventDefault();
 send();
 }
 };

 const activeUserCount = Object.keys(users).length;

 return (
 <motion.div
 initial={{ opacity: 0, x: 20 }}
 animate={{ opacity: 1, x: 0 }}
 className={`flex flex-col bg-ng-base/70 border border-ng-outline-dim/40 rounded-none backdrop-blur-lg overflow-hidden ${className}`}
 >
 {/* ─── Header ──────────────────────────────────────────────────────── */}
 <div
 className="flex items-center justify-between px-4 py-3 border-b border-ng-outline-dim/40 bg-ng-base/60 cursor-pointer select-none"
 onClick={() => setCollapsed(!collapsed)}
 >
 <div className="flex items-center gap-2">
 <Users className="w-4 h-4 text-ng-cyan" />
 <span className="text-sm font-semibold text-ng-on">Live Collaboration</span>
 {activeUserCount > 0 && (
 <span className="text-[10px] font-mono bg-ng-cyan-bright/15 border border-[var(--ng-cyan-bright)]/30 text-ng-cyan px-1.5 py-0.5 rounded-none">
 {activeUserCount} online
 </span>
 )}
 </div>
 <div className="flex items-center gap-2">
 {connected ? (
 <Wifi className="w-3.5 h-3.5 text-[var(--ng-lime)]" />
 ) : (
 <WifiOff className="w-3.5 h-3.5 text-[var(--ng-error)] animate-pulse" />
 )}
 <ChevronDown className={`w-4 h-4 text-ng-muted transition-transform ${collapsed ? "-rotate-90" : ""}`} />
 </div>
 </div>

 <AnimatePresence initial={false}>
 {!collapsed && (
 <motion.div
 key="body"
 initial={{ height: 0, opacity: 0 }}
 animate={{ height: "auto", opacity: 1 }}
 exit={{ height: 0, opacity: 0 }}
 transition={{ duration: 0.2 }}
 className="flex flex-col overflow-hidden"
 >
 {/* ─── Presence Bar ──────────────────────────────────────────── */}
 {Object.keys(users).length > 0 && (
 <div className="flex items-center gap-2 px-4 py-2 border-b border-ng-outline-dim/40/50 bg-ng-base/30 flex-wrap">
 {Object.entries(users).map(([uid, u]) => (
 <div key={uid} className="flex items-center gap-1.5 bg-ng-mid/40 px-2 py-1 rounded-none border border-ng-outline-dim/40/50">
 <StatusDot status={u.status} />
 <Avatar userId={uid} name={u.name} size="sm" />
 <span className="text-[11px] text-ng-on max-w-[80px] truncate">{u.name}</span>
 </div>
 ))}
 </div>
 )}

 {/* ─── Annotations Feed ──────────────────────────────────────── */}
 <div className="flex-1 overflow-y-auto max-h-[320px] custom-scrollbar p-3 flex flex-col gap-2">
 {loadingHistory && (
 <p className="text-xs text-ng-muted text-center py-4 animate-pulse">Loading history…</p>
 )}
 {!loadingHistory && annotations.length === 0 && (
 <p className="text-xs text-ng-muted text-center py-8">
 No notes yet. Be the first to annotate this incident.
 </p>
 )}
 {annotations.map((ann, i) => {
 const isMe = ann.user_id === currentUserId;
 const isTag = ann.annotation_type === "tag";
 const userName = users[ann.user_id]?.name ?? ann.user_id;
 const timeStr = ann.created_at
 ? new Date(ann.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
 : ann.ts
 ? new Date(ann.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
 : "";

 if (isTag) {
 return (
 <motion.div
 key={i}
 initial={{ opacity: 0, y: 4 }}
 animate={{ opacity: 1, y: 0 }}
 className="flex items-center gap-2 self-center"
 >
 <Hash className="w-3 h-3 text-[var(--ng-cyan)] flex-shrink-0" />
 <span className="text-[11px] bg-[var(--ng-cyan)]/15 border border-[var(--ng-cyan)]/30 text-[var(--ng-cyan)] px-2 py-0.5 rounded-none">
 {ann.content}
 </span>
 <span className="text-[10px] text-ng-muted">· {userName} · {timeStr}</span>
 </motion.div>
 );
 }

 return (
 <motion.div
 key={i}
 initial={{ opacity: 0, y: 4 }}
 animate={{ opacity: 1, y: 0 }}
 className={`flex gap-2 ${isMe ? "flex-row-reverse" : "flex-row"}`}
 >
 <Avatar userId={ann.user_id} name={userName} size="sm" />
 <div className={`flex flex-col gap-0.5 max-w-[75%] ${isMe ? "items-end" : "items-start"}`}>
 <div className="flex items-center gap-1.5">
 <span className="text-[10px] text-ng-muted">{userName}</span>
 {timeStr && (
 <span className="text-[9px] text-ng-muted flex items-center gap-0.5">
 <Clock className="w-2.5 h-2.5" /> {timeStr}
 </span>
 )}
 </div>
 <div
 className={`text-xs px-3 py-2 rounded-none leading-relaxed whitespace-pre-wrap break-words ${
 isMe
 ? "bg-[var(--ng-cyan-bright)]/20 border border-[var(--ng-cyan-bright)]/30 text-ng-on rounded-tr-none"
 : "bg-ng-mid/60 border border-ng-outline-dim/40/50 text-ng-on rounded-tl-none"
 }`}
 >
 {ann.content}
 </div>
 </div>
 </motion.div>
 );
 })}

 {/* Typing indicators */}
 {typingUsers.size > 0 && (
 <div className="flex items-center gap-1.5 px-1">
 <div className="flex gap-0.5">
 {[0, 1, 2].map((n) => (
 <span
 key={n}
 className="w-1.5 h-1.5 bg-ng-muted rounded-none animate-bounce"
 />
 ))}
 </div>
 <span className="text-[10px] text-ng-muted">
 {Array.from(typingUsers)
 .map((u) => users[u]?.name ?? u)
 .join(", ")}{" "}
 {typingUsers.size === 1 ? "is" : "are"} typing…
 </span>
 </div>
 )}

 <div ref={bottomRef} />
 </div>

 {/* ─── Input Bar ─────────────────────────────────────────────── */}
 <div className="p-3 border-t border-ng-outline-dim/40 bg-ng-base/40 flex flex-col gap-2">
 {/* Mode toggle */}
 <div className="flex gap-1">
 <button
 onClick={() => setInputMode("note")}
 className={`flex items-center gap-1 px-2.5 py-1 rounded-none text-[10px] font-mono uppercase tracking-wider transition-all border ${
 inputMode === "note"
 ? "bg-ng-cyan-bright/15 border-[var(--ng-cyan-bright)]/40 text-ng-cyan"
 : "border-ng-outline-dim/40 text-ng-muted hover:text-ng-on"
 }`}
 >
 <Pencil className="w-2.5 h-2.5" /> Note
 </button>
 <button
 onClick={() => setInputMode("tag")}
 className={`flex items-center gap-1 px-2.5 py-1 rounded-none text-[10px] font-mono uppercase tracking-wider transition-all border ${
 inputMode === "tag"
 ? "bg-[var(--ng-cyan)]/15 border-[var(--ng-cyan)]/40 text-[var(--ng-cyan)]"
 : "border-ng-outline-dim/40 text-ng-muted hover:text-ng-on"
 }`}
 >
 <Hash className="w-2.5 h-2.5" /> Tag
 </button>
 </div>

 {/* Text input + send */}
 <div className="flex gap-2 items-end">
 <textarea
 value={inputValue}
 onChange={(e) => { setInputValue(e.target.value); notifyTyping(); }}
 onKeyDown={handleKeyDown}
 placeholder={inputMode === "note" ? "Add a note… (Enter to send)" : "Add a tag (e.g. False Positive)"}
 rows={2}
 disabled={!connected}
 className="flex-1 bg-ng-mid/60 border border-ng-outline-dim/40 rounded-none px-3 py-2 text-xs text-ng-on placeholder:text-ng-muted focus:outline-none focus:border-ng-cyan/60 focus:ring-1 focus:ring-ng-cyan-bright/20 resize-none transition-all disabled:opacity-40 custom-scrollbar"
 />
 <button
 onClick={send}
 disabled={!connected || !inputValue.trim()}
 className="flex items-center justify-center w-8 h-8 rounded-none bg-[var(--ng-cyan-bright)]/20 border border-[var(--ng-cyan-bright)]/40 text-ng-cyan hover:bg-[var(--ng-cyan-bright)]/30 transition-all disabled:opacity-30 disabled:cursor-not-allowed flex-shrink-0"
 >
 <Send className="w-3.5 h-3.5" />
 </button>
 </div>

 <p className="text-[9px] text-ng-muted leading-none">
 {connected ? (
 <span className="text-[var(--ng-lime)]">● Connected</span>
 ) : (
 <span className="text-[var(--ng-error)]">● Reconnecting…</span>
 )}
 {" "}· Changes sync in real-time across all analysts
 </p>
 </div>
 </motion.div>
 )}
 </AnimatePresence>
 </motion.div>
 );
};

export default CollaborationPanel;
