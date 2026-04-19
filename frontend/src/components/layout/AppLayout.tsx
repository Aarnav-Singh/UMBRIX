"use client";

import { useState, useRef, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Menu, X, LayoutDashboard, Fingerprint, Crosshair, Target, BookOpen, Shield, Server, Lock, Network, Zap, FileText, ShieldCheck, Activity, Settings, Bell, Search, Terminal, Bug } from "lucide-react";
import { RealSparkline } from "@/components/ui/RealSparkline";
import { NavGroup } from "@/components/ui/NavGroup";
import { useThreatState } from "@/contexts/ThreatStateContext";
import { useEventStream } from "@/contexts/EventStreamContext";
import { GlassPanel } from "@/components/ui/GlassPanel";
import useSWR from "swr";
import { motion, AnimatePresence } from "framer-motion";

const NAV_GROUPS = [
  {
  label: "Operations",
  items: [
  { id: "dashboard", name: "Command Center", href: "/dashboard", icon: <LayoutDashboard className="w-4 h-4" /> },
  { id: "events", name: "Raw Events", href: "/events", icon: <Fingerprint className="w-4 h-4" /> },
  { id: "findings", name: "Threat Findings", href: "/findings", icon: <Crosshair className="w-4 h-4" /> },
  ]
  },
  {
  label: "Intelligence",
  items: [
  { id: "campaigns", name: "Campaigns", href: "/campaigns", icon: <Target className="w-4 h-4" /> },
  { id: "sigma-rules", name: "Sigma Rules", href: "/sigma-rules", icon: <BookOpen className="w-4 h-4" /> },
  { id: "sandbox", name: "Sandbox Exec", href: "/sandbox", icon: <Terminal className="w-4 h-4" /> },
  { id: "malware", name: "DNA Analysis", href: "/malware", icon: <Bug className="w-4 h-4" /> },
  ]
  },
  {
  label: "Infrastructure",
  items: [
  { id: "posture", name: "Posture", href: "/posture", icon: <Shield className="w-4 h-4" /> },
  { id: "assets", name: "Asset Registry", href: "/integrations", icon: <Server className="w-4 h-4" /> },
  { id: "vault", name: "Secure Vault", href: "/vault", icon: <Lock className="w-4 h-4" /> },
  ]
  },
  {
  label: "Automation",
  items: [
  { id: "pipeline", name: "ML Pipeline", href: "/pipeline", icon: <Network className="w-4 h-4" /> },
  { id: "soar", name: "SOAR Actions", href: "/soar", icon: <Zap className="w-4 h-4" /> },
  ]
  },
  {
  label: "Admin",
  items: [
  { id: "audit", name: "Audit Trail", href: "/audit", icon: <FileText className="w-4 h-4" /> },
  { id: "compliance", name: "Compliance", href: "/compliance", icon: <ShieldCheck className="w-4 h-4" /> },
  { id: "health", name: "System Health", href: "/health", icon: <Activity className="w-4 h-4" /> },
  { id: "settings", name: "Settings", href: "/settings", icon: <Settings className="w-4 h-4" /> },
  ]
  }
];

export function AppLayout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [hovering, setHovering] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const pathname = usePathname();
  const searchInputRef = useRef<HTMLInputElement>(null);

  const { threatState } = useThreatState();
  const { eventsRate } = useEventStream();

  // Fetch recent critical findings for notification bell
  const { data: findingsRes } = useSWR("/api/proxy/api/v1/findings", url => fetch(url).then(r => r.json()), { refreshInterval: 10000 });
  const findings = Array.isArray(findingsRes) ? findingsRes : (Array.isArray(findingsRes?.findings) ? findingsRes.findings : []);
  const recentCritical = findings.filter((f: any) => f.severity === "critical" && f.status !== "dismissed" && f.status !== "approved");
  const criticalCount = recentCritical.length;

  const expanded = sidebarOpen || hovering;

  const stateColor = {
  nominal: "text-ng-lime",
  elevated: "text-ng-magenta",
  incident: "text-ng-error",
  };
  const stateLabel = {
  nominal: "SYSTEM SECURE",
  elevated: "ELEVATED RISK",
  incident: "ACTIVE INCIDENT",
  };
  const headerBorderColor = {
    nominal: "cyan",
    elevated: "magenta",
    incident: "error"
  }[threatState] as any;

  useEffect(() => {
  const handler = (e: KeyboardEvent) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "k") {
  e.preventDefault();
  searchInputRef.current?.focus();
  }
  };
  window.addEventListener("keydown", handler);
  return () => window.removeEventListener("keydown", handler);
  }, []);

  if (pathname === "/") return <>{children}</>;

  return (
  <div className="flex flex-col h-screen w-full overflow-hidden bg-ng-base font-sans text-ng-on p-4 gap-4">
  {/* Floating Header */}
  <GlassPanel as="header" accent={headerBorderColor} className="shrink-0 h-14 flex items-center px-4 transition-colors duration-500 z-50 rounded-none">
  <div className="flex items-center gap-4 w-56 shrink-0">
  <Link href="/dashboard" className="flex items-center gap-2 group no-underline">
  <div className={`w-6 h-6 border flex items-center justify-center font-bold text-xs transition-colors rounded-none
  ${threatState === "incident" ? "border-ng-error bg-ng-error/10 text-ng-error" : "border-ng-cyan/30 bg-ng-base text-ng-cyan"}`}
  >
  UX
  </div>
  <span className="font-headline font-bold tracking-widest text-sm uppercase hidden sm:block text-ng-cyan">UMBRIX</span>
  </Link>
  <motion.button
  onClick={() => setSidebarOpen(!sidebarOpen)}
  className="md:hidden text-ng-muted hover:text-ng-on transition-colors ml-auto"
  >
  {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
  </motion.button>
  </div>

  <div className="flex-1 flex items-center px-4">
  <div className="relative w-full max-w-lg hidden md:block group">
  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ng-muted" />
  <input
  ref={searchInputRef}
  type="text"
  placeholder="SEARCH PLATFORM..."
  className="w-full bg-transparent border-b border-ng-outline-dim/40 h-8 pl-9 pr-12 text-[11px] font-mono focus:outline-none focus:border-ng-cyan/60 placeholder:text-ng-muted/40 transition-colors rounded-none"
  />
  <kbd className="absolute right-2 top-1/2 -translate-y-1/2 text-[9px] font-mono text-ng-muted border border-ng-outline-dim/40 px-1.5 py-0.5 group-focus-within:border-ng-cyan/50 group-focus-within:text-ng-cyan">
  ⌘K
  </kbd>
  </div>
  </div>

  <div className="flex items-center gap-4 ml-auto">
  {/* EPS Sparkline */}
  <div className="hidden md:flex items-center gap-2">
  <RealSparkline source="eps" width={60} height={18} />
  <span className="text-[11px] font-mono text-ng-cyan">{eventsRate} EPS</span>
  </div>

  {/* Bell */}
  <div className="relative">
  <button onClick={() => setNotifOpen(o => !o)} className="relative text-ng-muted hover:text-ng-on">
  <Bell className="w-4 h-4" />
  {criticalCount > 0 && (
  <span className="absolute -top-1 -right-1 w-3 h-3 bg-ng-error text-[7px] font-mono flex items-center justify-center rounded-none">
  {criticalCount > 9 ? "9+" : criticalCount}
  </span>
  )}
  </button>
  <AnimatePresence>
  {notifOpen && (
  <motion.div
  initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 4 }}
  className="absolute right-0 top-8 w-80 ng-surface-high border border-ng-outline-dim/40 z-50 p-3 rounded-none"
  >
  <div className="text-[10px] font-mono text-ng-muted uppercase tracking-widest mb-2">Recent Critical</div>
  {recentCritical.length === 0 ? (
  <div className="text-ng-muted text-[11px] py-2">No unresolved critical findings</div>
  ) : (
  recentCritical.slice(0, 5).map((f: any) => (
  <Link key={f.id} href={`/findings`} onClick={() => setNotifOpen(false)}
  className="flex items-center gap-2 py-1.5 border-b border-ng-outline-dim/40/50 last:border-0 hover:bg-ng-mid/50 no-underline">
  <span className="w-1.5 h-1.5 bg-ng-error shrink-0 rounded-none" />
  <span className="text-[11px] text-ng-on truncate">{f.summary || f.id}</span>
  </Link>
  ))
  )}
  </motion.div>
  )}
  </AnimatePresence>
  </div>

  {/* Threat State Pill */}
  <div className={`hidden sm:flex items-center gap-1.5 text-[10px] font-mono ${stateColor[threatState]}`}>
  <span className="w-1.5 h-1.5 rounded-none bg-current" />
  {stateLabel[threatState]}
  </div>

  {/* Profile */}
  <Link href="/profile" className="w-7 h-7 bg-ng-mid border border-ng-outline-dim/40 flex items-center justify-center text-ng-cyan text-[10px] font-mono no-underline hover:border-ng-cyan/60 rounded-none">
  OP
  </Link>
  </div>
  </GlassPanel>

  {/* Body Container */}
  <div className="flex flex-1 overflow-hidden gap-4">
  {/* Floating Sidebar */}
  <aside
  onMouseEnter={() => setHovering(true)}
  onMouseLeave={() => setHovering(false)}
  className={`shrink-0 flex flex-col transition-all duration-200 ease-out z-40 relative md:relative md:translate-x-0 absolute inset-y-0 left-0
  ${expanded ? "w-56" : "w-14"}
  ${sidebarOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"}
  `}
  >
  <GlassPanel className="flex flex-col flex-1 overflow-hidden h-full rounded-none">
  <div className="flex flex-col flex-1 py-4 min-h-0 overflow-y-auto overflow-x-hidden custom-scrollbar">
  {NAV_GROUPS.map(group => (
  <NavGroup key={group.label} label={group.label} items={group.items} expanded={expanded} />
  ))}
  </div>

  {/* Footer — Threat State Badge */}
  <div className="shrink-0 border-t border-ng-outline-dim/40 p-3 bg-ng-base/50 backdrop-blur-sm z-10">
  <div className={`flex items-center gap-2 text-[10px] font-mono ${stateColor[threatState]}`}>
  <span className="w-1.5 h-1.5 bg-current shrink-0 rounded-none" />
  {expanded && stateLabel[threatState]}
  </div>
  </div>
  </GlassPanel>
  </aside>

  {/* Page Content */}
  <main className="flex-1 overflow-auto relative rounded-none">
  {children}
  </main>
  </div>
  </div>
  );
}
