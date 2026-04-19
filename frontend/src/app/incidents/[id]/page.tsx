"use client";

import { use, useState, useEffect } from "react";
import useSWR from "swr";
import Link from "next/link";
import { 
 AlertTriangle, 
 ShieldAlert, 
 Clock, 
 MapPin, 
 Users, 
 MonitorSmartphone, 
 ChevronRight,
 Activity,
 CheckCircle2,
 ShieldOff,
 Search,
 Radar,
 Target,
 Network,
 Layers
} from "lucide-react";
import { CollaborationPanel } from "@/components/features/investigation/CollaborationPanel";
import { ThreatGraph, type STIXNode, type STIXEdge } from "@/components/features/investigation/ThreatGraph";
import { getUser } from "@/lib/auth";

// The shape coming from our v1 findings API
interface FindingDetails {
 finding_id: string;
 description: string;
 severity: string;
 confidence: string;
 status: string;
 title?: string; // Optional depending on how it's aggregated
 entities: {
 entity_id: string;
 type: string;
 name?: string;
 }[];
 created_at: string;
 updated_at: string;
 campaign_id?: string;
}

const fetcher = (url: string) => fetch(url).then((res) => {
 if (!res.ok) throw new Error("Failed to load incident");
 return res.json();
});

export default function IncidentDetailPage({ params }: { params: { id: string } | Promise<{ id: string }> }) {
  // In Next.js App Router, dynamic params can be a Promise
  const resolvedParams = "then" in params ? use(params) : params;
  const { id } = resolvedParams;
  const user = getUser();

  const [activeTab, setActiveTab] = useState<"details" | "threat-intel">("details");
 const [graphNodes, setGraphNodes] = useState<STIXNode[]>([]);
 const [graphEdges, setGraphEdges] = useState<STIXEdge[]>([]);
 const [graphLoading, setGraphLoading] = useState(false);

 // Fetch from findings API
 const { data: finding, error, isLoading } = useSWR<FindingDetails>(
 `/api/proxy/api/v1/findings/${id}`,
 fetcher,
 { refreshInterval: 10000 }
 );

 // Fetch STIX2 graph when switching to threat-intel tab
 useEffect(() => {
 if (activeTab !== "threat-intel" || !finding) return;
 setGraphLoading(true);
 const campaignId = finding.campaign_id || id;
 fetch(`/api/proxy/api/v1/threat-graph/entity/${campaignId}/context`)
 .then(r => r.ok ? r.json() : null)
 .then(data => {
 if (data) {
 setGraphNodes(data.nodes || []);
 setGraphEdges(data.edges || []);
 }
 })
 .catch(() => {})
 .finally(() => setGraphLoading(false));
 }, [activeTab, finding, id]);

 if (isLoading) {
 return (
 <div className="flex-1 flex flex-col items-center justify-center min-h-[500px] h-full bg-transparent">
 <div className="w-8 h-8 border-2 border-[var(--ng-cyan-bright)] border-b-transparent rounded-full animate-spin mb-4"></div>
 <p className="text-ng-muted text-sm font-mono uppercase tracking-widest font-bold animate-pulse">Establishing Connection...</p>
 </div>
 );
 }

 if (error || !finding) {
 return (
 <div className="flex-1 p-8 flex flex-col items-center justify-center text-center h-full bg-transparent">
 <div className="w-20 h-20 rounded-none bg-[var(--ng-error)]/10 flex items-center justify-center border border-[var(--ng-error)]/30 shadow-[0_0_20px_rgba(239,68,68,0.2)] mb-6">
 <AlertTriangle className="w-10 h-10 text-[var(--ng-error)]" />
 </div>
 <h2 className="font-headline tracking-widest uppercase text-2xl font-display font-bold text-ng-on mb-2">Incident Not Found</h2>
 <p className="text-ng-muted max-w-sm mb-8">The incident you requested could not be found or has been purged from active telemetry.</p>
 <Link href="/dashboard" className="px-6 py-2.5 bg-ng-mid border border-ng-outline-dim/40 text-ng-on text-[10px] font-mono tracking-widest uppercase rounded-none hover:bg-ng-mid/50 transition-colors">
 Return to SOC
 </Link>
 </div>
 );
 }

 // Determine colors based on severity
 const severityLower = finding.severity.toLowerCase();
 const isCritical = severityLower === 'critical';
 const isHigh = severityLower === 'high';
 const isMedium = severityLower === 'medium';
 
 const severityColor = isCritical 
 ? "text-[var(--ng-error)] bg-[var(--ng-error)]/10 border-[var(--ng-error)]/30" 
 : isHigh
 ? "text-[var(--ng-magenta)] bg-[var(--ng-magenta)]/10 border-[var(--ng-magenta)]/30"
 : isMedium
 ? "text-[var(--ng-cyan)] bg-[var(--ng-cyan)]/10 border-[var(--ng-cyan)]/30"
 : "text-ng-muted bg-ng-muted/10 border-ng-outline-dim/40/30";

 const severityTextColor = isCritical ? "text-[var(--ng-error)]" : isHigh ? "text-[var(--ng-magenta)]" : isMedium ? "text-[var(--ng-cyan)]" : "text-ng-muted";

 const title = finding.title || finding.description || "Suspicious Activity Detected";
 return (
 <div className="flex-1 flex flex-col h-full overflow-y-auto custom-scrollbar bg-transparent">
 {/* Content Header */}
 <header className="sticky top-0 z-10 p-6 flex items-center justify-between border-b border-ng-outline-dim/40/50 bg-ng-mid/80 backdrop-blur-xl">
 <div className="flex flex-col">
 <div className="flex items-center gap-2 text-[11px] font-bold text-ng-muted mb-1.5 uppercase tracking-widest">
 <span>Incidents</span>
 <ChevronRight className="w-3 h-3 text-ng-muted" />
 <span className="text-ng-muted">INC-{id.split('-')[0].substring(0,6)}</span>
 </div>
 <div className="flex items-center gap-4">
 <h2 className="font-headline tracking-widest uppercase text-2xl font-bold text-ng-on tracking-tight">{title}</h2>
 <div className="flex gap-2">
 <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-widest border ${finding.status === 'open' ? 'bg-[var(--ng-magenta)]/10 text-[var(--ng-magenta)] border-[var(--ng-magenta)]/30' : 'bg-[var(--ng-lime)]/10 text-[var(--ng-lime)] border-[var(--ng-lime)]/30'}`}>
 {finding.status}
 </span>
 <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-widest border ${severityColor}`}>
 {finding.severity}
 </span>
 </div>
 </div>
 </div>
 <div className="flex items-center gap-6">
 {/* Tab Bar */}
 <div className="flex items-center gap-1 bg-ng-base border border-ng-outline-dim/40 rounded-none p-1">
 <button
 onClick={() => setActiveTab("details")}
 className={`flex items-center gap-1.5 px-3 py-1.5 rounded-none text-xs font-bold uppercase tracking-wider transition-all ${
 activeTab === "details"
 ? "bg-ng-mid text-ng-on shadow"
 : "text-ng-muted hover:text-ng-on"
 }`}
 >
 <Layers className="w-3.5 h-3.5" /> Details
 </button>
 <button
 onClick={() => setActiveTab("threat-intel")}
 className={`flex items-center gap-1.5 px-3 py-1.5 rounded-none text-xs font-bold uppercase tracking-wider transition-all ${
 activeTab === "threat-intel"
 ? "bg-[var(--ng-cyan-bright)]/10 text-[var(--ng-cyan-bright)] border border-[var(--ng-cyan-bright)]/30 shadow"
 : "text-ng-muted hover:text-ng-on"
 }`}
 >
 <Network className="w-3.5 h-3.5" /> Threat Intel
 </button>
 </div>
 <div className="text-right hidden sm:block">
 <div className="text-[10px] text-ng-muted font-bold uppercase tracking-widest mb-1">Risk Assessed</div>
 <div className={`text-lg font-bold uppercase tracking-wide ${severityTextColor}`}>{finding.severity}</div>
 <div className="text-[9px] uppercase tracking-widest text-[var(--ng-cyan-bright)]">{finding.confidence || "High"} Confidence</div>
 </div>
 <div className="w-[1px] h-10 bg-ng-mid/50 hidden sm:block"></div>
 <div className="flex gap-3">
 <div className="flex items-center gap-2 px-3 py-1.5 bg-ng-base border border-ng-outline-dim/40/50 rounded-none text-[10px] font-mono text-ng-on shadow-inner">
 <Users className="w-3.5 h-3.5 text-ng-muted" />
 <span>{finding.entities?.filter(e => e.type === 'user').length || 0}</span>
 </div>
 <div className="flex items-center gap-2 px-3 py-1.5 bg-ng-base border border-ng-outline-dim/40/50 rounded-none text-[10px] font-mono text-ng-on shadow-inner">
 <MonitorSmartphone className="w-3.5 h-3.5 text-ng-muted" />
 <span>{finding.entities?.filter(e => e.type === 'host' || e.type === 'ip').length || 0}</span>
 </div>
 </div>
 </div>
 </header>

 {/* ── Details Tab ── */}
 {activeTab === "details" && (
 <div className="p-6 grid grid-cols-12 gap-6 max-w-screen-2xl mx-auto w-full">
 {/* Left Column: Summary & Scope */}
 <div className="col-span-12 xl:col-span-3 space-y-6">
 {/* What's Happening Card */}
 <div className="ng-surface p-5">
 <div className="flex items-center gap-2 mb-4">
 <Radar className="w-5 h-5 text-[var(--ng-cyan)]" />
 <h3 className="text-sm font-bold text-ng-on uppercase tracking-wider">Context Overview</h3>
 </div>
 <p className="text-xs leading-relaxed text-ng-muted mb-5">
 {finding.description}
 </p>
 <div className="p-3 bg-ng-base/50 rounded-none border border-ng-outline-dim/40/50 space-y-3 shadow-inner">
 <div className="flex justify-between items-center text-[11px]">
 <span className="text-ng-muted font-bold uppercase tracking-wider">First Identified</span>
 <span className="text-ng-on font-mono">{new Date(finding.created_at).toLocaleString()}</span>
 </div>
 <div className="flex justify-between items-center text-[11px]">
 <span className="text-ng-muted font-bold uppercase tracking-wider">Last Updated</span>
 <span className="text-ng-on font-mono">{new Date(finding.updated_at).toLocaleString()}</span>
 </div>
 <div className="flex justify-between items-center text-[11px]">
 <span className="text-ng-muted font-bold uppercase tracking-wider">Correlation ID</span>
 <span className="text-[var(--ng-cyan-bright)] font-mono">{finding.finding_id.substring(0,8)}</span>
 </div>
 </div>
 </div>

 {/* Affected Entities Card */}
 <div className="ng-surface p-5">
 <h3 className="text-[10px] font-bold text-ng-muted uppercase tracking-widest mb-4 flex items-center gap-2">
 <Target className="w-3.5 h-3.5 text-ng-muted" />
 AFFECTED ENTITIES
 </h3>
 <div className="space-y-3">
 {finding.entities?.length > 0 ? finding.entities.map((entity, idx) => (
 <div key={idx} className="flex items-center justify-between p-3 bg-ng-base rounded-none border border-ng-outline-dim/40/50 hover:border-ng-outline-dim/40 transition-colors">
 <div className="flex items-center gap-3">
 <div className="w-8 h-8 rounded shrink-0 bg-ng-mid flex items-center justify-center border border-ng-outline-dim/40">
 {entity.type === 'user' ? <Users className="w-4 h-4 text-[var(--ng-error)]" /> : <MonitorSmartphone className="w-4 h-4 text-[var(--ng-cyan-bright)]" />}
 </div>
 <div className="overflow-hidden">
 <p className="text-[10px] text-ng-muted uppercase tracking-widest font-bold mb-0.5">{entity.type}</p>
 <p className="text-xs font-bold text-ng-on truncate font-mono" title={entity.name || entity.entity_id}>
 {entity.name || entity.entity_id}
 </p>
 </div>
 </div>
 <ChevronRight className="w-4 h-4 text-ng-muted" />
 </div>
 )) : (
 <div className="p-4 bg-ng-base/50 rounded-none border border-ng-outline-dim/40 border-dashed text-center">
 <p className="text-xs text-ng-muted font-medium">No specific entities correlated.</p>
 </div>
 )}
 </div>
 </div>
 </div>

 {/* Center Column: Evidence & Timeline */}
 <div className="col-span-12 xl:col-span-6 space-y-6">
 {/* Evidence Overview Table */}
 <div className="ng-surface overflow-hidden flex flex-col h-[300px]">
 <div className="p-5 flex items-center justify-between border-b border-ng-outline-dim/40/50 bg-ng-base/30">
 <h3 className="text-sm font-bold text-ng-on uppercase tracking-wider">Evidence Matrix</h3>
 <div className="relative">
 <input className="bg-ng-base border border-ng-outline-dim/40/50 rounded shadow-inner text-[11px] font-medium py-1.5 pl-8 pr-4 w-48 focus:border-[var(--ng-cyan-bright)]/50 text-ng-on placeholder-ng-muted/50 focus:outline-none transition-colors" placeholder="Search logs..." type="text" />
 <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-ng-muted" />
 </div>
 </div>
 <div className="flex-1 overflow-x-auto custom-scrollbar">
 <table className="w-full text-left text-xs whitespace-nowrap">
 <thead className="bg-ng-base/50 text-ng-muted text-[10px] uppercase tracking-widest">
 <tr>
 <th className="px-5 py-3 font-bold">Vector</th>
 <th className="px-5 py-3 font-bold">Telemetry Payload</th>
 <th className="px-5 py-3 font-bold">Timestamp</th>
 <th className="px-5 py-3 font-bold">Validation</th>
 </tr>
 </thead>
 <tbody className="divide-y divide-ng-outline-dim/30/30">
 <tr className="hover:bg-ng-mid/50 transition-colors group">
 <td className="px-5 py-4"><Activity className="w-4 h-4 text-[var(--ng-magenta)]" /></td>
 <td className="px-5 py-4 text-ng-on font-medium">Anomaly detected via behavioral ML model</td>
 <td className="px-5 py-4 text-ng-muted font-mono">{new Date(finding.created_at).toLocaleTimeString()}</td>
 <td className="px-5 py-4"><span className="bg-[var(--ng-lime)]/10 text-[var(--ng-lime)] text-[10px] font-bold tracking-widest uppercase px-2 py-0.5 rounded border border-[var(--ng-lime)]/30">Valid</span></td>
 </tr>
 <tr className="hover:bg-ng-mid/50 transition-colors group">
 <td className="px-5 py-4"><ShieldOff className="w-4 h-4 text-[var(--ng-error)]" /></td>
 <td className="px-5 py-4 text-ng-on font-medium">Signature match: Cobalt Strike Beacon</td>
 <td className="px-5 py-4 text-ng-muted font-mono">{new Date(finding.created_at).toLocaleTimeString()}</td>
 <td className="px-5 py-4"><span className="bg-[var(--ng-lime)]/10 text-[var(--ng-lime)] text-[10px] font-bold tracking-widest uppercase px-2 py-0.5 rounded border border-[var(--ng-lime)]/30">Valid</span></td>
 </tr>
 </tbody>
 </table>
 </div>
 </div>

 {/* Activity Timeline */}
 <div className="ng-surface p-6">
 <div className="flex items-center justify-between mb-8">
 <h3 className="text-sm font-bold text-ng-on uppercase tracking-wider flex items-center gap-2">
 <Clock className="w-4 h-4 text-ng-muted" />
 Execution Timeline
 </h3>
 <div className="flex items-center gap-2">
 <input defaultChecked className="w-3.5 h-3.5 rounded border-ng-outline-dim/40 bg-ng-base text-[var(--ng-cyan-bright)] focus:ring-0 focus:ring-offset-0 cursor-pointer" type="checkbox" />
 <label className="text-[10px] font-bold uppercase tracking-wider text-ng-muted cursor-pointer">Key Events Only</label>
 </div>
 </div>
 <div className="relative pl-6 space-y-8 before:content-[''] before:absolute before:left-2 before:top-2 before:bottom-2 before:w-[2px] before:bg-ng-mid">
 
 <div className="flex items-start gap-4">
 <div className="mt-1 -ml-[23px] w-3 h-3 rounded-full bg-[var(--ng-error)] shadow-[0_0_10px_rgba(239,68,68,0.6)] border-2 border-ng-outline-dim/40 relative z-10 animate-pulse"></div>
 <div className="flex-1 bg-ng-base/50 border border-ng-outline-dim/40/50 rounded-none p-3">
 <div className="flex justify-between items-center mb-1">
 <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--ng-error)]">Detection Event</span>
 </div>
 <p className="text-xs text-ng-on font-medium">Finding triggered and normalized by ingest pipeline.</p>
 <span className="text-[10px] text-ng-muted font-mono mt-2 block">{new Date(finding.created_at).toLocaleString()}</span>
 </div>
 </div>
 
 <div className="flex items-start gap-4">
 <div className="mt-1 -ml-[23px] w-3 h-3 rounded-full bg-[var(--ng-cyan-bright)] border-2 border-ng-outline-dim/40 relative z-10"></div>
 <div className="flex-1 bg-ng-base/50 border border-ng-outline-dim/40/50 rounded-none p-3 opacity-80">
 <div className="flex justify-between items-center mb-1">
 <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--ng-cyan-bright)]">Automated Enrichment</span>
 </div>
 <p className="text-xs text-ng-on font-medium">Status initialized to <strong className="text-ng-on uppercase">{finding.status}</strong></p>
 <span className="text-[10px] text-ng-muted font-mono mt-2 block">{new Date(finding.updated_at).toLocaleString()}</span>
 </div>
 </div>
 
 </div>
 </div>
 </div>

 {/* Right Column: Remediation Hub & Activity */}
 <div className="col-span-12 xl:col-span-3 space-y-6">
 {/* Remediation Hub Sidebar */}
 <div className="ng-surface p-5 relative overflow-hidden group">
 <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-[var(--ng-cyan-bright)]/50 to-transparent" />
 
 <div className="flex items-center gap-2 mb-6 focus-border">
 <CheckCircle2 className="w-5 h-5 text-[var(--ng-cyan-bright)]" />
 <h3 className="text-sm font-bold text-ng-on uppercase tracking-wider">Mitigation Center</h3>
 </div>
 <div className="space-y-4">
 <button className="w-full bg-[var(--ng-cyan-bright)] text-ng-base font-bold py-3 rounded-none text-[10px] font-mono tracking-widest flex items-center justify-center gap-2 hover:bg-ng-cyan-bright/90 transition-all uppercase">
 <ShieldAlert className="w-4 h-4" />
 EXECUTE PLAYBOOK
 </button>
 
 <div className="pt-2 space-y-2">
 <p className="text-[9px] font-bold text-ng-muted uppercase tracking-widest mb-2 border-b border-ng-outline-dim/40/50 pb-2">Manual Actions</p>
 <button className="w-full text-left px-4 py-2.5 text-xs font-bold text-ng-on border border-ng-outline-dim/40 hover:border-ng-outline-dim/40 bg-ng-base hover:bg-ng-mid rounded-none flex items-center justify-between group transition-all uppercase tracking-wider">
 <span>Isolate Endpoint</span>
 <ChevronRight className="w-3.5 h-3.5 text-ng-muted group-hover:text-ng-on" />
 </button>
 <button className="w-full text-left px-4 py-2.5 text-xs font-bold text-ng-on border border-ng-outline-dim/40 hover:border-ng-outline-dim/40 bg-ng-base hover:bg-ng-mid rounded-none flex items-center justify-between group transition-all uppercase tracking-wider">
 <span>Revoke Tokens</span>
 <ChevronRight className="w-3.5 h-3.5 text-ng-muted group-hover:text-ng-on" />
 </button>
 <button className="w-full text-left px-4 py-2.5 text-xs font-bold text-ng-on border border-ng-outline-dim/40 hover:border-ng-outline-dim/40 bg-ng-base hover:bg-ng-mid rounded-none flex items-center justify-between group transition-all uppercase tracking-wider">
 <span>Assign to Team</span>
 <ChevronRight className="w-3.5 h-3.5 text-ng-muted group-hover:text-ng-on" />
 </button>
 </div>
 
 <div className="pt-4 border-t border-ng-outline-dim/40/50">
 <button className="w-full border border-[var(--ng-lime)]/30 text-[var(--ng-lime)] hover:bg-[var(--ng-lime)]/10 py-2.5 rounded-none text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition-all">
 Close Incident
 </button>
 </div>
 </div>
 </div>

 {/* Live Collaboration Panel */}
  <CollaborationPanel
    incidentId={id}
    currentUserId={user?.sub || "anonymous"}
    currentUserName={user?.name || user?.display_name || "Analyst"}
    className="w-full"
  />
 </div>
 </div>
 )} {/* end details tab */}

 {/* ── Threat Intelligence Tab ── */}
 {activeTab === "threat-intel" && (
 <div className="p-6 max-w-screen-2xl mx-auto w-full flex flex-col gap-4">
 <div className="flex items-center gap-3 mb-2">
 <Network className="w-5 h-5 text-[var(--ng-cyan-bright)]" />
 <h3 className="text-sm font-bold text-ng-on uppercase tracking-wider">STIX2 Threat Intelligence Graph</h3>
 <span className="text-[10px] text-ng-muted font-mono">
 {graphNodes.length} entities · {graphEdges.length} relationships
 </span>
 </div>

 {graphLoading && (
 <div className="flex items-center justify-center h-[400px] ng-surface border border-ng-outline-dim/40/50">
 <div className="flex flex-col items-center gap-3">
 <div className="w-8 h-8 border-2 border-[var(--ng-cyan-bright)] border-b-transparent rounded-full animate-spin" />
 <p className="text-xs text-ng-muted font-mono uppercase tracking-widest animate-pulse">Loading Threat Graph…</p>
 </div>
 </div>
 )}

 {!graphLoading && graphNodes.length === 0 && (
 <div className="flex flex-col items-center justify-center h-[400px] ng-surface border border-ng-outline-dim/40/50 border-dashed gap-4">
 <Network className="w-12 h-12 text-ng-muted" />
 <div className="text-center">
 <p className="text-sm font-bold text-ng-on">No Threat Intelligence Data</p>
 <p className="text-xs text-ng-muted mt-1 max-w-xs">
 No STIX2 entities are linked to this incident yet. Connect TAXII feeds or ingest threat bundles to populate this graph.
 </p>
 </div>
 </div>
 )}

 {!graphLoading && graphNodes.length > 0 && (
 <ThreatGraph
 nodes={graphNodes}
 edges={graphEdges}
 className="w-full"
 />
 )}
 </div>
 )}
 </div>
 );
}
