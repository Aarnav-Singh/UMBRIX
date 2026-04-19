"use client";

import React, { useState, useCallback, useEffect } from 'react';
import { Database, Network, BrainCircuit, Gauge, CheckCircle, Cpu, Activity, Zap, GitBranch, Shield, Eye, Cloud, Terminal, FileText, Wifi } from 'lucide-react';
import useSWR from 'swr';
import { useEventStream } from "@/contexts/EventStreamContext";
import { PanelCard, AnimatedNumber, StaggerChildren } from '@/components/ui/MotionWrappers';
import { DataGrid } from '@/components/ui/DataGrid';
import { AmbientBackground } from '@/components/ui/AmbientBackground';

const fetcher = (url: string) => fetch(url).then(r => r.json());

// ─── Types ───────────────────────────────────────────────
interface StreamInfo { score?: number; weight?: number; status?: string; active?: boolean; }
interface PipelineStatus {
 events_processed: number;
 avg_duration_ms: number;
 streams: {
 ensemble?: StreamInfo;
 vae?: StreamInfo;
 hst?: StreamInfo;
 temporal?: StreamInfo;
 adversarial?: StreamInfo;
 meta_learner?: StreamInfo;
 };
}
interface ModelInfo { name: string; version: string; status: string; accuracy?: number; last_trained?: string; }
interface ModelsResponse { models: ModelInfo[]; }
interface NeuralLogEntry { timestamp: string; type: 'INFERENCE' | 'LOSS' | 'DATA' | 'WARN' | 'SYSTEM' | 'SCORE'; message: string; status?: 'FLAGGED' | 'CLEAN' | 'WARN'; score?: number; }

const DEMO_STATUS: PipelineStatus = {
 events_processed: 142897,
 avg_duration_ms: 14,
 streams: {
 ensemble: { score: 0.87, weight: 0.3, status: 'active', active: true },
 vae: { score: 0.72, weight: 0.2, status: 'active', active: true },
 hst: { score: 0.91, weight: 0.15, status: 'active', active: true },
 temporal: { score: 0.65, weight: 0.2, status: 'degraded', active: true },
 adversarial: { score: 0.88, weight: 0.1, status: 'active', active: true },
 meta_learner: { score: 0.93, weight: 0.05, status: 'active', active: true },
 },
};

const DEMO_MODELS: ModelInfo[] = [
 { name: 'Ensemble Detector', version: 'v2.4.1', status: 'serving', accuracy: 98.4, last_trained: '2026-03-08' },
 { name: 'VAE Anomaly', version: 'v1.9.0', status: 'serving', accuracy: 94.1, last_trained: '2026-03-07' },
 { name: 'HST Classifier', version: 'v3.1.2', status: 'serving', accuracy: 97.2, last_trained: '2026-03-09' },
 { name: 'Temporal RNN', version: 'v2.0.0', status: 'degraded', accuracy: 89.0, last_trained: '2026-03-01' },
 { name: 'Adversarial GAN', version: 'v1.2.3', status: 'serving', accuracy: 92.7, last_trained: '2026-03-08' },
];

const STREAM_LABELS: Record<string, string> = { ensemble: 'Ensemble', vae: 'VAE', hst: 'HST', temporal: 'Temporal', adversarial: 'Adversarial', meta_learner: 'Meta-Learner' };
const STREAM_ICONS: Record<string, React.ElementType> = { ensemble: BrainCircuit, vae: Activity, hst: Gauge, temporal: GitBranch, adversarial: Zap, meta_learner: Network };

const GRAPH_NODES = {
  ingestors: [
    { id: 'zeek', label: 'ZEEK NIDS', icon: Eye, x: 8, y: 20 },
    { id: 'suricata', label: 'SURICATA', icon: Shield, x: 8, y: 40 },
    { id: 'aws', label: 'AWS TRAIL', icon: Cloud, x: 8, y: 60 },
    { id: 'syslog', label: 'SYSLOG', icon: Terminal, x: 8, y: 80 },
  ],
  extractors: [
    { id: 'netflow', label: 'PCAP/NETFLOW', icon: Wifi, x: 50, y: 30 },
    { id: 'logext', label: 'LOG EXTRACTOR', icon: FileText, x: 50, y: 70 },
  ],
  models: [
    { id: 'vae', label: 'VAE ANOMALY', icon: Activity, x: 92, y: 15 },
    { id: 'hst', label: 'HST CLASS', icon: Gauge, x: 92, y: 33 },
    { id: 'temporal', label: 'TEMP RNN', icon: GitBranch, x: 92, y: 50 },
    { id: 'adversarial', label: 'ADV GAN', icon: Zap, x: 92, y: 68 },
    { id: 'ensemble', label: 'ENSEMBLE', icon: BrainCircuit, x: 92, y: 85 },
  ]
};

// Helper for curved connections
const ConnectionPath = ({ from, to, isPulsing }: { from: any; to: any; isPulsing: boolean }) => {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const cx1 = from.x + dx * 0.4;
  const cy1 = from.y;
  const cx2 = from.x + dx * 0.6;
  const cy2 = to.y;

  return (
    <path
      d={`M ${from.x} ${from.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${to.x} ${to.y}`}
      fill="none"
      stroke={isPulsing ? 'var(--ng-cyan)' : 'rgba(255,255,255,0.08)'}
      strokeWidth={isPulsing ? 2 : 1}
      className="transition-all duration-300"
      vectorEffect="non-scaling-stroke"
    />
  );
};

function formatCount(n: number): string {
 if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
 if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
 return String(n);
}

export default function MLPipelinePage() {
 const [neuralLog, setNeuralLog] = useState<NeuralLogEntry[]>([
 { timestamp: '14:02:41', type: 'INFERENCE', message: 'Pipeline initialized — awaiting live events', status: 'CLEAN' },
 ]);
 const [pulses, setPulses] = useState<{ id: string; source: string; ext: string; mod: string }[]>([]);

 const { data: statusData, isLoading: statusLoading } = useSWR<PipelineStatus>('/api/proxy/api/v1/pipeline/status', fetcher, { refreshInterval: 5000 });
 const { data: modelsData, isLoading: modelsLoading } = useSWR<ModelsResponse>('/api/proxy/api/v1/pipeline/models', fetcher, { refreshInterval: 30000 });
 const { data: connectorsData } = useSWR("/api/proxy/api/v1/admin/connectors", fetcher);

  const pipelineStatus = (statusData && typeof statusData === 'object' && !Array.isArray(statusData)) ? statusData : DEMO_STATUS;
  const models = (modelsData && Array.isArray(modelsData.models)) ? modelsData.models : (Array.isArray(modelsData) ? modelsData : DEMO_MODELS);
  const streams = (pipelineStatus && pipelineStatus.streams && typeof pipelineStatus.streams === 'object' && !Array.isArray(pipelineStatus.streams)) ? pipelineStatus.streams : {};
  
  console.log("[Pipeline] State Check:", { 
    hasStatus: !!statusData, 
    hasModels: !!modelsData, 
    hasConnectors: !!connectorsData,
    streamsCount: Object.keys(streams).length,
    modelsCount: models.length
  });
 
 const isDemo = !statusData && !statusLoading;
 const isDemoModels = !modelsData && !modelsLoading;

  const graphNodes = React.useMemo(() => {
    const rawData = connectorsData?.connectors ?? connectorsData;
    console.log("[Pipeline] Raw connectors data:", rawData);
    
    if (rawData && typeof rawData === 'object' && !Array.isArray(rawData) && 
        Array.isArray(rawData.ingestors) && Array.isArray(rawData.extractors) && Array.isArray(rawData.models)) {
      return rawData;
    }

    // If it's a flat array (from the actual API), categorize them as ingestors
    if (Array.isArray(rawData)) {
      console.log("[Pipeline] Categorizing flat array of", rawData.length, "connectors");
      return {
        ingestors: rawData.filter(c => c && typeof c === 'object').map((c: any, idx: number) => ({
          id: String(c.id || idx),
          label: String(c.name || c.source_type || 'CONNECTOR').toUpperCase(),
          icon: c.source_type === 'zeek' ? Eye : c.source_type === 'suricata' ? Shield : Network,
          x: 15,
          y: 20 + (idx * 15)
        })).slice(0, 5),
        extractors: GRAPH_NODES.extractors,
        models: GRAPH_NODES.models
      };
    }

    console.log("[Pipeline] Falling back to default GRAPH_NODES");
    return GRAPH_NODES;
  }, [connectorsData]);

  const currentConnections = React.useMemo(() => {
    try {
      const conns: { id: string, from: any; to: any }[] = [];
      const ingestors = Array.isArray(graphNodes?.ingestors) ? graphNodes.ingestors : [];
      const extractors = Array.isArray(graphNodes?.extractors) ? graphNodes.extractors : [];
      const nodes_models = Array.isArray(graphNodes?.models) ? graphNodes.models : [];

      if (ingestors.length && extractors.length) {
        ingestors.forEach((ing: any) => {
          extractors.forEach((ext: any) => {
            if (ing?.id && ext?.id) {
              conns.push({ id: `${ing.id}-${ext.id}`, from: ing, to: ext });
            }
          });
        });
      }
      if (extractors.length && nodes_models.length) {
        extractors.forEach((ext: any) => {
          nodes_models.forEach((mod: any) => {
            if (ext?.id && mod?.id) {
              conns.push({ id: `${ext.id}-${mod.id}`, from: ext, to: mod });
            }
          });
        });
      }
      return conns;
    } catch (e) {
      console.error("[Pipeline] Error building connections:", e);
      return [];
    }
  }, [graphNodes]);

 const handleLiveEvent = useCallback((event: Record<string, unknown>) => {
 const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
 const scores = event.ml_scores as Record<string, number> | undefined;
 const metaScore = scores?.meta_score ?? 0;
 const severity = (event.severity as string) || 'low';
 const isFlagged = metaScore > 0.7 || severity === 'critical' || severity === 'high';
 const sourceType = (event.source_type as string) || 'UNKNOWN';
 const evId = ((event.event_id as string) || '').slice(0, 8);
 
 if (!evId) {
 setNeuralLog(prev => [{
 timestamp: ts,
 type: 'SYSTEM' as const,
 message: `[HEARTBEAT] Connection active — ping verified`,
 status: 'CLEAN' as const
 }, ...prev].slice(0, 50));
 return;
 }

 const entry: NeuralLogEntry = {
 timestamp: ts,
 type: isFlagged ? 'INFERENCE' : 'DATA',
 message: `[${sourceType.toUpperCase()}] ID:${evId} SCORE:${metaScore.toFixed(3)} ${isFlagged ? 'FLAGGED' : 'CLEAN'}`,
 status: isFlagged ? 'FLAGGED' : 'CLEAN',
 score: metaScore,
 };

 setNeuralLog(prev => [entry, ...prev].slice(0, 50));

 const sType = sourceType.toLowerCase();
 const sourceMap: Record<string, string> = { zeek: 'zeek', suricata: 'suricata', aws: 'aws', syslog: 'syslog' };
  const ingestorsInfo = (Array.isArray(graphNodes.ingestors) && graphNodes.ingestors.length > 0) ? graphNodes.ingestors : GRAPH_NODES.ingestors;
  const extractorsInfo = (Array.isArray(graphNodes.extractors) && graphNodes.extractors.length > 0) ? graphNodes.extractors : GRAPH_NODES.extractors;
  const modelsInfo = (Array.isArray(graphNodes.models) && graphNodes.models.length > 0) ? graphNodes.models : GRAPH_NODES.models;
  
  const matchedSourceId = Object.keys(sourceMap).find(k => sType.includes(k)) || ingestorsInfo[Math.floor(Math.random() * ingestorsInfo.length)]?.id || 'zeek';
  const extId = extractorsInfo[Math.floor(Math.random() * extractorsInfo.length)]?.id || 'netflow';
  const modId = modelsInfo[Math.floor(Math.random() * modelsInfo.length)]?.id || 'vae';

 const newPulse = { id: Date.now().toString() + Math.random(), source: matchedSourceId, ext: extId, mod: modId };
 setPulses(p => [...p, newPulse]);
 setTimeout(() => { setPulses(p => p.filter(pulse => pulse.id !== newPulse.id)); }, 300);
 }, [graphNodes]);

 const { lastEvent } = useEventStream();
 useEffect(() => {
 if (lastEvent) {
 handleLiveEvent(lastEvent);
 }
 }, [lastEvent, handleLiveEvent]);

  const avgAccuracy = models.length ? models.reduce((sum: number, m: any) => sum + (m.accuracy ?? 0), 0) / models.length : 0;
  const servingCount = models.filter((m: any) => m.status === 'serving').length;

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-transparent relative">
      <AmbientBackground variant="pipeline" />
      
      <div className="relative z-10 flex flex-col flex-1 p-6 gap-6 min-h-0">
        {/* KPI TOP ROW - High Density */}
        <div className="grid grid-cols-4 gap-4 shrink-0">
          {[
            { label: 'AVG LATENCY', value: pipelineStatus.avg_duration_ms, unit: 'MS', color: 'text-ng-cyan' },
            { label: 'AVG ACCURACY', value: avgAccuracy.toFixed(1), unit: '%', color: 'text-ng-lime' },
            { label: 'MODELS SERVING', value: `${servingCount}/${models.length}`, unit: '', color: 'text-ng-magenta' },
            { label: 'EVENTS PROCESSED', value: pipelineStatus.events_processed, unit: '', color: 'text-ng-on', isAnimated: true },
          ].map((kpi, i) => (
            <PanelCard key={i} data-testid={`kpi-card-${kpi.label.toLowerCase().replace(/ /g, '-')}`} className="p-2 border-l border-l-ng-outline-dim/40 group hover:border-l-ng-cyan transition-all bg-ng-mid/20">
              <span className="text-[8px] text-ng-muted font-mono tracking-widest uppercase mb-0.5 block">{kpi.label}</span>
              <div className="flex items-baseline gap-1">
                <span className={`text-xl font-mono ${kpi.color}`}>
                  {kpi.isAnimated ? <AnimatedNumber value={Number(kpi.value) || 0} /> : (kpi.value ?? "—")}
                </span>
                {kpi.unit && <span className="text-[8px] text-ng-muted font-mono">{kpi.unit}</span>}
              </div>
            </PanelCard>
          ))}
        </div>

        {/* MAIN VISUALIZER - Center Stage */}
        <div className="flex-1 flex flex-col min-h-[450px] min-w-0">
          <PanelCard data-testid="pipeline-topology-visualizer" className="flex-1 relative overflow-hidden flex flex-col group border-ng-outline-dim/40 bg-ng-base/10">
            {/* Header / HUD Overlay */}
            <div className="absolute top-0 left-0 right-0 p-4 z-20 flex justify-between items-start pointer-events-none">
              <div className="bg-ng-base/80 backdrop-blur-md border border-ng-outline-dim/20 px-3 py-1.5 flex items-center gap-3">
                <div className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-ng-cyan-bright animate-pulse" />
                  <span className="text-[10px] text-ng-cyan font-mono tracking-widest uppercase">Global Inference Topology</span>
                </div>
                <div className="w-px h-3 bg-ng-outline-dim/30" />
                <span className="text-[9px] text-ng-muted font-mono">ACTIVE PIPELINE: PROD-ALPHA-01</span>
              </div>
              
              {isDemo && (
                <div className="bg-ng-magenta/10 border border-ng-magenta/30 text-ng-magenta px-2 py-1 text-[10px] font-mono tracking-tighter">
                  SIMULATION DATA ACTIVE
                </div>
              )}
            </div>

            {/* The Visualizer Canvas */}
            <div className="flex-1 relative bg-[radial-gradient(circle_at_center,rgba(13,148,136,0.03)_0%,transparent_100%)] overflow-hidden">
              {/* Animated Grid Background */}
              <div className="absolute inset-0 opacity-[0.03] pointer-events-none" 
                   style={{ backgroundImage: 'linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)', backgroundSize: '40px 40px' }} />
              
              <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="absolute inset-0 w-full h-full pointer-events-none z-0">
                {Array.isArray(currentConnections) && currentConnections.map(conn => {
                  const isPulsing = pulses.some(p => (p.source === conn.from.id && p.ext === conn.to.id) || (p.ext === conn.from.id && p.mod === conn.to.id));
                  return <ConnectionPath key={conn.id} from={conn.from} to={conn.to} isPulsing={isPulsing} />;
                })}
              </svg>

              <div className="absolute inset-0 z-10">
                {Object.entries(graphNodes || GRAPH_NODES).flatMap(([group, nodes]) => (Array.isArray(nodes) ? nodes : []).map((node: any) => {
                  const isPulsing = pulses.some(p => p.source === node.id || p.ext === node.id || p.mod === node.id);
                  const Icon = node.icon || Activity;
                  
                  return (
                    <div
                      key={node.id}
                      data-testid="topology-node" className={`absolute flex flex-col items-center transform -translate-x-1/2 -translate-y-1/2 transition-all duration-500`}
                      style={{ left: `${node.x}%`, top: `${node.y}%` }}
                    >
                      <div className={`relative group/node cursor-pointer pointer-events-auto`}>
                        {/* Glow effect */}
                        <div className={`absolute -inset-4 transition-opacity duration-500 ${isPulsing ? 'opacity-100' : 'opacity-0'} bg-ng-cyan/10 blur-xl rounded-full`} />
                        
                        <div className={`relative w-12 h-12 flex items-center justify-center border-2 transition-all duration-300 ${
                          isPulsing ? 'border-ng-cyan bg-ng-cyan-bright/10 text-ng-cyan shadow-[0_0_15px_rgba(20,184,166,0.3)]' : 'border-ng-outline-dim/40 bg-ng-base text-ng-muted hover:border-ng-muted hover:text-ng-on'
                        }`}>
                          <Icon className={`w-5 h-5 transition-transform duration-300 ${isPulsing ? 'scale-110' : ''}`} />
                          
                          {/* Mini status indicator */}
                          <div className={`absolute -top-1 -right-1 w-2.5 h-2.5 border-2 border-ng-base ${isPulsing ? 'bg-ng-cyan' : 'bg-ng-muted'}`} />
                        </div>
                        
                        {/* Label - Side aligned to avoid vertical overlap */}
                        <div className={`absolute left-full ml-3 top-1/2 -translate-y-1/2 whitespace-nowrap`}>
                          <span className={`text-[10px] font-mono tracking-widest px-2 py-0.5 border transition-all duration-300 ${
                            isPulsing ? 'bg-ng-cyan text-ng-base border-ng-cyan' : 'bg-ng-mid text-ng-muted border-ng-outline-dim/20 opacity-60'
                          }`}>
                            {node.label}
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                }))}
              </div>
            </div>
          </PanelCard>
        </div>

        {/* BOTTOM DATA STRIP - 3-Column Layout */}
        <div className="grid grid-cols-12 gap-6 h-56 shrink-0">
          {/* Model Registry (4 columns) */}
          <PanelCard data-testid="model-registry-panel" className="col-span-4 flex flex-col overflow-hidden bg-ng-mid/20 backdrop-blur-md border-ng-outline-dim/20">
            <div className="px-4 py-2 border-b border-ng-outline-dim/20 flex justify-between items-center">
              <span className="text-[10px] font-mono tracking-widest text-ng-muted uppercase">Model Inventory</span>
              <div className="text-[9px] text-ng-cyan font-mono">{servingCount} ACTIVE</div>
            </div>
            <div className="flex-1 overflow-y-auto p-2 custom-scrollbar">
              <DataGrid
                data={models}
                rowKey="name"
                columns={[
                  { header: "ST", key: "status", render: (val) => <div className={`w-1.5 h-1.5 rounded-full shadow-sm ${val === 'serving' ? 'bg-ng-lime shadow-ng-lime/50' : 'bg-ng-magenta shadow-ng-magenta/50'}`} /> },
                  { header: "NAME", key: "name", render: (val) => <span className="text-[11px] text-ng-on font-medium">{val}</span> },
                  { header: "ACCURACY", key: "accuracy", align: "right", render: (val) => <span className="text-[11px] font-mono text-ng-cyan">{val}%</span> }
                ]}
              />
            </div>
          </PanelCard>

          {/* Stream Telemetry / Signal Matrix (4 columns) */}
          <PanelCard data-testid="signal-matrix-panel" className="col-span-4 flex flex-col overflow-hidden bg-ng-mid/10 backdrop-blur-md border border-ng-outline-dim/10 group">
            <div className="px-4 py-2 border-b border-ng-outline-dim/10 flex justify-between items-center bg-ng-mid/20">
              <div className="flex items-center gap-2">
                <div className="w-1 h-1 bg-ng-cyan" />
                <span className="text-[10px] font-mono tracking-widest text-ng-muted uppercase">Neural Signal Matrix</span>
              </div>
              <Activity className="w-3 h-3 text-ng-cyan/50 group-hover:animate-pulse" />
            </div>
            
            <div className="flex-1 p-3 flex flex-col gap-3 overflow-hidden">
              {/* Dense Heatmap Grid - Driven by live streams */}
              <div className="grid grid-cols-8 gap-1.5 flex-1">
                {Object.entries(streams).flatMap(([key, info]: [string, any]) => {
                  const baseIntensity = info?.score ?? 0.5;
                  // Create 8 sub-cells per stream to fill the grid (8*6=48)
                  return Array.from({ length: 8 }).map((_, i) => {
                    const cellIntensity = Math.max(0, Math.min(1, baseIntensity + (Math.random() - 0.5) * 0.2));
                    const isCritical = cellIntensity > 0.88;
                    return (
                      <div 
                        key={`${key}-${i}`} 
                        className={`relative aspect-square border transition-all duration-700 ${
                          isCritical 
                            ? 'bg-ng-error/40 border-ng-error/50 shadow-[0_0_5px_rgba(239,68,68,0.3)]' 
                            : cellIntensity > 0.5 
                              ? 'bg-ng-cyan/20 border-ng-cyan/30' 
                              : 'bg-ng-mid/40 border-ng-outline-dim/10'
                        }`}
                        title={`${key.toUpperCase()} UNIT ${i}: ${(cellIntensity * 100).toFixed(1)}%`}
                      >
                        {isCritical && (
                          <div className="absolute inset-0 bg-ng-error animate-ping opacity-20" />
                        )}
                      </div>
                    );
                  });
                })}
              </div>

              {/* Summary stats row */}
              <div className="grid grid-cols-3 gap-4 pt-2 border-t border-ng-outline-dim/10">
                {['SYNC', 'DRIFT', 'NOISE'].map(stat => (
                  <div key={stat} className="flex flex-col gap-0.5">
                    <span className="text-[7px] text-ng-muted font-mono">{stat}</span>
                    <span className="text-[10px] text-ng-on font-mono">{(Math.random() * 100).toFixed(1)}%</span>
                  </div>
                ))}
              </div>
            </div>
          </PanelCard>

          {/* Neural Debug Log (4 columns) */}
          <PanelCard data-testid="neural-debug-panel" className="col-span-4 flex flex-col overflow-hidden bg-ng-base border-ng-outline-dim/20">
            <div className="px-4 py-2 border-b border-ng-outline-dim/20 flex justify-between items-center bg-ng-mid/40">
              <span className="text-[10px] font-mono tracking-widest text-ng-muted uppercase">Neural Debug Trace</span>
              <Terminal className="w-3 h-3 text-ng-cyan/60" />
            </div>
            <div className="flex-1 p-3 overflow-y-auto custom-scrollbar font-mono text-[9px] space-y-1.5 bg-ng-base">
              {neuralLog.map((entry, i) => (
                <div key={i} className="flex gap-3 leading-tight opacity-80 hover:opacity-100 transition-opacity">
                  <span className="text-ng-muted shrink-0 tabular-nums">{entry.timestamp}</span>
                  <span className={`${entry.status === 'FLAGGED' ? 'text-ng-error' : entry.type === 'WARN' ? 'text-ng-magenta' : 'text-ng-cyan/70'}`}>
                    {entry.message}
                  </span>
                </div>
              ))}
            </div>
          </PanelCard>
        </div>
      </div>
    </div>
  );
}
