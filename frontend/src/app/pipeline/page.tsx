"use client";

import React, { useState, useCallback } from 'react';
import { Database, Network, BrainCircuit, Gauge, CheckCircle, Cpu, Activity, Zap, GitBranch, Shield, Eye, Cloud, Terminal, FileText, Wifi } from 'lucide-react';
import useSWR from 'swr';
import { useLiveEvents } from '@/hooks/useLiveEvents';

const fetcher = (url: string) => fetch(url).then(r => r.json());

// ─── Types ───────────────────────────────────────────────

interface StreamInfo {
  score?: number;
  weight?: number;
  status?: string;
  active?: boolean;
}

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

interface ModelInfo {
  name: string;
  version: string;
  status: string;
  accuracy?: number;
  last_trained?: string;
}

interface ModelsResponse {
  models: ModelInfo[];
}

interface NeuralLogEntry {
  timestamp: string;
  type: 'INFERENCE' | 'LOSS' | 'DATA' | 'WARN' | 'SYSTEM' | 'SCORE';
  message: string;
  status?: 'FLAGGED' | 'CLEAN' | 'WARN';
  score?: number;
}

// ─── Demo fallbacks ──────────────────────────────────────

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

const STREAM_LABELS: Record<string, string> = {
  ensemble: 'Ensemble',
  vae: 'VAE',
  hst: 'HST',
  temporal: 'Temporal',
  adversarial: 'Adversarial',
  meta_learner: 'Meta-Learner',
};

const STREAM_ICONS: Record<string, React.ElementType> = {
  ensemble: BrainCircuit,
  vae: Activity,
  hst: Gauge,
  temporal: GitBranch,
  adversarial: Zap,
  meta_learner: Network,
};

const GRAPH_NODES = {
  ingestors: [
    { id: 'zeek', label: 'Zeek NIDS', icon: Eye, x: 15, y: 20 },
    { id: 'suricata', label: 'Suricata', icon: Shield, x: 15, y: 40 },
    { id: 'aws', label: 'AWS Trail', icon: Cloud, x: 15, y: 60 },
    { id: 'syslog', label: 'Syslog', icon: Terminal, x: 15, y: 80 },
  ],
  extractors: [
    { id: 'netflow', label: 'PCAP & Netflow', icon: Wifi, x: 50, y: 30 },
    { id: 'logext', label: 'Log Extractor', icon: FileText, x: 50, y: 70 },
  ],
  models: [
    { id: 'vae', label: 'VAE Anomaly', icon: Activity, x: 85, y: 15 },
    { id: 'hst', label: 'HST Classifier', icon: Gauge, x: 85, y: 33 },
    { id: 'temporal', label: 'Temporal RNN', icon: GitBranch, x: 85, y: 50 },
    { id: 'adversarial', label: 'Adv GAN', icon: Zap, x: 85, y: 68 },
    { id: 'ensemble', label: 'Ensemble', icon: BrainCircuit, x: 85, y: 85 },
  ]
};

const graphConnections: { from: any; to: any; id: string }[] = [];
GRAPH_NODES.ingestors.forEach(ing => {
  GRAPH_NODES.extractors.forEach(ext => {
    graphConnections.push({ from: ing, to: ext, id: `${ing.id}-${ext.id}` });
  });
});
GRAPH_NODES.extractors.forEach(ext => {
  GRAPH_NODES.models.forEach(mod => {
    graphConnections.push({ from: ext, to: mod, id: `${ext.id}-${mod.id}` });
  });
});

function SkeletonBlock({ className }: { className?: string }) {
  return <div className={`animate-pulse bg-sf-surface/60 rounded ${className}`} />;
}

function StatusDot({ status }: { status?: string }) {
  const color = status === 'active' || status === 'serving'
    ? 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.7)]'
    : status === 'degraded'
    ? 'bg-yellow-400 shadow-[0_0_6px_rgba(251,191,36,0.7)]'
    : 'bg-slate-500';
  return <span className={`inline-block w-2 h-2 rounded-full ${color}`} />;
}

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function getLogColor(entry: NeuralLogEntry): string {
  if (entry.type === 'WARN') return 'text-yellow-400/70';
  if (entry.status === 'FLAGGED') return 'text-sf-accent/60';
  return 'text-sf-accent/50';
}

function getLogBodyColor(entry: NeuralLogEntry): string {
  if (entry.status === 'FLAGGED') return 'text-red-400';
  if (entry.status === 'WARN' || entry.type === 'WARN') return 'text-yellow-400';
  return 'text-slate-200';
}

export default function MLPipelinePage() {
  const [neuralLog, setNeuralLog] = useState<NeuralLogEntry[]>([
    { timestamp: '14:02:41', type: 'INFERENCE', message: 'Pipeline initialized — awaiting live events', status: 'CLEAN' },
  ]);
  const [pulses, setPulses] = useState<{ id: string; source: string; ext: string; mod: string }[]>([]);

  const { data: statusData, isLoading: statusLoading } = useSWR<PipelineStatus>(
    '/api/proxy/api/v1/pipeline/status', fetcher, { refreshInterval: 5000 }
  );
  const { data: modelsData, isLoading: modelsLoading } = useSWR<ModelsResponse>(
    '/api/proxy/api/v1/pipeline/models', fetcher, { refreshInterval: 30000 }
  );

  const pipelineStatus = statusData ?? DEMO_STATUS;
  const models = modelsData?.models ?? DEMO_MODELS;
  const streams = pipelineStatus.streams ?? {};

  // SSE: update neural log feed
  const handleLiveEvent = useCallback((event: Record<string, unknown>) => {
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
    const scores = event.ml_scores as Record<string, number> | undefined;
    const metaScore = scores?.meta_score ?? 0;
    const severity = (event.severity as string) || 'low';
    const isFlagged = metaScore > 0.7 || severity === 'critical' || severity === 'high';
    const sourceType = (event.source_type as string) || 'UNKNOWN';
    const evId = ((event.event_id as string) || '').slice(0, 8);

    const entry: NeuralLogEntry = {
      timestamp: ts,
      type: isFlagged ? 'INFERENCE' : 'DATA',
      message: `${sourceType.toUpperCase()}: Event ${evId} scored ${metaScore.toFixed(3)} ${isFlagged ? '[FLAGGED]' : '[CLEAN]'}`,
      status: isFlagged ? 'FLAGGED' : 'CLEAN',
      score: metaScore,
    };

    setNeuralLog(prev => [entry, ...prev].slice(0, 50));

    // dynamic graph pulse logic
    const sType = sourceType.toLowerCase();
    const sourceMap: Record<string, string> = { zeek: 'zeek', suricata: 'suricata', aws: 'aws', syslog: 'syslog' };
    const matchedSourceId = Object.keys(sourceMap).find(k => sType.includes(k)) || GRAPH_NODES.ingestors[Math.floor(Math.random() * GRAPH_NODES.ingestors.length)].id;
    const extId = GRAPH_NODES.extractors[Math.floor(Math.random() * GRAPH_NODES.extractors.length)].id;
    const modId = GRAPH_NODES.models[Math.floor(Math.random() * GRAPH_NODES.models.length)].id;

    const newPulse = { id: Date.now().toString() + Math.random(), source: matchedSourceId, ext: extId, mod: modId };
    setPulses(p => [...p, newPulse]);
    setTimeout(() => {
      setPulses(p => p.filter(pulse => pulse.id !== newPulse.id));
    }, 1500);
  }, []);

  useLiveEvents({ onEvent: handleLiveEvent });

  // Compute accuracy from models or use demo
  const avgAccuracy = models.length
    ? models.reduce((sum, m) => sum + (m.accuracy ?? 0), 0) / models.length
    : 98.4;

  const servingCount = models.filter(m => m.status === 'serving').length;

  return (
    <div className="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-6">
      <div className="flex flex-col gap-6 max-w-7xl mx-auto">
        <header className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">ML Pipeline</h1>
            <p className="text-sm text-sf-muted mt-1">Real-time model inference and training dynamics.</p>
          </div>
          <div className="flex items-center gap-3">
            {statusLoading
              ? <SkeletonBlock className="w-40 h-8" />
              : (
                <div className="text-[10px] font-mono text-sf-accent bg-sf-accent/10 px-3 py-1.5 rounded border border-sf-accent/30 flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-sf-accent animate-pulse" />
                  {formatCount(pipelineStatus.events_processed)} EVENTS PROCESSED
                </div>
              )
            }
          </div>
        </header>

        {/* ── Top KPI row (Borderless) ── */}
        <div className="flex items-center justify-between border-b border-white/5 pb-8">
          {/* Avg Duration */}
          <div>
            <p className="text-[10px] text-sf-muted uppercase tracking-widest font-medium mb-2">Avg Latency</p>
            {statusLoading
              ? <SkeletonBlock className="h-8 w-20" />
              : <p className="text-4xl font-display font-light text-white">{pipelineStatus.avg_duration_ms}<span className="text-sm text-sf-muted ml-1 font-mono">ms</span></p>
            }
          </div>
          {/* Accuracy */}
          <div>
            <p className="text-[10px] text-sf-muted uppercase tracking-widest font-medium mb-2">Avg Accuracy</p>
            {modelsLoading
              ? <SkeletonBlock className="h-8 w-20" />
              : <p className="text-4xl font-display font-light text-white">{avgAccuracy.toFixed(1)}<span className="text-sm text-sf-accent ml-1 font-mono">%</span></p>
            }
          </div>
          {/* Models serving */}
          <div>
            <p className="text-[10px] text-sf-muted uppercase tracking-widest font-medium mb-2">Models Serving</p>
            {modelsLoading
              ? <SkeletonBlock className="h-8 w-12" />
              : <p className="text-4xl font-display font-light text-white">{servingCount}<span className="text-sm text-sf-muted ml-1 font-mono">/ {models.length}</span></p>
            }
          </div>
          {/* Events counter */}
          <div className="text-right">
            <p className="text-[10px] text-sf-muted uppercase tracking-widest font-medium mb-2">Live Alert Feed</p>
            <p className="text-4xl font-display font-light text-sf-critical">{neuralLog.filter(l => l.type === 'INFERENCE').length}<span className="text-sm text-sf-muted ml-1 font-mono">EVT</span></p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Column: ML Flow Visualizer + Stream cards */}
          <div className="flex flex-col gap-6">
            <section className="flex flex-col gap-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sf-accent text-sm font-bold tracking-tight uppercase flex items-center gap-2">
                  <Activity className="w-4 h-4" />
                  ML Visualizer
                </h3>
                <span className="flex items-center gap-2 text-[10px] font-mono text-sf-accent bg-sf-accent/10 px-2 py-1 rounded border border-sf-accent/30 animate-pulse">
                  <span className="w-1.5 h-1.5 rounded-full bg-sf-accent" /> LIVE INFERENCE
                </span>
              </div>

              <div className="relative w-full aspect-[4/3] bg-sf-bg/50 border border-white/5 rounded-xl overflow-hidden group">
                <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(20,184,166,0.05)_0%,transparent_70%)]" />

                <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="absolute inset-0 w-full h-full pointer-events-none">
                  {graphConnections.map(conn => {
                    const isPulsing = pulses.some(
                      p => (p.source === conn.from.id && p.ext === conn.to.id) || 
                           (p.ext === conn.from.id && p.mod === conn.to.id)
                    );
                    return (
                      <path
                        key={conn.id}
                        vectorEffect="non-scaling-stroke"
                        d={`M ${conn.from.x} ${conn.from.y} C ${(conn.from.x + conn.to.x) / 2} ${conn.from.y}, ${(conn.from.x + conn.to.x) / 2} ${conn.to.y}, ${conn.to.x} ${conn.to.y}`}
                        fill="none"
                        className={`transition-colors duration-500 ${isPulsing ? 'stroke-sf-accent stroke-[3] opacity-100 drop-shadow-[0_0_5px_rgba(20,184,166,0.8)]' : 'stroke-sf-muted stroke-1 opacity-[0.15]'}`}
                      />
                    );
                  })}
                </svg>

                <div className="absolute inset-0 z-10 pointer-events-none">
                  {Object.entries(GRAPH_NODES).flatMap(([group, nodes]) => nodes.map(node => {
                    const isPulsing = pulses.some(p => p.source === node.id || p.ext === node.id || p.mod === node.id);
                    return (
                      <div
                        key={node.id}
                        className={`absolute flex flex-col items-center justify-center transform -translate-x-1/2 -translate-y-1/2 transition-all duration-300 ${isPulsing ? 'scale-110 drop-shadow-[0_0_12px_rgba(20,184,166,0.6)]' : ''}`}
                        style={{ left: `${node.x}%`, top: `${node.y}%` }}
                      >
                        <div className={`w-8 h-8 md:w-10 md:h-10 rounded border ${isPulsing ? 'border-sf-accent bg-sf-accent/20' : 'border-white/10 bg-sf-bg'} flex items-center justify-center transition-colors duration-300`}>
                          {node.icon && <node.icon className={`w-4 h-4 md:w-5 md:h-5 transition-colors duration-300 ${isPulsing ? 'text-sf-accent' : 'text-sf-muted/50'}`} />}
                        </div>
                        <span className="mt-2 text-[7px] md:text-[8px] font-medium text-sf-muted uppercase tracking-widest whitespace-nowrap bg-sf-bg/80 px-1 rounded transition-colors duration-300">
                          {node.label}
                        </span>
                      </div>
                    );
                  }))}
                </div>
              </div>
            </section>

            {/* ML Stream Cards */}
            <section className="space-y-3">
              <h4 className="text-[10px] font-bold text-sf-muted uppercase tracking-widest flex items-center gap-2">
                <Cpu className="w-4 h-4" /> ML Stream Status
              </h4>
              <div className="grid grid-cols-2 gap-x-8 gap-y-4">
                {statusLoading
                  ? Array.from({ length: 6 }).map((_, i) => <SkeletonBlock key={i} className="h-10" />)
                  : Object.entries(streams).map(([key, info]) => {
                      const Icon = STREAM_ICONS[key] ?? Activity;
                      const label = STREAM_LABELS[key] ?? key;
                      const score = (info as StreamInfo)?.score ?? 0;
                      const status = (info as StreamInfo)?.status ?? 'unknown';
                      const scoreColor = score > 0.8 ? 'text-sf-safe' : score > 0.6 ? 'text-sf-warning' : 'text-sf-critical';
                      return (
                         <div key={key} className="flex flex-col py-2 border-b border-white/5">
                           <div className="flex justify-between items-center mb-1">
                             <span className="text-[10px] text-sf-muted font-medium uppercase tracking-widest">{label}</span>
                             <span className={`text-[11px] font-mono ${scoreColor}`}>{(score * 100).toFixed(0)}%</span>
                           </div>
                           <div className="w-full h-[1px] bg-white/5 mt-1 relative">
                             <div className="absolute top-0 left-0 h-full transition-all duration-700"
                                  style={{ width: `${score * 100}%`, backgroundColor: score > 0.8 ? 'var(--sf-safe)' : score > 0.6 ? 'var(--sf-warning)' : 'var(--sf-critical)' }} />
                           </div>
                         </div>
                      );
                    })
                }
              </div>
            </section>
          </div>

          {/* Right Column: Metrics & Model Table & Neural Log */}
          <div className="flex flex-col gap-6">
            {/* Circular accuracy / confidence */}
            <section className="grid grid-cols-2 gap-4">
              <div className="flex flex-col items-center">
                <div className="flex w-full items-center justify-between mb-4">
                  <span className="text-[10px] font-medium text-sf-muted uppercase tracking-widest">Accuracy</span>
                </div>
                <div className="relative w-24 h-24 flex items-center justify-center">
                  <svg className="w-full h-full -rotate-90">
                    <circle className="text-slate-800" cx="48" cy="48" fill="transparent" r="40" stroke="currentColor" strokeWidth="2" />
                    <circle className="text-sf-accent transition-all duration-1000" cx="48" cy="48" fill="transparent" r="40" stroke="currentColor" strokeDasharray="251.2" strokeDashoffset={251.2 * (1 - avgAccuracy / 100)} strokeWidth="2" />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center mt-1">
                    <span className="text-xl font-display font-light text-white">{avgAccuracy.toFixed(1)}</span>
                    <span className="text-[8px] text-sf-muted uppercase -mt-1">%</span>
                  </div>
                </div>
              </div>

              <div className="flex flex-col items-center">
                <div className="flex w-full items-center justify-between mb-4">
                  <span className="text-[10px] font-medium text-sf-muted uppercase tracking-widest">Confidence</span>
                </div>
                <div className="relative w-24 h-24 flex items-center justify-center">
                  <svg className="w-full h-full -rotate-90">
                    <circle className="text-slate-800" cx="48" cy="48" fill="transparent" r="40" stroke="currentColor" strokeWidth="2" />
                    <circle className="text-sf-warning transition-all duration-1000" cx="48" cy="48" fill="transparent" r="40" stroke="currentColor" strokeDasharray="251.2" strokeDashoffset={251.2 * (1 - (streams.meta_learner?.score ?? 0.921))} strokeWidth="2" />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center mt-1">
                    <span className="text-xl font-display font-light text-white">{((streams.meta_learner?.score ?? 0.921) * 100).toFixed(1)}</span>
                    <span className="text-[8px] text-sf-muted uppercase -mt-1">%</span>
                  </div>
                </div>
              </div>
            </section>

            {/* Models table */}
            <section className="pt-4 border-t border-white/5">
              <h4 className="text-[10px] font-medium text-sf-muted uppercase tracking-widest mb-4 flex items-center gap-2">
                <Cpu className="w-4 h-4" /> Model Registry
              </h4>
              <div className="space-y-2.5">
                {modelsLoading
                  ? Array.from({ length: 4 }).map((_, i) => <SkeletonBlock key={i} className="h-10 rounded" />)
                  : models.map((m) => (
                      <div key={m.name} className="flex items-center justify-between gap-3 py-1.5 border-b border-sf-accent/5 last:border-0">
                        <div className="flex items-center gap-2 min-w-0">
                          <StatusDot status={m.status} />
                          <div className="min-w-0">
                            <p className="text-xs text-white font-medium truncate">{m.name}</p>
                            <p className="text-[9px] text-sf-muted font-mono">{m.version}</p>
                          </div>
                        </div>
                        <div className="text-right shrink-0">
                          {m.accuracy != null && (
                            <p className="text-xs font-bold text-sf-accent">{m.accuracy.toFixed(1)}%</p>
                          )}
                          {m.last_trained && (
                            <p className="text-[9px] text-sf-muted font-mono">{m.last_trained}</p>
                          )}
                        </div>
                      </div>
                    ))
                }
              </div>
            </section>

            {/* Neural Log Feed — Open Canvas */}
            <section className="flex-1 flex flex-col pt-4">
              <h4 className="text-[10px] font-medium text-sf-muted uppercase tracking-widest mb-4">Neural Log Feed</h4>
              <div className="font-mono text-[10px] space-y-3 text-sf-muted max-h-48 overflow-y-auto custom-scrollbar pr-2 flex-1">
                {neuralLog.map((entry, i) => (
                  <p key={i} className="flex gap-3 leading-relaxed">
                    <span className={`shrink-0 ${getLogColor(entry)}`}>{entry.timestamp}</span>
                    <span className={getLogBodyColor(entry)}>
                       {entry.message}
                    </span>
                  </p>
                ))}
              </div>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
}
