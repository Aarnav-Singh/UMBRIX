"use client";

import React, { useState } from "react";
import { Copy, Check } from "lucide-react";

interface SyntaxHighlightedJsonProps {
 data: unknown;
 className?: string;
}

function JsonNode({ value, depth = 0 }: { value: unknown; depth?: number }) {
 const [collapsed, setCollapsed] = useState(depth > 2);

 if (value === null) return <span className="text-ng-muted">null</span>;
 if (typeof value === "boolean")
 return <span className={value ? "text-ng-lime" : "text-ng-error"}>{String(value)}</span>;
 if (typeof value === "number") return <span className="text-ng-magenta">{value}</span>;
 if (typeof value === "string") return <span className="text-ng-lime">&quot;{value}&quot;</span>;

 if (Array.isArray(value)) {
 if (value.length === 0) return <span className="text-ng-muted">[]</span>;
 return (
 <span>
 <button onClick={() => setCollapsed(c => !c)} className="text-ng-muted hover:text-ng-on">
 {collapsed ? "▶ " : "▼ "}
 </button>
 {collapsed ? (
 <span className="text-ng-muted">[{value.length} items]</span>
 ) : (
 <>
 {"["}
 <div className="ml-4">
 {value.map((v, i) => (
 <div key={i}><JsonNode value={v} depth={depth + 1} />{i < value.length - 1 ? ",\u0020" : null}</div>
 ))}
 </div>
 {"]"}
 </>
 )}
 </span>
 );
 }

 if (typeof value === "object") {
 const keys = Object.keys(value as object);
 if (keys.length === 0) return <span className="text-ng-muted">{"{}"}</span>;
 return (
 <span>
 <button onClick={() => setCollapsed(c => !c)} className="text-ng-muted hover:text-ng-on">
 {collapsed ? "▶ " : "▼ "}
 </button>
 {collapsed ? (
 <span className="text-ng-muted">{"{"}{keys.length} keys{"}"}</span>
 ) : (
 <>
 {"{"}
 <div className="ml-4">
 {keys.map((k, i) => (
 <div key={k}>
 <span className="text-ng-cyan">&quot;{k}&quot;</span>
 <span className="text-ng-muted">: </span>
 <JsonNode value={(value as any)[k]} depth={depth + 1} />
 {i < keys.length - 1 ? ",\u0020" : null}
 </div>
 ))}
 </div>
 {"}"}
 </>
 )}
 </span>
 );
 }

 return <span className="text-ng-on">{String(value)}</span>;
}

export function SyntaxHighlightedJson({ data, className = "" }: SyntaxHighlightedJsonProps) {
 const [copied, setCopied] = useState(false);

 function copy() {
 navigator.clipboard.writeText(JSON.stringify(data, null, 2));
 setCopied(true);
 setTimeout(() => setCopied(false), 1500);
 }

 return (
 <div className={`relative group ${className}`}>
 <button
 onClick={copy}
 className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity text-ng-muted hover:text-ng-on"
 >
 {copied ? <Check className="w-3.5 h-3.5 text-ng-lime" /> : <Copy className="w-3.5 h-3.5" />}
 </button>
 <pre className="text-[11px] font-mono leading-5 whitespace-pre-wrap break-all p-3 bg-ng-base border border-ng-outline-dim/40 overflow-auto">
 <JsonNode value={data} />
 </pre>
 </div>
 );
}
