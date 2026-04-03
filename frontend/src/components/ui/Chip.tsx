"use client";

interface ChipProps {
    label: string;
    color?: string;
    variant?: "outlined" | "filled";
    className?: string;
}

export function Chip({ label, color = "var(--sf-bg)", variant = "outlined", className = "" }: ChipProps) {
    return (
        <span
            className={`inline-flex items-center text-[10px] font-mono tracking-wider leading-none px-1.5 py-0.5 rounded-sm ${className}`}
            style={{
                color,
                border: `1px solid ${color}40`,
                background: variant === "filled" ? `${color}20` : `${color}12`,
            }}
        >
            {label}
        </span>
    );
}
