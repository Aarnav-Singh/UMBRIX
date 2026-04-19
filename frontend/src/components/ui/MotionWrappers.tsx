"use client";

import React, { useRef, useEffect } from "react";
import { motion, useInView } from "framer-motion";

const tacticalEase = [0.2, 0.8, 0.2, 1];

interface MotionProps {
  children: React.ReactNode;
  className?: string;
  delay?: number;
  [key: string]: any;
}

export function FadeIn({ children, className = "", delay = 0, ...props }: MotionProps) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4, delay, ease: tacticalEase }}
      className={className}
      {...props}
    >
      {children}
    </motion.div>
  );
}

export function SlideIn({ children, className = "", delay = 0, direction = "up", ...props }: MotionProps & { direction?: "up" | "down" | "left" | "right" }) {
  const offset = {
    up: { y: 20 },
    down: { y: -20 },
    left: { x: 20 },
    right: { x: -20 },
  }[direction];

  return (
    <motion.div
      initial={{ opacity: 0, ...offset }}
      animate={{ opacity: 1, x: 0, y: 0 }}
      transition={{ duration: 0.5, delay, ease: tacticalEase }}
      className={className}
      {...props}
    >
      {children}
    </motion.div>
  );
}

export function ShimmerSkeleton({ className = "", ...props }: { className?: string; [key: string]: any }) {
  return (
    <div className={`sf-shimmer ${className}`} {...props}>
      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/5 to-transparent -translate-x-full animate-[shimmer_2s_infinite]" />
    </div>
  );
}

// Replaced GlassCard with PanelCard
interface PanelCardProps {
  children: React.ReactNode;
  className?: string;
  delay?: number;
  [key: string]: any;
}

export function PanelCard({ children, className = "", delay = 0, ...props }: PanelCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.2, delay, ease: tacticalEase }}
      className={`ng-surface ${className}`}
      {...props}
    >
      {children}
    </motion.div>
  );
}

// Fallback for any component still using GlassCard
export const GlassCard = PanelCard;

interface AnimatedNumberProps {
  value: number;
  duration?: number;
  className?: string;
  format?: (n: number) => string;
}

export function AnimatedNumber({ value, duration = 0.5, className = "", format }: AnimatedNumberProps) {
  const ref = useRef<HTMLSpanElement>(null);
  const prevValue = useRef(0);
  const isInView = useInView(ref, { once: true });

  useEffect(() => {
    if (!isInView || !ref.current) return;

    const startValue = prevValue.current;
    const endValue = value;
    const startTime = performance.now();
    const durationMs = duration * 1000;

    function tick(currentTime: number) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / durationMs, 1);
      
      const eased = 1 - Math.pow(1 - progress, 3);
      const currentVal = Math.round(startValue + (endValue - startValue) * eased);

      if (ref.current) {
        ref.current.innerText = format ? format(currentVal) : currentVal.toLocaleString();
      }

      if (progress < 1) {
        requestAnimationFrame(tick);
      } else {
        prevValue.current = value;
      }
    }

    requestAnimationFrame(tick);
  }, [value, duration, isInView, format]);

  return <span ref={ref} className={className}>{prevValue.current}</span>;
}
