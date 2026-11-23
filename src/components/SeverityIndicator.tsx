import { useEffect, useState } from 'react';
import { AlertOctagon, AlertTriangle, CheckCircle2, Info, ShieldAlert } from 'lucide-react';
import type { RemediationStatus, ScanStatus, SeverityLevel } from '../types';

export function AnimatedNumber({ value, suffix = '' }: { value: number; suffix?: string }) {
  const [display, setDisplay] = useState(value);

  useEffect(() => {
    const prefersReduced =
      typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReduced) {
      setDisplay(value);
      return;
    }

    const startVal = display;
    const diff = value - startVal;
    if (diff === 0) return;

    const duration = 380;
    const startTime = performance.now();
    let frameId = 0;

    const step = (now: number) => {
      const progress = Math.min(1, (now - startTime) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(startVal + diff * eased));
      if (progress < 1) {
        frameId = requestAnimationFrame(step);
      }
    };

    frameId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameId);
  }, [value]);

  return (
    <span className="tabular-nums font-mono">
      {display}
      {suffix}
    </span>
  );
}

export function SeverityText({ severity }: { severity: SeverityLevel }) {
  if (severity === 'Critical') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-rose-400 whitespace-nowrap">
        <AlertOctagon className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
        Critical
      </span>
    );
  }
  if (severity === 'High') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-orange-400 whitespace-nowrap">
        <ShieldAlert className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
        High
      </span>
    );
  }
  if (severity === 'Medium') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-400 whitespace-nowrap">
        <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
        Medium
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 whitespace-nowrap">
      <Info className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
      Low
    </span>
  );
}

export function RemediationText({ status }: { status: RemediationStatus }) {
  if (status === 'Resolved') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400 whitespace-nowrap">
        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
        Resolved
      </span>
    );
  }
  if (status === 'In Progress') {
    return <span className="text-xs font-medium text-cyan-300 whitespace-nowrap">In Progress</span>;
  }
  if (status === 'Accepted Risk') {
    return <span className="text-xs font-medium text-slate-400 whitespace-nowrap">Accepted Risk</span>;
  }
  return <span className="text-xs font-medium text-rose-300 whitespace-nowrap">Open</span>;
}

export function ScanStatusText({ status }: { status: ScanStatus }) {
  if (status === 'running') {
    return (
      <span className="inline-flex items-center gap-2 text-xs font-medium text-cyan-300 whitespace-nowrap">
        <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" aria-hidden="true" />
        Scanning
      </span>
    );
  }
  if (status === 'completed') {
    return <span className="text-xs font-medium text-emerald-400 whitespace-nowrap">Completed</span>;
  }
  if (status === 'stopped') {
    return <span className="text-xs font-medium text-amber-400 whitespace-nowrap">Stopped</span>;
  }
  if (status === 'failed') {
    return <span className="text-xs font-medium text-rose-400 whitespace-nowrap">Failed</span>;
  }
  return <span className="text-xs font-medium text-slate-400 whitespace-nowrap">Queued</span>;
}

export function scoreColorClass(score: number | null | undefined): string {
  if (score === null || score === undefined) return 'text-slate-400';
  if (score >= 80) return 'text-emerald-400';
  if (score >= 60) return 'text-amber-400';
  return 'text-rose-400';
}
