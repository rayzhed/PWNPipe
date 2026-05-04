import React from 'react';
import { Loader2, ShieldAlert } from 'lucide-react';
import { cn } from '@/lib/utils';

export default function BatchScanProgress({ progress }) {
  const { current, total, currentRepo, scanStep, scanLabel } = progress;
  const pct = total > 0 ? Math.round((current / total) * 100) : 0;
  const done = current > (scanStep != null ? 0 : 0);

  return (
    <main className="flex flex-1 flex-col items-center justify-center gap-6 px-6">
      <ShieldAlert className="size-10 text-primary animate-pulse" />

      <div className="text-center">
        <p className="font-mono text-xs text-muted-foreground mb-1">
          Scanning repository {current} of {total}
        </p>
        <p className="font-semibold text-base">
          {currentRepo ?? '…'}
        </p>
        {scanLabel && (
          <p className="mt-1 font-mono text-xs text-muted-foreground/70">{scanLabel}</p>
        )}
      </div>

      {/* Overall progress bar */}
      <div className="w-full max-w-sm">
        <div className="mb-1.5 flex justify-between font-mono text-[11px] text-muted-foreground/60">
          <span>Overall progress</span>
          <span>{pct}%</span>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-border">
          <div
            className="h-full rounded-full bg-primary transition-all duration-500"
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      {/* Completed list */}
      {done > 0 && (
        <p className="font-mono text-xs text-muted-foreground/50">
          {current - 1} repo{current > 2 ? 's' : ''} completed
        </p>
      )}
    </main>
  );
}
