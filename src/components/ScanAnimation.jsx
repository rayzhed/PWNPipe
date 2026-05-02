import React from 'react';
import { Check, Loader2 } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { cn } from '@/lib/utils';

const SCAN_STEPS = [
  'Connecting to GitHub API',
  'Fetching workflow files',
  'Parsing YAML',
  'Checking dangerous triggers',
  'Detecting template injections',
  'Verifying action pinning',
  'Auditing GITHUB_TOKEN permissions',
  'Running additional checks',
  'Calculating risk score',
];

export default function ScanAnimation({ currentStep, owner, repo }) {
  return (
    <main className="flex flex-1 items-center justify-center px-6 py-16">
      <Card className="w-full max-w-md overflow-hidden">
        {/* Terminal chrome */}
        <div className="flex items-center gap-1.5 border-b border-border bg-muted/30 px-4 py-3">
          <div className="size-2.5 rounded-full bg-red-500/80" />
          <div className="size-2.5 rounded-full bg-yellow-500/80" />
          <div className="size-2.5 rounded-full bg-green-500/80" />
          <span className="ml-3 font-mono text-xs text-muted-foreground">
            pwnpipe scan {owner}/{repo}
          </span>
        </div>

        {/* Steps */}
        <div className="space-y-0.5 p-5">
          {SCAN_STEPS.map((label, idx) => {
            const done    = idx < currentStep;
            const active  = idx === currentStep;
            const pending = idx > currentStep;

            return (
              <div
                key={label}
                className={cn(
                  'flex items-center gap-3 rounded px-2 py-1.5 transition-opacity duration-300',
                  pending && 'opacity-30'
                )}
              >
                {/* Icon */}
                <div className="flex w-5 shrink-0 justify-center">
                  {done   && <Check className="size-4 text-green-500" />}
                  {active && <Loader2 className="size-4 animate-spin text-primary" />}
                  {pending && <span className="font-mono text-xs text-muted-foreground">·</span>}
                </div>

                <span className={cn(
                  'font-mono text-sm',
                  done    && 'text-green-500/80',
                  active  && 'text-foreground',
                  pending && 'text-muted-foreground',
                )}>
                  {label}
                  {done && (
                    <span className="ml-2 text-[10px] text-green-500/50">done</span>
                  )}
                </span>
              </div>
            );
          })}
        </div>
      </Card>
    </main>
  );
}
