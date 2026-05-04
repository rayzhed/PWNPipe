import React, { useState, useMemo } from 'react';
import { ArrowLeft, ArrowUpDown, Shield, ShieldAlert, AlertTriangle, CheckCircle2, XCircle, ChevronRight, Download } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { calculateScore, countsBySeverity, scoreLabel } from '@/utils/scoring.js';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function severityColor(sev) {
  if (sev === 'critical') return 'text-red-400';
  if (sev === 'high')     return 'text-orange-400';
  if (sev === 'medium')   return 'text-yellow-400';
  return 'text-muted-foreground';
}

function scoreColor(s) {
  if (s >= 9.0) return 'text-red-400';
  if (s >= 7.0) return 'text-orange-400';
  if (s >= 4.0) return 'text-yellow-400';
  if (s >  0)   return 'text-blue-400';
  return 'text-emerald-400';
}

function exportCSV(rows) {
  const header = 'Repository,Score,Label,Critical,High,Medium,Low,Total,Status\n';
  const lines = rows.map(r =>
    `"${r.owner}/${r.repo}",${r.score.toFixed(1)},"${r.label}",${r.counts.critical},${r.counts.high},${r.counts.medium},${r.counts.low},${r.findings},${r.status}`
  );
  const blob = new Blob([header + lines.join('\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `pwnpipe-batch-${Date.now()}.csv`;
  a.click();
}

export default function BatchResults({ results, onReset, onViewRepo }) {
  const [sortKey, setSortKey] = useState('score');
  const [sortDir, setSortDir] = useState('desc');

  const rows = useMemo(() => results.map(r => {
    const findings = r.findings ?? [];
    const score = r.status === 'error' ? 0 : calculateScore(findings);
    const counts = countsBySeverity(findings);
    const label = scoreLabel(score);
    return { ...r, score, counts, label, findings: findings.length };
  }), [results]);

  const sorted = useMemo(() => {
    return [...rows].sort((a, b) => {
      let va, vb;
      if (sortKey === 'score')    { va = a.score; vb = b.score; }
      else if (sortKey === 'name') { va = `${a.owner}/${a.repo}`; vb = `${b.owner}/${b.repo}`; }
      else                        { va = a.counts[sortKey]; vb = b.counts[sortKey]; }
      if (va < vb) return sortDir === 'asc' ? -1 : 1;
      if (va > vb) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
  }, [rows, sortKey, sortDir]);

  function toggleSort(key) {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('desc'); }
  }

  const totals = useMemo(() => rows.reduce((acc, r) => {
    acc.critical += r.counts.critical;
    acc.high     += r.counts.high;
    acc.medium   += r.counts.medium;
    acc.low      += r.counts.low;
    acc.total    += r.findings;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0, total: 0 }), [rows]);

  const errorCount = rows.filter(r => r.status === 'error').length;
  const riskiest = rows.filter(r => r.score >= 7).length;

  function SortHeader({ col, label, className }) {
    const active = sortKey === col;
    return (
      <button
        onClick={() => toggleSort(col)}
        className={cn('flex items-center gap-1 font-mono text-[11px] text-muted-foreground/70 hover:text-foreground transition-colors', className)}
      >
        {label}
        <ArrowUpDown className={cn('size-3', active && 'text-primary')} />
      </button>
    );
  }

  return (
    <main className="flex flex-1 flex-col px-4 py-8 max-w-5xl mx-auto w-full">
      {/* Header */}
      <div className="mb-6 flex items-start justify-between gap-4">
        <div>
          <Button variant="ghost" size="sm" onClick={onReset} className="mb-3 -ml-2 gap-2 font-mono text-xs text-muted-foreground">
            <ArrowLeft className="size-3.5" />
            New scan
          </Button>
          <h1 className="text-xl font-bold">Batch Scan Results</h1>
          <p className="mt-1 font-mono text-xs text-muted-foreground">
            {rows.length} repositories scanned
            {errorCount > 0 && ` · ${errorCount} failed`}
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => exportCSV(rows)}
          className="gap-2 font-mono text-xs shrink-0"
        >
          <Download className="size-3.5" />
          Export CSV
        </Button>
      </div>

      {/* Summary cards */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          { label: 'Critical', count: totals.critical, color: 'text-red-400', bg: 'bg-red-950/20 border-red-800/30' },
          { label: 'High',     count: totals.high,     color: 'text-orange-400', bg: 'bg-orange-950/20 border-orange-800/30' },
          { label: 'Medium',   count: totals.medium,   color: 'text-yellow-400', bg: 'bg-yellow-950/20 border-yellow-800/30' },
          { label: 'Low',      count: totals.low,      color: 'text-blue-400',  bg: 'bg-blue-950/10 border-blue-800/20' },
        ].map(({ label, count, color, bg }) => (
          <div key={label} className={cn('rounded-lg border p-4', bg)}>
            <p className={cn('text-2xl font-bold', color)}>{count}</p>
            <p className="mt-0.5 font-mono text-xs text-muted-foreground">{label}</p>
          </div>
        ))}
      </div>

      {/* Exposure summary */}
      {riskiest > 0 && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-red-800/30 bg-red-950/10 px-4 py-3">
          <ShieldAlert className="size-4 shrink-0 text-red-400" />
          <p className="font-mono text-xs text-red-300">
            {riskiest} repo{riskiest > 1 ? 's' : ''} with risk score ≥ 7.0 — high or critical exposure
          </p>
        </div>
      )}

      {/* Table */}
      <div className="overflow-hidden rounded-lg border border-border bg-card/30">
        {/* Table header */}
        <div className="grid grid-cols-[1fr_auto_auto_auto_auto_auto_auto] items-center gap-4 border-b border-border bg-card/60 px-4 py-2.5">
          <SortHeader col="name"     label="Repository" />
          <SortHeader col="score"    label="Score" className="w-14 justify-end" />
          <SortHeader col="critical" label="Crit" className="w-10 justify-end" />
          <SortHeader col="high"     label="High" className="w-10 justify-end" />
          <SortHeader col="medium"   label="Med"  className="w-10 justify-end" />
          <SortHeader col="low"      label="Low"  className="w-10 justify-end" />
          <div className="w-6" />
        </div>

        {/* Rows */}
        <div className="divide-y divide-border/50">
          {sorted.map((row) => (
            <button
              key={`${row.owner}/${row.repo}`}
              onClick={() => row.status !== 'error' && onViewRepo(row)}
              disabled={row.status === 'error'}
              className={cn(
                'grid w-full grid-cols-[1fr_auto_auto_auto_auto_auto_auto] items-center gap-4 px-4 py-3 text-left transition-colors',
                row.status === 'error'
                  ? 'cursor-not-allowed opacity-50'
                  : 'hover:bg-card/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary'
              )}
            >
              {/* Repo name */}
              <div className="flex items-center gap-2 min-w-0">
                {row.status === 'error'
                  ? <XCircle className="size-3.5 shrink-0 text-red-500" />
                  : row.score === 0
                  ? <CheckCircle2 className="size-3.5 shrink-0 text-emerald-500" />
                  : row.score >= 7
                  ? <ShieldAlert className="size-3.5 shrink-0 text-red-400" />
                  : <Shield className="size-3.5 shrink-0 text-muted-foreground/50" />
                }
                <span className="truncate font-mono text-sm">
                  <span className="text-muted-foreground/60">{row.owner}/</span>
                  <span className="font-semibold">{row.repo}</span>
                </span>
                {row.status === 'error' && (
                  <span className="shrink-0 font-mono text-[10px] text-red-400">scan failed</span>
                )}
              </div>

              {/* Score */}
              <div className={cn('w-14 text-right font-mono text-sm font-bold', scoreColor(row.score))}>
                {row.status === 'error' ? '—' : row.score.toFixed(1)}
              </div>

              {/* Severity counts */}
              {['critical', 'high', 'medium', 'low'].map(sev => (
                <div
                  key={sev}
                  className={cn(
                    'w-10 text-right font-mono text-sm',
                    row.counts[sev] > 0 ? severityColor(sev) : 'text-muted-foreground/30'
                  )}
                >
                  {row.counts[sev] > 0 ? row.counts[sev] : '—'}
                </div>
              ))}

              <ChevronRight className={cn('size-3.5 text-muted-foreground/30', row.status !== 'error' && 'group-hover:text-primary')} />
            </button>
          ))}
        </div>
      </div>

      <p className="mt-4 font-mono text-xs text-muted-foreground/40 text-center">
        {totals.total} total findings across {rows.length} repositories
      </p>
    </main>
  );
}
