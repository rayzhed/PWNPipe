import React, { useState, useMemo } from 'react';
import { ArrowLeft, FileText, Check, Download, ChevronDown, FileCode2, List, FolderTree } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import RiskGauge from '@/components/RiskGauge.jsx';
import FindingCard from '@/components/FindingCard.jsx';
import OffensiveSummary from '@/components/OffensiveSummary.jsx';
import { calculateScore, countsBySeverity, sortFindings } from '@/utils/scoring.js';
import {
  buildMarkdownReport,
  buildSarif,
  buildCsv,
  download,
  generateSummaryCard,
  generateDetailedCard,
} from '@/utils/report-builders.js';
import { cn } from '@/lib/utils';

const SEVERITY_DOT = {
  critical: 'bg-red-600',
  high:     'bg-orange-500',
  medium:   'bg-yellow-500',
  low:      'bg-green-500',
};

const SEVERITY_BAR = {
  critical: 'bg-red-600',
  high:     'bg-orange-500',
  medium:   'bg-yellow-500',
  low:      'bg-green-500',
};

const FILTER_ACTIVE = {
  all:        'border-border/80 bg-white/5 text-foreground',
  critical:   'border-red-600/50 bg-red-600/15 text-red-500',
  high:       'border-orange-500/40 bg-orange-500/12 text-orange-400',
  medium:     'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
  low:        'border-green-500/35 bg-green-500/8 text-green-400',
  confirmed:  'border-emerald-500/40 bg-emerald-500/10 text-emerald-400',
  review:     'border-amber-500/40 bg-amber-500/10 text-amber-500',
};

const FILTERS = ['all', 'critical', 'high', 'medium', 'low'];

const SEV_PILL = {
  critical: 'bg-red-600/20 text-red-500',
  high:     'bg-orange-500/20 text-orange-400',
  medium:   'bg-yellow-500/15 text-yellow-400',
  low:      'bg-green-500/15 text-green-500',
};

const SCORE_CONFIDENCE = new Set(['CONFIRMED', 'HIGH']);
const isScoreable = f => !f.confidence || SCORE_CONFIDENCE.has(f.confidence);
const isGroupScoreable = g => isScoreable(g.findings[0]);

// Divider between confirmed and for-review sections
function SectionDivider({ label, count, variant = 'confirmed' }) {
  return (
    <div className={cn(
      'mb-3 flex items-center gap-3',
      variant === 'review' ? 'mt-6' : 'mt-1'
    )}>
      <div className={cn(
        'h-px flex-1',
        variant === 'confirmed' ? 'bg-gradient-to-r from-border to-transparent' : 'bg-border/40'
      )} />
      <span className={cn(
        'flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-widest',
        variant === 'confirmed' ? 'text-foreground/50' : 'text-muted-foreground/40'
      )}>
        {label}
        <span className={cn(
          'rounded px-1.5 py-px text-[9px]',
          variant === 'confirmed' ? 'bg-muted/50 text-muted-foreground/60' : 'bg-muted/30 text-muted-foreground/40'
        )}>
          {count}
        </span>
      </span>
      <div className="h-px w-6 bg-border/30" />
    </div>
  );
}

// File section header used in "by file" grouping mode
function FileSection({ file, fileGroups, counts }) {
  const [collapsed, setCollapsed] = useState(false);
  return (
    <div className="mb-5">
      <button
        onClick={() => setCollapsed(v => !v)}
        className="mb-2 flex w-full items-center gap-2.5 rounded-lg border border-border/50 bg-muted/20 px-4 py-2.5 text-left transition-colors hover:bg-muted/40"
      >
        <FileCode2 className="size-3.5 shrink-0 text-muted-foreground/60" />
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-foreground/80">{file}</span>
        <div className="flex shrink-0 items-center gap-1">
          {(['critical','high','medium','low']).map(s => counts[s] > 0 && (
            <span key={s} className={cn('rounded px-1.5 py-0.5 font-mono text-[10px] font-bold', SEV_PILL[s])}>
              {counts[s]}
            </span>
          ))}
        </div>
        <ChevronDown className={cn('size-3.5 shrink-0 text-muted-foreground/40 transition-transform duration-200', !collapsed && 'rotate-180')} />
      </button>
      {!collapsed && fileGroups.map(group => (
        <FindingCard
          key={`${file}-${group.rule}`}
          group={group}
          informational={!isGroupScoreable(group)}
        />
      ))}
    </div>
  );
}

function groupByRule(findingsList) {
  const ruleMap = new Map();
  const groups  = [];
  for (const f of findingsList) {
    if (!ruleMap.has(f.rule)) {
      ruleMap.set(f.rule, { rule: f.rule, severity: f.severity, title: f.title, findings: [f] });
      groups.push(ruleMap.get(f.rule));
    } else {
      ruleMap.get(f.rule).findings.push(f);
    }
  }
  return groups;
}

export default function ResultsDashboard({ result, onReset }) {
  const [filter,      setFilter]     = useState('all');
  const [fileFilter,  setFileFilter] = useState('all');
  const [confidence,  setConfidence] = useState('all'); // 'all' | 'confirmed' | 'review'
  const [groupBy,     setGroupBy]    = useState('rule'); // 'rule' | 'file'
  const [copied,      setCopied]     = useState(false);
  const [exporting,   setExporting]  = useState(false);
  const { owner, repo, findings, workflows, scannedAt, noWorkflows } = result;

  const score  = calculateScore(findings);
  const counts = countsBySeverity(findings);
  const sorted = useMemo(() => sortFindings(findings), [findings]);

  const scoreableFindings = useMemo(() => findings.filter(isScoreable),        [findings]);
  const reviewFindings    = useMemo(() => findings.filter(f => !isScoreable(f)), [findings]);

  // Severity + confidence filtered list — file filter intentionally excluded so
  // file chip counts reflect the active severity/confidence context, not the chip itself.
  const filteredBySevAndConf = useMemo(
    () => sorted.filter(f =>
      (filter === 'all' || f.severity === filter) &&
      (confidence === 'all' || (confidence === 'confirmed' ? isScoreable(f) : !isScoreable(f)))
    ),
    [sorted, filter, confidence]
  );

  // Per-file stats for the file filter chips (severity+confidence filtered, not file-filtered)
  const fileStats = useMemo(() => {
    const map = new Map();
    for (const f of filteredBySevAndConf) {
      if (!map.has(f.file)) map.set(f.file, { file: f.file, critical: 0, high: 0, medium: 0, low: 0 });
      const e = map.get(f.file);
      e[f.severity] = (e[f.severity] || 0) + 1;
    }
    const sevOrder = ['critical', 'high', 'medium', 'low'];
    return [...map.values()].sort((a, b) => {
      const aW = sevOrder.findIndex(s => a[s] > 0);
      const bW = sevOrder.findIndex(s => b[s] > 0);
      return (aW < 0 ? 99 : aW) - (bW < 0 ? 99 : bW);
    });
  }, [filteredBySevAndConf]);

  // Full filtered list (all three filters applied) used for grouping
  const filteredSorted = useMemo(
    () => filteredBySevAndConf.filter(f => fileFilter === 'all' || f.file === fileFilter),
    [filteredBySevAndConf, fileFilter]
  );

  const groups = useMemo(() => groupByRule(filteredSorted), [filteredSorted]);

  const byFile = useMemo(() => {
    if (groupBy !== 'file') return [];
    const fileMap = new Map();
    for (const f of filteredSorted) {
      if (!fileMap.has(f.file)) fileMap.set(f.file, []);
      fileMap.get(f.file).push(f);
    }
    const sevOrder = ['critical', 'high', 'medium', 'low'];
    return [...fileMap.entries()]
      .sort(([, a], [, b]) => {
        const aW = sevOrder.findIndex(s => a.some(f => f.severity === s));
        const bW = sevOrder.findIndex(s => b.some(f => f.severity === s));
        return (aW < 0 ? 99 : aW) - (bW < 0 ? 99 : bW);
      })
      .map(([file, fileFindings]) => ({
        file,
        fileGroups: groupByRule(fileFindings),
        counts:     countsBySeverity(fileFindings),
      }));
  }, [groupBy, filteredSorted]);

  return (
    <main className="mx-auto w-full max-w-3xl flex-1 px-5 py-8">
      {/* Repo header — title always visible; action buttons hidden in print */}
      <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="font-mono text-xl font-bold">
            {owner}/<span className="text-primary">{repo}</span>
          </h2>
          <p className="mt-1 font-mono text-xs text-muted-foreground">
            {workflows.length} workflow{workflows.length !== 1 ? 's' : ''} scanned
            {' · '}{findings.length} finding{findings.length !== 1 ? 's' : ''}
            {' · '}{new Date(scannedAt).toLocaleTimeString()}
          </p>
        </div>
        <div data-print-hide className="flex items-center gap-2">
          {findings.length > 0 && (
            <div className="relative">
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5"
                onClick={() => setExporting(v => !v)}
              >
                <Download className="size-3.5" />
                Export
                <ChevronDown className={cn('size-3 transition-transform', exporting && 'rotate-180')} />
              </Button>
              {exporting && (
                <div
                  className="absolute right-0 top-full z-50 mt-1 w-44 overflow-hidden rounded-lg border border-border bg-card shadow-xl"
                  onMouseLeave={() => setExporting(false)}
                >
                  {[
                    { label: 'Markdown',          ext: 'md',        action: () => { const md = buildMarkdownReport(result, groups, score); navigator.clipboard.writeText(md).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); }); setExporting(false); } },
                    { label: 'SARIF 2.1',         ext: 'sarif',     action: () => { download(`${owner}-${repo}.sarif`, JSON.stringify(buildSarif(result, groups), null, 2), 'application/json'); setExporting(false); } },
                    { label: 'JSON',              ext: 'json',      action: () => { download(`${owner}-${repo}-findings.json`, JSON.stringify({ repository: `${owner}/${repo}`, scannedAt: result.scannedAt, score, findings: result.findings }, null, 2), 'application/json'); setExporting(false); } },
                    { label: 'CSV',               ext: 'csv',       action: () => { download(`${owner}-${repo}-findings.csv`, buildCsv(groups), 'text/csv'); setExporting(false); } },
                    { label: 'Summary Card',      ext: 'png', action: () => { const c = generateSummaryCard(result, groups, score); c.toBlob(b => download(`${owner}-${repo}-security-card.png`, b, 'image/png')); setExporting(false); } },
                    { label: 'Full Report Card',  ext: 'png', action: () => { const c = generateDetailedCard(result, groups, score); c.toBlob(b => download(`${owner}-${repo}-full-report.png`, b, 'image/png')); setExporting(false); } },
                  ].map(({ label, ext, action }) => (
                    <button
                      key={label}
                      onClick={action}
                      className="flex w-full items-center justify-between px-3 py-2 text-left text-sm hover:bg-muted/60"
                    >
                      <span>{label}</span>
                      <span className="font-mono text-[10px] text-muted-foreground">.{ext}</span>
                    </button>
                  ))}
                  <div className="border-t border-border px-3 py-2">
                    <button
                      onClick={() => { window.print(); setExporting(false); }}
                      className="w-full text-left text-sm text-muted-foreground hover:text-foreground"
                    >
                      Print / Save PDF
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
          {copied && (
            <span className="flex items-center gap-1 font-mono text-xs text-green-400">
              <Check className="size-3" /> Copied!
            </span>
          )}
          <Button variant="ghost" size="sm" onClick={onReset} className="gap-1.5">
            <ArrowLeft className="size-4" />
            New scan
          </Button>
        </div>
      </div>

      {/* No workflows */}
      {noWorkflows && (
        <Card className="text-center">
          <CardContent className="py-12">
            <FileText className="mx-auto mb-4 size-10 text-muted-foreground/40" />
            <p className="mb-1 text-base font-semibold">No GitHub Actions workflows found</p>
            <p className="text-sm text-muted-foreground">
              No{' '}
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                .github/workflows/
              </code>
              {' '}directory in this repository.
            </p>
          </CardContent>
        </Card>
      )}

      {!noWorkflows && (
        <>
          {/* Score + severity breakdown — only this card is visible when printing */}
          <Card className="mb-5" data-print-show>
            <CardContent className="grid grid-cols-1 gap-6 pt-6 sm:grid-cols-[auto_1fr] sm:items-center">
              <RiskGauge score={score} />

              <div>
                <p className="mb-4 text-xs text-muted-foreground">Findings by severity</p>
                <div className="space-y-3">
                  {(['critical', 'high', 'medium', 'low']).map(sev => (
                    <div key={sev} className="flex items-center gap-3">
                      <div className={cn('size-2 shrink-0 rounded-full', SEVERITY_DOT[sev])} />
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border">
                        <div
                          className={cn('h-full rounded-full transition-all duration-700', SEVERITY_BAR[sev])}
                          style={{ width: findings.length > 0 ? `${(counts[sev] / findings.length) * 100}%` : '0%' }}
                        />
                      </div>
                      <span className={cn(
                        'w-5 text-right font-mono text-sm font-bold',
                        counts[sev] > 0 ? SEVERITY_DOT[sev].replace('bg-', 'text-') : 'text-muted-foreground'
                      )}>
                        {counts[sev]}
                      </span>
                      <span className="w-14 text-xs capitalize text-muted-foreground">{sev}</span>
                    </div>
                  ))}
                </div>
                {/* Score source breakdown */}
                {findings.length > 0 && (
                  <div className="mt-4 flex items-center gap-3 border-t border-border/40 pt-3">
                    <div className="flex items-center gap-1.5">
                      <span className="size-1.5 rounded-full bg-emerald-500/70 inline-block" />
                      <span className="font-mono text-[10px] text-muted-foreground/60">
                        {scoreableFindings.length} confirmed
                      </span>
                    </div>
                    <span className="text-border">·</span>
                    <div className="flex items-center gap-1.5">
                      <span className="size-1.5 rounded-full bg-amber-500/50 inline-block" />
                      <span className="font-mono text-[10px] text-muted-foreground/40">
                        {reviewFindings.length} for review
                      </span>
                    </div>
                    <span className="ml-auto font-mono text-[10px] text-muted-foreground/30 italic">
                      score reflects confirmed only
                    </span>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Offensive summary — visible in print */}
          <OffensiveSummary findings={findings} />

          {/* Sticky filter + navigation bar — screen only */}
          {findings.length > 0 && (
            <div data-print-hide className="sticky top-0 z-10 -mx-5 mb-4 border-b border-border/30 bg-background/95 px-5 pb-3 pt-2 backdrop-blur-sm">
              {/* Row 1: scrollable severity + confidence pills, pinned groupBy toggle */}
              <div className="flex items-center gap-2">
                {/* Horizontally scrollable pill track — never wraps */}
                <div className="relative min-w-0 flex-1 overflow-hidden">
                  <div className="flex items-center gap-2 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
                    {FILTERS.map(f => {
                      const active = filter === f;
                      const count  = f === 'all'
                        ? groups.length
                        : groups.filter(g => g.severity === f).length;
                      return (
                        <button
                          key={f}
                          onClick={() => setFilter(f)}
                          className={cn(
                            'shrink-0 whitespace-nowrap rounded-full border px-3 py-1 font-mono text-xs transition-colors',
                            active ? FILTER_ACTIVE[f] : 'border-border text-muted-foreground hover:border-border/80 hover:text-foreground'
                          )}
                        >
                          {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
                          {count > 0 && <span className="ml-1 opacity-60">({count})</span>}
                        </button>
                      );
                    })}
                    {/* Confidence filter — only when both tiers are present */}
                    {scoreableFindings.length > 0 && reviewFindings.length > 0 && (
                      <>
                        <span className="shrink-0 select-none text-sm text-border/50">·</span>
                        {(['all', 'confirmed', 'review']).map(c => (
                          <button
                            key={c}
                            onClick={() => setConfidence(c)}
                            className={cn(
                              'shrink-0 whitespace-nowrap rounded-full border px-3 py-1 font-mono text-xs transition-colors',
                              confidence === c
                                ? FILTER_ACTIVE[c] ?? FILTER_ACTIVE.all
                                : 'border-border text-muted-foreground hover:border-border/80 hover:text-foreground'
                            )}
                          >
                            {c === 'all' ? 'All' : c === 'confirmed' ? 'Confirmed' : 'For review'}
                            {c !== 'all' && (
                              <span className="ml-1 opacity-60">
                                ({c === 'confirmed' ? scoreableFindings.length : reviewFindings.length})
                              </span>
                            )}
                          </button>
                        ))}
                      </>
                    )}
                    {/* Trailing spacer so last pill isn't hidden under the fade */}
                    <span className="shrink-0 w-6" aria-hidden />
                  </div>
                  {/* Right edge fade — hints at overflow without showing scrollbar */}
                  <div className="pointer-events-none absolute inset-y-0 right-0 w-8 bg-gradient-to-l from-background/95 to-transparent" />
                </div>

                {/* Group-by toggle — always pinned to the right, never pushed off-screen */}
                <div className="shrink-0 flex items-center gap-px rounded-lg border border-border p-0.5">
                  <button
                    onClick={() => setGroupBy('rule')}
                    title="Group by rule"
                    className={cn('rounded px-2.5 py-1.5 transition-colors', groupBy === 'rule' ? 'bg-muted text-foreground' : 'text-muted-foreground hover:text-foreground')}
                  >
                    <List className="size-3.5" />
                  </button>
                  <button
                    onClick={() => setGroupBy('file')}
                    title="Group by file"
                    className={cn('rounded px-2.5 py-1.5 transition-colors', groupBy === 'file' ? 'bg-muted text-foreground' : 'text-muted-foreground hover:text-foreground')}
                  >
                    <FolderTree className="size-3.5" />
                  </button>
                </div>
              </div>

              {/* Row 2: file filter chips — single scrollable row, never wraps */}
              {fileStats.length > 1 && (
                <div className="relative mt-2">
                  <div className="flex items-center gap-1.5 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
                    <button
                      onClick={() => setFileFilter('all')}
                      className={cn(
                        'shrink-0 whitespace-nowrap rounded border px-2.5 py-0.5 font-mono text-[11px] transition-colors',
                        fileFilter === 'all' ? 'border-border/80 bg-white/5 text-foreground' : 'border-border/40 text-muted-foreground hover:text-foreground'
                      )}
                    >
                      All files
                    </button>
                    {fileStats.map(fs => {
                      const active = fileFilter === fs.file;
                      const short  = fs.file.split('/').pop();
                      const worst  = ['critical','high','medium','low'].find(s => fs[s] > 0) ?? 'low';
                      return (
                        <button
                          key={fs.file}
                          onClick={() => { setFileFilter(fs.file); setGroupBy('rule'); }}
                          title={fs.file}
                          className={cn(
                            'shrink-0 flex items-center gap-1.5 whitespace-nowrap rounded border px-2.5 py-0.5 font-mono text-[11px] transition-colors',
                            active ? FILTER_ACTIVE[worst] : 'border-border/40 text-muted-foreground hover:text-foreground'
                          )}
                        >
                          <FileCode2 className="size-3 shrink-0 opacity-70" />
                          {short}
                          <span className="opacity-60">
                            {fs.critical > 0 && <span className="text-red-500">{fs.critical}</span>}
                            {fs.high     > 0 && <span className="text-orange-400">{fs.high}</span>}
                          </span>
                        </button>
                      );
                    })}
                    {/* Trailing spacer so last chip clears the fade */}
                    <span className="shrink-0 w-6" aria-hidden />
                  </div>
                  {/* Right edge fade */}
                  <div className="pointer-events-none absolute inset-y-0 right-0 w-8 bg-gradient-to-l from-background/95 to-transparent" />
                </div>
              )}
            </div>
          )}

          {/* Findings — screen: filtered/animated; hidden in print */}
          <div data-print-hide>
            {findings.length === 0 ? (
              <Card className="text-center">
                <CardContent className="py-12">
                  <div className="mx-auto mb-4 text-4xl">✅</div>
                  <p className="mb-1 text-base font-semibold">Nothing found</p>
                  <p className="text-sm text-muted-foreground">
                    This tool misses things. Still worth checking by hand.
                  </p>
                </CardContent>
              </Card>
            ) : (
              <div className="animate-fade-in">
                {groupBy === 'file'
                  ? byFile.length > 0
                    ? byFile.map(({ file, fileGroups, counts: fc }) => (
                        <FileSection key={file} file={file} fileGroups={fileGroups} counts={fc} />
                      ))
                    : <p className="py-6 text-center font-mono text-xs text-muted-foreground">No findings match the current filter.</p>
                  : (() => {
                      if (groups.length === 0) return (
                        <p className="py-6 text-center font-mono text-xs text-muted-foreground">
                          No findings match the current filter.
                        </p>
                      );
                      const confirmedGroups = groups.filter(isGroupScoreable);
                      const reviewGroups    = groups.filter(g => !isGroupScoreable(g));
                      const hasBoth = confirmedGroups.length > 0 && reviewGroups.length > 0;
                      return (
                        <>
                          {hasBoth && (
                            <SectionDivider label="Confirmed Risk" count={confirmedGroups.length} variant="confirmed" />
                          )}
                          {confirmedGroups.map(group => (
                            <FindingCard key={group.rule} group={group} />
                          ))}
                          {hasBoth && (
                            <SectionDivider label="For Review" count={reviewGroups.length} variant="review" />
                          )}
                          {reviewGroups.map(group => (
                            <FindingCard key={group.rule} group={group} informational />
                          ))}
                        </>
                      );
                    })()
                }
              </div>
            )}
          </div>

          {/* Findings — print: all groups, fully expanded via CSS */}
          <div data-print-only>
            {groups.map(group => (
              <FindingCard key={`print-${group.rule}`} group={group} />
            ))}
          </div>

          {/* Footer */}
          <div data-print-hide>
            <Separator className="my-6" />
            <p className="text-center text-xs text-muted-foreground/50">
              Only scan repos you own or have permission to test.
            </p>
          </div>
        </>
      )}
    </main>
  );
}
