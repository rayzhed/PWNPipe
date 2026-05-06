import React, { useState } from 'react';
import { ChevronDown, MapPin, Info } from 'lucide-react';
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from '@/components/ui/collapsible';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { cvssScore } from '@/utils/scoring.js';

// --- Style maps -----------------------------------------------------------

const SEVERITY = {
  critical: {
    badge:        'critical',
    border:       'border-red-600/40',
    headerBg:     'bg-red-600/8',
    exploitBg:    'bg-red-600/7 border-l-red-600',
    exploitLabel: 'text-red-500',
    impactBorder: 'border-red-600/50 bg-red-600/15 text-red-500',
    occBg:        'border-red-600/20 bg-red-600/5 hover:bg-red-600/10',
  },
  high: {
    badge:        'high',
    border:       'border-orange-500/40',
    headerBg:     'bg-orange-500/8',
    exploitBg:    'bg-orange-500/7 border-l-orange-500',
    exploitLabel: 'text-orange-400',
    impactBorder: 'border-orange-500/40 bg-orange-500/12 text-orange-400',
    occBg:        'border-orange-500/20 bg-orange-500/5 hover:bg-orange-500/10',
  },
  medium: {
    badge:        'medium',
    border:       'border-yellow-500/35',
    headerBg:     'bg-yellow-500/5',
    exploitBg:    'bg-yellow-500/5 border-l-yellow-500',
    exploitLabel: 'text-yellow-400',
    impactBorder: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
    occBg:        'border-yellow-500/20 bg-yellow-500/5 hover:bg-yellow-500/10',
  },
  low: {
    badge:        'low',
    border:       'border-green-500/30',
    headerBg:     'bg-green-500/5',
    exploitBg:    'bg-green-500/5 border-l-green-500',
    exploitLabel: 'text-green-400',
    impactBorder: 'border-green-500/35 bg-green-500/8 text-green-400',
    occBg:        'border-green-500/20 bg-green-500/5 hover:bg-green-500/10',
  },
};

const CONFIDENCE_STYLE = {
  CONFIRMED: 'border-emerald-500/50 bg-emerald-500/10 text-emerald-400',
  HIGH:      'border-blue-500/40    bg-blue-500/10    text-blue-400',
  MEDIUM:    'border-amber-500/40   bg-amber-500/10   text-amber-500',
  LOW:       'border-gray-500/30    bg-gray-500/8     text-gray-400',
};

const OWASP_URL = {
  'CICD-SEC-1':  'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-01-Insufficient-Flow-Control-Mechanisms',
  'CICD-SEC-2':  'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-And-Access-Management',
  'CICD-SEC-3':  'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse',
  'CICD-SEC-4':  'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution',
  'CICD-SEC-5':  'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-05-Insufficient-PBAC',
  'CICD-SEC-6':  'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene',
  'CICD-SEC-7':  'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-07-Insecure-System-Configuration',
  'CICD-SEC-8':  'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-08-Ungoverned-Usage-Of-3rd-Party-Services',
  'CICD-SEC-9':  'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation',
  'CICD-SEC-10': 'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10-Insufficient-Logging-And-Visibility',
};

function cvssChipStyle(score) {
  if (score >= 9.0) return 'text-red-500 border-red-600/50 bg-red-600/15';
  if (score >= 7.0) return 'text-orange-400 border-orange-500/40 bg-orange-500/12';
  if (score >= 4.0) return 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10';
  return 'text-green-400 border-green-500/35 bg-green-500/8';
}

// --- Sub-components -------------------------------------------------------

function CodeSnippet({ snippet }) {
  if (!snippet?.length) return null;
  return (
    <div className="overflow-hidden rounded border border-border bg-[#080808] font-mono text-xs">
      {snippet.map(({ line, content, highlight }) => (
        <div
          key={line}
          className={cn(
            'flex border-l-2',
            highlight ? 'border-l-red-600 bg-red-600/10' : 'border-l-transparent'
          )}
        >
          <span className="w-10 shrink-0 select-none px-2 py-0.5 text-right text-muted-foreground/50">
            {line}
          </span>
          <span className={cn(
            'flex-1 py-0.5 pr-3 whitespace-pre',
            highlight ? 'text-foreground' : 'text-muted-foreground/70'
          )}>
            {content}
          </span>
        </div>
      ))}
    </div>
  );
}

function ReferenceBadges({ rep }) {
  const hasRefs = rep.confidence || rep.owasp || rep.cvss?.cwe || rep.cvss?.cve?.length || rep.cvss?.vector;
  if (!hasRefs) return null;

  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap items-center gap-1.5">
        {rep.confidence && (
          <span className={cn(
            'rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider',
            CONFIDENCE_STYLE[rep.confidence] ?? CONFIDENCE_STYLE.MEDIUM
          )}>
            {rep.confidence}
          </span>
        )}
        {rep.owasp && (
          <a
            href={OWASP_URL[rep.owasp] ?? '#'}
            target="_blank"
            rel="noreferrer"
            title={`OWASP CI/CD Security Top 10: ${rep.owasp}`}
            className="rounded border border-violet-500/35 bg-violet-500/10 px-2 py-0.5 font-mono text-[10px] text-violet-400 transition-colors hover:bg-violet-500/20"
          >
            {rep.owasp}
          </a>
        )}
        {rep.cvss?.cwe && (
          <a
            href={`https://cwe.mitre.org/data/definitions/${rep.cvss.cwe.replace('CWE-', '')}.html`}
            target="_blank"
            rel="noreferrer"
            className="rounded border border-border bg-muted/40 px-2 py-0.5 font-mono text-[10px] text-muted-foreground transition-colors hover:text-foreground"
          >
            {rep.cvss.cwe}
          </a>
        )}
        {rep.cvss?.cve?.map(id => (
          <a
            key={id}
            href={`https://nvd.nist.gov/vuln/detail/${id}`}
            target="_blank"
            rel="noreferrer"
            className="rounded border border-blue-500/30 bg-blue-500/10 px-2 py-0.5 font-mono text-[10px] text-blue-400 transition-colors hover:bg-blue-500/20"
          >
            {id}
          </a>
        ))}
      </div>
      {rep.cvss?.vector && (
        <p className="select-all font-mono text-[10px] text-muted-foreground/40">
          {rep.cvss.vector}
        </p>
      )}
    </div>
  );
}

function OccurrenceRow({ finding, s }) {
  const [open, setOpen] = useState(false);
  const hasSnippet = finding.snippet?.length > 0;

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger asChild>
        <button className={cn(
          'flex w-full items-start gap-2 rounded-md border px-3 py-2 text-left transition-colors',
          s.occBg
        )}>
          <MapPin className="mt-0.5 size-3 shrink-0 text-muted-foreground/60" />
          <div className="min-w-0 flex-1">
            {finding.title && (
              <p className="truncate font-mono text-[11px] text-foreground/80">{finding.title}</p>
            )}
            <p className="truncate font-mono text-[11px] text-muted-foreground/70">
              {finding.file}{finding.line ? `:${finding.line}` : ''}
              {finding.context ? <span className="ml-2 opacity-60">· {finding.context}</span> : null}
            </p>
          </div>
          {hasSnippet && (
            <ChevronDown className={cn(
              'mt-0.5 size-3 shrink-0 text-muted-foreground/50 transition-transform duration-150',
              open && 'rotate-180'
            )} />
          )}
        </button>
      </CollapsibleTrigger>

      {hasSnippet && (
        <CollapsibleContent className="overflow-hidden data-[state=open]:animate-collapsible-down data-[state=closed]:animate-collapsible-up">
          <div className="mt-1 ml-5">
            <CodeSnippet snippet={finding.snippet} />
          </div>
        </CollapsibleContent>
      )}
    </Collapsible>
  );
}

// --- Main card ------------------------------------------------------------

// informational=true → MEDIUM/LOW confidence: doesn't affect score.
// Visual treatment is muted to communicate lower urgency without hiding the finding.
export default function FindingCard({ group, informational = false }) {
  const rep   = group.findings[0];
  const rest  = group.findings.slice(1);
  const s     = SEVERITY[group.severity] ?? SEVERITY.low;
  const count = group.findings.length;
  const score = rep.cvss?.score ?? cvssScore(group.severity);

  const [open, setOpen] = useState(false);

  return (
    <Collapsible open={open} onOpenChange={setOpen} className="mb-2">
      <div className={cn(
        'rounded-lg border bg-card transition-colors',
        informational
          ? open ? 'border-border/60' : 'border-border/40'
          : open ? s.border : 'border-border/60'
      )}>

        {/* Header */}
        <CollapsibleTrigger asChild>
          <button className={cn(
            'flex w-full items-start gap-3 rounded-t-lg p-4 text-left transition-colors',
            informational
              ? open ? 'bg-muted/20' : 'hover:bg-muted/20'
              : open ? s.headerBg : 'hover:bg-muted/30'
          )}>
            <Badge
              variant={s.badge}
              className={cn('mt-0.5 shrink-0 uppercase', informational && 'opacity-60')}
            >
              {group.severity}
            </Badge>

            <div className="min-w-0 flex-1">
              <p className={cn(
                'text-sm font-semibold leading-snug',
                informational ? 'text-foreground/70' : 'text-foreground'
              )}>
                {group.title}
              </p>
              <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5">
                <span className="font-mono text-[11px] text-muted-foreground/60">
                  {count > 1
                    ? `${count} occurrences · ${rep.file}${rep.line ? `:${rep.line}` : ''}`
                    : `${rep.file}${rep.line ? `:${rep.line}` : ''}`
                  }
                </span>
                {rep.owasp && (
                  <span className="font-mono text-[10px] text-violet-400/60">{rep.owasp}</span>
                )}
                {/* Confidence badge — always visible in header */}
                {rep.confidence && (
                  <span className={cn(
                    'rounded border px-1.5 py-px font-mono text-[9px] font-semibold uppercase tracking-wide',
                    CONFIDENCE_STYLE[rep.confidence] ?? CONFIDENCE_STYLE.MEDIUM
                  )}>
                    {rep.confidence}
                  </span>
                )}
              </div>
            </div>

            <span className={cn(
              'shrink-0 rounded border px-2 py-0.5 font-mono text-[11px] font-bold',
              informational ? 'border-border/40 text-muted-foreground/50 bg-transparent' : cvssChipStyle(score)
            )}>
              {score.toFixed(1)}
            </span>

            <ChevronDown className={cn(
              'mt-0.5 size-4 shrink-0 text-muted-foreground/40 transition-transform duration-200',
              open && 'rotate-180'
            )} />
          </button>
        </CollapsibleTrigger>

        {/* Body */}
        <CollapsibleContent forceMount className="print-expand overflow-hidden data-[state=open]:animate-collapsible-down data-[state=closed]:h-0">
          <div className={cn(
            'border-t px-4 pb-4 pt-3 space-y-4',
            informational ? 'border-border/40' : s.border
          )}>

            {/* Informational notice */}
            {informational && (
              <div className="flex items-start gap-2 rounded-md border border-border/40 bg-muted/20 px-3 py-2">
                <Info className="mt-0.5 size-3.5 shrink-0 text-muted-foreground/50" />
                <p className="font-mono text-[11px] text-muted-foreground/60 leading-relaxed">
                  This finding has <span className="font-semibold">{rep.confidence}</span> confidence — it does not affect the risk score and may require manual verification.
                </p>
              </div>
            )}

            {rep.context && (
              <p className="border-b border-border/40 pb-2 font-mono text-[11px] text-muted-foreground">
                {rep.context}
              </p>
            )}

            {rep.detail && (
              <p className="text-sm leading-7 text-muted-foreground">
                {rep.detail}
              </p>
            )}

            <ReferenceBadges rep={rep} />

            <CodeSnippet snippet={rep.snippet} />

            {rep.exploit && (
              <div className={cn(
                'rounded-r-lg border-l-2 py-3 pl-4 pr-4',
                informational ? 'bg-muted/20 border-l-border' : s.exploitBg
              )}>
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                  <span className={cn(
                    'font-mono text-[10px] font-bold uppercase tracking-widest',
                    informational ? 'text-muted-foreground/50' : s.exploitLabel
                  )}>
                    Exploit Scenario
                  </span>
                  {rep.impact && (
                    <span className={cn(
                      'rounded-full border px-2 py-0.5 font-mono text-[10px]',
                      informational ? 'border-border/40 text-muted-foreground/50' : s.impactBorder
                    )}>
                      {rep.impact}
                    </span>
                  )}
                </div>
                <p className="text-xs leading-7 text-muted-foreground">{rep.exploit}</p>
              </div>
            )}

            {rep.remediation && (
              <div className="rounded-r-lg border-l-2 border-l-green-500/50 bg-green-500/5 py-3 pl-4 pr-4">
                <p className="mb-2 font-mono text-[10px] font-bold uppercase tracking-widest text-green-400/70">
                  Remediation
                </p>
                <pre className="whitespace-pre-wrap font-mono text-xs leading-7 text-muted-foreground">
                  {rep.remediation}
                </pre>
              </div>
            )}

            {rest.length > 0 && (
              <div>
                <p className="mb-2 font-mono text-[10px] font-bold uppercase tracking-widest text-muted-foreground/50">
                  {rest.length} more occurrence{rest.length > 1 ? 's' : ''}
                </p>
                <div className="space-y-1.5">
                  {rest.map((f, i) => (
                    <OccurrenceRow key={f.id ?? i} finding={f} s={s} index={i + 1} />
                  ))}
                </div>
              </div>
            )}
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  );
}
