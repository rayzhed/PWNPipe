import React, { useState } from 'react';
import { ChevronDown, MapPin } from 'lucide-react';
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
  CONFIRMED: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400',
  HIGH:      'border-blue-500/40    bg-blue-500/10    text-blue-400',
  MEDIUM:    'border-amber-500/40   bg-amber-500/10   text-amber-400',
  LOW:       'border-gray-500/30    bg-gray-500/10    text-gray-400',
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
        {/* Confidence */}
        {rep.confidence && (
          <span className={cn(
            'rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider',
            CONFIDENCE_STYLE[rep.confidence] ?? CONFIDENCE_STYLE.MEDIUM
          )}>
            {rep.confidence}
          </span>
        )}
        {/* OWASP CI/CD */}
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
        {/* CWE */}
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
        {/* CVE badges */}
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
      {/* CVSS vector string — selectable for copy-paste into reports */}
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

export default function FindingCard({ group }) {
  const rep   = group.findings[0];
  const rest  = group.findings.slice(1);
  const s     = SEVERITY[group.severity] ?? SEVERITY.low;
  const count = group.findings.length;
  const score = rep.cvss?.score ?? cvssScore(group.severity);

  const [open, setOpen] = useState(false);

  return (
    <Collapsible open={open} onOpenChange={setOpen} className="mb-2.5">
      <div className={cn('rounded-lg border bg-card transition-colors', open ? s.border : 'border-border')}>

        {/* Header */}
        <CollapsibleTrigger asChild>
          <button className={cn(
            'flex w-full items-start gap-3 rounded-t-lg p-4 text-left transition-colors',
            open ? s.headerBg : 'hover:bg-muted/40'
          )}>
            <Badge variant={s.badge} className="mt-0.5 shrink-0 uppercase">
              {group.severity}
            </Badge>

            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold leading-snug text-foreground">
                {group.title}
              </p>
              <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5">
                <span className="font-mono text-[11px] text-muted-foreground">
                  {count > 1
                    ? `${count} occurrences · ${rep.file}${rep.line ? `:${rep.line}` : ''}`
                    : `${rep.file}${rep.line ? `:${rep.line}` : ''}`
                  }
                </span>
                {/* Inline confidence + OWASP in header for quick scanning */}
                {rep.owasp && (
                  <span className="font-mono text-[10px] text-violet-400/70">{rep.owasp}</span>
                )}
              </div>
            </div>

            <span className={cn(
              'shrink-0 rounded border px-2 py-0.5 font-mono text-[11px] font-bold',
              cvssChipStyle(score)
            )}>
              {score.toFixed(1)}
            </span>

            <ChevronDown className={cn(
              'mt-0.5 size-4 shrink-0 text-muted-foreground transition-transform duration-200',
              open && 'rotate-180'
            )} />
          </button>
        </CollapsibleTrigger>

        {/* Body */}
        <CollapsibleContent forceMount className="print-expand overflow-hidden data-[state=open]:animate-collapsible-down data-[state=closed]:h-0">
          <div className={cn('border-t px-4 pb-4 pt-3 space-y-4', s.border)}>

            {/* Context */}
            {rep.context && (
              <p className="border-b border-border pb-2 font-mono text-[11px] text-muted-foreground">
                {rep.context}
              </p>
            )}

            {/* Detail */}
            {rep.detail && (
              <p className="text-sm leading-7 text-muted-foreground">
                {rep.detail}
              </p>
            )}

            {/* References: confidence · OWASP · CWE · CVE · CVSS vector */}
            <ReferenceBadges rep={rep} />

            {/* First occurrence code snippet */}
            <CodeSnippet snippet={rep.snippet} />

            {/* Exploit scenario */}
            {rep.exploit && (
              <div className={cn('rounded-r-lg border-l-2 py-3 pl-4 pr-4', s.exploitBg)}>
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                  <span className={cn('font-mono text-[10px] font-bold uppercase tracking-widest', s.exploitLabel)}>
                    Exploit Scenario
                  </span>
                  {rep.impact && (
                    <span className={cn('rounded-full border px-2 py-0.5 font-mono text-[10px]', s.impactBorder)}>
                      {rep.impact}
                    </span>
                  )}
                </div>
                <p className="text-xs leading-7 text-muted-foreground">{rep.exploit}</p>
              </div>
            )}

            {/* Remediation */}
            {rep.remediation && (
              <div className="rounded-r-lg border-l-2 border-l-green-500 bg-green-500/5 py-3 pl-4 pr-4">
                <p className="mb-2 font-mono text-[10px] font-bold uppercase tracking-widest text-green-400">
                  Remediation
                </p>
                <pre className="whitespace-pre-wrap font-mono text-xs leading-7 text-muted-foreground">
                  {rep.remediation}
                </pre>
              </div>
            )}

            {/* Additional occurrences */}
            {rest.length > 0 && (
              <div>
                <p className="mb-2 font-mono text-[10px] font-bold uppercase tracking-widest text-muted-foreground/60">
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
