import { findLineNumber, extractSnippet } from '../yaml-parser.js';

// Same supply-chain risk as unpinned actions: mutable branch/tag references can be
// force-pushed to malicious workflow code that runs with all inherited secrets.
const SHA_RE = /^[a-f0-9]{40}$/;

function classifyRef(ref) {
  if (!ref || ref === 'no ref') return 'no ref';
  if (SHA_RE.test(ref))               return null; // pinned — safe
  if (/^v\d|^\d+\.\d+/.test(ref))    return 'version tag (mutable)';
  if (/^[a-f0-9]{7,39}$/.test(ref))  return 'short SHA (not fully pinned)';
  return 'branch/tag (mutable)';
}

export function checkReusableWorkflowRef(workflow, rawContent, filename) {
  const findings = [];
  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    const uses = job.uses;
    if (typeof uses !== 'string') continue;
    if (uses.startsWith('./')) continue; // local workflow — different risk model

    const atIdx  = uses.lastIndexOf('@');
    const ref    = atIdx !== -1 ? uses.slice(atIdx + 1) : 'no ref';
    const refType = classifyRef(ref);
    if (refType === null) continue; // full 40-char SHA — safe

    const lineNumber = findLineNumber(rawContent, uses.slice(0, 40));
    const snippet    = extractSnippet(rawContent, lineNumber, 3);

    findings.push({
      id: `reusable-workflow-ref-${filename}-${jobId}`,
      rule: 'reusable-workflow-ref',
      severity: 'high',
      title: `Unpinned Reusable Workflow: \`${uses}\``,
      file: `.github/workflows/${filename}`,
      line: lineNumber,
      snippet,
      context: `Job: \`${job.name ?? jobId}\`  ·  Ref type: ${refType}`,
      detail: `Reusable workflow \`${uses}\` is called at \`${ref}\` (${refType}), not a full 40-character commit SHA. The referenced branch or tag can be force-pushed to point at malicious workflow code that runs in your pipeline with every secret passed via \`secrets: inherit\` or explicit secret mappings. The impact is identical to an unpinned action supply chain attack.`,
      exploit: `Compromise the external repo's maintainer account or take over a dormant repo → force-push \`${ref}\` to a workflow that reads and exfiltrates all inherited secrets via curl. Every caller repo immediately executes the malicious workflow code without any local file change — no PR, no diff, no warning.`,
      impact: 'Supply Chain RCE + Secret Exfiltration via Reusable Workflow',
      remediation: `Pin to a full commit SHA:\n\njobs:\n  ${jobId}:\n    uses: ${uses.split('@')[0]}@<40-char-sha>  # ${ref}\n\nUse Renovate or Dependabot to automate SHA updates. Also audit what secrets the workflow receives.`,
      cvss: {
        score:  8.8,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
        cwe:    'CWE-494',
        cve:    ['CVE-2025-30066'],
      },
    });
  }

  return findings;
}
