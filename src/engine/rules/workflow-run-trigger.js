import { getTriggers, getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// workflow_run has the same trust boundary as pull_request_target:
// it runs in the base repo's context with secrets, even when triggered by a fork.
// Checking out the triggering repo's HEAD code is a pwn-request equivalent.
const DANGEROUS_RUN_REFS = [
  'github.event.workflow_run.head_sha',
  'github.event.workflow_run.head_branch',
  'github.event.workflow_run.head_commit',
];

function checkoutUsesDangerousRunRef(step) {
  if (typeof step?.uses !== 'string') return false;
  if (!step.uses.startsWith('actions/checkout')) return false;
  const ref = String(step.with?.ref ?? '');
  return DANGEROUS_RUN_REFS.some(r => ref.includes(r));
}

export function checkWorkflowRunTrigger(workflow, rawContent, filename) {
  const findings = [];
  const triggers = getTriggers(workflow);
  if (!triggers.includes('workflow_run')) return findings;

  const jobs = workflow?.jobs ?? {};
  const lineNumber = findLineNumber(rawContent, 'workflow_run');
  const snippet = extractSnippet(rawContent, lineNumber, 4);
  let addedMediumFinding = false;

  for (const [jobId, job] of Object.entries(jobs)) {
    const steps = Array.isArray(job.steps) ? job.steps : [];
    const dangerousCheckout = steps.find(checkoutUsesDangerousRunRef);

    if (dangerousCheckout) {
      const checkoutLine = findLineNumber(rawContent, 'actions/checkout');
      const checkoutSnippet = extractSnippet(rawContent, checkoutLine, 4);
      findings.push({
        id: `workflow-run-trigger-pwn-${filename}-${jobId}`,
        rule: 'workflow-run-trigger',
        severity: 'critical',
        title: 'Pwn Request via workflow_run + Dangerous Checkout',
        file: filename,
        line: checkoutLine,
        snippet: checkoutSnippet,
        context: `Job: \`${job.name ?? jobId}\``,
        detail: `\`workflow_run\` executes in the base repository's trusted context with its secrets and write permissions, even when triggered by a fork. Checking out the triggering repo's code (\`${dangerousCheckout.with?.ref}\`) is a pwn-request: untrusted fork code executes with base-repo secrets. This mirrors the \`pull_request_target\` attack class.`,
        exploit: `Fork the repo → push a malicious build script or Makefile → trigger a workflow → the \`workflow_run\` handler checks out your fork code and runs it with the target's full secrets. No maintainer approval required. The attack is silent — it looks like a normal CI run.`,
        impact: 'Remote Code Execution + Full Secret Exfiltration from base repo',
        remediation: `Never check out the triggering workflow's HEAD. Download artifacts from the triggering run instead:\n\n- uses: actions/download-artifact@<sha>\n  with:\n    run-id: \${{ github.event.workflow_run.id }}\n\nIf you need to filter by repository:\n\nif: github.event.workflow_run.head_repository.full_name == github.repository`,
        cvss: {
          score:  9.8,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
          cwe:    'CWE-829',
        },
      });
    } else if (!addedMediumFinding) {
      addedMediumFinding = true;
      findings.push({
        id: `workflow-run-trigger-bare-${filename}`,
        rule: 'workflow-run-trigger',
        severity: 'medium',
        title: 'Dangerous Trigger: workflow_run runs in base repo context',
        file: filename,
        line: lineNumber,
        snippet,
        context: 'Workflow-level trigger',
        detail: `\`workflow_run\` runs in the base repository's context with its secrets, even when the triggering workflow originates from a fork. This is the same trust-boundary issue as \`pull_request_target\`. Any step that processes data from the triggering run without careful sanitization can escalate to secret exfiltration.`,
        exploit: `If any step downloads artifacts or processes data from the fork-triggered run, or if a future maintainer adds a dangerous checkout, this becomes a full pwn-request with access to all base-repo secrets.`,
        impact: 'Potential Secret Access from Fork-Triggered Workflows',
        remediation: `Restrict execution to your own repo:\n\nif: github.event.workflow_run.head_repository.full_name == github.repository\n\nOr only consume artifacts — never source code — from the triggering run. Add \`permissions: {}\` to enforce least privilege.`,
        cvss: {
          score:  5.4,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N',
          cwe:    'CWE-829',
        },
      });
    }
  }

  return findings;
}
