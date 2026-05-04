import { getTriggers, findLineNumber, extractSnippet } from '../yaml-parser.js';

const DANGEROUS_REFS = [
  'github.event.pull_request.head.sha',
  'github.event.pull_request.head.ref',
  'github.head_ref',
  'refs/pull/',
];

function checkoutUsesDangerousRef(step) {
  if (typeof step?.uses !== 'string') return false;
  if (!step.uses.startsWith('actions/checkout')) return false;
  const ref = step.with?.ref ?? '';
  return DANGEROUS_REFS.some(r => String(ref).includes(r));
}

export function checkDangerousTriggers(workflow, rawContent, filename) {
  const findings = [];
  const triggers = getTriggers(workflow);

  if (!triggers.includes('pull_request_target')) return findings;

  const jobs = workflow?.jobs ?? {};
  const lineNumber = findLineNumber(rawContent, 'pull_request_target');
  const snippet = extractSnippet(rawContent, lineNumber, 4);

  // Track whether a medium-severity "bare prt" finding has already been added.
  // We emit it at most once per workflow file to avoid duplicate findings across jobs.
  let addedMediumFinding = false;

  for (const [jobId, job] of Object.entries(jobs)) {
    const steps = Array.isArray(job.steps) ? job.steps : [];
    const dangerousCheckout = steps.find(checkoutUsesDangerousRef);

    if (dangerousCheckout) {
      // Critical finding is per-job because the dangerous checkout is job-specific.
      const checkoutLine = findLineNumber(rawContent, 'actions/checkout');
      const checkoutSnippet = extractSnippet(rawContent, checkoutLine, 4);

      findings.push({
        id: `dangerous-trigger-pwn-request-${filename}-${jobId}`,
        rule: 'dangerous-trigger',
        severity: 'critical',
        title: 'Pwn Request: pull_request_target + Dangerous Checkout',
        file: filename,
        line: checkoutLine,
        snippet: checkoutSnippet,
        context: `Job: \`${job.name ?? jobId}\``,
        detail: `\`pull_request_target\` runs with the base repo's secrets and permissions. Checking out the PR's HEAD code (\`${dangerousCheckout.with?.ref}\`) and running it is a classic "pwn request": untrusted code runs in a trusted context.`,
        exploit: `Fork the repo → modify Makefile / build scripts → open a PR. The workflow checks out your malicious code and executes it with the target repo's secrets. No approval required.`,
        impact: 'Remote Code Execution + Full Secret Exfiltration from base repo',
        remediation: `1. Remove the \`ref\` override from \`actions/checkout\`. Check out the base branch only.\n2. If you need PR code, build it in a separate sandboxed job with no secrets.\n3. Use \`pull_request\` instead of \`pull_request_target\` when secrets aren't needed.`,
        cvss: {
          score:  9.8,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
          cwe:    'CWE-829',
        },
      });
    } else if (!addedMediumFinding) {
      // One medium finding per workflow file — pull_request_target is a workflow-level
      // trigger, so duplicating it for every job creates noise without extra signal.
      addedMediumFinding = true;
      findings.push({
        id: `dangerous-trigger-prt-${filename}`,
        rule: 'dangerous-trigger',
        severity: 'medium',
        title: 'Dangerous Trigger: pull_request_target detected',
        file: filename,
        line: lineNumber,
        snippet,
        context: 'Workflow-level trigger',
        detail: `\`pull_request_target\` runs in the context of the base repository (with its secrets and write permissions) even for PRs from forks. Without careful isolation this can be escalated to code execution. Legitimate uses (label automation, comment bots) that perform no checkout carry minimal risk.`,
        exploit: `If any step processes PR data (labels, title, body) or if a later maintainer adds a checkout without pinning the ref, this becomes a full pwn-request vector.`,
        impact: 'Potential Secret Access from Fork-Submitted PRs',
        remediation: `Prefer \`pull_request\` for untrusted code. If \`pull_request_target\` is required (e.g., for labeling or commenting), ensure no step checks out or executes PR-controlled code, and restrict permissions with \`permissions:\`.`,
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
