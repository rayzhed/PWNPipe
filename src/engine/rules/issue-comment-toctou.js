import { getTriggers, findLineNumber, extractSnippet } from '../yaml-parser.js';

// Triggers that run in a trusted context but can be initiated by anyone via a comment/review
const COMMENT_TRIGGERS = new Set([
  'issue_comment',
  'pull_request_review',
  'pull_request_review_comment',
]);

// Mutable PR refs — branch names that can be force-pushed after the trigger fires
const MUTABLE_PR_REFS = [
  'github.event.pull_request.head.ref',
  'github.head_ref',
  'refs/pull/',
];

// Only checks explicit `ref:` inputs — refs passed via env vars or expression
// outputs (e.g. `ref: ${{ env.PR_REF }}`) are not detected by static analysis.
function checkoutUsesMutableRef(step) {
  if (typeof step?.uses !== 'string') return false;
  if (!step.uses.startsWith('actions/checkout')) return false;
  const ref = String(step.with?.ref ?? '');
  return MUTABLE_PR_REFS.some(r => ref.includes(r));
}

export function checkIssueCommentTOCTOU(workflow, rawContent, filename) {
  const findings = [];
  const triggers = getTriggers(workflow);
  const trigger = triggers.find(t => COMMENT_TRIGGERS.has(t));
  if (!trigger) return findings;

  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    const steps = Array.isArray(job.steps) ? job.steps : [];
    const badCheckout = steps.find(checkoutUsesMutableRef);
    if (!badCheckout) continue;

    const ref = String(badCheckout.with?.ref ?? '');
    const lineNumber = findLineNumber(rawContent, ref) || findLineNumber(rawContent, 'actions/checkout');
    const snippet = extractSnippet(rawContent, lineNumber, 4);

    findings.push({
      id:          `issue-comment-toctou-${filename}-${jobId}`,
      rule:        'issue-comment-toctou',
      severity:    'high',
      title:       `TOCTOU: \`${trigger}\` Checks Out PR Branch by Mutable Ref`,
      file:        filename,
      line:        lineNumber,
      snippet,
      context:     `Job: \`${job.name ?? jobId}\`  ·  Trigger: \`${trigger}\`  ·  Ref: \`${ref}\``,
      detail:      `The workflow triggers on \`${trigger}\` and checks out the PR head using a mutable branch ref. Between the comment/review event firing and the checkout executing, an attacker can force-push a new commit to the PR branch. The workflow then checks out and runs the new malicious code with the base repository's secrets and write permissions.`,
      exploit:     `Post a comment to trigger the workflow, then immediately force-push a malicious commit to the PR branch. The workflow picks up the force-pushed code and runs it in a trusted context with full secret access.`,
      impact:      'Arbitrary Code Execution in Trusted Context via TOCTOU Race',
      remediation: `Pin the checkout to the commit SHA, which cannot be changed after the event fires:\n\n# Wrong (mutable — can be force-pushed):\nref: \${{ github.event.pull_request.head.ref }}\n\n# Correct (immutable commit SHA):\nref: \${{ github.event.pull_request.head.sha }}\n\nBetter yet, avoid checking out PR-controlled code in \`${trigger}\` workflows entirely.`,
      cvss:        { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N', cwe: 'CWE-367' },
    });
  }

  return findings;
}
