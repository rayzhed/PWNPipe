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
      title:       `TOCTOU: \`${trigger}\` checks out mutable PR ref`,
      file:        filename,
      line:        lineNumber,
      snippet,
      context:     `Job: \`${job.name ?? jobId}\`  ·  Trigger: \`${trigger}\`  ·  Ref: \`${ref}\``,
      detail:      `\`${trigger}\` runs in a trusted context with the base repo's secrets. It checks out the PR branch by mutable ref — between the event firing and the checkout, an attacker can force-push to the PR branch. The job then runs the attacker's code with full secret access.`,
      exploit:     `Post a comment to fire the workflow, then immediately force-push a malicious commit to the PR branch. The checkout picks up the new commit and executes it with the base repo's secrets and write permissions.`,
      impact:      'RCE in Trusted Context via TOCTOU Race',
      remediation: `Check out by commit SHA instead of branch ref:\n\n- uses: actions/checkout@<sha>\n  with:\n    ref: \${{ github.event.pull_request.head.sha }}\n\nOr avoid checking out PR-controlled code in \`${trigger}\` workflows entirely.`,
      cvss:        { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N', cwe: 'CWE-367' },
    });
  }

  return findings;
}
