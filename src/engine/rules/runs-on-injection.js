import { findLineNumber, extractSnippet } from '../yaml-parser.js';

const EXPR_RE = /\$\{\{[\s\S]*?\}\}/;

// Contexts reachable by unauthenticated external users — truly dangerous in runs-on
const UNAUTH_CONTEXTS = [
  'github.event.issue',
  'github.event.pull_request',
  'github.event.comment',
  'github.event.review',
  'github.event.discussion',
  'github.event.commits',
  'github.head_ref',
  'github.event.workflow_run',
];

// matrix.* in runs-on is almost always a static matrix defined in the workflow itself (e.g.
// matrix: {os: [ubuntu-latest, windows-latest]}) — not attacker-controlled. Skip it entirely.

export function checkRunsOnInjection(workflow, rawContent, filename) {
  const findings = [];
  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    const runsOn = job['runs-on'];
    const runsOnStr = typeof runsOn === 'string'
      ? runsOn
      : (Array.isArray(runsOn) ? runsOn.join(' ') : '');

    if (!EXPR_RE.test(runsOnStr)) continue;

    const isUnauthControlled = UNAUTH_CONTEXTS.some(ctx => runsOnStr.includes(ctx));
    if (!isUnauthControlled) continue;

    const lineNumber = findLineNumber(rawContent, 'runs-on:');
    const snippet = extractSnippet(rawContent, lineNumber, 4);
    const jobName = job.name ?? jobId;

    const isFromPrEvent = runsOnStr.includes('github.event.pull_request') || runsOnStr.includes('github.head_ref');
    const severity = isFromPrEvent ? 'critical' : 'high';

    findings.push({
      id:          `runs-on-injection-${filename}-${jobId}`,
      rule:        'runs-on-injection',
      severity,
      title:       `\`runs-on\` Value Controlled by Untrusted External Input in Job \`${jobId}\``,
      file:        filename,
      line:        lineNumber,
      snippet,
      context:     `Job: \`${jobName}\`  ·  runs-on: \`${runsOnStr}\``,
      detail:      `The \`runs-on:\` label for job \`${jobId}\` is dynamically constructed from attacker-controlled event data (e.g. PR title, branch name, issue body). GitHub matches runner labels exactly — if an attacker controls the label value, they can route the job to a malicious self-hosted runner they register. The job then executes on attacker infrastructure with full access to all secrets and the GITHUB_TOKEN.`,
      exploit:     `An attacker registers a self-hosted runner with a label crafted to match the dynamic expression outcome. They submit a PR or open an issue that sets the runs-on value to match their runner label. The job is dispatched to the attacker-controlled machine, which exfiltrates all secrets and the GITHUB_TOKEN.`,
      impact:      'Job Hijacking — Attacker-Controlled Runner Executes with Secret Access',
      remediation: `Never derive \`runs-on:\` from untrusted event data. Use a static label or a hardcoded conditional:\n\nruns-on: ubuntu-latest\n\nIf OS variants are needed, use a static strategy matrix defined in the workflow file, not from event inputs.`,
      cvss:        { score: isFromPrEvent ? 9.8 : 8.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', cwe: 'CWE-99' },
    });
  }

  return findings;
}
