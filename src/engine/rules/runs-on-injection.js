import { findLineNumber, extractSnippet } from '../yaml-parser.js';

// Any expression in runs-on is suspicious — runners should be static labels
const EXPR_RE = /\$\{\{[\s\S]*?\}\}/;

const DANGEROUS_CONTEXTS = [
  'github.event.',
  'github.head_ref',
  'inputs.',
  'github.event.inputs.',
  'matrix.',
];

export function checkRunsOnInjection(workflow, rawContent, filename) {
  const findings = [];
  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    const runsOn = job['runs-on'];
    const runsOnStr = typeof runsOn === 'string'
      ? runsOn
      : (Array.isArray(runsOn) ? runsOn.join(' ') : '');

    if (!EXPR_RE.test(runsOnStr)) continue;
    if (!DANGEROUS_CONTEXTS.some(ctx => runsOnStr.includes(ctx))) continue;

    const lineNumber = findLineNumber(rawContent, 'runs-on:');
    const snippet = extractSnippet(rawContent, lineNumber, 4);
    const jobName = job.name ?? jobId;

    const isFromPrEvent = runsOnStr.includes('github.event.pull_request') || runsOnStr.includes('github.head_ref');
    const severity = isFromPrEvent ? 'critical' : 'high';

    findings.push({
      id:          `runs-on-injection-${filename}-${jobId}`,
      rule:        'runs-on-injection',
      severity,
      title:       `\`runs-on\` Value Controlled by Untrusted Input in Job \`${jobId}\``,
      file:        filename,
      line:        lineNumber,
      snippet,
      context:     `Job: \`${jobName}\`  ·  runs-on: \`${runsOnStr}\``,
      detail:      `The \`runs-on:\` label for job \`${jobId}\` is dynamically constructed from event data or user inputs. GitHub matches runner labels exactly — if an attacker controls the label, they can route the job to a malicious self-hosted runner they control. The job then executes on attacker infrastructure with full access to all secrets and the GITHUB_TOKEN.`,
      exploit:     `An attacker creates a self-hosted runner registered to their own repository or org with a crafted label. They then submit a PR or trigger an event that sets the label to match their runner. The workflow job is dispatched to the attacker's runner, which runs arbitrary code and has full access to all job secrets.`,
      impact:      'Job Hijacking → Attacker-Controlled Runner Executes with Secret Access',
      remediation: `Never use dynamic expressions in \`runs-on:\`. Use a static, allowlisted runner label:\n\nruns-on: ubuntu-latest\n\nIf multiple runner types are needed, use a static matrix or a conditional:\n\nruns-on: \${{ matrix.os == 'windows' && 'windows-latest' || 'ubuntu-latest' }}\n\nNever expose external inputs directly as the runner label.`,
      cvss:        { score: severity === 'critical' ? 9.8 : 8.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', cwe: 'CWE-99' },
    });
  }

  return findings;
}
