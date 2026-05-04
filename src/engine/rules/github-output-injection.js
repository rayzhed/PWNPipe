import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

const GITHUB_OUTPUT_WRITE_RE = />>?\s*\$GITHUB_OUTPUT/;
const EXPR_RE = /\$\{\{[\s\S]*?\}\}/;

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

export function checkGithubOutputInjection(workflow, rawContent, filename) {
  const findings = [];
  const steps = getAllSteps(workflow);

  for (const { jobId, jobName, step, stepIndex } of steps) {
    const run = step.run;
    if (typeof run !== 'string') continue;
    if (!GITHUB_OUTPUT_WRITE_RE.test(run)) continue;
    if (!EXPR_RE.test(run)) continue;
    if (!DANGEROUS_CONTEXTS.some(ctx => run.includes(ctx))) continue;

    const lineNumber = findLineNumber(rawContent, 'GITHUB_OUTPUT');
    const snippet = extractSnippet(rawContent, lineNumber, 4);

    findings.push({
      id:          `github-output-injection-${filename}-${jobId}-${stepIndex}`,
      rule:        'github-output-injection',
      severity:    'high',
      title:       'Unsanitized Input Written to GITHUB_OUTPUT',
      file:        filename,
      line:        lineNumber,
      snippet,
      context:     `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}`,
      detail:      'Attacker-controlled data is written to `$GITHUB_OUTPUT`. Outputs set here are consumed by subsequent steps via `${{ steps.ID.outputs.KEY }}`. If a consuming step interpolates the output into a `run:` block or into another env var, the attacker controls arbitrary shell input in that step.',
      exploit:     'Inject a newline-separated `KEY=VALUE` pair into the controlled input. When GitHub Actions parses `$GITHUB_OUTPUT`, each `KEY=VALUE` line becomes a named output. If a downstream step uses `${{ steps.X.outputs.target }}` inside a `run:` block, the injected value runs arbitrary shell commands.',
      impact:      'Step Output Injection → Code Execution in Consuming Steps',
      remediation: 'Never write unfiltered `${{ }}` expressions to `$GITHUB_OUTPUT`. Pass values through env vars and sanitize before writing:\n\nenv:\n  INPUT: ${{ github.event.issue.title }}\nrun: |\n  SAFE="$(echo "$INPUT" | tr -d \'\\n=\')"\n  echo "value=$SAFE" >> $GITHUB_OUTPUT',
      cvss:        { score: 8.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N', cwe: 'CWE-94' },
    });
  }

  return findings;
}
