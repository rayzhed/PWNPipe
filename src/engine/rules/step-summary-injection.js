import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

const SUMMARY_WRITE_RE = />>?\s*\$GITHUB_STEP_SUMMARY/;
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

export function checkStepSummaryInjection(workflow, rawContent, filename) {
  const findings = [];
  const steps = getAllSteps(workflow);

  for (const { jobId, jobName, step, stepIndex } of steps) {
    const run = step.run;
    if (typeof run !== 'string') continue;
    if (!SUMMARY_WRITE_RE.test(run)) continue;
    if (!EXPR_RE.test(run)) continue;
    if (!DANGEROUS_CONTEXTS.some(ctx => run.includes(ctx))) continue;

    const lineNumber = findLineNumber(rawContent, 'GITHUB_STEP_SUMMARY');
    const snippet = extractSnippet(rawContent, lineNumber, 4);

    findings.push({
      id:          `step-summary-injection-${filename}-${jobId}-${stepIndex}`,
      rule:        'step-summary-injection',
      severity:    'medium',
      title:       'Unsanitized Input Written to GITHUB_STEP_SUMMARY',
      file:        filename,
      line:        lineNumber,
      snippet,
      context:     `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}`,
      detail:      `Attacker-controlled data is written to \`$GITHUB_STEP_SUMMARY\`, which renders as Markdown in the Actions job summary page. An attacker can inject arbitrary Markdown including links to phishing pages or credential-harvesting images.`,
      exploit:     `Submit a PR with a title like \`Fix bug](https://evil.example/steal?token=\`. The rendered Markdown in the job summary will contain a crafted link. Maintainers clicking it are sent to an attacker-controlled site.`,
      impact:      'Markdown Injection in Job Summary',
      remediation: `Pass values through env vars before writing to the summary:\n\nenv:\n  INPUT: \${{ github.event.pull_request.title }}\nrun: |\n  SAFE="$(printf '%s' "$INPUT" | sed 's/[&<>\"]/\\\\&/g')"\n  echo "### Report for $SAFE" >> $GITHUB_STEP_SUMMARY`,
      cvss:        { score: 5.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', cwe: 'CWE-79' },
    });
  }

  return findings;
}
