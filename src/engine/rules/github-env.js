import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// Matches writes to $GITHUB_ENV or $GITHUB_PATH that also contain a ${{ }} expression
const GITHUB_ENV_WRITE_REGEX = />>?\s*\$GITHUB_ENV|>>?\s*\$GITHUB_PATH/;
const EXPR_REGEX = /\$\{\{[\s\S]*?\}\}/;

// Only contexts controllable by external (non-collaborator) attackers.
// github.event.inputs is intentionally excluded — workflow_dispatch requires write
// access, so only trusted collaborators can supply those values.
const DANGEROUS_INPUT_CONTEXTS = [
  'github.event.issue',
  'github.event.pull_request',
  'github.event.comment',
  'github.event.review',
  'github.event.discussion',
  'github.event.commits',
  'github.head_ref',
  'github.event.workflow_run',
];

export function checkGithubEnv(workflow, rawContent, filename) {
  const findings = [];
  const steps = getAllSteps(workflow);

  for (const { jobId, jobName, step, stepIndex } of steps) {
    const run = step.run;
    if (typeof run !== 'string') continue;
    if (!GITHUB_ENV_WRITE_REGEX.test(run)) continue;
    if (!EXPR_REGEX.test(run)) continue;

    const hasDangerousInput = DANGEROUS_INPUT_CONTEXTS.some(ctx => run.includes(ctx));
    if (!hasDangerousInput) continue;

    const lineNumber = findLineNumber(rawContent, 'GITHUB_ENV') ||
      findLineNumber(rawContent, 'GITHUB_PATH');
    const snippet = extractSnippet(rawContent, lineNumber, 4);

    findings.push({
      id: `github-env-${filename}-${jobId}-${stepIndex}`,
      rule: 'github-env',
      severity: 'high',
      title: 'Unsanitized Input Written to GITHUB_ENV / GITHUB_PATH',
      file: `.github/workflows/${filename}`,
      line: lineNumber,
      snippet,
      context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}`,
      detail: `Attacker-controlled data is written to \`$GITHUB_ENV\` or \`$GITHUB_PATH\`. These files set env vars and PATH for every step that follows. A multi-line value injects arbitrary environment variables.`,
      exploit: `Inject a newline in the controlled input followed by \`EVIL_VAR=malicious_value\`. GitHub Actions parses \`GITHUB_ENV\` line by line, so the injected line becomes a real environment variable in all following steps. This can override variables like \`NODE_OPTIONS\` or \`LD_PRELOAD\` to achieve code execution.`,
      impact: 'Environment Variable Injection → Code Execution in Subsequent Steps',
      remediation: `Never write unfiltered \`\${{ }}\` expressions to \`$GITHUB_ENV\`. Pass values through env vars first, then validate/sanitize before writing:\n\nenv:\n  INPUT: \${{ github.event.issue.title }}\nrun: |\n  # Validate INPUT contains no newlines before writing\n  echo "SAFE_VAR=$(echo "$INPUT" | tr -d '\\n')" >> $GITHUB_ENV`,
      cvss: {
        score:  8.5,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N',
        cwe:    'CWE-94',
      },
    });
  }

  return findings;
}
