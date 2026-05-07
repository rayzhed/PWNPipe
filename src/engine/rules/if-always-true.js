import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// Detects: if: ${{ expr }} == value  (comparison operator OUTSIDE ${{ }})
// GitHub resolves ${{ }} first, yielding a string. Then "string == value" is
// evaluated as an expression where the left side is an unknown identifier,
// or the whole string is non-empty — either way, always truthy.
const AFTER_RE  = /\$\{\{[\s\S]*?\}\}\s*(?:==|!=|>=|<=|>|<|&&|\|\|)/;
const BEFORE_RE = /(?:==|!=|>=|<=|>|<|&&|\|\|)\s*\$\{\{/;

// A pure ${{ ... }} with nothing else outside is fine — GitHub evaluates it correctly.
// Non-greedy inner match + negative lookahead prevents matching across multiple }} blocks.
const PURE_EXPR_RE = /^\s*\$\{\{[^}]*(?:\}(?!\})[^}]*)*\}\}\s*$/;

function isMixed(condition) {
  if (typeof condition !== 'string') return false;
  if (PURE_EXPR_RE.test(condition)) return false;
  return AFTER_RE.test(condition) || BEFORE_RE.test(condition);
}

export function checkIfAlwaysTrue(workflow, rawContent, filename) {
  const findings = [];
  const jobs = workflow?.jobs ?? {};
  const seen = new Set();

  for (const [jobId, job] of Object.entries(jobs)) {
    if (isMixed(job.if)) {
      const cond = String(job.if);
      const key = `job-${jobId}-${cond}`;
      if (!seen.has(key)) {
        seen.add(key);
        const lineNumber = findLineNumber(rawContent, cond) || findLineNumber(rawContent, jobId);
        findings.push(makeFinding(filename, lineNumber, extractSnippet(rawContent, lineNumber, 3),
          job.name ?? jobId, 'Job', cond, jobId));
      }
    }

    const steps = Array.isArray(job.steps) ? job.steps : [];
    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      if (!isMixed(step.if)) continue;
      const cond = String(step.if);
      const key = `step-${jobId}-${i}-${cond}`;
      if (!seen.has(key)) {
        seen.add(key);
        const label = step.name ?? step.uses ?? `step ${i + 1}`;
        const lineNumber = findLineNumber(rawContent, cond) || findLineNumber(rawContent, label);
        findings.push(makeFinding(filename, lineNumber, extractSnippet(rawContent, lineNumber, 3),
          label, 'Step', cond, jobId));
      }
    }
  }

  return findings;
}

function makeFinding(filename, lineNumber, snippet, name, level, condition, jobId) {
  return {
    id:          `if-always-true-${filename}-${jobId}-${name}`,
    rule:        'if-always-true',
    severity:    'high',
    title:       `${level} \`if:\` always evaluates to true`,
    file:        filename,
    line:        lineNumber,
    snippet,
    context:     `${level}: \`${name}\`  ·  Condition: \`${condition}\``,
    detail:      `\`\${{ expr }}\` gets resolved to a string before the comparison runs. The comparison then operates on that string, not a boolean — so the condition is always truthy. Any security gate using this pattern is silently bypassed.`,
    exploit:     `An attacker triggers the protected step in conditions it was never meant to run. If this guards a deploy, secret access, or privilege escalation, the gate is always open.`,
    impact:      'Security Gate Always Bypassed',
    remediation: `Move the comparison inside \`\${{ }}\`:\n\n# broken — always true:\nif: \${{ steps.x.outputs.result }} == 'expected'\n\n# fixed:\nif: \${{ steps.x.outputs.result == 'expected' }}\n\nOr drop the delimiters entirely in if::\nif: steps.x.outputs.result == 'expected'`,
    cvss:        { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', cwe: 'CWE-697' },
  };
}
