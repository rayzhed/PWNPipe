import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// Matches: github.actor == 'dependabot[bot]' etc.
// Only the equality form (==) is flagged — != is a legitimate exclusion pattern
// (e.g. "skip this step when triggered by a bot") and is not a bypass vulnerability.
const BOT_CONDITION_REGEX = /github\.actor\s*==\s*['"][^'"]*\[bot\]['"]/i;

function scanCondition(condition, rawContent, filename, jobId, jobName, context) {
  if (typeof condition !== 'string') return null;
  if (!BOT_CONDITION_REGEX.test(condition)) return null;

  const lineNumber = findLineNumber(rawContent, condition.trim().slice(0, 30));
  const snippet = extractSnippet(rawContent, lineNumber, 3);

  return {
    id: `bot-conditions-${filename}-${jobId}-${context}`,
    rule: 'bot-conditions',
    severity: 'medium',
    title: 'Spoofable Bot Actor Check',
    file: filename,
    line: lineNumber,
    snippet,
    context: `Job: \`${jobName}\`  ·  Condition: ${context}`,
    detail: `The condition \`${condition}\` checks \`github.actor\` to detect bots. However, \`github.actor\` is the account that *triggered* the event, not the account that submitted the PR. An attacker can name their account to match the pattern or trigger workflows under a bot account name.`,
    exploit: `Create a GitHub account named \`dependabot[bot]\` (or similar) → trigger the workflow → the condition evaluates to true, bypassing any intended access restrictions or skipping security checks meant only for bots.`,
    impact: 'Bypass of Bot-Based Access Control',
    remediation: `Use \`github.event.pull_request.user.login\` to check who submitted the PR, not who triggered the workflow. For Dependabot specifically, use the \`dependabot/fetch-metadata\` action or check the \`github.event.sender.type\` field.`,
    cvss: {
      score:  6.5,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
      cwe:    'CWE-863',
    },
  };
}

export function checkBotConditions(workflow, rawContent, filename) {
  const findings = [];
  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    // Check job-level if
    const jobFinding = scanCondition(job.if, rawContent, filename, jobId, job.name ?? jobId, 'job-level if');
    if (jobFinding) findings.push(jobFinding);

    // Check step-level if
    const steps = Array.isArray(job.steps) ? job.steps : [];
    steps.forEach((step, idx) => {
      const stepFinding = scanCondition(
        step.if,
        rawContent,
        filename,
        `${jobId}-step${idx}`,
        job.name ?? jobId,
        `step ${idx + 1} if`
      );
      if (stepFinding) findings.push(stepFinding);
    });
  }

  return findings;
}
