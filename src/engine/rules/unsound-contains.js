import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// Matches the VULNERABLE form: contains(github.actor, 'substring')
// where the user field is the FIRST argument (the string being searched in).
//
// This is NOT the same as the array form: contains(fromJSON('[...]'), github.actor)
// The array form performs EXACT element matching and is safe. We only flag the
// string form because it performs substring matching — e.g., contains(github.actor,
// 'alice') would match an actor named 'malice' or 'alice-admin'.
const CONTAINS_STRING_FORM_REGEX = /contains\s*\(\s*(?:github\.actor|github\.event\.sender\.login|github\.event\.pull_request\.user\.login)\s*,/i;

function checkCondition(condition, rawContent, filename, id, context) {
  if (typeof condition !== 'string') return null;
  if (!CONTAINS_STRING_FORM_REGEX.test(condition)) return null;

  const lineNumber = findLineNumber(rawContent, condition.trim().slice(0, 30));
  const snippet = extractSnippet(rawContent, lineNumber, 3);

  return {
    id: `unsound-contains-${filename}-${id}`,
    rule: 'unsound-contains',
    severity: 'medium',
    title: 'Unsound contains() Used for Authorization',
    file: `.github/workflows/${filename}`,
    line: lineNumber,
    snippet,
    context,
    detail: `\`contains(github.actor, 'substring')\` searches the actor's username for a substring. \`contains(github.actor, 'alice')\` matches 'malice', 'alice-admin', 'not-alice', etc. An attacker just registers an account that contains the trusted substring.\n\nThe array form \`contains(fromJSON('[\"alice\"]'), github.actor)\` is safe (exact element match, not substring).`,
    exploit: `Register a GitHub account whose username contains the trusted substring (e.g. if the check is \`contains(github.actor, 'bot')\`, register an account named \`mybot\` or \`robotuser\`). The condition evaluates to true and grants unauthorized access.`,
    impact: 'Authorization Bypass via Username Substring Match',
    remediation: `Use exact equality checks instead of \`contains()\` on the actor string:\n\nif: github.actor == 'trusted-user'\n\nFor multiple trusted users, use the array form:\n\nif: contains(fromJSON('["alice","bob"]'), github.actor)\n\nFor team/org membership, use \`actions/github-script\` to call the GitHub API.`,
    cvss: {
      score:  5.4,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
      cwe:    'CWE-284',
    },
  };
}

export function checkUnsoundContains(workflow, rawContent, filename) {
  const findings = [];
  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    const jobFinding = checkCondition(
      job.if, rawContent, filename,
      `${jobId}-job`, `Job: \`${job.name ?? jobId}\``
    );
    if (jobFinding) findings.push(jobFinding);

    const steps = Array.isArray(job.steps) ? job.steps : [];
    steps.forEach((step, idx) => {
      const stepFinding = checkCondition(
        step.if, rawContent, filename,
        `${jobId}-step${idx}`, `Job: \`${job.name ?? jobId}\`  ·  Step ${idx + 1}`
      );
      if (stepFinding) findings.push(stepFinding);
    });
  }

  return findings;
}
