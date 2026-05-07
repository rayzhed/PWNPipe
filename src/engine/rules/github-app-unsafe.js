import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// Actions that create GitHub App installation tokens
const APP_TOKEN_ACTIONS = [
  'actions/create-github-app-token',
  'tibdex/github-app-token',
];

function isAppTokenStep(uses) {
  if (typeof uses !== 'string') return false;
  const base = uses.split('@')[0];
  return APP_TOKEN_ACTIONS.includes(base);
}

export function checkGithubAppUnsafe(workflow, rawContent, filename) {
  const findings = [];
  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    const steps = Array.isArray(job.steps) ? job.steps : [];
    for (const step of steps) {
      if (!isAppTokenStep(step.uses)) continue;
      const inputs = step.with ?? {};
      const jobName = job.name ?? jobId;

      // skip-token-revoke: true disables automatic revocation at job end.
      // For tibdex/github-app-token the equivalent is revoke-token: false.
      // YAML parsers may produce booleans or strings depending on quoting.
      const skipsRevoke =
        inputs['skip-token-revoke'] === true  || inputs['skip-token-revoke'] === 'true' ||
        inputs['revoke-token']      === false || inputs['revoke-token']      === 'false';

      if (!skipsRevoke) continue;

      const inputKey = inputs['skip-token-revoke'] === true || inputs['skip-token-revoke'] === 'true'
        ? 'skip-token-revoke: true'
        : 'revoke-token: false';
      const lineNumber = findLineNumber(rawContent, inputKey.split(':')[0]) || findLineNumber(rawContent, step.uses.split('@')[0]);
      const snippet = extractSnippet(rawContent, lineNumber, 5);

      findings.push({
        id:          `github-app-skip-revoke-${filename}-${jobId}`,
        rule:        'github-app-unsafe',
        severity:    'high',
        title:       `GitHub App token with revocation disabled`,
        file:        filename,
        line:        lineNumber,
        snippet,
        context:     `Job: \`${jobName}\`  ·  Action: \`${step.uses}\`  ·  \`${inputKey}\``,
        detail:      `Token revocation is disabled. The token stays live for up to 1 hour after the job ends — any step that leaks it (logs, artifacts, compromised dependency) gives an attacker an hour of API access across every repo the App is installed on.`,
        exploit:     `A malicious dependency reads \`GH_TOKEN\`. With revocation off, it has up to 1 hour to clone repos, push commits, or exfiltrate secrets as the GitHub App identity.`,
        impact:      'Live Token After Job Ends + Up to 1h Exposure Window',
        remediation: `Remove \`${inputKey}\`. Tokens are revoked automatically at job end, limiting exposure to the job's execution window. If a downstream job needs the token, generate a fresh one there.`,
        cvss:        { score: 7.4, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N', cwe: 'CWE-672' },
      });
    }
  }

  return findings;
}
