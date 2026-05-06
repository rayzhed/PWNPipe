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

      const inputKey = inputs['skip-token-revoke'] === true ? 'skip-token-revoke: true' : 'revoke-token: false';
      const lineNumber = findLineNumber(rawContent, inputKey.split(':')[0]) || findLineNumber(rawContent, step.uses.split('@')[0]);
      const snippet = extractSnippet(rawContent, lineNumber, 5);

      findings.push({
        id:          `github-app-skip-revoke-${filename}-${jobId}`,
        rule:        'github-app-unsafe',
        severity:    'high',
        title:       `GitHub App Token Created with Token Revocation Disabled`,
        file:        filename,
        line:        lineNumber,
        snippet,
        context:     `Job: \`${jobName}\`  ·  Action: \`${step.uses}\`  ·  \`${inputKey}\``,
        detail:      `Automatic token revocation is disabled for this GitHub App installation token. The token stays valid until GitHub's default expiry (up to 1 hour) even after the job ends. If the token is written to logs, uploaded in an artifact, or captured by a compromised dependency running in the same job, the attacker retains API access to all repositories the App is installed on for the remainder of that window.`,
        exploit:     `A malicious dependency running in the same job reads the \`GH_TOKEN\` or \`GITHUB_TOKEN\` environment variable. With token revocation disabled, the attacker has up to 1 hour to clone repositories, push commits, or exfiltrate secrets as the GitHub App identity.`,
        impact:      'GitHub App Token Remains Valid After Job — Extended Secret Exposure Window',
        remediation: `Remove \`${inputKey}\`. Tokens are revoked automatically when the job completes, which limits the exposure to the job's own execution window. If a downstream job genuinely needs the token, generate a fresh one there instead of keeping the original alive.`,
        cvss:        { score: 7.4, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N', cwe: 'CWE-672' },
      });
    }
  }

  return findings;
}
