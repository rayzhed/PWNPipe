import { findLineNumber, extractSnippet } from '../yaml-parser.js';

function hasIdTokenWrite(perms) {
  if (typeof perms === 'string') return perms === 'write-all';
  if (typeof perms === 'object' && perms !== null) {
    return perms['id-token'] === 'write';
  }
  return false;
}

function jobHasEnvironment(job) {
  return job.environment !== undefined && job.environment !== null;
}

export function checkIdTokenWriteUnscoped(workflow, rawContent, filename) {
  const findings = [];
  const seen = new Set();
  const jobs = workflow?.jobs ?? {};

  const workflowPermsHasIdToken = hasIdTokenWrite(workflow?.permissions);

  // Case 1: id-token: write at workflow level (applies to all jobs)
  if (workflowPermsHasIdToken) {
    // Flag jobs that have no environment gate
    let flaggedAny = false;
    for (const [jobId, job] of Object.entries(jobs)) {
      if (!jobHasEnvironment(job)) {
        const id = `id-token-write-unscoped-${filename}-workflow-level-${jobId}`;
        if (seen.has(id)) continue;
        seen.add(id);
        flaggedAny = true;

        const lineNumber = findLineNumber(rawContent, 'id-token');
        const snippet = extractSnippet(rawContent, lineNumber, 4);

        findings.push({
          id,
          rule: 'id-token-write-unscoped',
          severity: 'high',
          title: 'id-token: write Without Environment Gate',
          file: filename,
          line: lineNumber,
          snippet,
          context: `Workflow-level permissions  ·  Job: \`${job.name ?? jobId}\` has no environment: block`,
          detail: `\`id-token: write\` is set at the workflow level, granting every job the ability to request OIDC tokens. Job \`${jobId}\` does not declare an \`environment:\`, so there is no deployment protection rule or environment secret to constrain who can trigger it. If the cloud IAM trust policy isn't tightly scoped to a specific environment, any workflow run can obtain cloud credentials.`,
          exploit: `Trigger the workflow (e.g., via push, PR, or workflow_dispatch). Since no environment gate requires approval, the OIDC token is automatically issued. If the cloud IAM role's trust policy matches on \`repo:owner/repo:*\` rather than \`repo:owner/repo:environment:production\`, the attacker's run can assume the IAM role and access cloud resources.`,
          impact: 'Unauthorized Cloud IAM Role Assumption via Unscoped OIDC Token',
          remediation: `1. Move \`id-token: write\` to only the specific jobs that require it.\n2. Add \`environment: production\` (or appropriate environment name) to those jobs.\n3. Scope your cloud IAM trust policy to the specific environment:\n   \`repo:owner/repo:environment:production\`\n\nThis ensures only approved deployment runs can request OIDC tokens.`,
          cvss: {
            score: 7.7,
            vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N',
            cwe: 'CWE-269',
          },
        });
      }
    }
  }

  // Case 2: id-token: write at job level, job has no environment
  for (const [jobId, job] of Object.entries(jobs)) {
    if (!hasIdTokenWrite(job.permissions)) continue;
    if (jobHasEnvironment(job)) continue;

    const id = `id-token-write-unscoped-${filename}-${jobId}`;
    if (seen.has(id)) continue;
    seen.add(id);

    const lineNumber = findLineNumber(rawContent, 'id-token');
    const snippet = extractSnippet(rawContent, lineNumber, 4);

    findings.push({
      id,
      rule: 'id-token-write-unscoped',
      severity: 'high',
      title: 'id-token: write Without Environment Gate',
      file: filename,
      line: lineNumber,
      snippet,
      context: `Job: \`${job.name ?? jobId}\`  ·  Has \`id-token: write\` but no \`environment:\``,
      detail: `Job \`${jobId}\` has \`id-token: write\` permission but no \`environment:\` declaration. Any workflow run that reaches this job can request an OIDC token. Without an environment gate, there are no deployment protection rules (required reviewers, wait timers) to prevent unauthorized token issuance.`,
      exploit: `Trigger the workflow. The job runs without requiring environment approval, issues an OIDC token, and can assume any cloud IAM role whose trust policy is scoped to this repository (rather than a specific protected environment).`,
      impact: 'Unauthorized OIDC Token Issuance → Cloud IAM Role Assumption',
      remediation: `Add an \`environment:\` declaration to the job:\n\njobs:\n  ${jobId}:\n    environment: production\n    permissions:\n      id-token: write\n\nThen scope your cloud IAM trust policy to \`repo:owner/repo:environment:production\`.`,
      cvss: {
        score: 7.7,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N',
        cwe: 'CWE-269',
      },
    });
  }

  return findings;
}
