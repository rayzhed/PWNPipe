import { findLineNumber, extractSnippet } from '../yaml-parser.js';

const WRITE_PERMISSIONS = [
  'actions', 'checks', 'contents', 'deployments', 'discussions',
  'id-token', 'issues', 'packages', 'pages', 'pull-requests',
  'repository-projects', 'security-events', 'statuses',
];

function isWriteAll(perms) {
  // The object-with-all-write case was removed — it produced false positives on
  // legitimately scoped objects that happen to set all used keys to 'write'.
  // Overly-broad objects are still caught by countWritePerms() > 2 below.
  return typeof perms === 'string' && perms === 'write-all';
}

function countWritePerms(perms) {
  if (typeof perms !== 'object' || perms === null) return 0;
  return Object.values(perms).filter(v => v === 'write').length;
}

export function checkExcessivePermissions(workflow, rawContent, filename) {
  const findings = [];

  const workflowPerms = workflow?.permissions;
  const jobs = workflow?.jobs ?? {};

  // Case 1: No permissions block anywhere
  const hasWorkflowPerms = workflowPerms !== undefined && workflowPerms !== null;
  const allJobsHavePerms = Object.values(jobs).every(j => j.permissions !== undefined && j.permissions !== null);

  if (!hasWorkflowPerms && !allJobsHavePerms) {
    const lineNumber = findLineNumber(rawContent, /^on:/);
    const snippet = extractSnippet(rawContent, lineNumber, 2);
    findings.push({
      id: `excessive-permissions-missing-${filename}`,
      rule: 'excessive-permissions',
      severity: 'high',
      title: 'No permissions: block, GITHUB_TOKEN defaults to write-all',
      file: filename,
      line: lineNumber,
      snippet,
      context: 'Workflow-level',
      detail: `When no \`permissions:\` block is set and the repo hasn't restricted default token permissions, GITHUB_TOKEN defaults to write access on contents, issues, pull-requests, packages, and more.`,
      exploit: `An attacker who compromises any step in this workflow (via supply chain, template injection, or script injection) immediately gets a GITHUB_TOKEN with write access to push code, publish packages, create/modify releases, and write to issues and PRs.`,
      impact: 'Full repository write access via GITHUB_TOKEN compromise',
      remediation: `Add a least-privilege \`permissions:\` block at the top of the workflow:\n\npermissions:\n  contents: read\n\nGrant additional permissions only to the specific jobs that require them.`,
      cvss: {
        score:  7.5,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
        cwe:    'CWE-269',
      },
    });
    return findings;
  }

  // Case 2: write-all explicitly set
  if (isWriteAll(workflowPerms)) {
    const lineNumber = findLineNumber(rawContent, 'write-all');
    const snippet = extractSnippet(rawContent, lineNumber, 3);
    findings.push({
      id: `excessive-permissions-write-all-${filename}`,
      rule: 'excessive-permissions',
      severity: 'high',
      title: 'Explicit write-all permissions on GITHUB_TOKEN',
      file: filename,
      line: lineNumber,
      snippet,
      context: 'Workflow-level',
      detail: `\`permissions: write-all\` grants write access to every GitHub API scope. This is the broadest possible token configuration.`,
      exploit: `Any compromised step (supply chain, template injection, malicious PR) gets a GITHUB_TOKEN with write access to everything: push code, publish packages, modify issues, create releases.`,
      impact: 'Full repository write access via GITHUB_TOKEN',
      remediation: `Replace with a minimal set of permissions. Most workflows only need:\n\npermissions:\n  contents: read`,
      cvss: {
        score:  7.1,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
        cwe:    'CWE-269',
      },
    });
  }

  // Case 3: Overly broad per-job permissions
  for (const [jobId, job] of Object.entries(jobs)) {
    const perms = job.permissions;
    if (!perms) continue;
    if (isWriteAll(perms)) {
      const lineNumber = findLineNumber(rawContent, 'write-all');
      const snippet = extractSnippet(rawContent, lineNumber, 3);
      findings.push({
        id: `excessive-permissions-job-write-all-${filename}-${jobId}`,
        rule: 'excessive-permissions',
        severity: 'high',
        title: `Job \`${jobId}\`: write-all permissions on GITHUB_TOKEN`,
        file: filename,
        line: lineNumber,
        snippet,
        context: `Job: \`${job.name ?? jobId}\``,
        detail: `Job \`${jobId}\` explicitly sets \`permissions: write-all\`, granting full write access to every GitHub API scope.`,
        exploit: `Any compromised step in this job gets a fully-privileged GITHUB_TOKEN.`,
        impact: 'Full GITHUB_TOKEN write access within job scope',
        remediation: `Restrict to the minimum required permissions for this specific job.`,
        cvss: {
          score:  7.1,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
          cwe:    'CWE-269',
        },
      });
    } else if (countWritePerms(perms) > 2) {
      const lineNumber = findLineNumber(rawContent, `${jobId}:`);
      const snippet = extractSnippet(rawContent, lineNumber, 5);
      findings.push({
        id: `excessive-permissions-job-broad-${filename}-${jobId}`,
        rule: 'excessive-permissions',
        severity: 'medium',
        title: `Job \`${jobId}\`: Overly broad GITHUB_TOKEN permissions`,
        file: filename,
        line: lineNumber,
        snippet,
        context: `Job: \`${job.name ?? jobId}\``,
        detail: `Job \`${jobId}\` grants write access to ${countWritePerms(perms)} permission scopes. Principle of least privilege is not followed.`,
        exploit: `A compromised step in this job can use the GITHUB_TOKEN to write to multiple resource types.`,
        impact: 'Overprivileged GITHUB_TOKEN',
        remediation: `Audit each \`write\` permission and remove those not strictly required by this job.`,
        cvss: {
          score:  5.4,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',
          cwe:    'CWE-269',
        },
      });
    }
  }

  return findings;
}
