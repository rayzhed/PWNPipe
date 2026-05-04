import { getTriggers, getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

const ARTIFACT_DOWNLOAD_ACTIONS = ['actions/download-artifact', 'dawidd6/action-download-artifact'];
const ENV_WRITE_RE = />>?\s*\$GITHUB_ENV|>>?\s*\$GITHUB_PATH/;

export function checkWorkflowRunArtifactEnvInjection(workflow, rawContent, filename) {
  const triggers = getTriggers(workflow);
  if (!triggers.includes('workflow_run')) return [];

  const findings = [];
  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    const steps = Array.isArray(job.steps) ? job.steps : [];

    const downloadStepIdx = steps.findIndex(s =>
      typeof s.uses === 'string' && ARTIFACT_DOWNLOAD_ACTIONS.some(a => s.uses.startsWith(a))
    );
    if (downloadStepIdx === -1) continue;

    // Look for a subsequent step that writes to GITHUB_ENV or GITHUB_PATH
    const envWriteStep = steps.slice(downloadStepIdx + 1).find(s =>
      typeof s.run === 'string' && ENV_WRITE_RE.test(s.run)
    );
    if (!envWriteStep) continue;

    const downloadStep = steps[downloadStepIdx];
    const lineNumber = findLineNumber(rawContent, downloadStep.uses.split('@')[0]) ||
      findLineNumber(rawContent, 'download-artifact');
    const snippet = extractSnippet(rawContent, lineNumber, 4);

    findings.push({
      id: `workflow-run-artifact-env-injection-${filename}-${jobId}`,
      rule: 'workflow-run-artifact-env-injection',
      severity: 'high',
      title: 'Artifact Content Written to GITHUB_ENV in workflow_run Context',
      file: filename,
      line: lineNumber,
      snippet,
      context: `Job: \`${job.name ?? jobId}\`  ·  Downloads artifact, then writes to \$GITHUB_ENV or \$GITHUB_PATH`,
      detail: `This workflow is triggered by \`workflow_run\` (privileged, has access to secrets) and downloads artifacts from the triggering run, then writes their content to \`$GITHUB_ENV\` or \`$GITHUB_PATH\`. A fork-submitted PR can run an unprivileged workflow that writes a poisoned artifact. The privileged \`workflow_run\` handler then downloads the artifact and injects attacker-controlled values into subsequent steps' environments.`,
      exploit: `1. Submit a PR from a fork. The unprivileged \`pull_request\` workflow writes a poisoned artifact file containing \`EVIL_VAR=attacker_value\` or a malicious binary path.\n2. The privileged \`workflow_run\` workflow triggers, downloads the artifact, and writes its contents to \`$GITHUB_ENV\`.\n3. All subsequent steps have the attacker's environment variables, enabling \`NODE_OPTIONS\` override, \`LD_PRELOAD\` injection, or PATH hijacking.`,
      impact: 'Environment Injection via Artifact Poisoning → Code Execution with Secrets Access',
      remediation: `1. Validate and sanitize artifact content before writing it to \`$GITHUB_ENV\` or \`$GITHUB_PATH\`.\n2. Use a strict allowlist of expected variable names and values.\n3. Never write raw artifact file content to env files — only write specific, validated key-value pairs.\n4. Consider using GitHub Actions OIDC or signed artifacts to verify the artifact source.`,
      cvss: {
        score: 8.8,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N',
        cwe: 'CWE-829',
      },
    });
  }

  return findings;
}
