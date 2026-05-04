import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// Known security-relevant action prefixes — continue-on-error on these masks real failures
const SECURITY_ACTIONS = [
  'github/codeql-action',
  'snyk/',
  'aquasecurity/trivy-action',
  'anchore/scan-action',
  'anchore/sbom-action',
  'returntocorp/semgrep-action',
  'SonarSource/sonarcloud-github-action',
  'dependency-check/',
  'trufflesecurity/trufflehog',
  'zricethezav/gitleaks-action',
  'ossf/scorecard-action',
  'bridgecrewio/checkov-action',
];

function isSecurityAction(uses) {
  if (!uses) return false;
  return SECURITY_ACTIONS.some(prefix => uses.startsWith(prefix));
}

export function checkContinueOnError(workflow, rawContent, filename) {
  const findings = [];
  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    const jobName = job.name ?? jobId;

    // Job-level continue-on-error: true
    if (job['continue-on-error'] === true) {
      const lineNumber = findLineNumber(rawContent, 'continue-on-error: true');
      const snippet = extractSnippet(rawContent, lineNumber, 4);
      findings.push({
        id:          `continue-on-error-job-${filename}-${jobId}`,
        rule:        'continue-on-error',
        severity:    'medium',
        title:       `Job \`${jobId}\` Has \`continue-on-error: true\` — All Failures Silenced`,
        file:        filename,
        line:        lineNumber,
        snippet,
        context:     `Job: \`${jobName}\`  ·  Job-level`,
        detail:      `\`continue-on-error: true\` at the job level causes GitHub Actions to mark the job as successful regardless of exit code. Any step failure — including supply chain compromises, injection attacks, or security scan findings — will be silently swallowed, and the workflow will report overall success.`,
        exploit:     `If any step in this job detects malicious activity (e.g., a secret scanner finds leaked credentials, or a step fails due to command injection), the pipeline still proceeds and reports success. This effectively blinds security tooling running in this job.`,
        impact:      'Security Failures Hidden — Pipeline Reports Success on Compromise',
        remediation: `Remove \`continue-on-error: true\` at the job level. If specific steps are expected to fail non-critically, apply \`continue-on-error\` only to those specific steps, not the entire job.`,
        cvss:        { score: 5.4, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N', cwe: 'CWE-390' },
      });
    }

    // Step-level continue-on-error: true on security tools
    const steps = job.steps;
    if (!Array.isArray(steps)) continue;

    for (let stepIndex = 0; stepIndex < steps.length; stepIndex++) {
      const step = steps[stepIndex];
      if (step['continue-on-error'] !== true) continue;
      if (!isSecurityAction(step.uses)) continue;

      const lineNumber = findLineNumber(rawContent, step.uses ?? 'continue-on-error');
      const snippet = extractSnippet(rawContent, lineNumber, 4);

      findings.push({
        id:          `continue-on-error-step-${filename}-${jobId}-${stepIndex}`,
        rule:        'continue-on-error',
        severity:    'low',
        title:       `Security Scan Step Has \`continue-on-error: true\` — Findings Will Not Block`,
        file:        filename,
        line:        lineNumber,
        snippet,
        context:     `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}  ·  \`${step.uses}\``,
        detail:      `The security scanning step \`${step.uses ?? ''}\` has \`continue-on-error: true\`. This means any findings reported by the scanner will not block the workflow from completing. High-severity vulnerabilities discovered by the scanner will be ignored and the pipeline will proceed to deploy or publish.`,
        exploit:     `An attacker introduces a dependency with a known CVE. The scanner detects it and exits with a non-zero code. Because \`continue-on-error: true\` is set, the pipeline continues — the vulnerable artifact gets deployed. The finding may appear in logs but never blocks the delivery.`,
        impact:      'Security Scanner Findings Not Enforced — Vulnerabilities Deployed',
        remediation: `Remove \`continue-on-error: true\` from the security scan step to allow it to block the pipeline on findings. If you need the pipeline to continue for informational-only scans, upload results to GitHub Code Scanning instead of relying on exit codes.`,
        cvss:        { score: 3.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N', cwe: 'CWE-390' },
      });
    }
  }

  return findings;
}
