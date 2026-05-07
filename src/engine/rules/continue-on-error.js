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
        title:       `Job \`${jobId}\` Has \`continue-on-error: true\``,
        file:        filename,
        line:        lineNumber,
        snippet,
        context:     `Job: \`${jobName}\`  ·  Job-level`,
        detail:      `\`continue-on-error: true\` at the job level makes GitHub Actions report the job as successful regardless of step exit codes. Every failure in this job is silently swallowed — the overall workflow shows green even if a security scan exits non-zero.`,
        exploit:     `If a step detects malicious activity (secret scanner finds leaked credentials, command injection causes a non-zero exit), the pipeline still proceeds and reports success. Security tooling in this job cannot block the pipeline.`,
        impact:      'Step Failures Ignored → Security Issues Not Enforced',
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
        title:       `Security Scan Step Has \`continue-on-error: true\``,
        file:        filename,
        line:        lineNumber,
        snippet,
        context:     `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}  ·  \`${step.uses}\``,
        detail:      `The security scanning step \`${step.uses ?? ''}\` has \`continue-on-error: true\`. Any findings the scanner reports will not block the workflow — the pipeline continues to deploy or publish regardless of severity.`,
        exploit:     `A dependency with a known CVE is introduced. The scanner exits with a non-zero code on detection. The pipeline continues regardless and the vulnerable artifact is deployed.`,
        impact:      'Security Scanner Findings Not Enforced',
        remediation: `Remove \`continue-on-error: true\` from the security scan step to allow it to block the pipeline on findings. If you need the pipeline to continue for informational-only scans, upload results to GitHub Code Scanning instead of relying on exit codes.`,
        cvss:        { score: 3.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N', cwe: 'CWE-390' },
      });
    }
  }

  return findings;
}
