import { findLineNumber, extractSnippet } from '../yaml-parser.js';

export function checkDependabotInsecureExecution(parsed, rawContent, filePath) {
  const findings = [];
  const updates = parsed?.updates;
  if (!Array.isArray(updates)) return findings;

  updates.forEach((update, idx) => {
    if (update?.['insecure-external-code-execution'] !== 'allow') return;

    const ecosystem = update?.['package-ecosystem'] ?? `entry ${idx}`;
    const lineNumber = findLineNumber(rawContent, 'insecure-external-code-execution');
    const snippet = extractSnippet(rawContent, lineNumber, 4);

    findings.push({
      id: `dependabot-insecure-execution-${filePath}-${idx}`,
      rule: 'dependabot-insecure-execution',
      severity: 'high',
      title: `Dependabot Allows Insecure External Code Execution (${ecosystem})`,
      file: filePath,
      line: lineNumber,
      snippet,
      context: `package-ecosystem: ${ecosystem}`,
      detail: `\`insecure-external-code-execution: allow\` permits Dependabot to execute code from third-party package managers (e.g., Bundler, npm postinstall scripts) during the dependency update process. This allows a malicious package author to run arbitrary code on GitHub's Dependabot infrastructure during version resolution or installation.`,
      exploit: `Publish a malicious package version that the target repo depends on. Include a postinstall script (for npm) or a Gemfile hook (for Bundler). When Dependabot opens a PR to update the dependency, it executes the malicious script with access to Dependabot's token and environment.`,
      impact: 'Remote Code Execution via Malicious Package in Dependabot Context',
      remediation: `Remove \`insecure-external-code-execution: allow\` from your \`dependabot.yml\`. If package manager scripts must run, isolate them in a sandboxed environment or use \`allow-conditions\` to restrict which dependencies can trigger updates.`,
      cvss: {
        score: 8.1,
        vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N',
        cwe: 'CWE-78',
      },
    });
  });

  return findings;
}
