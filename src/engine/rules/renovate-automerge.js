import { findLineNumber, extractSnippet } from '../yaml-parser.js';

// Check renovate.json / renovate.json5 for dangerous configuration options.
// Called with parsed JSON object (not YAML) and raw content string.

export function checkRenovateAutomerge(parsed, rawContent, filePath) {
  if (!parsed || typeof parsed !== 'object') return [];

  const findings = [];

  // automerge: true — PRs merged without human review
  if (parsed.automerge === true || parsed.platformAutomerge === true) {
    const key = parsed.automerge === true ? 'automerge' : 'platformAutomerge';
    const lineNumber = findLineNumber(rawContent, `"${key}"`);
    const snippet = extractSnippet(rawContent, lineNumber, 4);
    findings.push({
      id:          `renovate-automerge-${filePath}`,
      rule:        'renovate-automerge',
      severity:    'medium',
      title:       'Renovate Auto-Merge Enabled',
      file:        filePath,
      line:        lineNumber,
      snippet,
      context:     `\`${key}: true\``,
      detail:      `Renovate is configured with \`${key}: true\`. Dependency update PRs merge automatically without review. A malicious package version or a typosquatting package on a supported registry merges straight to the default branch, running attacker-controlled code in CI.`,
      exploit:     `An attacker publishes a malicious version of a dependency or a typosquatting package. Renovate opens a PR and it merges automatically. The malicious package runs in CI with access to all secrets. No reviewer sees the PR.`,
      impact:      'Malicious Dependency Auto-Merged Without Review',
      remediation: `Disable \`automerge\` or restrict it to patch-only updates with additional safeguards:\n\n"automergeType": "pr",\n"automergeStrategy": "squash",\n"stabilityDays": 3,\n"requiredStatusChecks": ["ci/security-scan"]\n\nConsider requiring at least one human approval even for patch updates.`,
      cvss:        { score: 6.3, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N', cwe: 'CWE-1188' },
    });
  }

  // allowedPostUpgradeCommands — arbitrary shell commands run after upgrade
  const cmds = parsed.allowedPostUpgradeCommands;
  if (Array.isArray(cmds) && cmds.length > 0) {
    const lineNumber = findLineNumber(rawContent, 'allowedPostUpgradeCommands');
    const snippet = extractSnippet(rawContent, lineNumber, 6);
    findings.push({
      id:          `renovate-post-upgrade-cmds-${filePath}`,
      rule:        'renovate-automerge',
      severity:    'high',
      title:       'Renovate `allowedPostUpgradeCommands` Enables Arbitrary Shell Execution',
      file:        filePath,
      line:        lineNumber,
      snippet,
      context:     `${cmds.length} command pattern(s) allowed`,
      detail:      `\`allowedPostUpgradeCommands\` configures shell commands that Renovate may execute after dependency upgrades. These commands run in CI with full workspace and secret access. Overly broad patterns (e.g., \`".*"\`) let a malicious package trigger arbitrary command execution.`,
      exploit:     `A malicious package version includes a Renovate \`postUpgradeTasks\` config that matches one of the allowed patterns. When Renovate processes the update, it runs the attacker-specified command in CI with secret access.`,
      impact:      'Arbitrary Code Execution in CI via Post-Upgrade Commands',
      remediation: `Restrict \`allowedPostUpgradeCommands\` to the absolute minimum set of specific commands needed. Avoid glob patterns that match arbitrary commands. Prefer \`"^npm run build$"\` over \`".*"\`.`,
      cvss:        { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N', cwe: 'CWE-78' },
    });
  }

  // dangerousAlwaysWriteToDefaultBranch — bypasses PR process entirely
  if (parsed.dangerousAlwaysWriteToDefaultBranch === true) {
    const lineNumber = findLineNumber(rawContent, 'dangerousAlwaysWriteToDefaultBranch');
    const snippet = extractSnippet(rawContent, lineNumber, 4);
    findings.push({
      id:          `renovate-direct-push-${filePath}`,
      rule:        'renovate-automerge',
      severity:    'high',
      title:       'Renovate `dangerousAlwaysWriteToDefaultBranch` Enabled (Direct Push to Default Branch)',
      file:        filePath,
      line:        lineNumber,
      snippet,
      context:     'dangerousAlwaysWriteToDefaultBranch: true',
      detail:      `\`dangerousAlwaysWriteToDefaultBranch: true\` makes Renovate push dependency updates directly to the default branch without opening a PR. Any dependency update, including a malicious one, lands on the branch immediately with no review or CI validation.`,
      exploit:     `A malicious package version is published. Renovate pushes the update straight to \`main\`, potentially bypassing branch protection. No reviewer sees the change before it reaches production.`,
      impact:      'Dependency Updates Pushed Directly to Default Branch Without Review',
      remediation: `Remove \`dangerousAlwaysWriteToDefaultBranch\`. Always use PRs for dependency updates so they are subject to branch protection rules, required reviews, and CI checks.`,
      cvss:        { score: 7.2, vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N', cwe: 'CWE-284' },
    });
  }

  return findings;
}
