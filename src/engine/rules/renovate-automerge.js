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
      title:       'Renovate Auto-Merge Enabled — Dependency Updates Bypass Review',
      file:        filePath,
      line:        lineNumber,
      snippet,
      context:     `\`${key}: true\``,
      detail:      `Renovate is configured with \`${key}: true\`. Dependency update PRs will be automatically merged without human review. A malicious package version or a typosquatting package on a supported registry can be automatically merged into the default branch, triggering CI pipelines with attacker-controlled code.`,
      exploit:     `An attacker publishes a patched version of a dependency (or a typosquatting package). Renovate opens a PR. With auto-merge enabled, the PR lands on \`main\` automatically — the malicious package runs in CI with access to all secrets. No reviewer ever sees the PR.`,
      impact:      'Supply Chain — Malicious Dependency Auto-Merged Without Review',
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
      detail:      `\`allowedPostUpgradeCommands\` configures shell commands that Renovate may execute after dependency upgrades. These commands run in the CI environment with access to the workspace and potentially secrets. If the allowed patterns are too broad (e.g., \`".*"\`) or a malicious package includes a Renovate post-upgrade script, arbitrary commands execute in CI.`,
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
      title:       'Renovate `dangerousAlwaysWriteToDefaultBranch` — Direct Push to Default Branch',
      file:        filePath,
      line:        lineNumber,
      snippet,
      context:     'dangerousAlwaysWriteToDefaultBranch: true',
      detail:      `\`dangerousAlwaysWriteToDefaultBranch: true\` instructs Renovate to push dependency updates directly to the default branch, bypassing the PR review process entirely. Any dependency update — including a malicious one — lands immediately on the protected branch without review or CI validation.`,
      exploit:     `A malicious package version is published. Renovate pushes the update directly to \`main\`. Branch protection rules are bypassed (Renovate may have elevated permissions). No reviewer sees the change before it reaches production.`,
      impact:      'Direct Push to Default Branch — Bypasses All PR Controls',
      remediation: `Remove \`dangerousAlwaysWriteToDefaultBranch\`. Always use PRs for dependency updates so they are subject to branch protection rules, required reviews, and CI checks.`,
      cvss:        { score: 7.2, vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N', cwe: 'CWE-284' },
    });
  }

  return findings;
}
