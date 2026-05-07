import { findLineNumber, extractSnippet } from '../yaml-parser.js';

const HIGH_RISK_ECOSYSTEMS = new Set(['npm', 'pip', 'pip-compile', 'pipenv', 'poetry']);

export function checkDependabotMissingCooldown(parsed, rawContent, filePath) {
  const findings = [];

  const updates = parsed?.updates;
  if (!Array.isArray(updates)) return findings;

  for (let i = 0; i < updates.length; i++) {
    const entry = updates[i];
    const ecosystem = entry['package-ecosystem'];
    if (!HIGH_RISK_ECOSYSTEMS.has(ecosystem)) continue;
    if (entry.cooldown !== undefined && entry.cooldown !== null) continue;

    const directory = entry.directory ?? '/';
    const lineNumber = findLineNumber(rawContent, `package-ecosystem: ${ecosystem}`);
    const snippet = extractSnippet(rawContent, lineNumber, 4);

    findings.push({
      id: `dependabot-missing-cooldown-${filePath}-${i}`,
      rule: 'dependabot-missing-cooldown',
      severity: 'low',
      title: `Dependabot: No cooldown for \`${ecosystem}\` updates`,
      file: filePath,
      line: lineNumber,
      snippet,
      context: `package-ecosystem: ${ecosystem}  ·  directory: ${directory}`,
      detail: `The \`${ecosystem}\` updates entry has no \`cooldown:\` setting. Without a cooldown, Dependabot immediately proposes any newly published version, including packages from just-compromised maintainer accounts that haven't been yanked yet.`,
      exploit: `An attacker publishes a malicious version of a dependency (e.g., by compromising a maintainer's npm/PyPI account or via a typosquatting package). Without a cooldown, Dependabot opens a PR within minutes. If auto-merge is enabled, the malicious dependency reaches the codebase and CI secrets before the attack is discovered.`,
      impact: 'Supply chain compromise via immediate malicious version pickup',
      remediation: `Add a \`cooldown:\` block to delay version proposals by at least 24–72 hours, giving the community time to detect compromised releases:\n\nupdates:\n  - package-ecosystem: ${ecosystem}\n    directory: ${directory}\n    schedule:\n      interval: daily\n    cooldown:\n      semver-patch: "1 day"\n      semver-minor: "3 days"\n      semver-major: "7 days"`,
      cvss: {
        score:  3.1,
        vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
        cwe:    'CWE-1288',
      },
    });
  }

  return findings;
}
