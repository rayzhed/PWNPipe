import { findLineNumber, extractSnippet } from '../yaml-parser.js';

const SHA40_RE = /^[a-f0-9]{40}$/;

// Languages that execute arbitrary system commands
const DANGEROUS_LANGUAGES = new Set(['system', 'script']);

export function checkPreCommitUnsafe(parsed, rawContent, filePath) {
  if (!parsed || !Array.isArray(parsed.repos)) return [];

  const findings = [];

  for (const repo of parsed.repos) {
    // Local hooks with system-level execution
    if (repo.repo === 'local') {
      if (!Array.isArray(repo.hooks)) continue;
      for (const hook of repo.hooks) {
        if (!DANGEROUS_LANGUAGES.has(hook.language)) continue;
        const entry = hook.entry ?? '';
        const lineNumber = findLineNumber(rawContent, entry) || findLineNumber(rawContent, 'language: system');
        const snippet = extractSnippet(rawContent, lineNumber, 5);
        findings.push({
          id:          `pre-commit-local-system-${filePath}-${hook.id ?? entry}`,
          rule:        'pre-commit-unsafe',
          severity:    'medium',
          title:       `Pre-commit Local Hook with \`language: ${hook.language}\` Executes Arbitrary System Commands`,
          file:        filePath,
          line:        lineNumber,
          snippet,
          context:     `Hook: \`${hook.id ?? 'unknown'}\`  ·  Entry: \`${entry}\``,
          detail:      `The local pre-commit hook \`${hook.id ?? entry}\` uses \`language: ${hook.language}\`, which runs the \`entry\` command directly against the host OS without any sandboxing. If this hook is triggered in CI against untrusted code (e.g., via a \`pull_request\` workflow that checks out the PR branch), the hook executes attacker-supplied shell scripts in the CI environment.`,
          exploit:     `An attacker submits a PR that modifies \`.pre-commit-config.yaml\` to change the \`entry\` of a local system hook to a malicious script, or the hook's \`entry\` references a file in the repo that the attacker controls. When CI runs pre-commit on the untrusted branch, the attacker's code executes with full CI secret access.`,
          impact:      'Arbitrary Code Execution in CI via Malicious Pre-commit Hook',
          remediation: `Avoid \`language: system\` or \`language: script\` in local hooks. Use \`language: python\`, \`language: node\`, or another sandboxed language. Pin external hook repos to SHA commits. If \`system\` is unavoidable, ensure the entry script is not modifiable by PR contributors.`,
          cvss:        { score: 7.0, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N', cwe: 'CWE-78' },
        });
      }
      continue;
    }

    // External repos not pinned to a SHA commit
    const rev = repo.rev ?? '';
    if (!rev) continue;
    if (SHA40_RE.test(rev)) continue; // pinned — safe

    const lineNumber = findLineNumber(rawContent, `rev: ${rev}`) || findLineNumber(rawContent, rev);
    const snippet = extractSnippet(rawContent, lineNumber, 5);
    findings.push({
      id:          `pre-commit-unpinned-${filePath}-${repo.repo}-${rev}`,
      rule:        'pre-commit-unsafe',
      severity:    'low',
      title:       `Pre-commit Hook Repo Not Pinned to SHA: \`${repo.repo}@${rev}\``,
      file:        filePath,
      line:        lineNumber,
      snippet,
      context:     `Repo: \`${repo.repo}\`  ·  Rev: \`${rev}\``,
      detail:      `The pre-commit hook repo \`${repo.repo}\` is pinned to \`${rev}\` (a tag or branch), not a full commit SHA. If the tag is force-moved or the branch updated with malicious code, the next CI run will execute the new version without any diff visible in this repo.`,
      exploit:     `An attacker with write access to \`${repo.repo}\` force-moves the \`${rev}\` tag to a commit with a malicious hook. The next CI run installs and runs it with secret access.`,
      impact:      'Unpinned Hook Repo Can Silently Change',
      remediation: `Pin to a full SHA commit:\n\n- repo: ${repo.repo}\n  rev: <FULL_40_CHAR_SHA>  # ${rev}\n\nVerify the SHA at the time of pinning corresponds to the intended version.`,
      cvss:        { score: 4.2, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N', cwe: 'CWE-829' },
    });
  }

  return findings;
}
