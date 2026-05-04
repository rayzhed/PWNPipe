import { findLineNumber, extractSnippet } from '../yaml-parser.js';

const SECRET_PATTERNS = [
  { name: 'GitHub Personal Access Token (classic)',  regex: /ghp_[a-zA-Z0-9]{36}/g },
  { name: 'GitHub OAuth Token',                      regex: /gho_[a-zA-Z0-9]{36}/g },
  { name: 'GitHub Fine-Grained PAT',                 regex: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g },
  { name: 'GitHub App Token',                        regex: /ghs_[a-zA-Z0-9]{36}/g },
  { name: 'GitHub Refresh Token',                    regex: /ghr_[a-zA-Z0-9]{36}/g },
  { name: 'GitLab PAT',                              regex: /glpat-[a-zA-Z0-9\-_]{20,}/g },
  { name: 'AWS Access Key ID',                       regex: /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g },
  // AWS Secret Access Key: the 40-char base64 pattern is too broad on its own (git SHAs,
  // hashes, and random strings all match). We require it to appear directly after a known
  // credential context keyword to dramatically reduce false positives.
  {
    name: 'AWS Secret Access Key',
    regex: /(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey|secret_access_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/g,
    captureGroup: 1,
  },
  // OpenAI API keys — support all current formats (updated April 2024+):
  //   sk-proj-...   project-scoped keys (current standard)
  //   sk-svcacct-... service account keys
  //   sk-None-...   legacy user-level keys
  //   sk-...        fully legacy (48 alphanum chars)
  { name: 'OpenAI API Key',                          regex: /\bsk-(?:proj|svcacct|None)-[a-zA-Z0-9_\-]{20,200}/g },
  { name: 'OpenAI API Key (legacy)',                  regex: /\bsk-[a-zA-Z0-9]{48}\b/g },
  { name: 'Slack Bot/App Token',                     regex: /xoxb-[0-9A-Za-z\-]{50,}/g },
  { name: 'Slack User Token',                        regex: /xoxp-[0-9A-Za-z\-]{50,}/g },
  { name: 'npm Publish Token',                       regex: /npm_[a-zA-Z0-9]{36}/g },
  { name: 'Docker Hub Token',                        regex: /dckr_pat_[a-zA-Z0-9\-_]{27}/g },
  { name: 'PyPI API Token',                          regex: /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}/g },
  { name: 'Anthropic API Key',                       regex: /sk-ant-[a-zA-Z0-9\-_]{90,}/g },
];

function redact(secret) {
  if (secret.length <= 8) return '***';
  return secret.slice(0, 4) + '*'.repeat(secret.length - 8) + secret.slice(-4);
}

export function checkHardcodedSecrets(workflow, rawContent, filename) {
  const findings = [];

  for (const { name, regex, captureGroup } of SECRET_PATTERNS) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(rawContent)) !== null) {
      // For patterns with a captureGroup, the secret is in a specific capture group
      // rather than the full match (avoids including the surrounding keyword in the finding).
      const secret = captureGroup != null ? match[captureGroup] : match[0];
      if (!secret) continue;

      const lineNumber = findLineNumber(rawContent, secret.slice(0, 12));
      const snippet = extractSnippet(rawContent, lineNumber, 2).map(s =>
        s.highlight
          ? { ...s, content: s.content.replace(secret, redact(secret)) }
          : s
      );

      findings.push({
        id: `hardcoded-secrets-${filename}-${name.replace(/\s/g, '-')}-${lineNumber}`,
        rule: 'hardcoded-secrets',
        severity: 'critical',
        title: `Hardcoded Secret: ${name}`,
        file: filename,
        line: lineNumber,
        snippet,
        context: `Detected pattern: ${name}`,
        detail: `A credential matching the pattern for a ${name} appears to be hardcoded directly in the workflow file. Even in private repos, this token can be extracted by anyone with read access, and it persists in git history forever.`,
        exploit: `Clone the repo (or access git history), extract the token, and use it to authenticate as the service owner. For a GITHUB_TOKEN this means full API access. For cloud credentials, it means lateral movement through your entire cloud infrastructure.`,
        impact: 'Credential Theft + Unauthorized API Access',
        remediation: `1. Immediately revoke the exposed credential at the service provider.\n2. Remove it from the workflow file and all git history (use \`git filter-repo\` or BFG Repo-Cleaner).\n3. Store secrets in GitHub Secrets (Settings → Secrets) and reference them as \`\${{ secrets.MY_SECRET }}\`.`,
        cvss: {
          score:  9.1,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
          cwe:    'CWE-798',
        },
      });
    }
  }

  return findings;
}
