import { findLineNumber, extractSnippet } from '../yaml-parser.js';

export function checkSecretsInherit(workflow, rawContent, filename) {
  const findings = [];
  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    if (!job.uses || job.secrets !== 'inherit') continue;

    // Same-repository reusable workflows (uses: ./.github/workflows/...) are much
    // lower risk — the called workflow is already in the same trust boundary and
    // visible in the same repo's git history. Flag as low severity only.
    const isSameRepo = typeof job.uses === 'string' && job.uses.startsWith('./');
    const severity = isSameRepo ? 'low' : 'medium';

    const lineNumber = findLineNumber(rawContent, 'secrets: inherit') ||
      findLineNumber(rawContent, "secrets: 'inherit'");
    const snippet = extractSnippet(rawContent, lineNumber, 4);

    findings.push({
      id: `secrets-inherit-${filename}-${jobId}`,
      rule: 'secrets-inherit',
      severity,
      title: isSameRepo
        ? 'secrets: inherit to Same-Repository Reusable Workflow'
        : 'secrets: inherit Passes All Secrets to Reusable Workflow',
      file: filename,
      line: lineNumber,
      snippet,
      context: `Job: \`${job.name ?? jobId}\`  ·  Calls: \`${job.uses}\``,
      detail: isSameRepo
        ? `\`secrets: inherit\` passes every caller secret to the reusable workflow at \`${job.uses}\`. Because the workflow is in the same repository, the risk is contained within the same trust boundary, but unnecessarily broad secret access is still a hygiene issue.`
        : `\`secrets: inherit\` passes every secret from the calling workflow to the reusable workflow at \`${job.uses}\`. If the reusable workflow is in a different repo or maintained by a third party, all your secrets are exposed to it.`,
      exploit: isSameRepo
        ? `Any vulnerability in \`${job.uses}\` (template injection, supply chain) gains access to all caller secrets, not just those it legitimately needs.`
        : `If the reusable workflow gets compromised (supply chain, maintainer account), every inherited secret (tokens, API keys, deployment credentials) is immediately accessible to the attacker.`,
      impact: isSameRepo
        ? 'Overly Broad Secret Access Within Same Repository'
        : 'All Caller Secrets Exposed to Third-Party Reusable Workflow',
      remediation: `Pass only the specific secrets the reusable workflow needs:\n\nsecrets:\n  SPECIFIC_SECRET: \${{ secrets.SPECIFIC_SECRET }}\n\nAudit the reusable workflow to determine exactly which secrets it requires.`,
      cvss: isSameRepo
        ? { score: 3.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', cwe: 'CWE-200' }
        : { score: 6.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', cwe: 'CWE-200' },
    });
  }

  return findings;
}
