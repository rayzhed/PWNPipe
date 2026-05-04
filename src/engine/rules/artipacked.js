import { findLineNumber, extractSnippet } from '../yaml-parser.js';

// Returns true if the artifact upload path includes the workspace root (and therefore
// the .git/ directory). Specific subdirectory uploads (dist/, build/, etc.) do not
// expose the embedded GITHUB_TOKEN and should not be flagged.
function uploadPathIncludesGitDir(pathValue) {
  if (pathValue === undefined || pathValue === null || pathValue === '') return true;
  const p = String(pathValue).trim();
  if (p === '.' || p === './') return true;
  if (p.includes('github.workspace') || p.includes('runner.workspace')) return true;
  // Any path starting with .git or containing **/.git suggests direct git dir access
  if (p.startsWith('.git')) return true;
  return false;
}

export function checkArtipacked(workflow, rawContent, filename) {
  const findings = [];
  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    const steps = Array.isArray(job.steps) ? job.steps : [];

    const checkoutStep = steps.find(s =>
      typeof s.uses === 'string' && s.uses.startsWith('actions/checkout')
    );
    if (!checkoutStep) continue;

    const persistCreds = checkoutStep.with?.['persist-credentials'];
    if (persistCreds === false || persistCreds === 'false') continue;

    const uploadStep = steps.find(s =>
      typeof s.uses === 'string' && s.uses.startsWith('actions/upload-artifact')
    );
    if (!uploadStep) continue;

    // Only flag if the upload path could include .git/ — uploading dist/ or build/
    // does not expose the embedded token (Artipacked is specifically about .git/config).
    if (!uploadPathIncludesGitDir(uploadStep.with?.path)) continue;

    const lineNumber = findLineNumber(rawContent, 'upload-artifact');
    const snippet = extractSnippet(rawContent, lineNumber, 4);

    findings.push({
      id: `artipacked-${filename}-${jobId}`,
      rule: 'artipacked',
      severity: 'medium',
      title: 'Artipacked: Git Credentials May Leak via Artifact',
      file: filename,
      line: lineNumber,
      snippet,
      context: `Job: \`${job.name ?? jobId}\``,
      detail: `\`actions/checkout\` without \`persist-credentials: false\` stores the GITHUB_TOKEN in \`.git/config\`. The workspace is then uploaded as an artifact, so anyone who downloads it gets the embedded token.`,
      exploit: `Download the artifact from the workflow run (GitHub UI or API), then read \`.git/config\` to extract the embedded GITHUB_TOKEN. The token may still be valid.`,
      impact: 'GITHUB_TOKEN Leak via Downloadable Artifact',
      remediation: `Add \`persist-credentials: false\` to your checkout step:\n\n- uses: actions/checkout@<sha>\n  with:\n    persist-credentials: false`,
      cvss: {
        score:  6.5,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
        cwe:    'CWE-312',
      },
    });
  }

  return findings;
}
