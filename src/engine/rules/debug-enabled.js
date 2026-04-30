import { findLineNumber, extractSnippet } from '../yaml-parser.js';

const DEBUG_VARS = [
  { key: 'ACTIONS_STEP_DEBUG', value: 'true' },
  { key: 'ACTIONS_RUNNER_DEBUG', value: 'true' },
];

function searchEnvBlock(envBlock, rawContent, filename) {
  const findings = [];
  if (!envBlock || typeof envBlock !== 'object') return findings;

  for (const { key, value } of DEBUG_VARS) {
    const envValue = String(envBlock[key] ?? '').toLowerCase();
    if (envValue !== 'true' && envValue !== '1') continue;

    const lineNumber = findLineNumber(rawContent, key);
    const snippet = extractSnippet(rawContent, lineNumber, 3);

    findings.push({
      id: `debug-enabled-${filename}-${key}`,
      rule: 'debug-enabled',
      severity: 'medium',
      title: `Debug Logging Enabled: ${key}`,
      file: `.github/workflows/${filename}`,
      line: lineNumber,
      snippet,
      context: `env variable: \`${key}: ${value}\``,
      detail: `\`${key}: true\` enables verbose debug logging in GitHub Actions. Debug logs include the full environment (all env vars), step inputs/outputs, and in some cases can expose secret values that would otherwise be masked.`,
      exploit: `Access the workflow run's debug logs (anyone with repo read access can view logs). Debug output may include secret values that GitHub's masking missed, full environment dumps, and internal tokens.`,
      impact: 'Potential Secret Exposure via Debug Logs',
      remediation: `Remove \`${key}: true\` from the workflow. Enable debug logging only temporarily when troubleshooting, using the repository's \`Actions secrets\` → \`ACTIONS_STEP_DEBUG\` setting, which avoids committing it to the workflow file.`,
      cvss: {
        score:  4.3,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N',
        cwe:    'CWE-532',
      },
    });
  }

  return findings;
}

export function checkDebugEnabled(workflow, rawContent, filename) {
  const findings = [];

  // Check workflow-level env
  findings.push(...searchEnvBlock(workflow?.env, rawContent, filename));

  // Check job-level and step-level env
  for (const [, job] of Object.entries(workflow?.jobs ?? {})) {
    findings.push(...searchEnvBlock(job?.env, rawContent, filename));
    const steps = Array.isArray(job.steps) ? job.steps : [];
    for (const step of steps) {
      findings.push(...searchEnvBlock(step?.env, rawContent, filename));
    }
  }

  // Deduplicate by id
  const seen = new Set();
  return findings.filter(f => {
    if (seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });
}
