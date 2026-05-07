import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// Patterns that print secrets or tokens directly to stdout.
// GitHub Actions masks *known* secret values in logs, but masking can be bypassed
// if the value is base64-encoded, URL-encoded, split across lines, or printed before
// the secret is registered with the runner.
const PATTERNS = [
  // echo ${{ secrets.ANYTHING }}
  { re: /echo\s+["']?\$\{\{\s*secrets\.[a-zA-Z_][a-zA-Z0-9_]*\s*\}\}["']?/, label: 'echoing secret expression' },
  // echo $GITHUB_TOKEN or echo "${GITHUB_TOKEN}"
  { re: /echo\s+["']?\$\{?GITHUB_TOKEN\}?["']?/, label: 'echoing GITHUB_TOKEN' },
  // cat, printf, print of GITHUB_TOKEN
  { re: /(?:cat|printf|print)\s[^#\n]*GITHUB_TOKEN/, label: 'printing GITHUB_TOKEN' },
  // Bare `env` command (dumps the entire environment including all secrets)
  // Only flag when `env` is used as a command, not `env VAR=val cmd` pattern
  { re: /(?:^|[\s;|&])(env)(?:\s*(?:&&|\|{1,2}|;|$))/, label: 'env command dumps all env vars' },
  // set -x or bash -x enables shell tracing, which echoes every command including secret values
  { re: /(?:^|[\s;|&])set\s+-[a-zA-Z]*x[a-zA-Z]*(?:\s|$)/, label: 'set -x enables shell tracing' },
  { re: /bash\s+-[a-zA-Z]*x[a-zA-Z]*\s/, label: 'bash -x enables shell tracing' },
];

export function checkTokenInLogs(workflow, rawContent, filename) {
  const findings = [];
  const steps = getAllSteps(workflow);

  for (const { jobId, jobName, step, stepIndex } of steps) {
    const run = step.run;
    if (typeof run !== 'string') continue;

    for (const { re, label } of PATTERNS) {
      const match = re.exec(run);
      if (!match) continue;

      const lineNumber = findLineNumber(rawContent, match[0].trim().slice(0, 25));
      const snippet    = extractSnippet(rawContent, lineNumber, 4);

      findings.push({
        id: `token-in-logs-${filename}-${jobId}-${stepIndex}-${label.slice(0, 20).replace(/\s/g, '-')}`,
        rule: 'token-in-logs',
        severity: 'medium',
        title: `Potential Secret Exposure in Logs: ${label}`,
        file: filename,
        line: lineNumber,
        snippet,
        context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}`,
        detail: `A \`run:\` block appears to print a secret, \`GITHUB_TOKEN\`, or the full environment to stdout. GitHub Actions masks registered secret values in logs, but base64-encoded, URL-encoded, or split values bypass masking — and \`set -x\` traces every expanded command verbatim.`,
        exploit: `Access the workflow run's logs (public for public repos; requires read access for private repos). Search for unmasked token values or decode base64 output. For shell tracing (\`set -x\`), every command line — including those with expanded secret values — appears verbatim in the trace output.`,
        impact: 'Secret or Token Exposure via Workflow Run Logs',
        remediation: `Never echo secrets or tokens directly. To check if a secret is set without printing it:\n\nif [ -n "\${{ secrets.MY_SECRET }}" ]; then echo "Secret is set (length \${#MY_SECRET})"; fi\n\nRemove \`set -x\` and bare \`env\` calls from production workflows. For \`GITHUB_TOKEN\`, use \`GITHUB_ACTIONS=true\` to detect CI context instead of printing the token.`,
        cvss: {
          score:  6.5,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
          cwe:    'CWE-532',
        },
      });
      break; // one finding per step
    }
  }

  return findings;
}
