import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

const SECRET_IN_RUN_RE = /\$\{\{\s*secrets\.[a-zA-Z_][a-zA-Z0-9_]*\s*\}\}/g;

export function checkSecretsOutsideEnv(workflow, rawContent, filename) {
  const findings = [];
  const steps = getAllSteps(workflow);

  for (const { jobId, jobName, step, stepIndex } of steps) {
    const run = step.run;
    if (typeof run !== 'string') continue;

    SECRET_IN_RUN_RE.lastIndex = 0;
    let match;
    while ((match = SECRET_IN_RUN_RE.exec(run)) !== null) {
      const expr = match[0];

      // Extract the secret name from the expression
      const secretName = expr.replace(/\$\{\{\s*secrets\./, '').replace(/\s*\}\}/, '').trim();

      // Check if the same secret is already mapped through env: — if so, the direct
      // usage in run: is still the problem because env: mapping doesn't help when the
      // expression itself is in the run: block.
      const lineNumber = findLineNumber(rawContent, expr.slice(0, 30));
      const snippet = extractSnippet(rawContent, lineNumber, 4);

      findings.push({
        id: `secrets-outside-env-${filename}-${jobId}-${stepIndex}-${secretName}`,
        rule: 'secrets-outside-env',
        severity: 'medium',
        title: `Secret Interpolated Directly in run: Block`,
        file: filename,
        line: lineNumber,
        snippet,
        context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}  ·  Secret: \`secrets.${secretName}\``,
        detail: `\`\${{ secrets.${secretName} }}\` is interpolated directly into the \`run:\` shell script. GitHub Actions masks registered secret values in logs, but masking can be defeated by string transformations (e.g., base64, URL encoding, character splitting).`,
        exploit: `An attacker with access to shell execution (via another vulnerability such as template injection) can extract the secret by encoding it: \`echo $SECRET | xxd | head\`. The masking only applies to the exact string value, not derivatives.`,
        impact: 'Secret Log Exposure via Masking Bypass',
        remediation: `Map secrets through \`env:\` and reference the env var in your shell script:\n\nenv:\n  MY_SECRET: \${{ secrets.${secretName} }}\nrun: |\n  echo "Using secret: $MY_SECRET"  # still masked in logs\n\nThis doesn't prevent log exposure but follows the least-exposure principle and avoids shell expansion issues.`,
        cvss: {
          score: 4.3,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
          cwe: 'CWE-532',
        },
      });
    }
  }

  return findings;
}
