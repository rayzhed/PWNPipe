import { findLineNumber, extractSnippet } from '../yaml-parser.js';

// Patterns that defeat GitHub Actions log redaction by passing secrets through transformations
const UNREDACTION_PATTERNS = [
  {
    re: /\$\{\{\s*toJSON\s*\(\s*secrets\s*\)\s*\}\}/i,
    label: 'toJSON(secrets) dumps all secrets as JSON — redaction fails',
  },
  {
    re: /\$\{\{\s*toPrettyJSON\s*\(\s*secrets\s*\)\s*\}\}/i,
    label: 'toPrettyJSON(secrets) dumps all secrets — redaction fails',
  },
  {
    re: /\$\{\{\s*format\s*\([^)]*secrets\.[a-zA-Z_][a-zA-Z0-9_]*[^)]*\)\s*\}\}/i,
    label: 'format() with secrets transforms the value, bypassing log masking',
  },
  {
    re: /\$\{\{\s*join\s*\([^)]*secrets\.[a-zA-Z_][a-zA-Z0-9_]*[^)]*\)\s*\}\}/i,
    label: 'join() with secrets can bypass log masking',
  },
];

function scanBlock(block) {
  if (!block || typeof block !== 'object') return null;
  const blockStr = JSON.stringify(block);
  for (const { re, label } of UNREDACTION_PATTERNS) {
    if (re.test(blockStr)) return { label, match: blockStr.match(re)?.[0] ?? '' };
  }
  return null;
}

export function checkUnredactedSecrets(workflow, rawContent, filename) {
  const findings = [];
  const seen = new Set();

  function addFinding(contextLabel, lineNumber, label, id) {
    if (seen.has(id)) return;
    seen.add(id);
    const snippet = extractSnippet(rawContent, lineNumber, 4);
    findings.push({
      id,
      rule: 'unredacted-secrets',
      severity: 'high',
      title: 'Secret Leak + Log Masking Bypassed',
      file: filename,
      line: lineNumber,
      snippet,
      context: contextLabel,
      detail: `${label}. GitHub Actions masks individual secret values in logs, but passing secrets through \`toJSON()\`, \`format()\`, or \`join()\` produces a new string the runner has never seen. That transformed value appears unmasked in the workflow logs.`,
      exploit: `Trigger the workflow and view the run's logs (public for public repos; requires read access for private repos). The secret value will appear unmasked in the log output. Additionally, \`toJSON(secrets)\` exposes every single secret in the repository in one call.`,
      impact: 'Full Secret Exposure in Logs',
      remediation: `Never pass secrets through expression functions. Reference secrets only directly in \`env:\` blocks:\n\nenv:\n  MY_SECRET: \${{ secrets.MY_SECRET }}\n\nNever use \`toJSON(secrets)\`, \`format()\`, or \`join()\` on secret values. To check if a secret exists, use \`secrets.MY_SECRET != ''\`.`,
      cvss: {
        score: 7.5,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
        cwe: 'CWE-532',
      },
    });
  }

  // Check workflow-level env
  const wfEnvResult = scanBlock(workflow?.env);
  if (wfEnvResult) {
    const ln = findLineNumber(rawContent, /toJSON\s*\(\s*secrets/i);
    addFinding('Workflow-level env', ln, wfEnvResult.label, `unredacted-secrets-${filename}-workflow-env`);
  }

  for (const [jobId, job] of Object.entries(workflow?.jobs ?? {})) {
    const jobEnvResult = scanBlock(job?.env);
    if (jobEnvResult) {
      const ln = findLineNumber(rawContent, /toJSON\s*\(\s*secrets/i);
      addFinding(`Job: \`${job.name ?? jobId}\`  ·  env`, ln, jobEnvResult.label, `unredacted-secrets-${filename}-${jobId}-env`);
    }

    const steps = Array.isArray(job.steps) ? job.steps : [];
    steps.forEach((step, idx) => {
      const stepEnvResult = scanBlock(step?.env);
      if (stepEnvResult) {
        const ln = findLineNumber(rawContent, /toJSON\s*\(\s*secrets/i);
        addFinding(
          `Job: \`${job.name ?? jobId}\`  ·  Step ${idx + 1}${step.name ? ` (${step.name})` : ''}  ·  env`,
          ln,
          stepEnvResult.label,
          `unredacted-secrets-${filename}-${jobId}-step${idx}-env`
        );
      }

      // Check run: block for inline usage
      if (typeof step.run === 'string') {
        for (const { re, label } of UNREDACTION_PATTERNS) {
          if (re.test(step.run)) {
            const ln = findLineNumber(rawContent, re);
            addFinding(
              `Job: \`${job.name ?? jobId}\`  ·  Step ${idx + 1}${step.name ? ` (${step.name})` : ''}  ·  run`,
              ln,
              label,
              `unredacted-secrets-${filename}-${jobId}-step${idx}-run`
            );
            break;
          }
        }
      }
    });
  }

  return findings;
}
