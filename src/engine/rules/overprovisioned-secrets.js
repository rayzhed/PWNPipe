import { findLineNumber, extractSnippet } from '../yaml-parser.js';

const TOJSON_SECRETS_RE = /\$\{\{\s*toJSON\s*\(\s*secrets\s*\)\s*\}\}/i;
const SECRETS_CONTEXT_RE = /\$\{\{\s*secrets\s*\}\}/i;

function scanForPattern(str) {
  if (typeof str !== 'string') return false;
  return TOJSON_SECRETS_RE.test(str) || SECRETS_CONTEXT_RE.test(str);
}

function scanEnvBlock(envBlock) {
  if (!envBlock || typeof envBlock !== 'object') return false;
  return Object.values(envBlock).some(v => scanForPattern(String(v ?? '')));
}

export function checkOverprovisionedSecrets(workflow, rawContent, filename) {
  const findings = [];
  const seen = new Set();

  const lineNumber = findLineNumber(rawContent, TOJSON_SECRETS_RE) ||
    findLineNumber(rawContent, SECRETS_CONTEXT_RE);

  function add(id, contextLabel, detail) {
    if (seen.has(id)) return;
    seen.add(id);
    const snippet = extractSnippet(rawContent, lineNumber, 4);
    findings.push({
      id,
      rule: 'overprovisioned-secrets',
      severity: 'high',
      title: 'Entire Secrets Context Passed to Environment',
      file: filename,
      line: lineNumber,
      snippet,
      context: contextLabel,
      detail,
      exploit: `Any code running in the affected step or subsequent steps has access to every repository secret via environment variables. An attacker who achieves code execution (template injection, supply chain) can enumerate and exfiltrate every secret with a single command: \`env | grep -v '^_'\`.`,
      impact: 'Full Repository Secret Exfiltration via Overprovisioned Environment',
      remediation: `Only pass the specific secrets each job or step needs:\n\nenv:\n  ONLY_THIS_SECRET: \${{ secrets.MY_SPECIFIC_SECRET }}\n\nNever pass \`toJSON(secrets)\` or the bare \`secrets\` context to env blocks or run scripts.`,
      cvss: {
        score: 7.5,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
        cwe: 'CWE-200',
      },
    });
  }

  // Workflow-level env
  if (scanEnvBlock(workflow?.env)) {
    add(
      `overprovisioned-secrets-${filename}-workflow-env`,
      'Workflow-level env',
      '`toJSON(secrets)` or the bare `secrets` context is passed to the workflow-level `env:` block, injecting every repository secret into the environment of every step in every job.'
    );
  }

  // Job and step envs, plus run: blocks
  for (const [jobId, job] of Object.entries(workflow?.jobs ?? {})) {
    if (scanEnvBlock(job?.env)) {
      add(
        `overprovisioned-secrets-${filename}-${jobId}-env`,
        `Job: \`${job.name ?? jobId}\`  ·  env`,
        `\`toJSON(secrets)\` or the bare \`secrets\` context is passed to job \`${jobId}\`'s \`env:\` block, making every repository secret available as environment variables to all steps in the job.`
      );
    }
    const steps = Array.isArray(job.steps) ? job.steps : [];
    steps.forEach((step, idx) => {
      if (scanEnvBlock(step?.env)) {
        add(
          `overprovisioned-secrets-${filename}-${jobId}-step${idx}-env`,
          `Job: \`${job.name ?? jobId}\`  ·  Step ${idx + 1}${step.name ? ` (${step.name})` : ''}  ·  env`,
          `\`toJSON(secrets)\` or the bare \`secrets\` context is passed to step ${idx + 1}'s \`env:\` block in job \`${jobId}\`, exposing all secrets as environment variables.`
        );
      }
      if (typeof step.run === 'string' && scanForPattern(step.run)) {
        add(
          `overprovisioned-secrets-${filename}-${jobId}-step${idx}-run`,
          `Job: \`${job.name ?? jobId}\`  ·  Step ${idx + 1}${step.name ? ` (${step.name})` : ''}  ·  run`,
          `\`toJSON(secrets)\` or the bare \`secrets\` context is used directly in a \`run:\` block in job \`${jobId}\` step ${idx + 1}, printing or passing all secrets to the shell.`
        );
      }
    });
  }

  return findings;
}
