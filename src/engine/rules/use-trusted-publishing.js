import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

const SECRET_REF_RE = /\$\{\{\s*secrets\.\w+\s*\}\}/;

function hasIdTokenWrite(workflow) {
  function check(perms) {
    if (!perms || typeof perms !== 'object') return false;
    return perms['id-token'] === 'write';
  }
  if (check(workflow.permissions)) return true;
  for (const job of Object.values(workflow.jobs ?? {})) {
    if (check(job.permissions)) return true;
  }
  return false;
}

function envHasSecretRef(envBlock, ...keys) {
  if (!envBlock || typeof envBlock !== 'object') return null;
  for (const key of keys) {
    const val = String(envBlock[key] ?? '');
    if (SECRET_REF_RE.test(val)) return key;
  }
  return null;
}

function collectStepEnv(step, workflow, jobId) {
  const merged = {};
  const wfEnv = workflow.env ?? {};
  const job = (workflow.jobs ?? {})[jobId] ?? {};
  const jobEnv = job.env ?? {};
  const stepEnv = step.env ?? {};
  Object.assign(merged, wfEnv, jobEnv, stepEnv);
  return merged;
}

export function checkUseTrustedPublishing(workflow, rawContent, filename) {
  const findings = [];

  const alreadyOidc = hasIdTokenWrite(workflow);
  const steps = getAllSteps(workflow);

  for (const { jobId, jobName, step, stepIndex } of steps) {
    const uses = (step.uses ?? '').split('@')[0];
    const run = step.run ?? '';
    const stepWith = step.with ?? {};
    const env = collectStepEnv(step, workflow, jobId);

    // PyPI via gh-action-pypi-publish with long-lived token
    if (uses === 'pypa/gh-action-pypi-publish') {
      if (alreadyOidc) continue;
      const passwordVal = String(stepWith.password ?? stepWith.token ?? '');
      if (!SECRET_REF_RE.test(passwordVal)) continue;

      const lineNumber = findLineNumber(rawContent, 'pypa/gh-action-pypi-publish');
      const snippet = extractSnippet(rawContent, lineNumber, 4);
      findings.push({
        id: `use-trusted-publishing-pypi-${filename}-${jobId}-${stepIndex}`,
        rule: 'use-trusted-publishing',
        severity: 'medium',
        title: 'PyPI publish using long-lived API token instead of OIDC',
        file: filename,
        line: lineNumber,
        snippet,
        context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}`,
        detail: `The step publishes to PyPI using a long-lived API token stored as a secret (\`${passwordVal}\`). Long-lived tokens are a persistent credential that can be leaked, stolen, or remain valid long after they should have been rotated. PyPI supports OIDC Trusted Publishing which issues short-lived tokens scoped to the workflow run — no stored secret required.`,
        exploit: `If the repository secrets are ever exposed (e.g., via a template injection, a malicious pull request with access to secrets, or a GitHub breach), the long-lived PyPI token can be used to publish malicious package versions indefinitely until it's manually revoked.`,
        impact: 'Long-lived credential exposure enabling supply chain attack via malicious package publish',
        remediation: `Configure PyPI Trusted Publishing for this repository at https://pypi.org/manage/account/publishing/ and update the workflow:\n\npermissions:\n  id-token: write\n\n- uses: pypa/gh-action-pypi-publish@<sha>\n  # No password: needed with Trusted Publishing`,
        cvss: {
          score:  5.9,
          vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
          cwe:    'CWE-522',
        },
      });
      continue;
    }

    // npm publish with long-lived token
    if (/\bnpm\s+publish\b/.test(run) || /\bnpx\s+npm\s+publish\b/.test(run)) {
      if (alreadyOidc) continue;
      const tokenKey = envHasSecretRef(env, 'NPM_TOKEN', 'NODE_AUTH_TOKEN');
      if (!tokenKey) continue;

      const lineNumber = findLineNumber(rawContent, /\bnpm\s+publish\b/);
      const snippet = extractSnippet(rawContent, lineNumber, 4);
      findings.push({
        id: `use-trusted-publishing-npm-${filename}-${jobId}-${stepIndex}`,
        rule: 'use-trusted-publishing',
        severity: 'medium',
        title: 'npm publish using long-lived token instead of OIDC provenance',
        file: filename,
        line: lineNumber,
        snippet,
        context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}  ·  Token key: ${tokenKey}`,
        detail: `The step publishes to npm using a long-lived \`${tokenKey}\` stored as a secret. Long-lived npm tokens remain valid until manually revoked and can be used to publish packages from any machine if leaked. npm supports OIDC-based provenance publishing (--provenance flag) which scopes tokens to a single workflow run.`,
        exploit: `If \`${tokenKey}\` is leaked (supply chain attack, template injection, or GitHub secret exposure), an attacker can publish malicious versions of the npm package without any further access to the repository.`,
        impact: 'Long-lived credential exposure enabling supply chain attack via malicious npm package publish',
        remediation: `Configure npm OIDC publishing and update the workflow:\n\npermissions:\n  id-token: write\n\n- run: npm publish --provenance --access public\n  env:\n    NODE_AUTH_TOKEN: \${{ secrets.GITHUB_TOKEN }}\n\nSee: https://docs.npmjs.com/generating-provenance-statements`,
        cvss: {
          score:  5.9,
          vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
          cwe:    'CWE-522',
        },
      });
      continue;
    }

    // twine upload with long-lived token
    if (/\btwine\s+upload\b/.test(run)) {
      if (alreadyOidc) continue;
      const tokenKey = envHasSecretRef(env, 'TWINE_PASSWORD', 'TWINE_TOKEN');
      if (!tokenKey) continue;

      const lineNumber = findLineNumber(rawContent, /\btwine\s+upload\b/);
      const snippet = extractSnippet(rawContent, lineNumber, 4);
      findings.push({
        id: `use-trusted-publishing-twine-${filename}-${jobId}-${stepIndex}`,
        rule: 'use-trusted-publishing',
        severity: 'medium',
        title: 'twine upload using long-lived credential instead of OIDC',
        file: filename,
        line: lineNumber,
        snippet,
        context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}  ·  Token key: ${tokenKey}`,
        detail: `The step uploads to PyPI using \`twine\` with a long-lived \`${tokenKey}\` stored as a secret. This is functionally equivalent to storing the PyPI API token as a persistent credential. PyPI Trusted Publishing eliminates the need for this token by issuing short-lived OIDC tokens scoped to the specific workflow run.`,
        exploit: `If \`${tokenKey}\` is leaked, an attacker can publish malicious PyPI package versions at any time without any additional repository access.`,
        impact: 'Long-lived credential exposure enabling supply chain attack via malicious PyPI package publish',
        remediation: `Switch to \`pypa/gh-action-pypi-publish\` with OIDC Trusted Publishing configured at https://pypi.org/manage/account/publishing/ — no stored token required:\n\npermissions:\n  id-token: write\n\n- uses: pypa/gh-action-pypi-publish@<sha>`,
        cvss: {
          score:  5.9,
          vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
          cwe:    'CWE-522',
        },
      });
    }
  }

  return findings;
}
