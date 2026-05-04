import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// ACTIONS_ALLOW_UNSECURE_COMMANDS=true re-enables the ::set-env:: and ::add-path::
// workflow commands that GitHub deprecated and disabled in November 2020 (GHSA-7r5p-mfr3-mhqh)
// because they allowed any step to inject environment variables via stdout.
const KEY = 'ACTIONS_ALLOW_UNSECURE_COMMANDS';

function checkEnvBlock(envBlock, rawContent, filename, contextLabel) {
  if (!envBlock || typeof envBlock !== 'object') return null;
  const val = String(envBlock[KEY] ?? '').toLowerCase();
  if (val !== 'true' && val !== '1') return null;

  const lineNumber = findLineNumber(rawContent, KEY);
  const snippet = extractSnippet(rawContent, lineNumber, 3);

  return {
    id: `actions-allow-unsecure-commands-${filename}-${contextLabel.replace(/[^\w]/g, '-')}`,
    rule: 'actions-allow-unsecure-commands',
    severity: 'high',
    title: 'Deprecated Unsafe Workflow Commands Re-Enabled',
    file: filename,
    line: lineNumber,
    snippet,
    context: contextLabel,
    detail: `\`ACTIONS_ALLOW_UNSECURE_COMMANDS: true\` re-enables the \`::set-env::\` and \`::add-path::\` workflow commands that GitHub deprecated and disabled in November 2020. These commands let any step inject environment variables into all subsequent steps by printing specially formatted strings to stdout — no file write required. GitHub removed them in response to GHSA-7r5p-mfr3-mhqh.`,
    exploit: `A compromised action or a step that processes attacker-controlled input emits \`::set-env name=NODE_OPTIONS::--require /tmp/evil.js\` to stdout. Actions parses this line and injects \`NODE_OPTIONS\` into the environment. The next Node.js step automatically loads the attacker's module, achieving code execution with full access to secrets.`,
    impact: 'Environment Variable Injection → Code Execution in Subsequent Steps',
    remediation: `Remove \`ACTIONS_ALLOW_UNSECURE_COMMANDS: true\`. Migrate any \`::set-env::\` usage to the secure file-based approach:\n\n# Instead of: echo "::set-env name=FOO::value"\necho "FOO=value" >> $GITHUB_ENV\n\n# Instead of: echo "::add-path::/my/path"\necho "/my/path" >> $GITHUB_PATH\n\nNever write unfiltered user input to either file.`,
    cvss: {
      score:  8.0,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N',
      cwe:    'CWE-78',
      cve:    ['CVE-2020-15228'],
    },
  };
}

export function checkActionsAllowUnsecureCommands(workflow, rawContent, filename) {
  const findings = [];
  const seen = new Set();

  function add(finding) {
    if (!finding || seen.has(finding.id)) return;
    seen.add(finding.id);
    findings.push(finding);
  }

  add(checkEnvBlock(workflow?.env, rawContent, filename, 'Workflow-level env'));

  for (const [jobId, job] of Object.entries(workflow?.jobs ?? {})) {
    add(checkEnvBlock(job?.env, rawContent, filename, `Job: \`${job.name ?? jobId}\``));

    // Step-level env blocks can also re-enable the unsecure commands
    const steps = Array.isArray(job.steps) ? job.steps : [];
    steps.forEach((step, idx) => {
      add(checkEnvBlock(step?.env, rawContent, filename,
        `Job: \`${job.name ?? jobId}\`  ·  Step ${idx + 1}${step.name ? ` (${step.name})` : ''}`));
    });
  }

  return findings;
}
