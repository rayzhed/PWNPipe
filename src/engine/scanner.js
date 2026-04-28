import { listWorkflowFiles, getWorkflowContent } from './github-api.js';
import { parseWorkflow } from './yaml-parser.js';
import { RULE_META } from './rules/metadata.js';
import {
  checkTemplateInjection,
  checkDangerousTriggers,
  checkWorkflowRunTrigger,
  checkUnpinnedActions,
  checkUnpinnedDockerImage,
  checkReusableWorkflowRef,
  checkExcessivePermissions,
  checkSelfHostedRunner,
  checkArtipacked,
  checkBotConditions,
  checkGithubEnv,
  checkActionsAllowUnsecureCommands,
  checkHardcodedSecrets,
  checkSecretsInherit,
  checkCachePoisoning,
  checkCurlPipeSh,
  checkObfuscation,
  checkTokenInLogs,
  checkDebugEnabled,
  checkUnsoundContains,
} from './rules/index.js';

const RULES = [
  // Injection / code execution
  checkTemplateInjection,
  checkGithubEnv,
  checkActionsAllowUnsecureCommands,
  // Trigger misuse (pwn request family)
  checkDangerousTriggers,
  checkWorkflowRunTrigger,
  // Supply chain (pinning)
  checkUnpinnedActions,
  checkUnpinnedDockerImage,
  checkReusableWorkflowRef,
  checkCurlPipeSh,
  checkCachePoisoning,
  // Permissions & access
  checkExcessivePermissions,
  checkSelfHostedRunner,
  checkSecretsInherit,
  // Secrets & credential hygiene
  checkHardcodedSecrets,
  checkArtipacked,
  checkTokenInLogs,
  // Authorization logic
  checkBotConditions,
  checkUnsoundContains,
  // Operational risk
  checkObfuscation,
  checkDebugEnabled,
];

/**
 * Main scan orchestrator.
 *
 * @param {string} owner
 * @param {string} repo
 * @param {string} token
 * @param {function} onProgress  - called with ({ step, label, done, total })
 * @returns {Promise<ScanResult>}
 */
export async function scanRepository(owner, repo, token, onProgress = () => {}) {
  const steps = [
    'Connecting to GitHub API',
    'Fetching workflow files',
    'Parsing YAML',
    'Checking dangerous triggers',
    'Detecting template injections',
    'Verifying action pinning',
    'Auditing GITHUB_TOKEN permissions',
    'Running additional checks',
    'Calculating risk score',
  ];

  let lastRateLimit = null;

  function progress(stepIndex) {
    onProgress({ step: stepIndex, label: steps[stepIndex], total: steps.length });
  }

  progress(0);

  // Step 1: list workflow files
  progress(1);
  const { files, rateLimit: rl1 } = await listWorkflowFiles(owner, repo, token);
  if (rl1) lastRateLimit = rl1;

  if (files.length === 0) {
    return {
      owner, repo,
      workflows: [],
      findings: [],
      rateLimit: lastRateLimit,
      scannedAt: new Date().toISOString(),
      noWorkflows: true,
    };
  }

  // Step 2: fetch and parse each workflow
  progress(2);
  const workflows = [];
  for (const file of files) {
    const { content, rateLimit: rl2 } = await getWorkflowContent(owner, repo, file.path, token);
    if (rl2) lastRateLimit = rl2;
    const parsed = parseWorkflow(content);
    workflows.push({ name: file.name, path: file.path, content, parsed });
  }

  // Steps 3-8: apply rules
  const findings = [];

  for (let ri = 0; ri < RULES.length; ri++) {
    const progressStep = Math.min(3 + Math.floor(ri / 2), 7);
    progress(progressStep);

    const rule = RULES[ri];
    for (const wf of workflows) {
      if (!wf.parsed) continue;
      try {
        const wfFindings = rule(wf.parsed, wf.content, wf.name);
        findings.push(...wfFindings);
      } catch (err) {
        if (import.meta.env.DEV) console.warn(`[PWNPipe] Rule ${rule.name} threw on ${wf.name}:`, err);
      }
    }
  }

  // Attach OWASP CI/CD Top 10 category and detection confidence to every finding
  for (const f of findings) {
    const meta = RULE_META[f.rule];
    if (!meta) continue;
    f.owasp      = meta.owasp ?? null;
    f.confidence = typeof meta.confidence === 'function'
      ? meta.confidence(f)
      : (meta.confidence ?? 'MEDIUM');
  }

  // Step 9: score
  progress(8);

  return {
    owner,
    repo,
    workflows,
    findings,
    rateLimit: lastRateLimit,
    scannedAt: new Date().toISOString(),
    noWorkflows: false,
  };
}
