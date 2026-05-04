import { listWorkflowFiles, getWorkflowContent, listActionFiles, getOptionalFileContent } from './github-api.js';
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
  checkActionYmlTemplateInjection,
  checkActionYmlUnpinnedUses,
  checkKnownVulnerableActions,
  checkSecretsOutsideEnv,
  checkUnredactedSecrets,
  checkWorkflowRunArtifactEnvInjection,
  checkDependabotInsecureExecution,
  checkDependabotConfusedDeputy,
  checkHardcodedContainerCredentials,
  checkIdTokenWriteUnscoped,
  checkPrRunsOnSelfHosted,
  checkOverprovisionedSecrets,
} from './rules/index.js';

const WORKFLOW_RULES = [
  // Injection / code execution
  checkTemplateInjection,
  checkGithubEnv,
  checkActionsAllowUnsecureCommands,
  // Trigger misuse (pwn request family)
  checkDangerousTriggers,
  checkWorkflowRunTrigger,
  checkWorkflowRunArtifactEnvInjection,
  // Supply chain (pinning)
  checkUnpinnedActions,
  checkUnpinnedDockerImage,
  checkReusableWorkflowRef,
  checkCurlPipeSh,
  checkCachePoisoning,
  checkKnownVulnerableActions,
  // Permissions & access
  checkExcessivePermissions,
  checkSelfHostedRunner,
  checkPrRunsOnSelfHosted,
  checkSecretsInherit,
  checkIdTokenWriteUnscoped,
  // Secrets & credential hygiene
  checkHardcodedSecrets,
  checkArtipacked,
  checkTokenInLogs,
  checkSecretsOutsideEnv,
  checkUnredactedSecrets,
  checkOverprovisionedSecrets,
  checkHardcodedContainerCredentials,
  // Authorization logic
  checkBotConditions,
  checkUnsoundContains,
  checkDependabotConfusedDeputy,
  // Operational risk
  checkObfuscation,
  checkDebugEnabled,
];

// Rules that operate purely on rawContent — run these on action files too
const RAW_CONTENT_RULES = [
  checkHardcodedSecrets,
  checkCurlPipeSh,
  checkTokenInLogs,
  checkObfuscation,
];

// Rules specifically for composite action.yml files
const ACTION_RULES = [
  checkActionYmlTemplateInjection,
  checkActionYmlUnpinnedUses,
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
    'Fetching action files',
    'Fetching dependabot.yml',
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

  // Step 2: discover action files
  progress(2);
  const { files: actionFileList, rateLimit: rl2 } = await listActionFiles(owner, repo, token);
  if (rl2) lastRateLimit = rl2;

  // Step 3: fetch dependabot config (.yml preferred, .yaml fallback)
  progress(3);
  let dependabotFile = null;
  for (const depPath of ['.github/dependabot.yml', '.github/dependabot.yaml']) {
    const { content: depContent, rateLimit: rl3 } = await getOptionalFileContent(owner, repo, depPath, token);
    if (rl3) lastRateLimit = rl3;
    if (depContent !== null) {
      dependabotFile = { path: depPath, content: depContent, parsed: parseWorkflow(depContent) };
      break;
    }
  }

  if (files.length === 0 && actionFileList.length === 0 && !dependabotFile) {
    return {
      owner, repo,
      workflows: [],
      actionFiles: [],
      dependabotFile: null,
      findings: [],
      rateLimit: lastRateLimit,
      scannedAt: new Date().toISOString(),
      noWorkflows: true,
    };
  }

  // Step 4: fetch and parse each workflow
  progress(4);
  const workflows = [];
  for (const file of files) {
    const { content, rateLimit: rlWf } = await getWorkflowContent(owner, repo, file.path, token);
    if (rlWf) lastRateLimit = rlWf;
    const parsed = parseWorkflow(content);
    workflows.push({ name: file.name, path: file.path, content, parsed });
  }

  // Fetch and parse each action file
  const actionFiles = [];
  for (const file of actionFileList) {
    const { content, rateLimit: rlAf } = await getWorkflowContent(owner, repo, file.path, token);
    if (rlAf) lastRateLimit = rlAf;
    const parsed = parseWorkflow(content);
    actionFiles.push({ name: file.name, path: file.path, content, parsed });
  }

  // Steps 5-10: apply rules
  const findings = [];

  for (let ri = 0; ri < WORKFLOW_RULES.length; ri++) {
    const progressStep = Math.min(5 + Math.floor(ri / 3), 9);
    progress(progressStep);

    const rule = WORKFLOW_RULES[ri];
    for (const wf of workflows) {
      if (!wf.parsed) continue;
      try {
        const wfFindings = rule(wf.parsed, wf.content, wf.path);
        findings.push(...wfFindings);
      } catch (err) {
        if (import.meta.env.DEV) console.warn(`[PWNPipe] Rule ${rule.name} threw on ${wf.path}:`, err);
      }
    }
  }

  // Run action-specific rules on action files
  for (const actionFile of actionFiles) {
    if (!actionFile.parsed) continue;

    for (const rule of ACTION_RULES) {
      try {
        const af = rule(actionFile.parsed, actionFile.content, actionFile.path);
        findings.push(...af);
      } catch (err) {
        if (import.meta.env.DEV) console.warn(`[PWNPipe] Action rule ${rule.name} threw on ${actionFile.path}:`, err);
      }
    }

    // Run rawContent rules on action files
    for (const rule of RAW_CONTENT_RULES) {
      try {
        const af = rule(actionFile.parsed, actionFile.content, actionFile.path);
        findings.push(...af);
      } catch (err) {
        if (import.meta.env.DEV) console.warn(`[PWNPipe] Raw rule ${rule.name} threw on ${actionFile.path}:`, err);
      }
    }
  }

  // Run dependabot-specific rule on dependabot.yml
  if (dependabotFile && dependabotFile.parsed) {
    try {
      const df = checkDependabotInsecureExecution(dependabotFile.parsed, dependabotFile.content, dependabotFile.path);
      findings.push(...df);
    } catch (err) {
      if (import.meta.env.DEV) console.warn('[PWNPipe] checkDependabotInsecureExecution threw:', err);
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

  // Step 11: score
  progress(10);

  return {
    owner,
    repo,
    workflows,
    actionFiles,
    dependabotFile,
    findings,
    rateLimit: lastRateLimit,
    scannedAt: new Date().toISOString(),
    noWorkflows: files.length === 0,
  };
}
