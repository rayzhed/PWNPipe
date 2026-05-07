import {
  listWorkflowFiles,
  getWorkflowContent,
  listActionFiles,
  getOptionalFileContent,
  getRepoMetadata,
  verifyCommitInRepo,
  resolveTagToSha,
  getRepositorySecurityInfo,
} from './github-api.js';
import { parseWorkflow, getAllSteps, findLineNumber, extractSnippet } from './yaml-parser.js';
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
  checkConcurrencyMissing,
  checkShellCmd,
  checkDependabotMissingCooldown,
  checkUseTrustedPublishing,
  checkGithubOutputInjection,
  checkStepSummaryInjection,
  checkMatrixInjection,
  checkRunsOnInjection,
  checkMissingTimeout,
  checkContinueOnError,
  checkRenovateAutomerge,
  checkPreCommitUnsafe,
  checkIfAlwaysTrue,
  checkIssueCommentTOCTOU,
  checkGithubAppUnsafe,
} from './rules/index.js';

const WORKFLOW_RULES = [
  // Injection / code execution
  checkTemplateInjection,
  checkGithubEnv,
  checkActionsAllowUnsecureCommands,
  // Trigger misuse
  checkDangerousTriggers,
  checkWorkflowRunTrigger,
  checkWorkflowRunArtifactEnvInjection,
  // Supply chain
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
  checkUseTrustedPublishing,
  // Authorization logic
  checkBotConditions,
  checkUnsoundContains,
  checkDependabotConfusedDeputy,
  // Shell safety
  checkShellCmd,
  // Operational risk
  checkObfuscation,
  checkDebugEnabled,
  checkConcurrencyMissing,
  // Injection variants
  checkGithubOutputInjection,
  checkStepSummaryInjection,
  checkMatrixInjection,
  checkRunsOnInjection,
  // Resilience / visibility
  checkMissingTimeout,
  checkContinueOnError,
  // Authorization logic — condition bypass
  checkIfAlwaysTrue,
  // TOCTOU / trigger misuse
  checkIssueCommentTOCTOU,
  // Third-party integrations
  checkGithubAppUnsafe,
];

// Rules that work on raw YAML content — also applied to action.yml files
const RAW_CONTENT_RULES = [
  checkHardcodedSecrets,
  checkCurlPipeSh,
  checkTokenInLogs,
  checkObfuscation,
];

// Rules specific to composite action.yml files
const ACTION_RULES = [
  checkActionYmlTemplateInjection,
  checkActionYmlUnpinnedUses,
];

const SHA40_RE = /^[a-f0-9]{40}$/;

function collectUsesRefs(workflows) {
  const refs = [];
  for (const wf of workflows) {
    if (!wf.parsed) continue;
    const steps = getAllSteps(wf.parsed);
    for (const { step } of steps) {
      const uses = step.uses;
      if (typeof uses !== 'string') continue;
      if (uses.startsWith('./') || uses.startsWith('docker://')) continue;
      const atIdx = uses.lastIndexOf('@');
      if (atIdx === -1) continue;
      const actionPath = uses.slice(0, atIdx);
      const ref = uses.slice(atIdx + 1);
      const parts = actionPath.split('/');
      const owner = parts[0];
      const repo  = parts[1];
      if (!owner || !repo) continue;
      refs.push({ owner, repo, ref, uses, file: wf.path, rawContent: wf.content });
    }
  }
  return refs;
}

async function runNetworkRules(workflows, token, onProgress) {
  if (!token) return [];

  const findings = [];
  const refs = collectUsesRefs(workflows);

  // archived-uses
  onProgress('Checking for archived action repositories');
  const uniqueRepos = new Map();
  for (const r of refs) {
    const key = `${r.owner}/${r.repo}`;
    if (!uniqueRepos.has(key)) uniqueRepos.set(key, []);
    uniqueRepos.get(key).push(r);
  }

  for (const [repoKey, repoRefs] of uniqueRepos) {
    const [owner, repo] = repoKey.split('/');
    let archived = null;
    try {
      const result = await getRepoMetadata(owner, repo, token);
      archived = result.archived;
    } catch { /* skip */ }
    if (archived !== true) continue;

    for (const r of repoRefs) {
      const lineNumber = findLineNumber(r.rawContent, r.uses.slice(0, 40));
      const snippet    = extractSnippet(r.rawContent, lineNumber, 4);
      findings.push({
        id:          `archived-uses-${r.file}-${r.uses}`,
        rule:        'archived-uses',
        severity:    'medium',
        title:       `Uses archived repository: \`${repoKey}\``,
        file:        r.file,
        line:        lineNumber,
        snippet,
        context:     `Action: \`${r.uses}\``,
        detail:      `The action \`${r.uses}\` is hosted in the archived repository \`${repoKey}\`. Archived repositories receive no security fixes or updates. Any vulnerability discovered will never be patched.`,
        exploit:     `If a vulnerability is found in the archived action (command injection, secret exfiltration), the maintainer will never release a fix. Attackers actively monitor archived projects used in CI pipelines.`,
        impact:      'Persistent unpatched vulnerability in CI supply chain',
        remediation: `Replace \`${r.uses}\` with an actively maintained alternative, a community fork, or inline the functionality directly into your workflow.`,
        cvss: { score: 5.4, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', cwe: 'CWE-1104' },
      });
    }
  }

  // impostor-commit
  onProgress('Verifying pinned commit SHAs');
  const shaRefs    = refs.filter(r => SHA40_RE.test(r.ref) && r.owner !== 'actions');
  const uniqueShas = new Map();
  for (const r of shaRefs) {
    const key = `${r.owner}/${r.repo}@${r.ref}`;
    if (!uniqueShas.has(key)) uniqueShas.set(key, []);
    uniqueShas.get(key).push(r);
  }

  for (const [shaKey, shaGroup] of uniqueShas) {
    const atIdx     = shaKey.lastIndexOf('@');
    const ownerRepo = shaKey.slice(0, atIdx);
    const sha       = shaKey.slice(atIdx + 1);
    const [owner, repo] = ownerRepo.split('/');
    let exists = null, repoExists = null;
    try {
      const result = await verifyCommitInRepo(owner, repo, sha, token);
      exists     = result.exists;
      repoExists = result.repoExists;
    } catch { /* skip */ }

    // Confirmed impostor: repo is accessible but this SHA is not in it
    if (exists === false) {
      for (const r of shaGroup) {
        const lineNumber = findLineNumber(r.rawContent, r.ref.slice(0, 20));
        const snippet    = extractSnippet(r.rawContent, lineNumber, 4);
        findings.push({
          id:          `impostor-commit-${r.file}-${r.ref}`,
          rule:        'impostor-commit',
          severity:    'critical',
          title:       `Impostor commit: SHA not in \`${ownerRepo}\``,
          file:        r.file,
          line:        lineNumber,
          snippet,
          context:     `Action: \`${r.uses}\`  ·  SHA: \`${sha}\``,
          detail:      `SHA \`${sha}\` isn't reachable from any branch or tag of \`${ownerRepo}\`. It exists in GitHub's shared fork object pool but was never merged into the main repo — a confirmed impostor commit.`,
          exploit:     `Fork \`${ownerRepo}\`, push a commit with the matching SHA. Any pipeline pinned to this SHA resolves it from your fork and runs attacker-controlled code with full secret access.`,
          impact:      'Supply Chain RCE + Full Secret Access',
          remediation: `Verify the correct SHA for the intended version at \`https://github.com/${ownerRepo}/releases\` and update the \`uses:\` reference.`,
          cvss: { score: 9.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', cwe: 'CWE-829' },
        });
      }
      continue;
    }

    // Unverifiable: repo returned 404 — deleted, renamed, or private.
    // The old name may be available for registration (name-squatting risk).
    if (repoExists === false) {
      // Deduplicate to one finding per ownerRepo — all steps share the same root risk
      const r = shaGroup[0];
      const lineNumber = findLineNumber(r.rawContent, r.ref.slice(0, 20));
      const snippet    = extractSnippet(r.rawContent, lineNumber, 4);
      const allUses    = [...new Set(shaGroup.map(x => x.uses))].join(', ');
      findings.push({
        id:          `impostor-commit-unverifiable-${ownerRepo.replace('/', '-')}`,
        rule:        'impostor-commit',
        severity:    'medium',
        title:       `\`${ownerRepo}\` returned 404 — renamed, deleted, or squattable`,
        file:        r.file,
        line:        lineNumber,
        snippet,
        context:     `Action(s): \`${allUses}\`  ·  SHA: \`${sha}\``,
        detail:      `The repo \`${ownerRepo}\` doesn't exist or isn't accessible. If the name is free to register, anyone can create it and serve arbitrary action code at this path. The SHA pin helps but doesn't block name squatting.`,
        exploit:     `Register \`${ownerRepo}\` on GitHub, push any action code. Workflows pinned to this path resolve to attacker-controlled code — the SHA still resolves via GitHub's shared fork object pool.`,
        impact:      'Possible Name Squatting + Unverifiable Action Source',
        remediation: `Find the current URL for this action (it may have been renamed or archived).\nUpdate the \`uses:\` reference and re-pin to a fresh SHA.\nIf the action is gone with no successor, remove or replace it.`,
        cvss: { score: 5.9, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N', cwe: 'CWE-829' },
      });
    }
  }

  // ref-version-mismatch
  onProgress('Checking pinned SHA / version comment alignment');
  const VERSION_COMMENT_RE = /uses:\s+\S+@([a-f0-9]{40})\s+#\s*(v[\w.\-]+)/;
  const mismatchCandidates = [];

  for (const wf of workflows) {
    if (!wf.content) continue;
    const lines = wf.content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const m = VERSION_COMMENT_RE.exec(lines[i]);
      if (!m) continue;
      const sha = m[1];
      const tag = m[2];
      const usesMatch = lines[i].match(/uses:\s+([^@/\s]+\/[^@/\s]+)[^@]*@/);
      if (!usesMatch) continue;
      const parts = usesMatch[1].split('/');
      const owner = parts[0];
      const repo  = parts[1];
      if (!owner || !repo || owner === 'actions') continue;
      mismatchCandidates.push({ owner, repo, sha, tag, lineNumber: i + 1, file: wf.path, rawContent: wf.content });
    }
  }

  const uniqueTags = new Map();
  for (const c of mismatchCandidates) {
    const key = `${c.owner}/${c.repo}@${c.tag}`;
    if (!uniqueTags.has(key)) uniqueTags.set(key, []);
    uniqueTags.get(key).push(c);
  }

  for (const [, tagGroup] of uniqueTags) {
    const first = tagGroup[0];
    let resolvedSha = null;
    try {
      const result = await resolveTagToSha(first.owner, first.repo, first.tag, token);
      resolvedSha = result.sha;
    } catch { /* skip */ }
    if (!resolvedSha) continue;

    for (const c of tagGroup) {
      if (resolvedSha === c.sha) continue;
      const snippet = extractSnippet(c.rawContent, c.lineNumber, 4);
      findings.push({
        id:          `ref-version-mismatch-${c.file}-${c.sha.slice(0, 12)}`,
        rule:        'ref-version-mismatch',
        severity:    'low',
        title:       `Pinned SHA does not match comment tag \`${c.tag}\` in \`${c.owner}/${c.repo}\``,
        file:        c.file,
        line:        c.lineNumber,
        snippet,
        context:     `Comment: \`${c.tag}\`  ·  Pinned: \`${c.sha.slice(0, 12)}…\`  ·  Tag resolves to: \`${resolvedSha.slice(0, 12)}…\``,
        detail:      `The comment \`# ${c.tag}\` signals intent to pin to version \`${c.tag}\`, but the SHA \`${c.sha}\` does not match what \`${c.tag}\` currently resolves to (\`${resolvedSha}\`). Either the pin was updated without updating the comment, or the tag was force-moved after pinning.`,
        exploit:     `If the tag was force-moved to a malicious commit, the pin comment falsely advertises a trusted version. This misleads code reviewers into trusting a pin that may no longer correspond to the stated version.`,
        impact:      'Misleading pin comment reduces supply chain audit confidence',
        remediation: `Re-pin to the correct SHA for \`${c.tag}\`:\n\nuses: ${c.owner}/${c.repo}@${resolvedSha}  # ${c.tag}`,
        cvss: { score: 3.7, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N', cwe: 'CWE-345' },
      });
    }
  }

  return findings;
}

/**
 * Main scan orchestrator.
 */
export async function scanRepository(owner, repo, token, onProgress = () => {}) {
  const steps = [
    'Connecting to GitHub API',
    'Fetching workflow files',
    'Fetching action files',
    'Fetching dependabot config',
    'Fetching renovate / pre-commit config',
    'Parsing YAML',
    'Checking dangerous triggers',
    'Detecting template injections',
    'Verifying action pinning',
    'Auditing GITHUB_TOKEN permissions',
    'Running additional checks',
    'Network enrichment checks',
    'Checking repository security settings',
    'Calculating risk score',
  ];

  let lastRateLimit = null;

  function progress(stepIndex) {
    onProgress({ step: stepIndex, label: steps[stepIndex], total: steps.length });
  }

  progress(0);

  // Step 1: workflow files
  progress(1);
  const { files, rateLimit: rl1 } = await listWorkflowFiles(owner, repo, token);
  if (rl1) lastRateLimit = rl1;

  // Step 2: action files
  progress(2);
  const { files: actionFileList, rateLimit: rl2 } = await listActionFiles(owner, repo, token);
  if (rl2) lastRateLimit = rl2;

  // Step 3: dependabot config (.yml preferred, .yaml fallback)
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

  // Step 4: renovate + pre-commit configs
  progress(4);
  let renovateFile = null;
  for (const rPath of ['renovate.json', 'renovate.json5', '.github/renovate.json', '.github/renovate.json5']) {
    const { content: rContent } = await getOptionalFileContent(owner, repo, rPath, token);
    if (rContent !== null) {
      let parsed = null;
      try { parsed = JSON.parse(rContent); } catch { /* invalid JSON */ }
      renovateFile = { path: rPath, content: rContent, parsed };
      break;
    }
  }

  let preCommitFile = null;
  for (const pcPath of ['.pre-commit-config.yaml', '.pre-commit-config.yml']) {
    const { content: pcContent } = await getOptionalFileContent(owner, repo, pcPath, token);
    if (pcContent !== null) {
      preCommitFile = { path: pcPath, content: pcContent, parsed: parseWorkflow(pcContent) };
      break;
    }
  }

  if (files.length === 0 && actionFileList.length === 0 && !dependabotFile && !renovateFile && !preCommitFile) {
    return {
      owner, repo,
      workflows: [],
      actionFiles: [],
      dependabotFile: null,
      renovateFile: null,
      preCommitFile: null,
      securityInfo: null,
      findings: [],
      rateLimit: lastRateLimit,
      scannedAt: new Date().toISOString(),
      noWorkflows: true,
    };
  }

  // Step 5: fetch and parse workflow files
  progress(5);
  const workflows = [];
  for (const file of files) {
    const { content, rateLimit: rlWf } = await getWorkflowContent(owner, repo, file.path, token);
    if (rlWf) lastRateLimit = rlWf;
    const parsed = parseWorkflow(content);
    workflows.push({ name: file.name, path: file.path, content, parsed });
  }

  // Fetch and parse action files
  const actionFiles = [];
  for (const file of actionFileList) {
    const { content, rateLimit: rlAf } = await getWorkflowContent(owner, repo, file.path, token);
    if (rlAf) lastRateLimit = rlAf;
    const parsed = parseWorkflow(content);
    actionFiles.push({ name: file.name, path: file.path, content, parsed });
  }

  // Steps 6-11: static rules on workflow files
  const findings = [];

  for (let ri = 0; ri < WORKFLOW_RULES.length; ri++) {
    const progressStep = Math.min(6 + Math.floor(ri / 5), 10);
    progress(progressStep);

    const rule = WORKFLOW_RULES[ri];
    for (const wf of workflows) {
      if (!wf.parsed) continue;
      try {
        findings.push(...rule(wf.parsed, wf.content, wf.path));
      } catch (err) {
        if (import.meta.env.DEV) console.warn(`[PWNPipe] Rule ${rule.name} threw on ${wf.path}:`, err);
      }
    }
  }

  // Action-specific rules
  for (const af of actionFiles) {
    if (!af.parsed) continue;
    for (const rule of ACTION_RULES) {
      try { findings.push(...rule(af.parsed, af.content, af.path)); } catch (err) {
        if (import.meta.env.DEV) console.warn(`[PWNPipe] Action rule ${rule.name} threw on ${af.path}:`, err);
      }
    }
    for (const rule of RAW_CONTENT_RULES) {
      try { findings.push(...rule(af.parsed, af.content, af.path)); } catch (err) {
        if (import.meta.env.DEV) console.warn(`[PWNPipe] Raw rule ${rule.name} threw on ${af.path}:`, err);
      }
    }
  }

  // Dependabot rules
  if (dependabotFile?.parsed) {
    try {
      findings.push(...checkDependabotInsecureExecution(dependabotFile.parsed, dependabotFile.content, dependabotFile.path));
    } catch (err) {
      if (import.meta.env.DEV) console.warn('[PWNPipe] checkDependabotInsecureExecution threw:', err);
    }
    try {
      findings.push(...checkDependabotMissingCooldown(dependabotFile.parsed, dependabotFile.content, dependabotFile.path));
    } catch (err) {
      if (import.meta.env.DEV) console.warn('[PWNPipe] checkDependabotMissingCooldown threw:', err);
    }
  }

  // Renovate rules
  if (renovateFile?.parsed) {
    try {
      findings.push(...checkRenovateAutomerge(renovateFile.parsed, renovateFile.content, renovateFile.path));
    } catch (err) {
      if (import.meta.env.DEV) console.warn('[PWNPipe] checkRenovateAutomerge threw:', err);
    }
  }

  // Pre-commit rules
  if (preCommitFile?.parsed) {
    try {
      findings.push(...checkPreCommitUnsafe(preCommitFile.parsed, preCommitFile.content, preCommitFile.path));
    } catch (err) {
      if (import.meta.env.DEV) console.warn('[PWNPipe] checkPreCommitUnsafe threw:', err);
    }
  }

  // Step 11: network enrichment (existing: archived, impostor, mismatch)
  progress(11);
  try {
    const networkFindings = await runNetworkRules(
      workflows,
      token,
      (label) => onProgress({ step: 11, label, total: steps.length }),
    );
    findings.push(...networkFindings);
  } catch (err) {
    if (import.meta.env.DEV) console.warn('[PWNPipe] runNetworkRules threw:', err);
  }

  // Step 12: repository security settings check
  progress(12);
  let securityInfo = null;
  if (token) {
    try {
      securityInfo = await getRepositorySecurityInfo(owner, repo, token);
      if (securityInfo.rateLimit) lastRateLimit = securityInfo.rateLimit;

      const secFindings = buildSecurityInfoFindings(owner, repo, securityInfo);
      findings.push(...secFindings);
    } catch (err) {
      if (import.meta.env.DEV) console.warn('[PWNPipe] getRepositorySecurityInfo threw:', err);
    }
  }

  // Attach OWASP + confidence to every finding
  for (const f of findings) {
    const meta = RULE_META[f.rule];
    if (!meta) continue;
    f.owasp      = meta.owasp ?? null;
    f.confidence = typeof meta.confidence === 'function'
      ? meta.confidence(f)
      : (meta.confidence ?? 'MEDIUM');
  }

  progress(13);

  return {
    owner,
    repo,
    workflows,
    actionFiles,
    dependabotFile,
    renovateFile,
    preCommitFile,
    securityInfo,
    findings,
    rateLimit: lastRateLimit,
    scannedAt: new Date().toISOString(),
    noWorkflows: files.length === 0,
  };
}

function buildSecurityInfoFindings(owner, repo, info) {
  const findings = [];

  if (info.branchProtection === false) {
    findings.push({
      id:          `repo-no-branch-protection-${owner}-${repo}`,
      rule:        'repo-branch-protection',
      severity:    'high',
      title:       `No Branch Protection on \`${info.defaultBranch}\``,
      file:        `${owner}/${repo}`,
      line:        null,
      snippet:     null,
      context:     `Default branch: \`${info.defaultBranch}\``,
      detail:      `The default branch \`${info.defaultBranch}\` has no branch protection rules. Anyone with write access can push directly, bypassing required reviews and status checks. CI workflows triggered by \`push\` to the default branch may run against unreviewed code.`,
      exploit:     `A collaborator (or an attacker who compromises a collaborator's token) force-pushes malicious workflow changes to \`${info.defaultBranch}\` without any review. The next workflow run executes the attacker's code with full secret access.`,
      impact:      'Unreviewed Code Executes with Full CI Secret Access',
      remediation: `Enable branch protection on \`${info.defaultBranch}\`:\n- Require pull request reviews (at least 1 approval)\n- Require status checks to pass before merging\n- Prevent force pushes\n- Consider enabling required linear history`,
      cvss:        { score: 7.4, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N', cwe: 'CWE-284' },
    });
  }

  if (info.secretScanning === 'disabled') {
    findings.push({
      id:          `repo-secret-scanning-disabled-${owner}-${repo}`,
      rule:        'repo-secret-scanning',
      severity:    'medium',
      title:       'GitHub Secret Scanning Disabled',
      file:        `${owner}/${repo}`,
      line:        null,
      snippet:     null,
      context:     'Repository security settings',
      detail:      `GitHub Secret Scanning is disabled. Secrets accidentally committed to the repository (API tokens, private keys, connection strings) go undetected and stay in git history where anyone with read access can find them.`,
      exploit:     `A developer commits an AWS access key. Without secret scanning the commit goes unnoticed. An attacker with read access finds it in git history and uses it to access cloud infrastructure.`,
      impact:      'Leaked Secrets in Git History Not Detected',
      remediation: `Enable GitHub Secret Scanning in Settings > Security & analysis > Secret scanning. Also enable push protection to block secrets before they are committed.`,
      cvss:        { score: 5.9, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', cwe: 'CWE-522' },
    });
  }

  if (info.pushProtection === 'disabled' && info.secretScanning === 'enabled') {
    findings.push({
      id:          `repo-push-protection-disabled-${owner}-${repo}`,
      rule:        'repo-push-protection',
      severity:    'medium',
      title:       'Secret Scanning Push Protection Disabled',
      file:        `${owner}/${repo}`,
      line:        null,
      snippet:     null,
      context:     'Repository security settings',
      detail:      `Secret Scanning is enabled but Push Protection is disabled. Push Protection blocks commits containing known secret patterns before they reach the repository. Without it, a committed secret lands in git history and needs to be rotated after the fact.`,
      exploit:     `A developer commits a credential. Secret scanning detects it after the push, but the commit is already in git history and may have been replicated. There is a window between commit and detection where the secret is live.`,
      impact:      'Secrets Committed Before Detection',
      remediation: `Enable Push Protection in Settings > Security & analysis > Secret scanning > Push protection.`,
      cvss:        { score: 4.7, vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N', cwe: 'CWE-522' },
    });
  }



  return findings;
}
