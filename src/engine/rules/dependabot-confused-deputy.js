import { getTriggers, findLineNumber, extractSnippet } from '../yaml-parser.js';

// Matches actor equality checks that gate privileged operations on dependabot identity
const DEPENDABOT_ACTOR_EQ_RE = /github\.actor\s*==\s*['"]dependabot\[bot\]['"]|github\.actor\s*==\s*['"]dependabot['"]/i;
const DEPENDABOT_ACTOR_CONTAINS_RE = /contains\s*\(\s*(?:github\.actor|github\.event\.sender\.login)\s*,\s*['"]dependabot['"]/i;

function checkCondition(condition) {
  if (typeof condition !== 'string') return false;
  return DEPENDABOT_ACTOR_EQ_RE.test(condition) || DEPENDABOT_ACTOR_CONTAINS_RE.test(condition);
}

export function checkDependabotConfusedDeputy(workflow, rawContent, filename) {
  const findings = [];
  const seen = new Set();
  const triggers = getTriggers(workflow);

  // Pattern 1: push trigger matching dependabot/** branches
  const onBlock = workflow?.on;
  if (onBlock && typeof onBlock === 'object' && !Array.isArray(onBlock)) {
    const pushConfig = onBlock?.push;
    if (pushConfig && typeof pushConfig === 'object') {
      const branches = pushConfig?.branches ?? [];
      const branchArr = Array.isArray(branches) ? branches : [branches];
      const matchesDependabot = branchArr.some(b => String(b).includes('dependabot'));
      if (matchesDependabot) {
        const lineNumber = findLineNumber(rawContent, 'dependabot');
        const snippet = extractSnippet(rawContent, lineNumber, 4);
        const id = `dependabot-confused-deputy-${filename}-push-branch`;
        if (!seen.has(id)) {
          seen.add(id);
          findings.push({
            id,
            rule: 'dependabot-confused-deputy',
            severity: 'medium',
            title: 'Workflow Triggered on dependabot/** Push Branches',
            file: filename,
            line: lineNumber,
            snippet,
            context: 'Workflow-level push trigger',
            detail: `This workflow triggers on \`push\` events matching \`dependabot/**\` branch patterns. An attacker can create a branch named \`dependabot/evil\`, push to it, and trigger the workflow. Although the attacker controls the branch name, the workflow runs with the repo's secrets if permissions are not restricted.`,
            exploit: `Create a branch named \`dependabot/npm_and_yarn/evil\` and push code. The workflow triggers as if it were a real Dependabot update. If the workflow grants elevated permissions based on the branch name or the \`github.actor\` identity, the attacker's code runs with those elevated privileges.`,
            impact: 'Privilege Escalation via Dependabot Branch Name Spoofing',
            remediation: `Do not use branch name patterns to grant elevated trust. Verify Dependabot updates using the \`dependabot/fetch-metadata\` action, which validates the update metadata cryptographically. Require PR review for all dependency updates.`,
            cvss: {
              score: 6.3,
              vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N',
              cwe: 'CWE-287',
            },
          });
        }
      }
    }
  }

  // Pattern 2 & 3: github.actor == 'dependabot[bot]' used in job or step conditions
  const jobs = workflow?.jobs ?? {};
  for (const [jobId, job] of Object.entries(jobs)) {
    if (checkCondition(job.if)) {
      const lineNumber = findLineNumber(rawContent, DEPENDABOT_ACTOR_EQ_RE) ||
        findLineNumber(rawContent, 'dependabot[bot]');
      const snippet = extractSnippet(rawContent, lineNumber, 4);
      const id = `dependabot-confused-deputy-${filename}-${jobId}-job-if`;
      if (!seen.has(id)) {
        seen.add(id);
        findings.push(makeActorFinding(id, filename, lineNumber, snippet, job.name ?? jobId, 'job-level if'));
      }
    }

    const steps = Array.isArray(job.steps) ? job.steps : [];
    steps.forEach((step, idx) => {
      if (checkCondition(step.if)) {
        const lineNumber = findLineNumber(rawContent, DEPENDABOT_ACTOR_EQ_RE) ||
          findLineNumber(rawContent, 'dependabot[bot]');
        const snippet = extractSnippet(rawContent, lineNumber, 4);
        const id = `dependabot-confused-deputy-${filename}-${jobId}-step${idx}-if`;
        if (!seen.has(id)) {
          seen.add(id);
          findings.push(makeActorFinding(id, filename, lineNumber, snippet, job.name ?? jobId, `step ${idx + 1} if`));
        }
      }
    });
  }

  return findings;
}

function makeActorFinding(id, filename, lineNumber, snippet, jobName, context) {
  return {
    id,
    rule: 'dependabot-confused-deputy',
    severity: 'medium',
    title: 'Dependabot Confused Deputy: github.actor Check Can Be Spoofed',
    file: filename,
    line: lineNumber,
    snippet,
    context: `Job: \`${jobName}\`  ·  ${context}`,
    detail: `Gating privileged operations on \`github.actor == 'dependabot[bot]'\` is vulnerable to the confused deputy attack. After a Dependabot PR is created, an attacker can resolve merge conflicts or force-push to the PR branch — Dependabot's bot identity remains as \`github.actor\` for the original PR event, but the code being run is now attacker-controlled.`,
    exploit: `1. Wait for Dependabot to open a PR.\n2. Comment \`@dependabot rebase\` to trigger a merge conflict resolution.\n3. Force-push malicious code to the \`dependabot/\` branch.\n4. The workflow runs the attacker's code while \`github.actor\` still shows \`dependabot[bot]\`, bypassing the actor check.`,
    impact: 'Privilege Escalation via Dependabot Identity Confused Deputy',
    remediation: `Use \`dependabot/fetch-metadata\` to verify Dependabot updates properly. For secrets approval patterns, use \`if: \${{ steps.dependabot-metadata.outputs.update-type == 'version-update:semver-patch' }}\` rather than actor identity. Require CODEOWNERS review for all Dependabot PRs.`,
    cvss: {
      score: 6.3,
      vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N',
      cwe: 'CWE-287',
    },
  };
}
