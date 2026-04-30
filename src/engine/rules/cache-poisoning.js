import { getAllSteps, getTriggers, findLineNumber, extractSnippet } from '../yaml-parser.js';

const RELEASE_TRIGGERS = new Set(['release', 'push', 'workflow_dispatch', 'schedule']);
const CACHE_ACTIONS = ['actions/cache', 'actions/setup-node', 'actions/setup-python',
  'actions/setup-java', 'actions/setup-go', 'actions/setup-dotnet'];

const PULL_REQUEST_TRIGGERS = new Set(['pull_request', 'pull_request_target']);

export function checkCachePoisoning(workflow, rawContent, filename) {
  const triggers = getTriggers(workflow);

  const hasPRTrigger = triggers.some(t => PULL_REQUEST_TRIGGERS.has(t));
  const hasReleaseTrigger = triggers.some(t => RELEASE_TRIGGERS.has(t));

  if (!hasPRTrigger || !hasReleaseTrigger) return [];

  const steps = getAllSteps(workflow);

  // Find the first cache action usage to anchor the finding.
  // We emit ONE finding per workflow file — the risk is at the workflow level
  // (shared triggers), not per individual cache step. Emitting one finding per
  // step creates noise without extra signal.
  const firstCacheStep = steps.find(({ step }) => {
    const uses = step.uses ?? '';
    return CACHE_ACTIONS.some(a => uses.startsWith(a));
  });

  if (!firstCacheStep) return [];

  const { jobName, step, stepIndex } = firstCacheStep;
  const uses = step.uses ?? '';
  const lineNumber = findLineNumber(rawContent, uses.split('@')[0]);
  const snippet = extractSnippet(rawContent, lineNumber, 4);
  const releaseTriggerNames = triggers.filter(t => RELEASE_TRIGGERS.has(t)).join(', ');

  return [{
    id: `cache-poisoning-${filename}`,
    rule: 'cache-poisoning',
    severity: 'high',
    title: 'Potential Cache Poisoning in Release Workflow',
    file: `.github/workflows/${filename}`,
    line: lineNumber,
    snippet,
    context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}  ·  Triggers: ${triggers.join(', ')}`,
    detail: `This workflow responds to both \`pull_request\` (which lets fork PRs write to shared caches) and \`${releaseTriggerNames}\` (release/publish path). A poisoned cache entry written during a PR build can be restored during a later release build if cache keys or restore-key prefixes overlap.`,
    exploit: `1. Open a PR that writes malicious artifacts into the shared cache.\n2. The release build restores the poisoned cache (shared key prefix).\n3. Malicious code ships in the published artifact or gets deployed to prod.\n\nNote: pull_request_target runs in the base branch context, giving PR jobs write access to the default branch cache scope, which release workflows can restore.`,
    impact: 'Supply Chain Compromise via Cache Poisoning',
    remediation: `1. Use completely separate, non-overlapping cache keys for PR and release builds (avoid shared restore-key prefixes).\n2. Do not restore PR-written caches in release/deploy workflows.\n3. Add integrity verification (hash checks) for restored cache contents.\n4. Consider disabling cache writes on PRs from forks with \`if: github.event.pull_request.head.repo.full_name == github.repository\`.`,
    cvss: {
      score:  8.0,
      vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N',
      cwe:    'CWE-345',
    },
  }];
}
