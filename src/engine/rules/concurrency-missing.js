import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

const DEPLOY_ACTIONS = new Set([
  'actions/deploy-pages',
  'softprops/action-gh-release',
  'pypa/gh-action-pypi-publish',
  'JS-DevTools/npm-publish',
]);

const WRITE_PERMS = new Set(['contents', 'deployments', 'packages', 'pages']);

function hasDeployStep(workflow) {
  const steps = getAllSteps(workflow);
  for (const { step } of steps) {
    const uses = step.uses ?? '';
    if (DEPLOY_ACTIONS.has(uses.split('@')[0])) return true;
    const run = step.run ?? '';
    if (/\bnpm\s+publish\b/.test(run)) return true;
  }
  return false;
}

function hasWritePermission(workflow) {
  function check(perms) {
    if (!perms || typeof perms !== 'object') return false;
    for (const key of WRITE_PERMS) {
      if (perms[key] === 'write') return true;
    }
    return false;
  }

  if (check(workflow.permissions)) return true;
  for (const job of Object.values(workflow.jobs ?? {})) {
    if (check(job.permissions)) return true;
  }
  return false;
}

function hasEnvironment(workflow) {
  for (const job of Object.values(workflow.jobs ?? {})) {
    if (job.environment !== undefined && job.environment !== null) return true;
  }
  return false;
}

export function checkConcurrencyMissing(workflow, rawContent, filename) {
  if (workflow.concurrency !== undefined && workflow.concurrency !== null) return [];

  const isDeployWorkflow = hasEnvironment(workflow) || hasWritePermission(workflow) || hasDeployStep(workflow);
  if (!isDeployWorkflow) return [];

  const lineNumber = findLineNumber(rawContent, /^on:/);
  const snippet = extractSnippet(rawContent, lineNumber, 4);

  return [{
    id: `concurrency-missing-${filename}`,
    rule: 'concurrency-missing',
    severity: 'medium',
    title: 'Deploy/Write Workflow Missing Concurrency Control',
    file: filename,
    line: lineNumber,
    snippet,
    context: 'Workflow-level — no concurrency: block found',
    detail: `This workflow performs deployments or write operations but has no \`concurrency:\` block. Without concurrency control, two parallel runs triggered at the same time (e.g., two pushes in quick succession) will both execute write/deploy operations simultaneously, leading to race conditions or double-deploys.`,
    exploit: `Push two commits rapidly or trigger the workflow twice concurrently. Both runs proceed without waiting for the other. In deployment contexts this can result in partial or duplicate releases; in package-publish workflows both runs may attempt to publish the same version, one of which will fail and leave the registry in an inconsistent state.`,
    impact: 'Race condition, double-deploy, or duplicate release',
    remediation: `Add a concurrency group to the workflow:\n\nconcurrency:\n  group: \${{ github.workflow }}-\${{ github.ref }}\n  cancel-in-progress: true\n\nFor deployment workflows where you want queuing instead of cancellation, use \`cancel-in-progress: false\`.`,
    cvss: {
      score:  4.3,
      vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N',
      cwe:    'CWE-362',
    },
  }];
}
