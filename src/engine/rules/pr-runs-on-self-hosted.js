import { getTriggers, findLineNumber, extractSnippet } from '../yaml-parser.js';

const PR_TRIGGERS = new Set(['pull_request', 'pull_request_target']);

const GITHUB_HOSTED = new Set([
  'ubuntu-latest', 'ubuntu-24.04', 'ubuntu-22.04', 'ubuntu-20.04', 'ubuntu-slim',
  'ubuntu-24.04-arm', 'ubuntu-22.04-arm',
  'windows-latest', 'windows-2025', 'windows-2022', 'windows-2019', 'windows-2025-vs2026',
  'windows-11-arm',
  'macos-latest', 'macos-15', 'macos-14', 'macos-13', 'macos-12', 'macos-26',
  'macos-15-intel', 'macos-26-intel', 'macos-13-large',
  'macos-latest-large', 'macos-14-large', 'macos-15-large', 'macos-26-large',
  'macos-latest-xlarge', 'macos-14-xlarge', 'macos-15-xlarge', 'macos-26-xlarge',
  'ubuntu-22.04-large', 'ubuntu-22.04-xlarge',
  'ubuntu-24.04-large', 'ubuntu-24.04-xlarge',
]);

const GITHUB_RUNNER_PREFIXES = ['ubuntu-', 'windows-', 'macos-'];

function isSelfHosted(runsOn) {
  if (!runsOn) return false;
  if (typeof runsOn === 'string' && runsOn.includes('${{')) return false;
  const labels = Array.isArray(runsOn) ? runsOn : [runsOn];
  const labelStrings = labels.map(l => String(l).toLowerCase());
  if (labelStrings.some(l => l === 'self-hosted')) return true;
  if (labelStrings.some(l => GITHUB_HOSTED.has(l))) return false;
  if (labelStrings.some(l => GITHUB_RUNNER_PREFIXES.some(p => l.startsWith(p)))) return false;
  return true;
}

export function checkPrRunsOnSelfHosted(workflow, rawContent, filename) {
  const findings = [];
  const triggers = getTriggers(workflow);
  const hasPrTrigger = triggers.some(t => PR_TRIGGERS.has(t));

  if (!hasPrTrigger) return findings;

  const triggerList = triggers.filter(t => PR_TRIGGERS.has(t)).join(', ');
  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    if (!isSelfHosted(job['runs-on'])) continue;

    const lineNumber = findLineNumber(rawContent, 'self-hosted') ||
      findLineNumber(rawContent, `${jobId}:`);
    const snippet = extractSnippet(rawContent, lineNumber, 4);

    findings.push({
      id: `pr-runs-on-self-hosted-${filename}-${jobId}`,
      rule: 'pr-runs-on-self-hosted',
      severity: 'high',
      title: `PR Workflow Runs on Self-Hosted Runner`,
      file: filename,
      line: lineNumber,
      snippet,
      context: `Job: \`${job.name ?? jobId}\`  ·  Trigger: ${triggerList}  ·  Runner: ${JSON.stringify(job['runs-on'])}`,
      detail: `Job \`${jobId}\` runs on a self-hosted runner and is triggered by \`${triggerList}\`. Anyone can submit a pull request — including from a fork — causing their code to execute on your persistent infrastructure. Self-hosted runners retain state between runs (filesystem, credentials, tool installations, network access) and may have access to your internal network.`,
      exploit: `1. Fork the repository and submit a PR.\n2. Modify any file that gets executed during the workflow (build scripts, Makefile, test runner config).\n3. The workflow runs the attacker's code on the self-hosted runner.\n4. Extract cached credentials, pivot to internal network, install persistent backdoors, or exfiltrate data from the runner's filesystem.`,
      impact: 'Persistent Infrastructure Compromise via Fork PR Code Execution',
      remediation: `1. Use GitHub-hosted runners (\`ubuntu-latest\`) for workflows triggered by pull requests.\n2. If self-hosted runners are required for PR workflows, run them in ephemeral containers that are destroyed after each job.\n3. Isolate self-hosted runners from production networks and credentials.\n4. For \`pull_request_target\`, audit every step — it runs with base-repo secrets even for fork PRs.`,
      cvss: {
        score: 8.3,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
        cwe: 'CWE-829',
      },
    });
  }

  return findings;
}
