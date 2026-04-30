import { getTriggers, findLineNumber, extractSnippet } from '../yaml-parser.js';

const GITHUB_HOSTED = new Set([
  // Ubuntu x64
  'ubuntu-latest', 'ubuntu-24.04', 'ubuntu-22.04', 'ubuntu-20.04', 'ubuntu-slim',
  // Ubuntu ARM64 (free on public repos since Jan 2025)
  'ubuntu-24.04-arm', 'ubuntu-22.04-arm',
  // Windows x64
  'windows-latest', 'windows-2025', 'windows-2022', 'windows-2019',
  'windows-2025-vs2026',
  // Windows ARM64
  'windows-11-arm',
  // macOS ARM64 (M-series)
  'macos-latest', 'macos-15', 'macos-14', 'macos-13', 'macos-12', 'macos-26',
  // macOS Intel (x64)
  'macos-15-intel', 'macos-26-intel', 'macos-13-large',
  // macOS larger runners (Team/Enterprise)
  'macos-latest-large', 'macos-14-large', 'macos-15-large', 'macos-26-large',
  'macos-latest-xlarge', 'macos-14-xlarge', 'macos-15-xlarge', 'macos-26-xlarge',
  // Ubuntu larger runners (Team/Enterprise) — fixed labels
  'ubuntu-22.04-large', 'ubuntu-22.04-xlarge',
  'ubuntu-24.04-large', 'ubuntu-24.04-xlarge',
]);

// Triggers that external, non-collaborator attackers can actually fire.
// workflow_dispatch and repository_dispatch require write-level access (or a
// repo-scoped PAT), so they are NOT public in the attacker model and are excluded.
const PUBLIC_TRIGGERS = new Set([
  'push', 'pull_request', 'pull_request_target', 'issues', 'issue_comment',
  'discussion', 'discussion_comment', 'release', 'create', 'delete',
  'fork', 'watch', 'star',
]);

// Common GitHub-hosted runner label prefixes — used to avoid flagging org-specific
// larger runner labels (e.g. "ubuntu-latest-8-cores") as self-hosted.
const GITHUB_RUNNER_PREFIXES = ['ubuntu-', 'windows-', 'macos-'];

function isSelfHosted(runsOn) {
  if (!runsOn) return false;

  // runs-on can be a matrix expression — skip if we can't resolve it statically
  if (typeof runsOn === 'string' && runsOn.includes('${{')) return false;

  const labels = Array.isArray(runsOn) ? runsOn : [runsOn];
  const labelStrings = labels.map(l => String(l).toLowerCase());

  // Explicit self-hosted label is definitive
  if (labelStrings.some(l => l === 'self-hosted')) return true;

  // Any known GitHub-hosted label in the set → not self-hosted
  if (labelStrings.some(l => GITHUB_HOSTED.has(l))) return false;

  // Labels matching GitHub-hosted prefixes are likely org-configured larger runners
  if (labelStrings.some(l => GITHUB_RUNNER_PREFIXES.some(p => l.startsWith(p)))) return false;

  // All labels are unknown — treat as potentially self-hosted
  return true;
}

export function checkSelfHostedRunner(workflow, rawContent, filename) {
  const findings = [];
  const jobs = workflow?.jobs ?? {};
  const triggers = getTriggers(workflow);
  const hasPublicTrigger = triggers.some(t => PUBLIC_TRIGGERS.has(t));

  for (const [jobId, job] of Object.entries(jobs)) {
    if (!isSelfHosted(job['runs-on'])) continue;

    const lineNumber = findLineNumber(rawContent, 'self-hosted') ||
      findLineNumber(rawContent, `${jobId}:`);
    const snippet = extractSnippet(rawContent, lineNumber, 4);
    const severity = hasPublicTrigger ? 'high' : 'medium';

    findings.push({
      id: `self-hosted-runner-${filename}-${jobId}`,
      rule: 'self-hosted-runner',
      severity,
      title: `Self-Hosted Runner${hasPublicTrigger ? ' with Public Trigger' : ''}`,
      file: `.github/workflows/${filename}`,
      line: lineNumber,
      snippet,
      context: `Job: \`${job.name ?? jobId}\`  ·  Triggers: ${triggers.join(', ') || 'unknown'}`,
      detail: `Job \`${jobId}\` runs on a self-hosted runner (${JSON.stringify(job['runs-on'])}). Self-hosted runners are persistent machines. Any code executed on them leaves lasting artifacts.${hasPublicTrigger ? ' This workflow triggers on public events, so external contributors can send PRs/issues that run code on your infrastructure.' : ''}`,
      exploit: `An attacker who achieves code execution on this runner can: install persistent backdoors or keyloggers, access the internal network and pivot to other systems, read credentials cached from previous runs, exfiltrate all secrets in the runner's environment. Tools and credentials persist between workflow runs.`,
      impact: hasPublicTrigger ? 'Persistent Infrastructure Compromise via Public Trigger' : 'Persistent Infrastructure Access',
      remediation: `1. Prefer GitHub-hosted runners (\`ubuntu-latest\`) for untrusted code execution.\n2. If self-hosted runners are required, run them in ephemeral containers (never persistent VMs).\n3. Restrict workflow triggers to trusted actors only.\n4. Implement runner isolation with no internal network access.`,
      cvss: hasPublicTrigger
        ? { score: 8.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H', cwe: 'CWE-829' }
        : { score: 5.9, vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N', cwe: 'CWE-829' },
    });
  }

  return findings;
}
