import { findLineNumber, extractSnippet } from '../yaml-parser.js';

// Triggers that can be activated externally — these are the ones worth flagging
const EXTERNAL_TRIGGERS = new Set([
  'push', 'pull_request', 'pull_request_target', 'workflow_run',
  'issue_comment', 'issues', 'discussion', 'discussion_comment',
  'release', 'schedule', 'workflow_dispatch',
]);

function hasExternalTrigger(on) {
  if (!on) return false;
  if (typeof on === 'string') return EXTERNAL_TRIGGERS.has(on);
  if (Array.isArray(on)) return on.some(t => EXTERNAL_TRIGGERS.has(t));
  if (typeof on === 'object') return Object.keys(on).some(k => EXTERNAL_TRIGGERS.has(k));
  return false;
}

export function checkMissingTimeout(workflow, rawContent, filename) {
  if (!hasExternalTrigger(workflow?.on)) return [];

  const findings = [];
  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    if (job['timeout-minutes'] !== undefined && job['timeout-minutes'] !== null) continue;

    const jobName = job.name ?? jobId;
    const lineNumber = findLineNumber(rawContent, `${jobId}:`) || findLineNumber(rawContent, 'runs-on:');
    const snippet = extractSnippet(rawContent, lineNumber, 3);

    findings.push({
      id:          `missing-timeout-${filename}-${jobId}`,
      rule:        'missing-timeout',
      severity:    'low',
      title:       `Job \`${jobId}\` Has No \`timeout-minutes\``,
      file:        filename,
      line:        lineNumber,
      snippet,
      context:     `Job: \`${jobName}\`  ·  Default timeout: 360 minutes`,
      detail:      `Job \`${jobId}\` does not set \`timeout-minutes\`. GitHub's default job timeout is 360 minutes (6 hours). A hung step — caused by a dependency waiting for a lock, a flaky network call, or a deliberate denial-of-service via malicious input — will consume runner minutes for up to 6 hours before being killed.`,
      exploit:     `An attacker submits a PR that triggers this workflow with an input that causes a step to hang indefinitely (e.g., a network request to a controlled endpoint that never responds). Without a timeout, the job consumes org-level runner minutes until the 6-hour GitHub limit is hit. Repeated over many PRs, this exhausts CI capacity.`,
      impact:      'Denial of Service / CI Cost Exhaustion',
      remediation: `Set an appropriate \`timeout-minutes\` on the job:\n\njobs:\n  ${jobId}:\n    timeout-minutes: 30\n\nChoose a value that gives the job enough time under normal conditions but limits damage from stuck runs.`,
      cvss:        { score: 3.7, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L', cwe: 'CWE-400' },
    });
  }

  return findings;
}
