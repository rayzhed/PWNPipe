import { findLineNumber, extractSnippet } from '../yaml-parser.js';

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

  const jobs = workflow?.jobs ?? {};
  const jobEntries = Object.entries(jobs);
  if (jobEntries.length === 0) return [];

  // Collect jobs missing timeout-minutes
  const missingJobs = jobEntries
    .filter(([, job]) => job['timeout-minutes'] === undefined || job['timeout-minutes'] === null)
    .map(([id, job]) => job.name ?? id);

  if (missingJobs.length === 0) return [];

  const lineNumber = findLineNumber(rawContent, /^on:/);
  const snippet = extractSnippet(rawContent, lineNumber, 3);

  const jobList = missingJobs.length <= 4
    ? missingJobs.map(n => `\`${n}\``).join(', ')
    : `${missingJobs.slice(0, 3).map(n => `\`${n}\``).join(', ')} and ${missingJobs.length - 3} more`;

  return [{
    id:          `missing-timeout-${filename}`,
    rule:        'missing-timeout',
    severity:    'low',
    title:       `${missingJobs.length} Job${missingJobs.length > 1 ? 's' : ''} Without \`timeout-minutes\` (Default: 6h)`,
    file:        filename,
    line:        lineNumber,
    snippet,
    context:     `Jobs: ${jobList}`,
    detail:      `${missingJobs.length === jobEntries.length ? 'None' : `${missingJobs.length} of ${jobEntries.length}`} of this workflow's jobs set \`timeout-minutes\`. GitHub's default is 360 minutes (6 hours). A hung step — caused by a dependency waiting for a lock, a flaky network call, or a deliberate denial-of-service via malicious input — will consume runner minutes for up to 6 hours before being killed.`,
    exploit:     `An attacker submits a PR that triggers this workflow with an input causing a step to hang indefinitely (e.g., a network request to a controlled endpoint that never responds). Without a timeout, the job consumes CI minutes until GitHub's 6-hour limit. Repeated across many PRs this exhausts org-level runner capacity.`,
    impact:      'Denial of Service / CI Cost Exhaustion via Hung Jobs',
    remediation: `Set \`timeout-minutes\` on each job to a value generous enough for normal runs but tight enough to limit stuck runs:\n\njobs:\n  build:\n    timeout-minutes: 30`,
    cvss:        { score: 3.7, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L', cwe: 'CWE-400' },
  }];
}
