import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

const SHA_REGEX = /^[a-f0-9]{40}$/;

const GITHUB_OFFICIAL_PREFIXES = ['actions/', 'github/'];

function classifyAction(uses) {
  const isOfficial = GITHUB_OFFICIAL_PREFIXES.some(p => uses.startsWith(p));
  return isOfficial ? 'medium' : 'high';
}

export function checkUnpinnedActions(workflow, rawContent, filename) {
  const findings = [];
  const steps = getAllSteps(workflow);

  for (const { jobId, jobName, step, stepIndex } of steps) {
    const uses = step.uses;
    if (typeof uses !== 'string') continue;
    if (uses.startsWith('./')) continue;    // local action — skip
    if (uses.startsWith('docker://')) continue;  // docker action — skip

    const atIdx = uses.lastIndexOf('@');
    if (atIdx === -1) {
      // No @ at all — definitely unpinned
      const lineNumber = findLineNumber(rawContent, uses.slice(0, 30));
      findings.push(makeFinding(filename, jobId, jobName, stepIndex, uses, 'no ref', 'high', lineNumber, rawContent));
      continue;
    }

    const ref = uses.slice(atIdx + 1);
    if (!SHA_REGEX.test(ref)) {
      const severity = classifyAction(uses);
      const lineNumber = findLineNumber(rawContent, uses.slice(0, 30));
      findings.push(makeFinding(filename, jobId, jobName, stepIndex, uses, ref, severity, lineNumber, rawContent));
    }
  }

  return findings;
}

function makeFinding(filename, jobId, jobName, stepIndex, uses, ref, severity, lineNumber, rawContent) {
  // Determine ref type: tags conventionally start with 'v' or a digit; anything else
  // is likely a branch name. We can't know for certain without the git remote, so
  // we label ambiguous cases as 'branch/tag' rather than guessing.
  let refType;
  if (ref === 'no ref') {
    refType = 'no ref';
  } else if (/^v\d|^\d+\.\d+/.test(ref)) {
    refType = 'version tag';
  } else if (/^[a-f0-9]{7,39}$/.test(ref)) {
    refType = 'short SHA (not pinned)';
  } else {
    refType = 'branch/tag';
  }
  const snippet = extractSnippet(rawContent, lineNumber, 3);

  return {
    id: `unpinned-actions-${filename}-${jobId}-${stepIndex}`,
    rule: 'unpinned-actions',
    severity,
    title: `Unpinned Action: \`${uses}\``,
    file: filename,
    line: lineNumber,
    snippet,
    context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}  ·  Ref type: ${refType}`,
    detail: `Action \`${uses}\` is pinned to \`${ref}\` (${refType}), not a full 40-character commit SHA. A tag or branch can be force-pushed to point at any arbitrary commit.`,
    exploit: `If the action owner's account gets compromised, an attacker force-pushes \`${ref}\` to a malicious commit. Every repo using this action runs attacker-controlled code with access to all secrets. This is exactly how the tj-actions/changed-files attack worked in March 2025. 23,000+ repos were hit.`,
    impact: 'Supply Chain RCE + Full Secret Exfiltration',
    remediation: `Pin to a full commit SHA:\n\nuses: ${uses.split('@')[0]}@<40-char-sha>  # ${ref}\n\nUse tools like \`pin-github-action\` or Renovate/Dependabot to automate SHA pinning with automated updates.`,
    cvss: severity === 'high'
      ? {
          score:  8.8,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
          cwe:    'CWE-494',
          cve:    ['CVE-2025-30066', 'CVE-2025-26909'],
        }
      : {
          score:  6.3,
          vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N',
          cwe:    'CWE-494',
        },
  };
}
