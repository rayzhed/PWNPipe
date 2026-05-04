import { getActionSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

const SHA_REGEX = /^[a-f0-9]{40}$/;
const GITHUB_OFFICIAL_PREFIXES = ['actions/', 'github/'];

function classifyAction(uses) {
  const isOfficial = GITHUB_OFFICIAL_PREFIXES.some(p => uses.startsWith(p));
  return isOfficial ? 'medium' : 'high';
}

export function checkActionYmlUnpinnedUses(actionParsed, rawContent, filePath) {
  const findings = [];
  const steps = getActionSteps(actionParsed);

  for (const { step, stepIndex } of steps) {
    const uses = step.uses;
    if (typeof uses !== 'string') continue;
    if (uses.startsWith('./')) continue;
    if (uses.startsWith('docker://')) continue;

    const atIdx = uses.lastIndexOf('@');
    if (atIdx === -1) {
      const lineNumber = findLineNumber(rawContent, uses.slice(0, 30));
      findings.push(makeFinding(filePath, stepIndex, uses, 'no ref', 'high', lineNumber, rawContent, step));
      continue;
    }

    const ref = uses.slice(atIdx + 1);
    if (!SHA_REGEX.test(ref)) {
      const severity = classifyAction(uses);
      const lineNumber = findLineNumber(rawContent, uses.slice(0, 30));
      findings.push(makeFinding(filePath, stepIndex, uses, ref, severity, lineNumber, rawContent, step));
    }
  }

  return findings;
}

function makeFinding(filePath, stepIndex, uses, ref, severity, lineNumber, rawContent, step) {
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
    id: `action-yml-unpinned-uses-${filePath}-${stepIndex}`,
    rule: 'action-yml-unpinned-uses',
    severity,
    title: `Unpinned Action in Composite Action: \`${uses}\``,
    file: filePath,
    line: lineNumber,
    snippet,
    context: `Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}  ·  Ref type: ${refType}`,
    detail: `Action \`${uses}\` inside a composite action is pinned to \`${ref}\` (${refType}), not a full 40-character commit SHA. A force-push to this tag or branch silently replaces the code executed by every caller of this composite action.`,
    exploit: `If the action owner's account is compromised, an attacker force-pushes \`${ref}\` to a malicious commit. Every repository calling this composite action runs the attacker's code with access to all secrets passed to the action.`,
    impact: 'Supply Chain RCE via Unpinned Dependency in Composite Action',
    remediation: `Pin to a full commit SHA:\n\nuses: ${uses.split('@')[0]}@<40-char-sha>  # ${ref}\n\nUse Renovate or Dependabot to automate SHA updates.`,
    cvss: {
      score: 7.5,
      vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H',
      cwe: 'CWE-829',
    },
  };
}
