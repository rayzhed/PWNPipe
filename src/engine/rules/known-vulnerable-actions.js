import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

const KNOWN_VULNERABLE = [
  {
    action: 'tj-actions/changed-files',
    affectedTags: null,
    cve: 'CVE-2025-30066',
    cvss: 9.3,
    description: 'All version tags of tj-actions/changed-files were repointed to a malicious commit that printed secrets to logs. Over 23,000 repositories were affected.',
    fixedAt: null,
    advisoryUrl: 'https://github.com/tj-actions/changed-files/security/advisories/GHSA-mrrh-fwg8-r2c3',
  },
  {
    action: 'reviewdog/action-setup',
    affectedTags: ['v1'],
    cve: 'CVE-2025-30154',
    cvss: 8.6,
    description: 'reviewdog/action-setup@v1 was compromised as part of the tj-actions supply chain attack. The tag was repointed to a malicious commit.',
    fixedAt: 'v1.3.0',
    advisoryUrl: 'https://github.com/reviewdog/action-setup/security/advisories/GHSA-9f6j-hqjc-5f6m',
  },
  {
    action: 'ultralytics/actions',
    affectedTags: null,
    cve: null,
    cvss: 8.0,
    description: 'ultralytics/actions was compromised with a cryptominer payload injected via a malicious PR to the upstream action repository.',
    fixedAt: null,
    advisoryUrl: 'https://github.com/ultralytics/actions/security/advisories/GHSA-7x29-qqmq-v6qc',
  },
  {
    action: 'actions/checkout',
    affectedTags: ['v1', 'v2', 'v3'],
    cve: null,
    cvss: 6.5,
    description: 'actions/checkout before v4 persists the GITHUB_TOKEN in .git/config (ArtiPACKED). Combined with artifact upload, this leaks the token to anyone with repo read access.',
    fixedAt: 'v4',
    advisoryUrl: 'https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/',
  },
  {
    action: 'docker/login-action',
    affectedTags: ['v1'],
    cve: null,
    cvss: 5.0,
    description: 'docker/login-action@v1 logged Docker credentials in plain text when debug mode was enabled.',
    fixedAt: 'v2',
    advisoryUrl: 'https://github.com/docker/login-action/security',
  },
];

function isAffected(vuln, tag) {
  if (vuln.affectedTags === null) return true;
  return vuln.affectedTags.includes(tag);
}

function severityFromCvss(score) {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  return 'medium';
}

export function checkKnownVulnerableActions(workflow, rawContent, filename) {
  const findings = [];
  const steps = getAllSteps(workflow);

  for (const { jobId, jobName, step, stepIndex } of steps) {
    const uses = step.uses;
    if (typeof uses !== 'string') continue;

    const atIdx = uses.lastIndexOf('@');
    const actionName = atIdx !== -1 ? uses.slice(0, atIdx) : uses;
    const tag = atIdx !== -1 ? uses.slice(atIdx + 1) : '';

    for (const vuln of KNOWN_VULNERABLE) {
      if (actionName !== vuln.action) continue;
      if (!isAffected(vuln, tag)) continue;

      const lineNumber = findLineNumber(rawContent, uses.slice(0, 40));
      const snippet = extractSnippet(rawContent, lineNumber, 3);
      const severity = severityFromCvss(vuln.cvss);
      const cveLabel = vuln.cve ? ` (${vuln.cve})` : '';
      const fixNote = vuln.fixedAt ? ` Fixed at \`${vuln.fixedAt}\`.` : ' No safe version available — remove or replace this action.';

      findings.push({
        id: `known-vulnerable-actions-${filename}-${jobId}-${stepIndex}-${vuln.action.replace(/\//g, '-')}`,
        rule: 'known-vulnerable-actions',
        severity,
        title: `Known Vulnerable Action${cveLabel}: \`${uses}\``,
        file: filename,
        line: lineNumber,
        snippet,
        context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}`,
        detail: vuln.description,
        exploit: `This action has a publicly disclosed vulnerability with CVSS ${vuln.cvss}. See: ${vuln.advisoryUrl}`,
        impact: `Confirmed Supply Chain Compromise + CVSS ${vuln.cvss}`,
        remediation: `Update immediately.${fixNote}\n\nAdvisory: ${vuln.advisoryUrl}`,
        cvss: {
          score: vuln.cvss,
          vector: severity === 'critical'
            ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
            : severity === 'high'
              ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N'
              : 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
          cwe: 'CWE-829',
          ...(vuln.cve ? { cve: [vuln.cve] } : {}),
        },
      });
      break;
    }
  }

  return findings;
}
