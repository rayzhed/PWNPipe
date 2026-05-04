import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// Matches: curl ... | bash, wget ... | sh, curl ... | python, etc.
// The shell/interpreter must follow the pipe to avoid false positives on
// patterns like `curl ... | jq` or `curl ... | grep`.
const PIPE_SHELL_RE = /\b(?:curl|wget)\b[^|#\n]*\|\s*(?:ba|da|z|fi|a|c)?sh\b|\b(?:curl|wget)\b[^|#\n]*\|\s*(?:python3?|ruby|perl|node)\b/;

// Process substitution: bash <(curl ...) or sh <(wget ...)
const PROC_SUB_RE = /\b(?:ba|da|z|c)?sh\s+<\s*\(\s*(?:curl|wget)\b/;

export function checkCurlPipeSh(workflow, rawContent, filename) {
  const findings = [];
  const steps = getAllSteps(workflow);

  for (const { jobId, jobName, step, stepIndex } of steps) {
    const run = step.run;
    if (typeof run !== 'string') continue;

    const pipeMatch  = PIPE_SHELL_RE.exec(run);
    const procMatch  = PROC_SUB_RE.exec(run);
    const hit = pipeMatch ?? procMatch;
    if (!hit) continue;

    const lineNumber = findLineNumber(rawContent, hit[0].trim().slice(0, 25));
    const snippet    = extractSnippet(rawContent, lineNumber, 4);

    findings.push({
      id: `curl-pipe-sh-${filename}-${jobId}-${stepIndex}`,
      rule: 'curl-pipe-sh',
      severity: 'high',
      title: 'Remote Script Executed Without Integrity Check',
      file: filename,
      line: lineNumber,
      snippet,
      context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}`,
      detail: `A remote script is fetched and piped directly into a shell interpreter without any checksum or signature verification. If the remote host, CDN, or DNS is compromised at the moment of the workflow run, attacker-controlled code executes silently in the pipeline with access to all secrets.`,
      exploit: `1. Compromise the domain, CDN, S3 bucket, or GitHub release hosting the script.\n2. Replace the script with a payload that reads \`$GITHUB_TOKEN\` and all env secrets and exfiltrates them.\n3. Every repo running this workflow automatically fetches and executes the payload — no repo change needed.`,
      impact: 'Supply Chain RCE + Full Secret Exfiltration',
      remediation: `Download the script, verify its SHA-256, then execute:\n\ncurl -fsSL https://example.com/install.sh -o /tmp/install.sh\necho "<expected-sha256>  /tmp/install.sh" | sha256sum -c\nbash /tmp/install.sh\n\nBetter: vendor the script in the repo and reference it with a relative path. Best: use a pinned action that wraps the installer.`,
      cvss: {
        score:  8.1,
        vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
        cwe:    'CWE-494',
      },
    });
  }

  return findings;
}
