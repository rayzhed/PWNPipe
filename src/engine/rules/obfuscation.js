import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// Only patterns with a strong signal-to-noise ratio are included here.
// Removed high-false-positive patterns:
//   eval           — ubiquitous in shell scripts; too broad without context
//   python -c      — common one-liner idiom, not inherently obfuscation
//   perl -e        — same as above
//   ruby -e        — same as above
//   /dev/urandom   — standard random data source, not obfuscation
const OBFUSCATION_PATTERNS = [
  { pattern: /base64\s+-d/, label: 'base64 decode' },
  { pattern: /base64\s+--decode/, label: 'base64 decode' },
  // eval with command substitution is the suspicious form (e.g. eval $(curl ...))
  // rather than eval with a static string literal
  { pattern: /\beval\s+\$[({]/, label: 'eval with command substitution' },
  { pattern: /printf\s+['"]\\x/, label: 'hex escape printf' },
  { pattern: /\bxxd\b/, label: 'xxd hex tool' },
  { pattern: /openssl\s+enc\s+-d/, label: 'openssl decode' },
];

export function checkObfuscation(workflow, rawContent, filename) {
  const findings = [];
  const steps = getAllSteps(workflow);

  for (const { jobId, jobName, step, stepIndex } of steps) {
    const run = step.run;
    if (typeof run !== 'string') continue;

    for (const { pattern, label } of OBFUSCATION_PATTERNS) {
      if (!pattern.test(run)) continue;

      const lineNumber = findLineNumber(rawContent, pattern);
      const snippet = extractSnippet(rawContent, lineNumber, 4);

      findings.push({
        id: `obfuscation-${filename}-${jobId}-${stepIndex}-${label.replace(/\s/g, '-')}`,
        rule: 'obfuscation',
        severity: 'medium',
        title: `Potential Obfuscation: ${label}`,
        file: `.github/workflows/${filename}`,
        line: lineNumber,
        snippet,
        context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}`,
        detail: `The use of \`${label}\` in a \`run:\` block can be used to execute obfuscated or encoded payloads that bypass static analysis and code review. While sometimes legitimate, this pattern is commonly used in malicious workflows to hide backdoors.`,
        exploit: `A compromised dependency or a malicious PR contributor encodes a payload in base64/hex → the workflow decodes and executes it at runtime, completely bypassing any static analysis of the workflow YAML.`,
        impact: 'Potential Hidden Payload Execution',
        remediation: `Review the obfuscated command and replace it with a clear, readable equivalent. If encoding is genuinely needed (e.g., for binary data), add a comment explaining the encoded content and its source.`,
        cvss: {
          score:  5.5,
          vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N',
          cwe:    'CWE-506',
        },
      });
      break; // one finding per step
    }
  }

  return findings;
}
