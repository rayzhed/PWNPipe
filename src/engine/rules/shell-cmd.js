import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

export function checkShellCmd(workflow, rawContent, filename) {
  const findings = [];
  const steps = getAllSteps(workflow);

  for (const { jobId, jobName, step, stepIndex } of steps) {
    const shell = step.shell;
    if (shell !== 'cmd' && shell !== 'powershell') continue;

    const lineNumber = findLineNumber(rawContent, `shell: ${shell}`);
    const snippet = extractSnippet(rawContent, lineNumber, 4);

    if (shell === 'cmd') {
      findings.push({
        id: `shell-cmd-${filename}-${jobId}-${stepIndex}`,
        rule: 'shell-cmd',
        severity: 'high',
        title: `Legacy Shell: \`shell: cmd\` in step`,
        file: `.github/workflows/${filename}`,
        line: lineNumber,
        snippet,
        context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}`,
        detail: `The step uses \`shell: cmd\` (Windows Command Prompt). CMD uses \`%VAR%\` expansion and \`^\` as an escape character. These differ significantly from bash semantics — injection patterns are less well understood, sanitisation is harder, and most CI security guidance focuses on bash. Any user-controlled input interpolated into a CMD run block is at elevated risk.`,
        exploit: `If any part of the run block contains user-controlled input (e.g., a branch name, PR title, or artifact path), an attacker can craft input exploiting CMD-specific expansion rules (\`%VAR%\`, delayed expansion \`!VAR!\`, or argument splitting via \`^\`) to break out of the intended command and execute arbitrary commands.`,
        impact: 'Command Injection / Arbitrary Code Execution',
        remediation: `Switch to \`shell: pwsh\` (PowerShell Core) or \`shell: bash\` which are available on Windows runners and have better-understood injection mitigations. Ensure no user-controlled input is interpolated into the run script without sanitisation.`,
        cvss: {
          score:  7.3,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
          cwe:    'CWE-78',
        },
      });
    } else {
      findings.push({
        id: `shell-cmd-${filename}-${jobId}-${stepIndex}`,
        rule: 'shell-cmd',
        severity: 'medium',
        title: `Legacy Shell: \`shell: powershell\` in step`,
        file: `.github/workflows/${filename}`,
        line: lineNumber,
        snippet,
        context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}${step.name ? ` (${step.name})` : ''}`,
        detail: `The step uses \`shell: powershell\` (Windows PowerShell 5.x). PowerShell has distinct injection surfaces including \`-Command\` string interpolation and expandable strings (\`"...\`). PowerShell 5.x is also unmaintained on non-Windows platforms; \`pwsh\` (PowerShell Core) is preferred. Injection patterns in PowerShell are less commonly audited than bash.`,
        exploit: `User-controlled input interpolated into a PowerShell run block can exploit string expansion to inject commands. For example, a value like \`"; Invoke-Expression $env:MALICIOUS"\` can break out of the intended expression and run arbitrary code with access to all secrets.`,
        impact: 'Command Injection / Secret Exfiltration',
        remediation: `Switch to \`shell: pwsh\` (PowerShell Core) which is cross-platform and actively maintained. Ensure no user-controlled input is interpolated into the run script. Use \`[System.Management.Automation.WildcardPattern]::Escape()\` or parameterised invocations for any dynamic values.`,
        cvss: {
          score:  5.4,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
          cwe:    'CWE-78',
        },
      });
    }
  }

  return findings;
}
