/**
 * Generate a dynamic offensive summary paragraph based on scan findings.
 * Covers all 20 detection rules.
 */
export function generateSummary(findings) {
  if (!findings || findings.length === 0) {
    return 'Nothing caught. This tool misses things, so check manually too.';
  }

  const rules      = new Set(findings.map(f => f.rule));
  const severities = new Set(findings.map(f => f.severity));
  const parts      = [];

  const hasCritical         = severities.has('critical');
  const hasInjection        = rules.has('template-injection');
  const hasGithubEnv        = rules.has('github-env');
  const hasUnsecureCmds     = rules.has('actions-allow-unsecure-commands');
  const hasPwnRequest       = rules.has('dangerous-trigger');
  const hasWorkflowRun      = rules.has('workflow-run-trigger');
  const hasUnpinnedActions  = rules.has('unpinned-actions');
  const hasUnpinnedDocker   = rules.has('unpinned-docker-image');
  const hasReusableWf       = rules.has('reusable-workflow-ref');
  const hasCurlPipe         = rules.has('curl-pipe-sh');
  const hasCachePoison      = rules.has('cache-poisoning');
  const hasNoPerms          = rules.has('excessive-permissions');
  const hasSelfHosted       = rules.has('self-hosted-runner');
  const hasSecretsInherit   = rules.has('secrets-inherit');
  const hasHardcoded        = rules.has('hardcoded-secrets');
  const hasArtipacked       = rules.has('artipacked');
  const hasTokenLogs        = rules.has('token-in-logs');
  const hasBotConditions    = rules.has('bot-conditions');
  const hasUnsoundContains  = rules.has('unsound-contains');
  const hasObfuscation      = rules.has('obfuscation');
  const hasDebug            = rules.has('debug-enabled');

  if (hasCritical) {
    parts.push('This repo is **highly exploitable**.');
  }

  // ── Credentials ──────────────────────────────────────────────────────────
  if (hasHardcoded) {
    parts.push('Hardcoded credentials found in workflow files. Treat them as **already compromised** and rotate immediately.');
  }

  // ── Injection / code execution ────────────────────────────────────────────
  if (hasPwnRequest && hasInjection) {
    parts.push('An external attacker gets **code execution with full secret access** by chaining `pull_request_target` with an unsafe checkout and template injection through issue/PR content. No maintainer interaction needed.');
  } else if (hasPwnRequest) {
    parts.push('The `pull_request_target` trigger with a dangerous checkout lets anyone fork the repo, open a PR, and run code with the base repo\'s secrets.');
  } else if (hasInjection) {
    parts.push('Template injections in `run:` blocks let attackers execute arbitrary commands through issue titles, PR descriptions, and comment bodies.');
  }

  if (hasWorkflowRun) {
    parts.push('`workflow_run` carries the same trust-boundary risk as `pull_request_target`: fork-triggered workflows run with base repo secrets, and any unsafe checkout becomes a full pwn-request.');
  }

  if (hasGithubEnv) {
    parts.push('Unsanitized data written to `$GITHUB_ENV` lets attackers inject environment variables into every subsequent step, including `NODE_OPTIONS`, `LD_PRELOAD`, and `PATH`.');
  }

  if (hasUnsecureCmds) {
    parts.push('`ACTIONS_ALLOW_UNSECURE_COMMANDS: true` re-enables the deprecated `::set-env::` and `::add-path::` commands. Any step can inject env vars into all following steps by printing to stdout — no file write needed.');
  }

  // ── Supply chain ──────────────────────────────────────────────────────────
  const supplyChainIssues = [hasUnpinnedActions, hasUnpinnedDocker, hasReusableWf, hasCurlPipe].filter(Boolean).length;

  if (supplyChainIssues > 1 && hasNoPerms) {
    parts.push('Multiple supply-chain attack surfaces (unpinned actions, Docker images, reusable workflows, or remote scripts) combined with excessive GITHUB_TOKEN permissions create a **kill chain**: compromise any upstream dependency and get full repo write access.');
  } else {
    if (hasUnpinnedActions && hasNoPerms) {
      parts.push('Unpinned actions plus excessive GITHUB_TOKEN permissions is a **supply chain kill chain**: whoever controls the action tag gets full write access to the repo, packages, and releases.');
    } else {
      if (hasUnpinnedActions) {
        parts.push('Unpinned actions (tag or branch, not SHA) mean anyone who can push to that tag runs code in every consumer repo. This is exactly how the tj-actions attack compromised 23,000+ repos.');
      }
      if (hasNoPerms) {
        parts.push('Excessive GITHUB_TOKEN permissions amplify every other finding. Any code execution gets repo write access to push code, publish packages, and create releases.');
      }
    }

    if (hasUnpinnedDocker) {
      parts.push('Unpinned Docker images (`docker://image:tag` without a sha256 digest) can be silently repointed after any CI run — no repo change required, no diff visible in code review.');
    }

    if (hasReusableWf) {
      parts.push('Unpinned reusable workflows called at a mutable branch or tag execute whatever code is at that ref at runtime. A compromised maintainer account is all an attacker needs.');
    }

    if (hasCurlPipe) {
      parts.push('Remote scripts piped directly into a shell (`curl | bash`) execute whatever code the remote host returns. Compromise the CDN, DNS, or hosting bucket and every pipeline run becomes your shell.');
    }
  }

  if (hasCachePoison) {
    parts.push('This workflow handles both PRs and releases with shared cache keys. A fork PR can poison the cache; the release build restores and ships the malicious artifact.');
  }

  // ── Infrastructure ────────────────────────────────────────────────────────
  if (hasSelfHosted) {
    parts.push('Self-hosted runners are persistent machines. Code execution leaves backdoors, cached credentials, and lateral-movement pivot points that survive between workflow runs.');
  }

  // ── Credential hygiene ────────────────────────────────────────────────────
  if (hasSecretsInherit) {
    parts.push('`secrets: inherit` hands every caller secret to the reusable workflow. If that workflow is compromised via supply chain or maintainer account takeover, all credentials are immediately accessible.');
  }

  if (hasArtipacked) {
    parts.push('Git credentials stored in the workspace get uploaded as artifacts. Anyone with repo read access can download the artifact and extract the embedded GITHUB_TOKEN from `.git/config`.');
  }

  if (hasTokenLogs) {
    parts.push('Secrets or GITHUB_TOKEN appear to be echoed to workflow logs. GitHub\'s masking can be bypassed with base64-encoding or shell tracing (`set -x`) — treat any secret that has been logged as already leaked.');
  }

  // ── Authorization bypass ──────────────────────────────────────────────────
  if (hasBotConditions || hasUnsoundContains) {
    parts.push('Authorization checks using `github.actor` comparisons can be bypassed: attackers register an account matching the expected username or substring, making the condition evaluate to true.');
  }

  // ── Operational risk ──────────────────────────────────────────────────────
  if (hasObfuscation) {
    parts.push('Base64-decoded or hex-decoded commands in `run:` blocks hide payloads from static analysis. Review the decoded content — this pattern is a common indicator of supply-chain compromise or a malicious insider.');
  }

  if (hasDebug) {
    parts.push('Debug logging (`ACTIONS_STEP_DEBUG` or `ACTIONS_RUNNER_DEBUG`) is enabled in a committed workflow. Debug output includes full environment dumps and can expose secrets that GitHub\'s log masking missed.');
  }

  return parts.join(' ');
}
