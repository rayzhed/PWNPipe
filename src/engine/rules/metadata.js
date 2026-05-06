/**
 * Per-rule metadata: OWASP CI/CD Security Top 10 category and detection confidence.
 *
 * OWASP CI/CD Top 10 (2022): https://owasp.org/www-project-top-10-ci-cd-security-risks/
 *   CICD-SEC-1  Insufficient Flow Control Mechanisms
 *   CICD-SEC-2  Inadequate Identity and Access Management
 *   CICD-SEC-3  Dependency Chain Abuse
 *   CICD-SEC-4  Poisoned Pipeline Execution (PPE)
 *   CICD-SEC-5  Insufficient PBAC (Pipeline-Based Access Controls)
 *   CICD-SEC-6  Insufficient Credential Hygiene
 *   CICD-SEC-7  Insecure System Configuration
 *   CICD-SEC-8  Ungoverned Usage of 3rd Party Services
 *   CICD-SEC-9  Improper Artifact Integrity Validation
 *   CICD-SEC-10 Insufficient Logging and Visibility
 *
 * Confidence:
 *   CONFIRMED — pattern is unambiguous; exploitation requires no extra preconditions
 *   HIGH      — strong signal, low false-positive rate; edge cases exist
 *   MEDIUM    — probable issue; manual review or additional context needed to confirm
 *   LOW       — informational; many legitimate uses; treat as a lead, not a finding
 *
 * confidence may be a string (rule-level) or a function(finding) → string
 * for rules where confidence differs per finding type.
 */
export const RULE_META = {
  'template-injection':              { owasp: 'CICD-SEC-4', confidence: 'HIGH'      },
  'dangerous-trigger':               { owasp: 'CICD-SEC-4', confidence: (f) => f.severity === 'critical' ? 'CONFIRMED' : 'HIGH' },
  'workflow-run-trigger':            { owasp: 'CICD-SEC-4', confidence: (f) => f.severity === 'critical' ? 'CONFIRMED' : 'HIGH' },
  'unpinned-actions':                { owasp: 'CICD-SEC-3', confidence: 'CONFIRMED' },
  'unpinned-docker-image':           { owasp: 'CICD-SEC-3', confidence: 'CONFIRMED' },
  'reusable-workflow-ref':           { owasp: 'CICD-SEC-3', confidence: 'CONFIRMED' },
  'excessive-permissions':           { owasp: 'CICD-SEC-5', confidence: (f) => f.severity === 'high' ? 'HIGH' : 'MEDIUM' },
  'self-hosted-runner':              { owasp: 'CICD-SEC-7', confidence: (f) => f.severity === 'high' ? 'HIGH' : 'MEDIUM' },
  'artipacked':                      { owasp: 'CICD-SEC-6', confidence: 'HIGH'      },
  'bot-conditions':                  { owasp: 'CICD-SEC-2', confidence: 'HIGH'      },
  'github-env':                      { owasp: 'CICD-SEC-4', confidence: 'HIGH'      },
  'actions-allow-unsecure-commands': { owasp: 'CICD-SEC-7', confidence: 'CONFIRMED' },
  'hardcoded-secrets':               { owasp: 'CICD-SEC-6', confidence: 'HIGH'      },
  'secrets-inherit':                 { owasp: 'CICD-SEC-6', confidence: (f) => f.severity === 'medium' ? 'HIGH' : 'MEDIUM' },
  'cache-poisoning':                 { owasp: 'CICD-SEC-3', confidence: 'MEDIUM'    },
  'curl-pipe-sh':                    { owasp: 'CICD-SEC-3', confidence: 'HIGH'      },
  'obfuscation':                     { owasp: 'CICD-SEC-4', confidence: 'MEDIUM'    },
  'token-in-logs':                   { owasp: 'CICD-SEC-6', confidence: 'MEDIUM'    },
  'debug-enabled':                   { owasp: 'CICD-SEC-7', confidence: 'CONFIRMED' },
  'unsound-contains':                { owasp: 'CICD-SEC-2', confidence: 'HIGH'      },
  'concurrency-missing':             { owasp: 'CICD-SEC-1', confidence: 'MEDIUM'    },
  'shell-cmd':                       { owasp: 'CICD-SEC-4', confidence: (f) => f.severity === 'high' ? 'HIGH' : 'MEDIUM' },
  'dependabot-missing-cooldown':     { owasp: 'CICD-SEC-3', confidence: 'LOW'       },
  'use-trusted-publishing':          { owasp: 'CICD-SEC-6', confidence: 'MEDIUM'    },
  'archived-uses':                        { owasp: 'CICD-SEC-3', confidence: 'CONFIRMED' },
  'impostor-commit':                      { owasp: 'CICD-SEC-3', confidence: (f) => f.severity === 'critical' ? 'CONFIRMED' : 'MEDIUM' },
  'ref-version-mismatch':                 { owasp: 'CICD-SEC-3', confidence: 'MEDIUM'    },
  'action-yml-template-injection':        { owasp: 'CICD-SEC-4', confidence: 'HIGH'      },
  'action-yml-unpinned-uses':             { owasp: 'CICD-SEC-3', confidence: 'CONFIRMED' },
  'known-vulnerable-actions':             { owasp: 'CICD-SEC-3', confidence: 'CONFIRMED' },
  'secrets-outside-env':                  { owasp: 'CICD-SEC-6', confidence: 'HIGH'      },
  'unredacted-secrets':                   { owasp: 'CICD-SEC-6', confidence: 'HIGH'      },
  'workflow-run-artifact-env-injection':  { owasp: 'CICD-SEC-4', confidence: 'HIGH'      },
  'dependabot-insecure-execution':        { owasp: 'CICD-SEC-4', confidence: 'HIGH'      },
  'dependabot-confused-deputy':           { owasp: 'CICD-SEC-2', confidence: 'HIGH'      },
  'hardcoded-container-credentials':      { owasp: 'CICD-SEC-6', confidence: 'CONFIRMED' },
  'id-token-write-unscoped':              { owasp: 'CICD-SEC-5', confidence: (f) => f.severity === 'high' ? 'HIGH' : 'MEDIUM' },
  'pr-runs-on-self-hosted':               { owasp: 'CICD-SEC-7', confidence: 'HIGH'      },
  'overprovisioned-secrets':              { owasp: 'CICD-SEC-5', confidence: 'MEDIUM'    },
  'github-output-injection':             { owasp: 'CICD-SEC-4', confidence: 'HIGH'      },
  'step-summary-injection':              { owasp: 'CICD-SEC-4', confidence: 'HIGH'      },
  'matrix-injection':                    { owasp: 'CICD-SEC-4', confidence: 'HIGH'      },
  'runs-on-injection':                   { owasp: 'CICD-SEC-7', confidence: (f) => f.severity === 'critical' ? 'CONFIRMED' : 'HIGH' },
  'missing-timeout':                     { owasp: 'CICD-SEC-7', confidence: 'MEDIUM'    },
  'continue-on-error':                   { owasp: 'CICD-SEC-10', confidence: (f) => f.severity === 'medium' ? 'HIGH' : 'MEDIUM' },
  'renovate-automerge':                  { owasp: 'CICD-SEC-3', confidence: 'CONFIRMED' },
  'pre-commit-unsafe':                   { owasp: 'CICD-SEC-3', confidence: 'HIGH'      },
  'repo-branch-protection':              { owasp: 'CICD-SEC-2', confidence: 'CONFIRMED' },
  'repo-secret-scanning':               { owasp: 'CICD-SEC-10', confidence: 'CONFIRMED' },
  'repo-push-protection':               { owasp: 'CICD-SEC-10', confidence: 'CONFIRMED' },
  'if-always-true':                     { owasp: 'CICD-SEC-2', confidence: 'CONFIRMED' },
  'issue-comment-toctou':               { owasp: 'CICD-SEC-4', confidence: 'CONFIRMED' },
  'github-app-unsafe':                  { owasp: 'CICD-SEC-6', confidence: 'CONFIRMED' },
};
