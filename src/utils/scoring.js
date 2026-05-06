/**
 * CVSS v3.1-aligned severity scoring.
 *
 * Individual findings carry their own cvss.score (set in each rule file).
 * The tier fallbacks below are only used when a finding pre-dates per-rule scoring.
 *
 *   Critical  9.0–10.0
 *   High      7.0–8.9
 *   Medium    4.0–6.9
 *   Low       0.1–3.9
 */

// Fallback CVSS base scores per severity tier (used when finding lacks cvss.score)
const CVSS_BASE = {
  critical: 9.8,
  high:     7.5,
  medium:   5.4,
  low:      2.3,
};

/**
 * Compute the aggregate CVSS-aligned risk score (0.0–10.0) for a set of findings.
 *
 * Only CONFIRMED and HIGH confidence findings drive the score.
 * MEDIUM and LOW confidence findings are informational — they appear in the UI
 * but do not raise the score, preventing unverified heuristics from inflating risk.
 *
 * Method: start from the highest individual finding score among confirmed findings,
 * then apply a secondary factor for finding density and combo multipliers.
 */
export function calculateScore(findings) {
  if (!findings || findings.length === 0) return 0.0;

  // Only score-eligible findings: CONFIRMED or HIGH confidence.
  // Findings without a confidence field (edge case) default to eligible.
  const SCORING_CONFIDENCE = new Set(['CONFIRMED', 'HIGH']);
  const scoreable = findings.filter(
    f => !f.confidence || SCORING_CONFIDENCE.has(f.confidence)
  );

  if (scoreable.length === 0) return 0.0;

  // Use per-finding CVSS score when available, fall back to severity-tier default
  let base = Math.max(...scoreable.map(f => f.cvss?.score ?? CVSS_BASE[f.severity] ?? 0));

  // Secondary density factor: count unique high/critical scoreable RULE TYPES.
  // 10 unpinned-action findings are still one vulnerability class.
  const highRules = new Set(
    scoreable
      .filter(f => f.severity === 'critical' || f.severity === 'high')
      .map(f => f.rule)
  );
  const densityBonus = Math.max(0, Math.min(0.8, (highRules.size - 1) * 0.15));
  base = Math.min(10.0, base + densityBonus);

  // Combo multipliers — chained attacks raise the effective score.
  // Only count rules that have at least one scoreable finding.
  const scoreableRules = new Set(scoreable.map(f => f.rule));
  const rules = scoreableRules;

  // Pwn request chain: RCE via expression injection + privileged trigger context
  if ((rules.has('template-injection') || rules.has('github-output-injection') ||
       rules.has('matrix-injection') || rules.has('runs-on-injection')) &&
     (rules.has('dangerous-trigger') || rules.has('workflow-run-trigger'))) {
    base = Math.min(10.0, base + 0.2);
  }
  // Supply chain kill chain: unpinned dependency + write permissions
  if ((rules.has('unpinned-actions') || rules.has('unpinned-docker-image') ||
       rules.has('reusable-workflow-ref') || rules.has('curl-pipe-sh')) &&
      rules.has('excessive-permissions')) {
    base = Math.min(10.0, base + 0.15);
  }
  // Persistent infra attack: self-hosted runner reachable from public trigger
  if (rules.has('self-hosted-runner') &&
     (rules.has('dangerous-trigger') || rules.has('workflow-run-trigger'))) {
    base = Math.min(10.0, base + 0.1);
  }
  // Full compromise chain: hardcoded secret + token in logs (double exposure)
  if (rules.has('hardcoded-secrets') && rules.has('token-in-logs')) {
    base = Math.min(10.0, base + 0.1);
  }

  return Math.round(base * 10) / 10;
}

/**
 * CVSS v3.1 severity label from a 0.0–10.0 score.
 */
export function scoreLabel(score) {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score >  0.0) return 'LOW';
  return 'NONE';
}

export function scoreColor(score) {
  if (score >= 9.0) return '#dc2626';
  if (score >= 7.0) return '#f97316';
  if (score >= 4.0) return '#eab308';
  if (score >  0.0) return '#22c55e';
  return '#6b7280';
}

export function countsBySeverity(findings) {
  return {
    critical: findings.filter(f => f.severity === 'critical').length,
    high:     findings.filter(f => f.severity === 'high').length,
    medium:   findings.filter(f => f.severity === 'medium').length,
    low:      findings.filter(f => f.severity === 'low').length,
  };
}

export function sortFindings(findings) {
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  return [...findings].sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));
}

/**
 * CVSS base score for a single finding severity.
 */
export function cvssScore(severity) {
  return CVSS_BASE[severity] ?? 0;
}
