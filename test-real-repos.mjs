/**
 * Real-repo validation harness.
 * Usage:  node test-real-repos.mjs [owner/repo ...]
 *
 * Tests a curated set of repos chosen to exercise different rule categories
 * and flag obvious false positives or missed detections.
 */
import { scanRepository } from './src/engine/scanner.js';
import { calculateScore } from './src/utils/scoring.js';

const TOKEN = process.env.GH_TOKEN || process.env.VITE_DEV_TOKEN;
if (!TOKEN) { console.error('Set GH_TOKEN or VITE_DEV_TOKEN'); process.exit(1); }

// ── Test matrix ──────────────────────────────────────────────────────────────
// Each entry: what we expect to find (or NOT find) so we can spot regressions.
// "expect" is just documentation — the harness prints findings and you review.
const REPOS = [
  // --- Hardened / security-conscious repos (expect: LOW noise, zero or few low-sev findings)
  { slug: 'ossf/scorecard',               note: 'OSSF security scorecard — should be well hardened' },
  { slug: 'sigstore/cosign',              note: 'Supply-chain security tool — expect minimal findings' },
  { slug: 'github/codeql-action',         note: 'GitHub first-party action — expect clean' },

  // --- Repos known / likely to trigger our rules (expect: real findings)
  { slug: 'actions/checkout',             note: 'Widely pinned, own SHA — expect CONFIRMED unpinned in older branches?' },
  { slug: 'renovatebot/renovate',         note: 'Should trigger renovate-automerge rule' },
  { slug: 'pre-commit/pre-commit',        note: 'Should trigger pre-commit-unsafe rule' },
  { slug: 'pypa/pip',                     note: 'PyPI publish — expect use-trusted-publishing or hardcoded token' },
  { slug: 'vercel/next.js',               note: 'Large JS repo — broad workflow surface' },
  { slug: 'django/django',                note: 'Python — expect some missing timeouts, no dangerous patterns' },
  { slug: 'expressjs/express',            note: 'JS — minimal CI, good false-positive check' },

  // --- Medium-complexity repos (balanced signal/noise check)
  { slug: 'cli/cli',                      note: 'GitHub CLI — first-party, likely hardened but non-trivial' },
  { slug: 'kubernetes/kubernetes',        note: 'Large repo — many workflows, stress test for perf + noise' },
];

const SEV_COLOR = { critical: '\x1b[31m', high: '\x1b[33m', medium: '\x1b[34m', low: '\x1b[2m' };
const RESET = '\x1b[0m';
const BOLD  = '\x1b[1m';

function sev(s, text) { return `${SEV_COLOR[s] ?? ''}${text}${RESET}`; }

async function runOne(slug) {
  const [owner, repo] = slug.split('/');
  process.stdout.write(`\n${BOLD}▶ ${slug}${RESET}  `);
  const start = Date.now();
  let result;
  try {
    result = await scanRepository(owner, repo, TOKEN, () => {});
  } catch (e) {
    console.log(`\x1b[31mERROR: ${e.message}\x1b[0m`);
    return null;
  }
  const ms = Date.now() - start;

  const { findings, workflows } = result;
  const score = calculateScore(findings);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  const bar = ['critical','high','medium','low']
    .filter(s => counts[s] > 0)
    .map(s => sev(s, `${counts[s]} ${s}`))
    .join('  ');

  console.log(`${bar || '\x1b[32m✓ clean\x1b[0m'}  |  score ${score.toFixed(1)}  |  ${workflows.length} workflow(s)  |  ${ms}ms`);

  if (findings.length > 0) {
    // Group by rule for a compact view
    const byRule = new Map();
    for (const f of findings) {
      if (!byRule.has(f.rule)) byRule.set(f.rule, { severity: f.severity, count: 0, files: new Set() });
      const e = byRule.get(f.rule); e.count++; e.files.add(f.file);
    }
    for (const [rule, { severity, count, files }] of [...byRule].sort((a,b) => {
      const ord = ['critical','high','medium','low'];
      return ord.indexOf(a[1].severity) - ord.indexOf(b[1].severity);
    })) {
      const filesStr = [...files].slice(0,2).join(', ') + (files.size > 2 ? ` +${files.size-2}` : '');
      console.log(`   ${sev(severity, severity.padEnd(8))}  ${rule.padEnd(38)} ×${count}  ${filesStr}`);
    }
  }

  return { slug, findings, score, counts };
}

// ── Main ─────────────────────────────────────────────────────────────────────
const targets = process.argv.slice(2).length
  ? process.argv.slice(2).map(s => ({ slug: s, note: '' }))
  : REPOS;

console.log(`\nTesting ${targets.length} repos  (token: ${TOKEN.slice(0,8)}…)\n${'─'.repeat(72)}`);

const results = [];
for (const { slug, note } of targets) {
  if (note) process.stdout.write(`\x1b[2m  ${note}\x1b[0m`);
  const r = await runOne(slug);
  if (r) results.push(r);
  // small delay to avoid secondary rate limit
  await new Promise(res => setTimeout(res, 800));
}

// ── Summary table ─────────────────────────────────────────────────────────────
console.log(`\n${'═'.repeat(72)}`);
console.log(`${BOLD}SUMMARY${RESET}`);
console.log(`${'─'.repeat(72)}`);
for (const { slug, score, counts, findings } of results) {
  const c = counts.critical, h = counts.high, m = counts.medium, l = counts.low;
  const total = c + h + m + l;
  const scoreStr = score >= 7 ? sev('high', score.toFixed(1)) : score >= 4 ? sev('medium', score.toFixed(1)) : sev('low', score.toFixed(1));
  console.log(`  ${slug.padEnd(32)}  score ${scoreStr}  |  ${
    [c&&sev('critical',`${c}C`), h&&sev('high',`${h}H`), m&&sev('medium',`${m}M`), l&&sev('low',`${l}L`)].filter(Boolean).join(' ') || '✓'
  }`);
}
console.log(`${'─'.repeat(72)}\n`);
