/**
 * Detailed finding inspector for a single repo.
 * Usage: node test-inspect-repo.mjs owner/repo [rule-filter]
 * Shows every individual finding with file, line, and snippet.
 */
import { scanRepository } from './src/engine/scanner.js';
import { calculateScore, countsBySeverity } from './src/utils/scoring.js';

const TOKEN = process.env.GH_TOKEN || process.env.VITE_DEV_TOKEN;
if (!TOKEN) { console.error('Set GH_TOKEN or VITE_DEV_TOKEN'); process.exit(1); }

const [slug, ruleFilter] = process.argv.slice(2);
if (!slug) { console.error('Usage: node test-inspect-repo.mjs owner/repo [rule]'); process.exit(1); }
const [owner, repo] = slug.split('/');

const SEV = { critical: '\x1b[31m', high: '\x1b[33m', medium: '\x1b[34m', low: '\x1b[2m' };
const R = '\x1b[0m', B = '\x1b[1m';

console.log(`\nScanning ${slug}…`);
const result = await scanRepository(owner, repo, TOKEN, () => {});
const { findings, workflows } = result;
const score = calculateScore(findings);
const counts = countsBySeverity(findings);

const filtered = ruleFilter ? findings.filter(f => f.rule === ruleFilter) : findings;
const sevOrder = ['critical', 'high', 'medium', 'low'];
filtered.sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));

console.log(`\n${B}${slug}${R}  score ${score.toFixed(1)}  |  ${workflows.length} workflows  |  ${findings.length} total findings`);
if (ruleFilter) console.log(`Showing rule: ${ruleFilter} (${filtered.length} findings)\n`);
else console.log(`C:${counts.critical} H:${counts.high} M:${counts.medium} L:${counts.low}\n`);

for (const f of filtered) {
  const c = SEV[f.severity] ?? '';
  console.log(`${c}${B}[${f.severity.toUpperCase()}]${R} ${c}${f.rule}${R}`);
  console.log(`  File   : ${f.file}${f.line ? `:${f.line}` : ''}`);
  if (f.context) console.log(`  Context: ${f.context}`);
  if (f.snippet && typeof f.snippet === 'string') {
    const lines = f.snippet.split('\n').slice(0, 4);
    console.log(`  Snippet:`);
    for (const l of lines) console.log(`    ${l}`);
  }
  console.log();
}
