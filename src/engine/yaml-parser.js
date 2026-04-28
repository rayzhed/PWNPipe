import yaml from 'js-yaml';

/**
 * Parse a YAML workflow string into a JS object.
 * Returns null on parse failure.
 */
export function parseWorkflow(yamlContent) {
  try {
    return yaml.load(yamlContent);
  } catch {
    return null;
  }
}

/**
 * Get all steps from a parsed workflow (flattens across jobs).
 * Returns [{ jobId, jobName, step, stepIndex }]
 */
export function getAllSteps(workflow) {
  if (!workflow?.jobs) return [];
  const results = [];
  for (const [jobId, job] of Object.entries(workflow.jobs)) {
    if (!Array.isArray(job.steps)) continue;
    job.steps.forEach((step, idx) => {
      results.push({ jobId, jobName: job.name ?? jobId, step, stepIndex: idx });
    });
  }
  return results;
}

/**
 * Extract the triggers from a parsed workflow.
 * Always returns an array of trigger names.
 */
export function getTriggers(workflow) {
  const on = workflow?.on;
  if (!on) return [];
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on;
  if (typeof on === 'object') return Object.keys(on);
  return [];
}

/**
 * Find the approximate line number of a pattern in raw YAML content.
 */
export function findLineNumber(rawContent, pattern) {
  const lines = rawContent.split('\n');
  const regex = typeof pattern === 'string' ? new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) : pattern;
  for (let i = 0; i < lines.length; i++) {
    if (regex.test(lines[i])) return i + 1;
  }
  return 1;
}

/**
 * Extract a small snippet of context lines around a line number.
 */
export function extractSnippet(rawContent, lineNumber, context = 3) {
  const lines = rawContent.split('\n');
  const start = Math.max(0, lineNumber - 1 - context);
  const end = Math.min(lines.length, lineNumber - 1 + context + 1);
  return lines
    .slice(start, end)
    .map((l, i) => ({ line: start + i + 1, content: l, highlight: start + i + 1 === lineNumber }));
}
