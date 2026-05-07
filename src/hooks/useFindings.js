import { useState, useMemo } from 'react';
import { sortFindings, countsBySeverity } from '@/utils/scoring.js';

const SCORE_CONFIDENCE = new Set(['CONFIRMED', 'HIGH']);

export const isScoreable      = f => !f.confidence || SCORE_CONFIDENCE.has(f.confidence);
export const isGroupScoreable = g => isScoreable(g.findings[0]);

export function groupByRule(findingsList) {
  const ruleMap = new Map();
  const groups  = [];
  for (const f of findingsList) {
    if (!ruleMap.has(f.rule)) {
      ruleMap.set(f.rule, { rule: f.rule, severity: f.severity, title: f.title, findings: [f] });
      groups.push(ruleMap.get(f.rule));
    } else {
      ruleMap.get(f.rule).findings.push(f);
    }
  }
  return groups;
}

export function useFindings(findings) {
  const [filter,     setFilter]     = useState('all');
  const [fileFilter, setFileFilter] = useState('all');
  const [confidence, setConfidence] = useState('all');
  const [groupBy,    setGroupBy]    = useState('rule');
  const [copied,     setCopied]     = useState(false);
  const [exporting,  setExporting]  = useState(false);

  const sorted = useMemo(() => sortFindings(findings), [findings]);

  const scoreableFindings = useMemo(() => findings.filter(isScoreable),          [findings]);
  const reviewFindings    = useMemo(() => findings.filter(f => !isScoreable(f)), [findings]);

  // Severity + confidence filtered — file filter intentionally excluded so
  // file chip counts reflect the active severity/confidence context.
  const filteredBySevAndConf = useMemo(
    () => sorted.filter(f =>
      (filter === 'all' || f.severity === filter) &&
      (confidence === 'all' || (confidence === 'confirmed' ? isScoreable(f) : !isScoreable(f)))
    ),
    [sorted, filter, confidence]
  );

  const fileStats = useMemo(() => {
    const map = new Map();
    for (const f of filteredBySevAndConf) {
      if (!map.has(f.file)) map.set(f.file, { file: f.file, critical: 0, high: 0, medium: 0, low: 0 });
      const e = map.get(f.file);
      e[f.severity] = (e[f.severity] || 0) + 1;
    }
    const sevOrder = ['critical', 'high', 'medium', 'low'];
    return [...map.values()].sort((a, b) => {
      const aW = sevOrder.findIndex(s => a[s] > 0);
      const bW = sevOrder.findIndex(s => b[s] > 0);
      return (aW < 0 ? 99 : aW) - (bW < 0 ? 99 : bW);
    });
  }, [filteredBySevAndConf]);

  const filteredSorted = useMemo(
    () => filteredBySevAndConf.filter(f => fileFilter === 'all' || f.file === fileFilter),
    [filteredBySevAndConf, fileFilter]
  );

  const groups = useMemo(() => groupByRule(filteredSorted), [filteredSorted]);

  const byFile = useMemo(() => {
    if (groupBy !== 'file') return [];
    const fileMap = new Map();
    for (const f of filteredSorted) {
      if (!fileMap.has(f.file)) fileMap.set(f.file, []);
      fileMap.get(f.file).push(f);
    }
    const sevOrder = ['critical', 'high', 'medium', 'low'];
    return [...fileMap.entries()]
      .sort(([, a], [, b]) => {
        const aW = sevOrder.findIndex(s => a.some(f => f.severity === s));
        const bW = sevOrder.findIndex(s => b.some(f => f.severity === s));
        return (aW < 0 ? 99 : aW) - (bW < 0 ? 99 : bW);
      })
      .map(([file, fileFindings]) => ({
        file,
        fileGroups: groupByRule(fileFindings),
        counts:     countsBySeverity(fileFindings),
      }));
  }, [groupBy, filteredSorted]);

  return {
    filter,     setFilter,
    fileFilter, setFileFilter,
    confidence, setConfidence,
    groupBy,    setGroupBy,
    copied,     setCopied,
    exporting,  setExporting,
    sorted,
    scoreableFindings,
    reviewFindings,
    filteredBySevAndConf,
    fileStats,
    filteredSorted,
    groups,
    byFile,
  };
}
