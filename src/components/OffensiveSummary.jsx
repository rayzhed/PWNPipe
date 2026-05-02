import React from 'react';
import { AlertTriangle } from 'lucide-react';
import { generateSummary } from '@/utils/summary-generator.js';

// Convert **bold** and `code` markers to JSX
function renderMarkdown(text) {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i} className="text-foreground">{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code key={i} className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[12px] text-foreground">
          {part.slice(1, -1)}
        </code>
      );
    }
    return part;
  });
}

export default function OffensiveSummary({ findings }) {
  const summary = generateSummary(findings);
  if (!summary) return null;

  return (
    <div className="mb-5 rounded-lg border border-primary/30 bg-primary/5 p-4">
      <div className="mb-2 flex items-center gap-2">
        <AlertTriangle className="size-4 text-primary" />
        <span className="font-mono text-[11px] font-bold uppercase tracking-widest text-primary">
          Attacker's Perspective
        </span>
      </div>
      <p className="text-sm leading-7 text-muted-foreground">
        {renderMarkdown(summary)}
      </p>
    </div>
  );
}
