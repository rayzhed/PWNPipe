import React from 'react';
import { scoreColor, scoreLabel } from '@/utils/scoring.js';

export default function RiskGauge({ score }) {
  const color  = scoreColor(score);
  const label  = scoreLabel(score);
  const display = score.toFixed(1);

  const cx = 80, cy = 82, r = 60;
  const startAngle = 225;
  const sweepAngle = 270;

  function polar(angle) {
    const rad = (angle - 90) * (Math.PI / 180);
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
  }

  const trackStart  = polar(startAngle);
  const trackEnd    = polar(startAngle + sweepAngle);
  const filledSweep = (score / 10) * sweepAngle;
  const fillEnd     = polar(startAngle + filledSweep);
  const largeArc    = filledSweep > 180 ? 1 : 0;

  const trackD = `M ${trackStart.x} ${trackStart.y} A ${r} ${r} 0 1 1 ${trackEnd.x} ${trackEnd.y}`;
  const fillD  = score === 0
    ? ''
    : `M ${trackStart.x} ${trackStart.y} A ${r} ${r} 0 ${largeArc} 1 ${fillEnd.x} ${fillEnd.y}`;

  // CVSS severity band ticks
  const BANDS = [
    { at: 4.0 / 10, color: '#eab308' },
    { at: 7.0 / 10, color: '#f97316' },
    { at: 9.0 / 10, color: '#dc2626' },
  ];

  return (
    <div className="flex flex-col items-center">
      <svg width={160} height={150} viewBox="0 0 160 150" className="overflow-visible">
        {/* Track */}
        <path
          d={trackD}
          fill="none"
          stroke="hsl(var(--border))"
          strokeWidth={10}
          strokeLinecap="round"
        />

        {/* Severity band tick marks */}
        {BANDS.map(({ at, color: tickColor }) => {
          const angle = startAngle + at * sweepAngle;
          const inner = polar_r(cx, cy, r - 8, angle);
          const outer = polar_r(cx, cy, r + 8, angle);
          return (
            <line
              key={at}
              x1={inner.x} y1={inner.y}
              x2={outer.x} y2={outer.y}
              stroke={tickColor}
              strokeWidth={1.5}
              opacity={0.5}
            />
          );
        })}

        {/* Filled arc */}
        {score > 0 && (
          <path
            d={fillD}
            fill="none"
            stroke={color}
            strokeWidth={10}
            strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 6px ${color}88)` }}
          />
        )}

        {/* Score number */}
        <text
          x={cx} y={cy + 8}
          textAnchor="middle"
          style={{
            fontFamily: 'var(--font-mono, monospace)',
            fontSize: 30,
            fontWeight: 700,
            fill: color,
            filter: `drop-shadow(0 0 8px ${color}55)`,
          }}
        >
          {display}
        </text>

        {/* /10 label */}
        <text
          x={cx} y={cy + 24}
          textAnchor="middle"
          style={{
            fontFamily: 'var(--font-mono, monospace)',
            fontSize: 10,
            fill: 'hsl(var(--muted-foreground))',
          }}
        >
          CVSS / 10.0
        </text>
      </svg>

      {/* Severity label */}
      <span
        className="mt-[-10px] font-mono text-[11px] font-bold tracking-widest uppercase"
        style={{ color, textShadow: `0 0 12px ${color}55` }}
      >
        {label}
      </span>

      {/* CVSS band legend */}
      <div className="mt-3 flex items-center gap-3 font-mono text-[10px] text-muted-foreground/60">
        <span className="flex items-center gap-1"><span className="size-1.5 rounded-full bg-green-500" />Low &lt;4.0</span>
        <span className="flex items-center gap-1"><span className="size-1.5 rounded-full bg-yellow-500" />Med 4–7</span>
        <span className="flex items-center gap-1"><span className="size-1.5 rounded-full bg-orange-500" />High 7–9</span>
        <span className="flex items-center gap-1"><span className="size-1.5 rounded-full bg-red-600" />Crit ≥9</span>
      </div>
    </div>
  );
}

function polar_r(cx, cy, r, angle) {
  const rad = (angle - 90) * (Math.PI / 180);
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}
