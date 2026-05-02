import * as React from 'react';
import { cva } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const badgeVariants = cva(
  'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold font-mono tracking-wide transition-colors',
  {
    variants: {
      variant: {
        default:   'border-transparent bg-primary/15 text-primary',
        secondary: 'border-border bg-secondary text-secondary-foreground',
        outline:   'border-border text-foreground',
        // Severity variants
        critical: 'border-red-600/50 bg-red-600/15 text-red-500',
        high:     'border-orange-500/40 bg-orange-500/12 text-orange-400',
        medium:   'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
        low:      'border-green-500/35 bg-green-500/8 text-green-400',
      },
    },
    defaultVariants: { variant: 'default' },
  }
);

const Badge = React.forwardRef(({ className, variant, ...props }, ref) => (
  <div ref={ref} className={cn(badgeVariants({ variant }), className)} {...props} />
));
Badge.displayName = 'Badge';

export { Badge, badgeVariants };
