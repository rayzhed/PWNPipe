import React from 'react';
import { Github, GitMerge, LogOut, Activity } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { cn } from '@/lib/utils';
import { redirectToGitHub } from '@/auth/github-oauth.js';

export default function Header({ user, onLogout, rateLimit }) {
  const rateLow = rateLimit && rateLimit.remaining >= 0 && rateLimit.remaining < 100;

  return (
    <header className="sticky top-0 z-50 flex h-14 items-center justify-between border-b border-border bg-background/95 px-5 backdrop-blur">
      {/* Logo */}
      <div className="flex items-center gap-3">
        <div className="flex size-7 items-center justify-center rounded-md border border-primary/30 bg-primary/10">
          <GitMerge
            className="size-4 text-primary"
            style={{ filter: 'drop-shadow(0 0 5px rgba(220,38,38,0.55))' }}
          />
        </div>
        <span className="font-mono text-lg font-bold tracking-wide text-primary text-shadow-red">
          PWNPipe
        </span>
        <Separator orientation="vertical" className="h-4" />
        <span className="hidden rounded border border-border bg-card px-2 py-0.5 font-mono text-[11px] text-muted-foreground sm:inline">
          CI/CD Attack Surface Analyzer
        </span>
      </div>

      {/* Right */}
      <div className="flex items-center gap-3">
        {rateLimit && rateLimit.remaining >= 0 && (
          <div className={cn(
            'flex items-center gap-1.5 font-mono text-xs',
            rateLow ? 'text-orange-400' : 'text-muted-foreground'
          )}>
            <Activity className="size-3" />
            {rateLimit.remaining}/{rateLimit.limit}
          </div>
        )}

        {user ? (
          <div className="flex items-center gap-2.5">
            <img
              src={user.avatar_url}
              alt={user.login}
              className="size-7 rounded-full border border-border"
            />
            <span className="hidden text-sm text-muted-foreground sm:inline">
              {user.login}
            </span>
            <Button variant="ghost" size="sm" onClick={onLogout} className="gap-1.5 text-xs">
              <LogOut className="size-3.5" />
              <span className="hidden sm:inline">Sign out</span>
            </Button>
          </div>
        ) : (
          <Button variant="outline" size="sm" onClick={redirectToGitHub}>
            <Github className="size-4" />
            Sign in
          </Button>
        )}
      </div>
    </header>
  );
}
