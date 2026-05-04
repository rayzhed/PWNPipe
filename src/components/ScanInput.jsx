import React, { useState } from 'react';
import { Search, Zap, Layers } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { parseRepoInput } from '@/engine/github-api.js';
import RepoList from '@/components/RepoList.jsx';
import { listUserRepos } from '@/engine/github-api.js';

export default function ScanInput({ user, token, rateLimit, onScan, onBatchScan }) {
  const [value, setValue]         = useState('');
  const [error, setError]         = useState('');
  const [batchLoading, setBatchLoading] = useState(false);

  function handleChange(e) {
    const v = e.target.value;
    setValue(v);
    setError('');
    // Auto-trigger when a full GitHub URL is pasted
    const parsed = parseRepoInput(v);
    if (parsed && v.includes('github.com/')) {
      onScan(parsed.owner, parsed.repo);
    }
  }

  function handleSubmit(e) {
    e.preventDefault();
    setError('');
    const parsed = parseRepoInput(value);
    if (!parsed) {
      setError('Use "owner/repo" or paste a GitHub URL.');
      return;
    }
    onScan(parsed.owner, parsed.repo);
  }

  // Rate limit display
  const hasRateLimit   = rateLimit && rateLimit.remaining >= 0;
  const remaining      = hasRateLimit ? rateLimit.remaining  : (user ? 5000 : 60);
  const limit          = hasRateLimit ? rateLimit.limit      : (user ? 5000 : 60);
  const pct            = Math.max(0, Math.min(100, (remaining / limit) * 100));
  const rateLow        = hasRateLimit && remaining < 200;
  const rateCritical   = hasRateLimit && remaining < 50;
  const resetMins      = hasRateLimit && rateLimit.reset
    ? Math.max(0, Math.ceil((rateLimit.reset * 1000 - Date.now()) / 60000))
    : null;

  return (
    <main className="flex flex-1 flex-col items-center px-6 py-16">
      {/* User badge */}
      {user ? (
        <div className="mb-10 flex items-center gap-3">
          <img
            src={user.avatar_url}
            alt={user.login}
            className="size-9 rounded-full border-2 border-border"
          />
          <div className="text-left">
            <p className="text-sm font-semibold">{user.name || user.login}</p>
            <p className="font-mono text-xs text-muted-foreground">@{user.login}</p>
          </div>
        </div>
      ) : (
        <p className="mb-10 font-mono text-xs text-muted-foreground/60">
          Guest mode · public repos only · 60 req/h
        </p>
      )}

      <h2 className="mb-2 text-center text-2xl font-bold sm:text-3xl">
        Scan a GitHub repository
      </h2>
      <p className="mb-8 text-center text-sm text-muted-foreground">
        Paste a GitHub URL or enter{' '}
        <code className="rounded bg-card px-1.5 py-0.5 font-mono text-[12px]">owner/repo</code>
      </p>

      {/* Search input */}
      <form onSubmit={handleSubmit} className="w-full max-w-lg">
        <Card className={cn('overflow-hidden', error && 'border-primary/60 ring-1 ring-primary/30')}>
          <div className="flex items-center h-12">
            <input
              value={value}
              onChange={handleChange}
              placeholder="owner/repo"
              autoFocus
              className="flex-1 h-full bg-transparent font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none px-4"
            />
            <Button
              type="submit"
              disabled={!value.trim()}
              className={cn(
                'rounded-none rounded-r-lg border-l border-border h-full px-5 shrink-0',
                !value.trim() && 'opacity-40'
              )}
            >
              <Search className="size-4" />
              Scan
            </Button>
          </div>
        </Card>

        {error && (
          <p className="mt-2 font-mono text-xs text-primary">{error}</p>
        )}
      </form>

      {/* Rate limit bar */}
      <div className="mt-5 w-full max-w-lg">
        <div className="mb-1.5 flex items-center justify-between font-mono text-[11px]">
          <span className="flex items-center gap-1.5 text-muted-foreground/70">
            <Zap className="size-3" />
            API quota
          </span>
          <span className={cn(
            'transition-colors',
            rateCritical ? 'text-red-400' : rateLow ? 'text-amber-400' : 'text-muted-foreground/70'
          )}>
            {remaining.toLocaleString()} / {limit.toLocaleString()} req
            {rateLow && resetMins !== null && (
              <span className="ml-1.5 opacity-70">· resets in {resetMins}m</span>
            )}
          </span>
        </div>
        <div className="h-1 w-full overflow-hidden rounded-full bg-border">
          <div
            className={cn(
              'h-full rounded-full transition-all duration-700',
              rateCritical ? 'bg-red-500' : rateLow ? 'bg-amber-400' : 'bg-primary'
            )}
            style={{ width: `${pct}%` }}
          />
        </div>
        <div className="mt-2 flex flex-wrap gap-4 text-[11px] text-muted-foreground/60">
          {user ? <span>✓ Public &amp; private repos</span> : <span>✓ Public repos only</span>}
          <span>✓ Read-only — no writes</span>
        </div>
      </div>

      {/* Repo list — only for logged-in users */}
      {user && token && (
        <div className="mt-12 w-full max-w-2xl">
          <div className="mb-4 flex items-center gap-3">
            <div className="h-px flex-1 bg-border" />
            <span className="font-mono text-xs text-muted-foreground">or pick from your repositories</span>
            <div className="h-px flex-1 bg-border" />
            <button
              onClick={async () => {
                setBatchLoading(true);
                try {
                  const { repos } = await listUserRepos(token, 50);
                  if (repos.length > 20) {
                    const ok = window.confirm(
                      `Scan ${repos.length} repositories? This will use ~${repos.length * 15} API calls and may take several minutes.`
                    );
                    if (!ok) { setBatchLoading(false); return; }
                  }
                  onBatchScan(repos);
                } catch {
                  setBatchLoading(false);
                }
              }}
              disabled={batchLoading}
              className={cn(
                'flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5 font-mono text-xs transition-colors',
                batchLoading ? 'opacity-50 cursor-not-allowed' : 'hover:border-primary/50 hover:text-primary text-muted-foreground'
              )}
              title="Scan all your accessible repositories"
            >
              <Layers className="size-3" />
              {batchLoading ? 'Loading…' : 'Scan all'}
            </button>
          </div>
          <RepoList token={token} onScan={onScan} />
        </div>
      )}
    </main>
  );
}
