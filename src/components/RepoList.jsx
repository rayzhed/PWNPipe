import React, { useState, useEffect, useMemo } from 'react';
import { Lock, Globe, Search, Star, GitFork, Loader2, AlertTriangle, Clock } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import { listUserRepos } from '@/engine/github-api.js';

function timeAgo(dateStr) {
  const diff = (Date.now() - new Date(dateStr)) / 1000;
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 2592000) return `${Math.floor(diff / 86400)}d ago`;
  return `${Math.floor(diff / 2592000)}mo ago`;
}

const LANG_COLORS = {
  JavaScript: '#f1e05a', TypeScript: '#3178c6', Python: '#3572A5',
  Go: '#00ADD8', Rust: '#dea584', Java: '#b07219', 'C++': '#f34b7d',
  C: '#555555', Ruby: '#701516', PHP: '#4F5D95', Swift: '#F05138',
  Kotlin: '#A97BFF', Shell: '#89e051', HTML: '#e34c26', CSS: '#563d7c',
};

export default function RepoList({ token, onScan }) {
  const [repos, setRepos]     = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [query, setQuery]     = useState('');
  const [filter, setFilter]   = useState('all'); // 'all' | 'private' | 'public'

  useEffect(() => {
    if (!token) return;
    setLoading(true);
    setError(null);
    listUserRepos(token)
      .then(({ repos: data }) => { setRepos(data); setLoading(false); })
      .catch(err => { setError(err.message); setLoading(false); });
  }, [token]);

  const filtered = useMemo(() => {
    return repos.filter(r => {
      if (filter === 'private' && !r.private) return false;
      if (filter === 'public'  &&  r.private) return false;
      if (!query) return true;
      const q = query.toLowerCase();
      return r.full_name.toLowerCase().includes(q) ||
             (r.description ?? '').toLowerCase().includes(q);
    });
  }, [repos, query, filter]);

  const privateCount = repos.filter(r => r.private).length;
  const publicCount  = repos.filter(r => !r.private).length;

  if (loading) {
    return (
      <div className="flex flex-col items-center gap-3 py-16 text-muted-foreground">
        <Loader2 className="size-6 animate-spin text-primary" />
        <span className="font-mono text-xs">Fetching your repositories…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
        <AlertTriangle className="size-5 text-primary" />
        <span className="font-mono text-xs">{error}</span>
      </div>
    );
  }

  return (
    <div className="w-full max-w-2xl">
      {/* Search + filter bar */}
      <div className="mb-4 flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Filter repositories…"
            className="h-9 pl-8 font-mono text-sm"
          />
        </div>

        {/* Filter pills */}
        <div className="flex gap-1">
          {[
            { key: 'all',     label: `All (${repos.length})` },
            { key: 'private', label: `Private (${privateCount})` },
            { key: 'public',  label: `Public (${publicCount})` },
          ].map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setFilter(key)}
              className={cn(
                'rounded-md px-3 py-1.5 font-mono text-xs transition-colors',
                filter === key
                  ? 'bg-primary text-primary-foreground'
                  : 'border border-border bg-card text-muted-foreground hover:text-foreground'
              )}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Repo grid — scrollable, filter stays fixed above */}
      <div className="h-[380px] overflow-y-auto rounded-lg border border-border bg-card/30 p-3">
        {filtered.length === 0 ? (
          <p className="py-10 text-center font-mono text-xs text-muted-foreground">
            No repositories match.
          </p>
        ) : (
          <div className="grid gap-2 sm:grid-cols-2">
            {filtered.map(repo => (
              <RepoCard key={repo.id} repo={repo} onScan={onScan} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function RepoCard({ repo, onScan }) {
  const isPrivate = repo.private;
  const langColor = LANG_COLORS[repo.language] ?? '#6b7280';

  return (
    <button
      onClick={() => onScan(repo.owner.login, repo.name)}
      className={cn(
        'group relative flex flex-col gap-2 rounded-lg border p-4 text-left transition-all duration-150',
        'hover:shadow-md focus:outline-none focus-visible:ring-2 focus-visible:ring-primary',
        isPrivate
          ? 'border-amber-500/30 bg-amber-950/10 hover:border-amber-500/60 hover:bg-amber-950/20'
          : 'border-border bg-card hover:border-border/80 hover:bg-card/80'
      )}
    >
      {/* Private badge */}
      {isPrivate && (
        <span className="absolute right-3 top-3 flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[10px] font-medium text-amber-400">
          <Lock className="size-2.5" />
          private
        </span>
      )}

      {/* Repo name */}
      <div className="flex items-center gap-2 pr-16">
        {isPrivate
          ? <Lock className="size-3.5 shrink-0 text-amber-500/70" />
          : <Globe className="size-3.5 shrink-0 text-muted-foreground/50" />
        }
        <span className={cn(
          'truncate font-mono text-sm font-semibold group-hover:text-primary',
          isPrivate ? 'text-amber-100' : 'text-foreground'
        )}>
          {repo.name}
        </span>
      </div>

      {/* Description */}
      {repo.description && (
        <p className="line-clamp-2 text-xs leading-relaxed text-muted-foreground">
          {repo.description}
        </p>
      )}

      {/* Meta row */}
      <div className="mt-auto flex items-center gap-3 font-mono text-[11px] text-muted-foreground/60">
        {repo.language && (
          <span className="flex items-center gap-1.5">
            <span
              className="size-2 rounded-full"
              style={{ backgroundColor: langColor }}
            />
            {repo.language}
          </span>
        )}
        {repo.stargazers_count > 0 && (
          <span className="flex items-center gap-1">
            <Star className="size-3" />
            {repo.stargazers_count}
          </span>
        )}
        {repo.forks_count > 0 && (
          <span className="flex items-center gap-1">
            <GitFork className="size-3" />
            {repo.forks_count}
          </span>
        )}
        <span className="ml-auto flex items-center gap-1">
          <Clock className="size-3" />
          {timeAgo(repo.pushed_at)}
        </span>
      </div>

      {/* Hover indicator */}
      <div className={cn(
        'absolute inset-x-0 bottom-0 h-px rounded-b-lg transition-opacity',
        'opacity-0 group-hover:opacity-100',
        isPrivate ? 'bg-amber-500/50' : 'bg-primary/50'
      )} />
    </button>
  );
}
