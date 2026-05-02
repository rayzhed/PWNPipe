import React from 'react';
import { Github, GitMerge, Zap, GitBranch, Lock, Server, Key, Eye, RefreshCcw, Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { redirectToGitHub } from '@/auth/github-oauth.js';

const FEATURES = [
  { icon: Zap,         label: 'Template Injection' },
  { icon: GitBranch,   label: 'Pwn Request Detection' },
  { icon: Shield,      label: 'Supply Chain Audit' },
  { icon: Lock,        label: 'GITHUB_TOKEN Permissions' },
  { icon: Server,      label: 'Self-Hosted Runner Risk' },
  { icon: Key,         label: 'Hardcoded Secrets' },
  { icon: Eye,         label: 'Obfuscation Detection' },
  { icon: RefreshCcw,  label: '20 Detection Rules' },
];

export default function LoginScreen({ onContinueAsGuest }) {
  return (
    <main className="flex flex-1 flex-col items-center justify-center px-6 py-20 text-center">
      {/* Logo mark */}
      <div className="mb-6 flex size-16 items-center justify-center rounded-2xl border border-primary/25 bg-primary/8 glow-red">
        <GitMerge
          className="size-8 text-primary"
          style={{ filter: 'drop-shadow(0 0 10px rgba(220,38,38,0.6))' }}
        />
      </div>

      {/* Pill */}
      <Badge variant="default" className="mb-6 rounded-full px-4 py-1 text-[11px] tracking-widest uppercase">
        Offensive Security Tool
      </Badge>

      {/* Title */}
      <h1 className="mb-3 font-mono text-[clamp(52px,10vw,84px)] font-bold leading-none tracking-tight">
        PWN<span className="text-primary text-shadow-red">Pipe</span>
      </h1>

      <p className="mb-2 max-w-md text-base leading-relaxed text-muted-foreground">
        GitHub Actions attack surface scanner for red teamers and bug bounty hunters.
        Find CI/CD vulnerabilities in your workflows.
      </p>
      <p className="mb-10 font-mono text-xs text-muted-foreground/60">
        Public &amp; private repos · 20 detection rules · 30s scan
      </p>

      {/* Feature pills */}
      <div className="mb-12 flex max-w-lg flex-wrap justify-center gap-2">
        {FEATURES.map(({ icon: Icon, label }) => (
          <span
            key={label}
            className="flex items-center gap-1.5 rounded-full border border-border bg-card px-3 py-1.5 text-xs text-muted-foreground"
          >
            <Icon className="size-3 text-primary" />
            {label}
          </span>
        ))}
      </div>

      {/* CTA */}
      <Button
        size="lg"
        onClick={redirectToGitHub}
        className="glow-red-lg gap-2.5 px-8 text-base font-semibold transition-all hover:glow-red-lg hover:-translate-y-0.5"
      >
        <Github className="size-5" />
        Connect with GitHub
      </Button>
      <p className="mt-3 text-xs text-muted-foreground/60">
        Requires{' '}
        <code className="rounded bg-card px-1 py-0.5 font-mono text-[11px]">repo</code>
        {' '}scope for private repositories
      </p>

      <button
        onClick={onContinueAsGuest}
        className="mt-4 font-mono text-xs text-muted-foreground/50 underline-offset-2 hover:text-muted-foreground hover:underline"
      >
        Continue without login (public repos only · 60 req/h)
      </button>

      {/* Disclaimer */}
      <Card className="mt-16 max-w-lg">
        <CardContent className="pt-5 text-xs leading-relaxed text-muted-foreground">
          <span className="font-medium text-foreground/70">Legal: </span>
          Only scan repos you own or have permission to test. Unauthorized scanning breaks GitHub's ToS.
        </CardContent>
      </Card>
    </main>
  );
}
