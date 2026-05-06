# PWNPipe

GitHub Actions static analyzer. Scans any public repository's workflow files for injection vectors, supply chain risks, and permission misconfigurations.

https://rayzhed.github.io/PWNPipe/

## Use cases & MVP

**Target users:** security engineers, DevSecOps practitioners, and open-source maintainers who need to audit GitHub Actions workflows without installing anything locally.

**User journeys:**
- As a security engineer, I scan any public repo without authenticating and get a risk report in under 30 seconds, so I can triage CI/CD attack surface quickly.
- As a DevSecOps practitioner, I log in with GitHub OAuth to scan private repos and export findings as SARIF for direct upload to the GitHub Security tab.
- As an open-source maintainer, I run a batch scan across all my repositories to surface supply chain risks at a glance and prioritise remediation.

**MVP scope:** detect the 20 highest-impact GitHub Actions misconfigurations (template injection, unpinned actions, excessive permissions, hardcoded secrets) across public repos, and display each finding with a CVSS score and remediation steps.

Everything beyond that — private repo access, network enrichment, batch scanning, multi-format export, SARIF — is a post-MVP layer built on top.

## Compliance & reporting

Every finding includes a **CVSS v3.1 base score + vector**, **CWE ID**, **CVE references** where applicable, **OWASP CI/CD Security Top 10** category, and a detection confidence level (CONFIRMED / HIGH / MEDIUM / LOW).

The aggregate risk score (0-10) follows CVSS v3.1 severity bands and applies chaining bonuses for combined attack paths (e.g. injection + privileged trigger, supply chain + write permissions).

Export formats from the results page:

| Format | Use |
|---|---|
| Markdown | Paste into pentest reports or audit documents |
| SARIF 2.1 (OASIS standard) | Import to GitHub Security tab via `upload-sarif` action |
| JSON | Raw findings for custom tooling or ticket trackers |
| CSV | Severity, CVSS, Confidence, OWASP, CWE, CVE, file, line, description, impact per finding |
| Summary Card (PNG) | Risk score visual with severity breakdown |
| Full Report Card (PNG) | All findings as a shareable image |
| Print / PDF | Browser print — findings expand automatically |

## Rules (58)

| Rule | OWASP | Confidence |
|---|---|---|
| Template injection (`${{ github.event.* }}` in `run:`) | CICD-SEC-4 | HIGH |
| Dangerous triggers (`pull_request_target`, `workflow_dispatch`) | CICD-SEC-4 | CONFIRMED / HIGH |
| `workflow_run` trigger misuse | CICD-SEC-4 | CONFIRMED / HIGH |
| Unpinned actions (tag instead of SHA) | CICD-SEC-3 | CONFIRMED |
| Unpinned Docker images | CICD-SEC-3 | CONFIRMED |
| Reusable workflow ref not pinned to SHA | CICD-SEC-3 | CONFIRMED |
| Excessive `permissions` | CICD-SEC-5 | HIGH / MEDIUM |
| Self-hosted runner exposure | CICD-SEC-7 | HIGH / MEDIUM |
| Artipacked (artifact poisoning) | CICD-SEC-6 | HIGH |
| Bypassable bot conditions | CICD-SEC-2 | HIGH |
| `GITHUB_ENV` write from untrusted input | CICD-SEC-4 | HIGH |
| `ACTIONS_ALLOW_UNSECURE_COMMANDS` enabled | CICD-SEC-7 | CONFIRMED |
| Hardcoded secrets | CICD-SEC-6 | HIGH |
| `secrets: inherit` on reusable workflows | CICD-SEC-6 | HIGH / MEDIUM |
| Cache poisoning vectors | CICD-SEC-3 | MEDIUM |
| `curl \| sh` and pipe-to-shell patterns | CICD-SEC-3 | HIGH |
| Obfuscated shell commands | CICD-SEC-4 | MEDIUM |
| Token leaked to logs | CICD-SEC-6 | MEDIUM |
| `ACTIONS_STEP_DEBUG` enabled | CICD-SEC-7 | CONFIRMED |
| Unsound `contains()` authorization checks | CICD-SEC-2 | HIGH |
| Template injection in composite `action.yml` | CICD-SEC-4 | HIGH |
| Unpinned `uses:` in composite actions | CICD-SEC-3 | CONFIRMED |
| Known CVE-affected actions (e.g. CVE-2025-30066) | CICD-SEC-3 | CONFIRMED |
| Secrets expanded outside `env:` context | CICD-SEC-6 | HIGH |
| Unredacted secrets in step output | CICD-SEC-6 | HIGH |
| `workflow_run` artifact `GITHUB_ENV` injection | CICD-SEC-4 | HIGH |
| Dependabot insecure step execution | CICD-SEC-4 | HIGH |
| Dependabot confused-deputy bypass | CICD-SEC-2 | HIGH |
| Hardcoded container registry credentials | CICD-SEC-6 | CONFIRMED |
| `id-token: write` at workflow scope (not job scope) | CICD-SEC-5 | HIGH / MEDIUM |
| PRs running on self-hosted runners | CICD-SEC-7 | HIGH |
| Overprovisioned secrets in job env | CICD-SEC-5 | MEDIUM |
| Concurrency missing on write/deploy workflows | CICD-SEC-1 | MEDIUM |
| `shell: cmd` / `shell: powershell` in steps | CICD-SEC-4 | HIGH / MEDIUM |
| Dependabot cooldown missing (npm/pip) | CICD-SEC-3 | LOW |
| PyPI/npm publish using long-lived token (use OIDC instead) | CICD-SEC-6 | MEDIUM |
| Uses archived action repository (network) | CICD-SEC-3 | CONFIRMED |
| Impostor commit - SHA not reachable from canonical repo (network) | CICD-SEC-3 | CONFIRMED |
| Action ref version/comment mismatch (network) | CICD-SEC-3 | MEDIUM |
| `GITHUB_OUTPUT` write from untrusted input | CICD-SEC-4 | HIGH |
| `GITHUB_STEP_SUMMARY` Markdown injection | CICD-SEC-4 | HIGH |
| `strategy.matrix` populated from untrusted event data | CICD-SEC-4 | HIGH |
| `runs-on` label controlled by untrusted input | CICD-SEC-7 | CONFIRMED / HIGH |
| Job missing `timeout-minutes` (DoS / cost) | CICD-SEC-7 | MEDIUM |
| `continue-on-error: true` silencing security failures | CICD-SEC-10 | HIGH / MEDIUM |
| Renovate auto-merge / post-upgrade commands / direct push | CICD-SEC-3 | CONFIRMED |
| Pre-commit hook not pinned to SHA / `language: system` | CICD-SEC-3 | HIGH |
| Branch protection disabled on default branch (network) | CICD-SEC-2 | CONFIRMED |
| GitHub Secret Scanning disabled (network) | CICD-SEC-10 | CONFIRMED |
| Secret Scanning Push Protection disabled (network) | CICD-SEC-10 | CONFIRMED |
| `if:` condition always true (mixed `${{ }}` + comparison outside delimiters) | CICD-SEC-2 | CONFIRMED |
| `issue_comment` / PR review TOCTOU - mutable checkout ref | CICD-SEC-4 | CONFIRMED |
| GitHub App token with revocation disabled (`skip-token-revoke: true`) | CICD-SEC-6 | CONFIRMED |
| Batch multi-repo scan with aggregate risk table | - | - |

## Architecture

```
Browser (React + Vite)
  |- GitHub API          fetch workflow files, user info
  \- Cloudflare Worker   OAuth code exchange (keeps client_secret off the client)
```

Analysis runs entirely in the browser. No scan data is sent anywhere.

## Technical choices

**React 18 + Vite** — React's component model maps cleanly onto the multi-phase UI (login → scan → results). Vite gives sub-second HMR and tree-shakes the 58-rule engine down to a lean production bundle. A vanilla JS approach would have required re-implementing state management from scratch; a heavier meta-framework (Next.js, Remix) would add server-side infrastructure requirements that conflict with the deliberately server-less, privacy-first design.

**Tailwind CSS + Radix UI** — Tailwind provides a consistent dark-mode design system through CSS variables with no runtime overhead, keeping the bundle small. Radix UI handles accessible collapsible/disclosure patterns for finding cards (keyboard navigation, ARIA attributes) that would otherwise require significant manual ARIA work.

**Cloudflare Workers** — The OAuth `client_secret` must never reach the browser. A Cloudflare Worker is the minimal viable backend: a single edge function with no persistent state, zero cold-start latency, and a free tier sufficient for expected traffic. The alternative (Netlify Functions, Vercel Serverless) would work equally well; Cloudflare was chosen for the `wrangler` developer experience and its built-in secret management via `wrangler secret put`.

**GitHub Pages** — Static hosting that matches the zero-server architecture. HTTPS and global CDN are included at no cost. The SPA routing limitation (GitHub Pages has no dynamic routes) is handled with the standard 404 → `index.html` redirect already in `public/404.html`.

## Local dev

```bash
npm install
npm run dev   # http://localhost:5173/PWNPipe/
```

Add `VITE_DEV_TOKEN=ghp_...` to `.env.local` to skip the OAuth flow in dev.

## Self-hosting

**1. GitHub OAuth App** - set the callback URL to `https://YOUR_USERNAME.github.io/PWNPipe/` and copy the client ID into `src/config.js`.

**2. Cloudflare Worker**

```bash
cd worker
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
npx wrangler secret put ALLOWED_ORIGIN   # https://YOUR_USERNAME.github.io
npx wrangler deploy
```

Update `WORKER_URL` in `src/config.js` with the deployed worker URL.

**3. GitHub Pages** - push to `main`, the included workflow handles the build and deploy.

## URL scheme

```
/PWNPipe/owner/repo   scans the repo on load
/PWNPipe/             scan input
```
