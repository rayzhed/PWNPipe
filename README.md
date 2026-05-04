# PWNPipe

GitHub Actions static analyzer. Scans any public repository's workflow files for injection vectors, supply chain risks, and permission misconfigurations.

https://rayzhed.github.io/PWNPipe/

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

## Rules (39)

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

## Architecture

```
Browser (React + Vite)
  |- GitHub API          fetch workflow files, user info
  \- Cloudflare Worker   OAuth code exchange (keeps client_secret off the client)
```

Analysis runs entirely in the browser. No scan data is sent anywhere.

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
