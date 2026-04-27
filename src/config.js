export const CONFIG = {
  // GitHub OAuth App client_id — public, safe to commit
  GITHUB_CLIENT_ID: 'Ov23liBGeK8EIlXd4fsU',

  // Cloudflare Worker URL from `wrangler deploy` output
  WORKER_URL: 'https://pwnpipe-auth.rayzhed.workers.dev',

  // 'repo' = public + private repos, 'public_repo' = public only
  OAUTH_SCOPE: 'repo',

  // Set VITE_APP_URL in your .env.local or CI environment for production deployments.
  // Must match the callback URL registered in your GitHub OAuth App settings.
  APP_URL: import.meta.env.VITE_APP_URL ?? 'http://localhost:5173/',
};
