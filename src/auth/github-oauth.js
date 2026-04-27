import { CONFIG } from '../config.js';

/**
 * Redirect the browser to GitHub's OAuth authorization page.
 */
export function redirectToGitHub() {
  const params = new URLSearchParams({
    client_id: CONFIG.GITHUB_CLIENT_ID,
    scope: CONFIG.OAUTH_SCOPE,
    redirect_uri: CONFIG.APP_URL,
  });
  window.location.href = `https://github.com/login/oauth/authorize?${params}`;
}

/**
 * Extract the OAuth `code` from the URL query string, then clean it.
 * Returns null if no code is present.
 */
export function extractOAuthCode() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  if (code) {
    // Remove the code from the URL without triggering a reload
    window.history.replaceState({}, document.title, window.location.pathname);
  }
  return code;
}

/**
 * Exchange an OAuth code for a GitHub access token via the Cloudflare Worker.
 * @param {string} code
 * @returns {Promise<string>} access_token
 */
export async function exchangeCodeForToken(code) {
  const response = await fetch(`${CONFIG.WORKER_URL}/auth`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();

  if (!data.access_token) {
    throw new Error('No access_token in worker response. Check Worker configuration.');
  }

  return data.access_token;
}
