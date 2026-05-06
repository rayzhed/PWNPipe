/**
 * PWNPipe OAuth Worker (Cloudflare Workers)
 *
 * Sole responsibility: exchange a GitHub OAuth code for an access_token.
 * The frontend never touches client_secret — it lives here as a secret env var.
 *
 * Environment variables (set via `wrangler secret put`):
 *   GITHUB_CLIENT_ID     — your GitHub OAuth App client_id
 *   GITHUB_CLIENT_SECRET — your GitHub OAuth App client_secret
 *   ALLOWED_ORIGIN       — your GitHub Pages URL, e.g. https://you.github.io
 */

const CORS_HEADERS = (origin) => ({
  'Access-Control-Allow-Origin': origin,
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
});

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
};

export default {
  async fetch(request, env) {
    // Fail closed — if ALLOWED_ORIGIN isn't configured, reject all cross-origin requests
    // rather than defaulting to '*' which lets any origin use this endpoint.
    const origin = env.ALLOWED_ORIGIN;
    if (!origin) {
      return new Response(JSON.stringify({ error: 'Worker not configured: ALLOWED_ORIGIN secret is missing.' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...SECURITY_HEADERS },
      });
    }

    const corsAndSecurity = { ...CORS_HEADERS(origin), ...SECURITY_HEADERS };

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsAndSecurity });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: SECURITY_HEADERS });
    }

    let code;
    try {
      const body = await request.json();
      code = body?.code;
    } catch {
      return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsAndSecurity },
      });
    }

    if (typeof code !== 'string' || code.length < 10 || code.length > 200) {
      return new Response(JSON.stringify({ error: 'Invalid "code" field' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsAndSecurity },
      });
    }

    // Exchange code → token with GitHub
    const ghResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
      }),
    });

    if (!ghResponse.ok) {
      return new Response(JSON.stringify({ error: 'GitHub OAuth endpoint error' }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', ...corsAndSecurity },
      });
    }

    const data = await ghResponse.json();

    if (data.error) {
      return new Response(JSON.stringify({ error: data.error_description ?? data.error }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsAndSecurity },
      });
    }

    return new Response(JSON.stringify({ access_token: data.access_token }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsAndSecurity },
    });
  },
};
