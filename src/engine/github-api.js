const GITHUB_API = 'https://api.github.com';

/**
 * Shared fetch wrapper for GitHub API calls.
 * Returns { data, rateLimit } where rateLimit = { remaining, limit, reset }.
 */
async function ghFetch(url, token) {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(url, { headers });

  const rateLimit = {
    remaining: parseInt(response.headers.get('X-RateLimit-Remaining') ?? '-1', 10),
    limit: parseInt(response.headers.get('X-RateLimit-Limit') ?? '-1', 10),
    reset: parseInt(response.headers.get('X-RateLimit-Reset') ?? '0', 10),
  };

  if (response.status === 404) {
    const err = new Error('Repository not found or no access (404).');
    err.code = 'NOT_FOUND';
    throw err;
  }
  if (response.status === 403) {
    const err = new Error('API rate limit exceeded or insufficient permissions (403).');
    err.code = 'RATE_LIMIT';
    err.rateLimit = rateLimit;
    throw err;
  }
  if (response.status === 401) {
    const err = new Error('GitHub token is invalid or expired (401).');
    err.code = 'UNAUTHORIZED';
    throw err;
  }
  if (!response.ok) {
    const err = new Error(`GitHub API error: ${response.status} ${response.statusText}`);
    err.code = 'API_ERROR';
    throw err;
  }

  const data = await response.json();
  return { data, rateLimit };
}

/**
 * Fetch the authenticated user's profile.
 */
export async function getAuthenticatedUser(token) {
  const { data, rateLimit } = await ghFetch(`${GITHUB_API}/user`, token);
  return { user: data, rateLimit };
}

/**
 * List all workflow files in .github/workflows/.
 * Returns { files: [{name, path, sha, download_url}], rateLimit }.
 */
export async function listWorkflowFiles(owner, repo, token) {
  let result;
  try {
    result = await ghFetch(
      `${GITHUB_API}/repos/${owner}/${repo}/contents/.github/workflows`,
      token
    );
  } catch (err) {
    if (err.code === 'NOT_FOUND') {
      // .github/workflows doesn't exist — not an error, just no workflows
      return { files: [], rateLimit: null };
    }
    throw err;
  }

  const { data, rateLimit } = result;
  const yamlFiles = data.filter(f => f.name.endsWith('.yml') || f.name.endsWith('.yaml'));
  return { files: yamlFiles, rateLimit };
}

/**
 * Fetch the raw YAML content of a workflow file.
 * Returns { content: string, rateLimit }.
 */
export async function getWorkflowContent(owner, repo, path, token) {
  const rawHeaders = {
    Accept: 'application/vnd.github.raw+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) rawHeaders.Authorization = `Bearer ${token}`;

  const response = await fetch(
    `${GITHUB_API}/repos/${owner}/${repo}/contents/${path}`,
    { headers: rawHeaders }
  );

  const rateLimit = {
    remaining: parseInt(response.headers.get('X-RateLimit-Remaining') ?? '-1', 10),
    limit: parseInt(response.headers.get('X-RateLimit-Limit') ?? '-1', 10),
    reset: parseInt(response.headers.get('X-RateLimit-Reset') ?? '0', 10),
  };

  if (!response.ok) {
    const err = new Error(`Failed to fetch ${path}: ${response.status}`);
    err.code = 'API_ERROR';
    throw err;
  }

  const content = await response.text();
  return { content, rateLimit };
}

/**
 * Fetch a single optional file. Returns { content: null, rateLimit: null } on 404.
 * Returns { content: string, rateLimit }.
 */
export async function getOptionalFileContent(owner, repo, path, token) {
  const rawHeaders = {
    Accept: 'application/vnd.github.raw+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) rawHeaders.Authorization = `Bearer ${token}`;

  const response = await fetch(
    `${GITHUB_API}/repos/${owner}/${repo}/contents/${path}`,
    { headers: rawHeaders }
  );

  const rateLimit = {
    remaining: parseInt(response.headers.get('X-RateLimit-Remaining') ?? '-1', 10),
    limit: parseInt(response.headers.get('X-RateLimit-Limit') ?? '-1', 10),
    reset: parseInt(response.headers.get('X-RateLimit-Reset') ?? '0', 10),
  };

  if (response.status === 404) {
    return { content: null, rateLimit: null };
  }
  if (!response.ok) {
    const err = new Error(`Failed to fetch ${path}: ${response.status}`);
    err.code = 'API_ERROR';
    throw err;
  }

  const content = await response.text();
  return { content, rateLimit };
}

/**
 * List every action.yml / action.yaml in the repo using the Git Trees API (one request,
 * full recursive traversal). Falls back to root + .github/actions/ scan if the tree is
 * truncated (repos > ~100k files).
 * Returns { files: [{name, path}], rateLimit }.
 */
export async function listActionFiles(owner, repo, token) {
  // Try Git Trees API first — single call, finds action.yml anywhere (monorepos included)
  try {
    const { data, rateLimit } = await ghFetch(
      `${GITHUB_API}/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`,
      token
    );

    if (!data.truncated && Array.isArray(data.tree)) {
      const files = data.tree
        .filter(e => e.type === 'blob' && (e.path.endsWith('/action.yml') || e.path.endsWith('/action.yaml') || e.path === 'action.yml' || e.path === 'action.yaml'))
        .map(e => ({ name: e.path.split('/').pop(), path: e.path }));
      return { files, rateLimit };
    }
  } catch {
    // fall through to directory-based scan
  }

  // Fallback: check root + .github/actions/ recursively up to depth 3
  const files = [];
  let lastRateLimit = null;

  for (const name of ['action.yml', 'action.yaml']) {
    const { content, rateLimit } = await getOptionalFileContent(owner, repo, name, token);
    if (rateLimit) lastRateLimit = rateLimit;
    if (content !== null) files.push({ name, path: name });
  }

  async function listDir(dirPath, depth) {
    if (depth > 3) return;
    let result;
    try {
      result = await ghFetch(`${GITHUB_API}/repos/${owner}/${repo}/contents/${dirPath}`, token);
    } catch (err) {
      if (err.code === 'NOT_FOUND') return;
      throw err;
    }
    const { data, rateLimit } = result;
    if (rateLimit) lastRateLimit = rateLimit;
    if (!Array.isArray(data)) return;
    for (const entry of data) {
      if (entry.type === 'dir') {
        await listDir(entry.path, depth + 1);
      } else if (entry.type === 'file' && (entry.name === 'action.yml' || entry.name === 'action.yaml')) {
        files.push({ name: entry.name, path: entry.path });
      }
    }
  }

  await listDir('.github/actions', 1);
  return { files, rateLimit: lastRateLimit };
}

/**
 * List repositories accessible to the authenticated user.
 * Fetches all pages (up to maxRepos) and returns { repos: [...], rateLimit }.
 */
export async function listUserRepos(token, maxRepos = 300) {
  const perPage = 100;
  const allRepos = [];
  let lastRateLimit = null;

  for (let page = 1; allRepos.length < maxRepos; page++) {
    const params = new URLSearchParams({
      affiliation: 'owner,collaborator,organization_member',
      sort: 'pushed',
      direction: 'desc',
      per_page: String(perPage),
      page: String(page),
    });
    const { data, rateLimit } = await ghFetch(
      `${GITHUB_API}/user/repos?${params}`,
      token
    );
    if (rateLimit) lastRateLimit = rateLimit;
    allRepos.push(...data);
    // GitHub returns fewer than perPage items on the last page
    if (data.length < perPage) break;
  }

  return { repos: allRepos.slice(0, maxRepos), rateLimit: lastRateLimit };
}

/**
 * Parse "owner/repo" or full GitHub URL into { owner, repo }.
 */
export function parseRepoInput(input) {
  input = input.trim().replace(/\/$/, '');

  // Full URL: https://github.com/owner/repo
  const urlMatch = input.match(/github\.com\/([^/]+)\/([^/]+)/);
  if (urlMatch) {
    return { owner: urlMatch[1], repo: urlMatch[2] };
  }

  // Short form: owner/repo
  const shortMatch = input.match(/^([^/]+)\/([^/]+)$/);
  if (shortMatch) {
    return { owner: shortMatch[1], repo: shortMatch[2] };
  }

  return null;
}
