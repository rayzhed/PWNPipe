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
 * Fetch a file's raw content, returning null if it doesn't exist (404).
 * Returns { content: string|null, rateLimit }.
 */
export async function getOptionalFileContent(owner, repo, path, token) {
  const rawHeaders = {
    Accept: 'application/vnd.github.raw+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) rawHeaders.Authorization = `Bearer ${token}`;

  let response;
  try {
    response = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/contents/${path}`, { headers: rawHeaders });
  } catch {
    return { content: null, rateLimit: null };
  }

  const rateLimit = {
    remaining: parseInt(response.headers.get('X-RateLimit-Remaining') ?? '-1', 10),
    limit: parseInt(response.headers.get('X-RateLimit-Limit') ?? '-1', 10),
    reset: parseInt(response.headers.get('X-RateLimit-Reset') ?? '0', 10),
  };

  if (response.status === 404) return { content: null, rateLimit };
  if (!response.ok) return { content: null, rateLimit };

  const content = await response.text();
  return { content, rateLimit };
}

/**
 * Discover all action.yml / action.yaml files in a repo using the Git Trees API.
 * Falls back to checking root + .github/actions/ if the tree is truncated.
 * Returns { files: [{path, download_url}], rateLimit }.
 */
export async function listActionFiles(owner, repo, token) {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  let response;
  try {
    response = await fetch(
      `${GITHUB_API}/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`,
      { headers }
    );
  } catch {
    return { files: [], rateLimit: null };
  }

  const rateLimit = {
    remaining: parseInt(response.headers.get('X-RateLimit-Remaining') ?? '-1', 10),
    limit: parseInt(response.headers.get('X-RateLimit-Limit') ?? '-1', 10),
    reset: parseInt(response.headers.get('X-RateLimit-Reset') ?? '0', 10),
  };

  if (response.status === 404) return { files: [], rateLimit };
  if (!response.ok) return { files: [], rateLimit };

  const data = await response.json();

  if (!data.truncated && Array.isArray(data.tree)) {
    const actionFiles = data.tree.filter(
      item => item.type === 'blob' && (item.path.endsWith('/action.yml') || item.path.endsWith('/action.yaml') || item.path === 'action.yml' || item.path === 'action.yaml')
    );
    return {
      files: actionFiles.map(f => ({
        path: f.path,
        download_url: `https://raw.githubusercontent.com/${owner}/${repo}/HEAD/${f.path}`,
      })),
      rateLimit,
    };
  }

  // Fallback: check root and .github/actions/ manually
  const candidates = ['action.yml', 'action.yaml'];
  const found = [];
  for (const name of candidates) {
    try {
      const r = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/contents/${name}`, { headers });
      if (r.ok) {
        const d = await r.json();
        found.push({ path: d.path, download_url: d.download_url });
      }
    } catch { /* ignore */ }
  }

  try {
    const r = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/contents/.github/actions`, { headers });
    if (r.ok) {
      const dirs = await r.json();
      for (const dir of dirs) {
        if (dir.type !== 'dir') continue;
        for (const name of ['action.yml', 'action.yaml']) {
          try {
            const r2 = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/contents/${dir.path}/${name}`, { headers });
            if (r2.ok) {
              const d = await r2.json();
              found.push({ path: d.path, download_url: d.download_url });
            }
          } catch { /* ignore */ }
        }
      }
    }
  } catch { /* ignore */ }

  return { files: found, rateLimit };
}

/**
 * Check if a GitHub repository is archived.
 * Returns { archived: boolean, rateLimit } or { archived: null } on 404/error.
 */
export async function getRepoMetadata(owner, repo, token) {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  let response;
  try {
    response = await fetch(`${GITHUB_API}/repos/${owner}/${repo}`, { headers });
  } catch {
    return { archived: null, rateLimit: null };
  }

  const rateLimit = {
    remaining: parseInt(response.headers.get('X-RateLimit-Remaining') ?? '-1', 10),
    limit: parseInt(response.headers.get('X-RateLimit-Limit') ?? '-1', 10),
    reset: parseInt(response.headers.get('X-RateLimit-Reset') ?? '0', 10),
  };

  if (response.status === 404 || response.status === 403 || !response.ok) {
    return { archived: null, rateLimit };
  }

  const data = await response.json();
  return { archived: data.archived === true, rateLimit };
}

/**
 * Verify that a commit SHA is reachable from the canonical repo's refs.
 * Returns { exists: boolean|null, rateLimit }.
 * exists: true = 200, exists: false = 404 or 422, exists: null = 403 or error.
 */
export async function verifyCommitInRepo(owner, repo, sha, token) {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  let response;
  try {
    response = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/commits/${sha}`, { headers });
  } catch {
    return { exists: null, rateLimit: null };
  }

  const rateLimit = {
    remaining: parseInt(response.headers.get('X-RateLimit-Remaining') ?? '-1', 10),
    limit: parseInt(response.headers.get('X-RateLimit-Limit') ?? '-1', 10),
    reset: parseInt(response.headers.get('X-RateLimit-Reset') ?? '0', 10),
  };

  if (response.status === 200) return { exists: true, rateLimit };
  if (response.status === 404 || response.status === 422) return { exists: false, rateLimit };
  // 403 = rate limit or permission issue — treat as unknown
  return { exists: null, rateLimit };
}

/**
 * Resolve a tag name to its commit SHA.
 * Returns { sha: string|null, rateLimit }.
 */
export async function resolveTagToSha(owner, repo, tag, token) {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  let response;
  try {
    response = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/git/ref/tags/${encodeURIComponent(tag)}`, { headers });
  } catch {
    return { sha: null, rateLimit: null };
  }

  const rateLimit = {
    remaining: parseInt(response.headers.get('X-RateLimit-Remaining') ?? '-1', 10),
    limit: parseInt(response.headers.get('X-RateLimit-Limit') ?? '-1', 10),
    reset: parseInt(response.headers.get('X-RateLimit-Reset') ?? '0', 10),
  };

  if (!response.ok) return { sha: null, rateLimit };

  const data = await response.json();
  const refSha = data?.object?.sha ?? null;

  // If the tag points to a tag object (annotated tag), we need to dereference it
  if (data?.object?.type === 'tag') {
    let derefResponse;
    try {
      derefResponse = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/git/tags/${refSha}`, { headers });
    } catch {
      return { sha: refSha, rateLimit };
    }
    if (derefResponse.ok) {
      const tagData = await derefResponse.json();
      return { sha: tagData?.object?.sha ?? refSha, rateLimit };
    }
  }

  return { sha: refSha, rateLimit };
}

/**
 * Fetch repository security features and branch protection status.
 * Returns {
 *   defaultBranch: string,
 *   secretScanning: 'enabled'|'disabled'|null,
 *   pushProtection: 'enabled'|'disabled'|null,
 *   branchProtection: boolean|null,  // true = protected, false = not, null = unknown
 *   codeScanning: boolean|null,
 *   rateLimit
 * }
 */
export async function getRepositorySecurityInfo(owner, repo, token) {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  let repoData = null;
  let lastRateLimit = null;

  try {
    const r = await fetch(`${GITHUB_API}/repos/${owner}/${repo}`, { headers });
    lastRateLimit = {
      remaining: parseInt(r.headers.get('X-RateLimit-Remaining') ?? '-1', 10),
      limit: parseInt(r.headers.get('X-RateLimit-Limit') ?? '-1', 10),
      reset: parseInt(r.headers.get('X-RateLimit-Reset') ?? '0', 10),
    };
    if (r.ok) repoData = await r.json();
  } catch { /* ignore */ }

  const defaultBranch = repoData?.default_branch ?? 'main';
  const sa = repoData?.security_and_analysis ?? null;
  const secretScanning = sa?.secret_scanning?.status ?? null;
  const pushProtection = sa?.secret_scanning_push_protection?.status ?? null;

  // Branch protection
  let branchProtection = null;
  try {
    const r2 = await fetch(
      `${GITHUB_API}/repos/${owner}/${repo}/branches/${encodeURIComponent(defaultBranch)}/protection`,
      { headers }
    );
    if (r2.status === 200) branchProtection = true;
    else if (r2.status === 404) branchProtection = false;
    // 403 = not admin — leave as null
  } catch { /* ignore */ }

  // Code scanning — check if any analysis exists
  let codeScanning = null;
  if (token) {
    try {
      const r3 = await fetch(
        `${GITHUB_API}/repos/${owner}/${repo}/code-scanning/analyses?per_page=1`,
        { headers }
      );
      if (r3.status === 200) {
        const data = await r3.json();
        codeScanning = Array.isArray(data) && data.length > 0;
      } else if (r3.status === 404) {
        codeScanning = false;
      }
    } catch { /* ignore */ }
  }

  return { defaultBranch, secretScanning, pushProtection, branchProtection, codeScanning, rateLimit: lastRateLimit };
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
