import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// docker login -p <value> or --password <value> where value is not a secret ref
const DOCKER_LOGIN_RE = /docker\s+login(?:\s+\S+)?\s+(?:-p|--password)(?:\s+|=)(?!\$\{\{\s*secrets\.)([^\s'"]+|'[^']+'|"[^"]+")/;
// echo "hardcoded" | docker login --password-stdin  (piped password not from secrets)
const DOCKER_STDIN_RE = /echo\s+(?:"(?!\$\{\{\s*secrets\.)[^"]*"|'(?!\$\{\{\s*secrets\.)[^']*'|\$\{\{(?!\s*secrets\.)[\s\S]{0,80}?\}\})\s*\|+\s*docker\s+login/;

function isSecretRef(value) {
  if (typeof value !== 'string') return true; // non-strings are not hardcoded
  return value.startsWith('${{') && value.includes('secrets.');
}

function checkCredentials(creds, rawContent, filename, contextLabel, id) {
  if (!creds || typeof creds !== 'object') return null;
  const username = creds.username;
  const password = creds.password;

  if (!password) return null;
  if (isSecretRef(String(password))) return null;

  const lineNumber = findLineNumber(rawContent, 'credentials') || findLineNumber(rawContent, 'password');
  const snippet = extractSnippet(rawContent, lineNumber, 4);

  return {
    id,
    rule: 'hardcoded-container-credentials',
    severity: 'high',
    title: 'Hardcoded Docker Registry Credentials',
    file: filename,
    line: lineNumber,
    snippet,
    context: contextLabel,
    detail: `Docker registry credentials are hardcoded in the \`credentials:\` block instead of being referenced from GitHub Secrets. The password \`${String(password).slice(0, 6)}...\` (and${username ? ` username \`${username}\`,` : ''} if hardcoded) is committed to the workflow file and persists in git history.`,
    exploit: `Anyone with read access to the repository (or its git history) can extract the registry credentials and authenticate to the Docker registry to pull private images, push malicious images, or delete existing images.`,
    impact: 'Docker Registry Credential Theft → Unauthorized Image Access or Supply Chain Attack',
    remediation: `Store credentials in GitHub Secrets and reference them:\n\ncredentials:\n  username: \${{ secrets.DOCKER_USERNAME }}\n  password: \${{ secrets.DOCKER_PASSWORD }}\n\nImmediately rotate the exposed credentials.`,
    cvss: {
      score: 7.5,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      cwe: 'CWE-798',
    },
  };
}

export function checkHardcodedContainerCredentials(workflow, rawContent, filename) {
  const findings = [];
  const seen = new Set();

  function add(finding) {
    if (!finding || seen.has(finding.id)) return;
    seen.add(finding.id);
    findings.push(finding);
  }

  const jobs = workflow?.jobs ?? {};

  for (const [jobId, job] of Object.entries(jobs)) {
    // Check container credentials
    const containerCreds = job?.container?.credentials;
    add(checkCredentials(
      containerCreds, rawContent, filename,
      `Job: \`${job.name ?? jobId}\`  ·  container.credentials`,
      `hardcoded-container-credentials-${filename}-${jobId}-container`
    ));

    // Check service credentials
    const services = job?.services ?? {};
    for (const [svcId, svc] of Object.entries(services)) {
      add(checkCredentials(
        svc?.credentials, rawContent, filename,
        `Job: \`${job.name ?? jobId}\`  ·  services.${svcId}.credentials`,
        `hardcoded-container-credentials-${filename}-${jobId}-service-${svcId}`
      ));
    }

    // Check docker login commands in run: steps
    const steps = Array.isArray(job.steps) ? job.steps : [];
    steps.forEach((step, idx) => {
      const run = step.run;
      if (typeof run !== 'string') return;

      const isExplicitPwd = DOCKER_LOGIN_RE.test(run);
      const isStdinPwd    = DOCKER_STDIN_RE.test(run);
      if (!isExplicitPwd && !isStdinPwd) return;

      const lineNumber = findLineNumber(rawContent, 'docker login');
      const snippet = extractSnippet(rawContent, lineNumber, 4);
      const id = `hardcoded-container-credentials-${filename}-${jobId}-step${idx}-docker-login`;
      if (seen.has(id)) return;
      seen.add(id);

      findings.push({
        id,
        rule: 'hardcoded-container-credentials',
        severity: 'high',
        title: 'Hardcoded Docker Credentials in docker login Command',
        file: filename,
        line: lineNumber,
        snippet,
        context: `Job: \`${job.name ?? jobId}\`  ·  Step ${idx + 1}${step.name ? ` (${step.name})` : ''}`,
        detail: `A \`docker login\` command uses \`-p\` or \`--password\` with a value that does not reference a GitHub Secret. Hardcoded passwords in workflow files are committed to git history and exposed to everyone with repository access.`,
        exploit: `Read the workflow file or git history to extract the Docker registry password. Use it to authenticate to the registry and pull private images, push malicious images, or overwrite existing tags.`,
        impact: 'Docker Registry Credential Theft → Registry Compromise',
        remediation: `Use a secret reference:\n\n- run: echo "\${{ secrets.DOCKER_PASSWORD }}" | docker login -u "\${{ secrets.DOCKER_USERNAME }}" --password-stdin\n\nImmediately rotate the exposed password.`,
        cvss: {
          score: 7.5,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
          cwe: 'CWE-798',
        },
      });
    });
  }

  return findings;
}
