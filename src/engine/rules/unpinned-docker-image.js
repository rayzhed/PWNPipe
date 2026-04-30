import { getAllSteps, findLineNumber, extractSnippet } from '../yaml-parser.js';

// A docker:// action is only safe when pinned to a sha256 image digest.
// Tags (including 'latest') are mutable and can be silently repointed.
const DIGEST_RE = /@sha256:[a-f0-9]{64}$/;

export function checkUnpinnedDockerImage(workflow, rawContent, filename) {
  const findings = [];
  const steps = getAllSteps(workflow);

  for (const { jobId, jobName, step, stepIndex } of steps) {
    const uses = step.uses;
    if (typeof uses !== 'string') continue;
    if (!uses.startsWith('docker://')) continue;
    if (DIGEST_RE.test(uses)) continue; // pinned — safe

    // Extract the image name and tag for display
    const imageRef = uses.slice('docker://'.length);
    const colonIdx = imageRef.lastIndexOf(':');
    const atIdx    = imageRef.lastIndexOf('@');
    const tag = atIdx !== -1  ? imageRef.slice(atIdx + 1)
              : colonIdx !== -1 ? imageRef.slice(colonIdx + 1)
              : 'latest (implicit)';

    const lineNumber = findLineNumber(rawContent, uses.slice(0, 35));
    const snippet    = extractSnippet(rawContent, lineNumber, 3);

    findings.push({
      id: `unpinned-docker-image-${filename}-${jobId}-${stepIndex}`,
      rule: 'unpinned-docker-image',
      severity: 'high',
      title: `Unpinned Docker Image: \`${imageRef}\``,
      file: `.github/workflows/${filename}`,
      line: lineNumber,
      snippet,
      context: `Job: \`${jobName}\`  ·  Step ${stepIndex + 1}  ·  Tag: ${tag}`,
      detail: `Docker image tag \`${tag}\` is mutable — it can be silently repointed to any image without touching the workflow file. If the Docker Hub account, registry, or image maintainer is compromised, the malicious image runs automatically in your pipeline with full access to secrets and GITHUB_TOKEN.`,
      exploit: `Compromise the Docker Hub account hosting this image → push a malicious image under the same tag (\`${tag}\`) → every repo running this workflow immediately executes the payload. Unlike Git tag mutations, Docker Hub tag reassignment leaves no commit in the consuming repo's history — the attack is invisible to standard code review.`,
      impact: 'Supply Chain RCE + Full Secret Exfiltration',
      remediation: `Pin to the image content digest instead of a mutable tag:\n\n# Get the digest:\ndocker pull ${imageRef} --quiet\ndocker inspect ${imageRef} --format='{{index .RepoDigests 0}}'\n\n# Then pin in the workflow:\nuses: docker://${imageRef.split(':')[0]}@sha256:<64-hex-chars>  # was: ${tag}\n\nUse Renovate's Docker datasource to keep the pinned digest updated automatically.`,
      cvss: {
        score:  8.8,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
        cwe:    'CWE-494',
      },
    });
  }

  return findings;
}
