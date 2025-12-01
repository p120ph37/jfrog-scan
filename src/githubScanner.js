import { Octokit } from '@octokit/rest';
import { throttling } from '@octokit/plugin-throttling';
import { satisfies, valid } from 'semver';

// Branch patterns to scan
const DEFAULT_BRANCH_PATTERNS = ['main', 'master', 'dev'];
const RELEASE_BRANCH_RE = /^\d+\.\d+$/;

// Create Octokit with throttling plugin for rate limit handling
const ThrottledOctokit = Octokit.plugin(throttling);

export class GitHubScanner {
  constructor({ token, org, onRateLimit }) {
    this.org = org;
    this.onRateLimit = onRateLimit;
    
    this.octokit = new ThrottledOctokit({
      auth: token,
      throttle: {
        onRateLimit: (retryAfter, options, octokit, retryCount) => {
          if (this.onRateLimit) {
            this.onRateLimit({ type: 'rate-limit', retryAfter, retryCount });
          }
          // Retry up to 5 times
          if (retryCount < 5) {
            return true; // Retry after waiting
          }
          return false;
        },
        onSecondaryRateLimit: (retryAfter, options, octokit, retryCount) => {
          if (this.onRateLimit) {
            this.onRateLimit({ type: 'secondary-rate-limit', retryAfter, retryCount });
          }
          // Retry up to 3 times for secondary limits
          if (retryCount < 3) {
            return true;
          }
          return false;
        },
      },
    });
  }

  // List all repositories in the organization
  async listRepos() {
    const repos = [];
    for await (const response of this.octokit.paginate.iterator(
      this.octokit.repos.listForOrg,
      { org: this.org, per_page: 100 }
    )) {
      repos.push(...response.data);
    }
    return repos;
  }

  // List branches matching our patterns
  async listMatchingBranches(repo) {
    const branches = [];
    try {
      for await (const response of this.octokit.paginate.iterator(
        this.octokit.repos.listBranches,
        { owner: this.org, repo, per_page: 100 }
      )) {
        for (const branch of response.data) {
          if (this.#branchMatches(branch.name)) {
            branches.push(branch.name);
          }
        }
      }
    } catch (err) {
      // Empty repo or no access
      if (err.status !== 404 && err.status !== 409) throw err;
    }
    return branches;
  }

  #branchMatches(name) {
    return DEFAULT_BRANCH_PATTERNS.includes(name) || RELEASE_BRANCH_RE.test(name);
  }

  // Find all package.json files in the repo using Git Trees API
  async findPackageJsonPaths(repo, branch) {
    try {
      const { data } = await this.octokit.git.getTree({
        owner: this.org,
        repo,
        tree_sha: branch,
        recursive: 'true',
      });

      // Find all package.json files (not in node_modules)
      return data.tree
        .filter(item => 
          item.type === 'blob' && 
          item.path.endsWith('package.json') &&
          !item.path.includes('node_modules/')
        )
        .map(item => item.path);
    } catch (err) {
      if (err.status === 404 || err.status === 409) return [];
      throw err;
    }
  }

  // Get file content from a repo/branch
  async getFileContent(repo, branch, path) {
    try {
      const { data } = await this.octokit.repos.getContent({
        owner: this.org,
        repo,
        path,
        ref: branch,
      });
      if (data.type !== 'file') return null;
      return Buffer.from(data.content, 'base64').toString('utf8');
    } catch (err) {
      if (err.status === 404) return null;
      throw err;
    }
  }

  // Scan a single package.json location for compromised packages
  async scanPackageLocation(repo, branch, packageJsonPath, compromisedMap) {
    const dir = packageJsonPath === 'package.json' ? '' : packageJsonPath.replace(/\/package\.json$/, '');
    const lockfilePath = dir ? `${dir}/package-lock.json` : 'package-lock.json';
    
    const result = {
      repo,
      branch,
      path: packageJsonPath,
      lockfileFound: false,
      critical: [],    // Exact matches in lockfile
      danger: [],      // Semver range could match
      caution: [],     // Package name matches but semver doesn't
      errors: [],
    };

    // Get package.json
    let packageJson;
    try {
      const content = await this.getFileContent(repo, branch, packageJsonPath);
      if (!content) return null;
      packageJson = JSON.parse(content);
    } catch (err) {
      result.errors.push(`Failed to parse ${packageJsonPath}: ${err.message}`);
      return result;
    }

    // Get package-lock.json (optional)
    let lockfile;
    try {
      const content = await this.getFileContent(repo, branch, lockfilePath);
      if (content) {
        result.lockfileFound = true;
        lockfile = JSON.parse(content);
      }
    } catch (err) {
      result.errors.push(`Failed to parse ${lockfilePath}: ${err.message}`);
    }

    // Check lockfile for exact matches (CRITICAL)
    if (lockfile) {
      result.critical = this.#checkLockfile(lockfile, compromisedMap);
    }

    // Check package.json for semver and name matches
    const { danger, caution } = this.#checkPackageJsonAllLevels(packageJson, compromisedMap);
    result.danger = danger;
    result.caution = caution;

    return result;
  }

  // Scan a single repo/branch for compromised packages
  async scanBranch(repo, branch, compromisedMap) {
    const results = [];
    
    // Find all package.json files in the repo
    const packageJsonPaths = await this.findPackageJsonPaths(repo, branch);
    
    for (const path of packageJsonPaths) {
      const result = await this.scanPackageLocation(repo, branch, path, compromisedMap);
      if (result) {
        results.push(result);
      }
    }
    
    return results;
  }

  // Check lockfile for exact version matches
  #checkLockfile(lockfile, compromisedMap) {
    const matches = [];
    const seen = new Set();

    // npm lockfile v2/v3 format (packages field)
    if (lockfile.packages) {
      for (const [path, pkg] of Object.entries(lockfile.packages)) {
        if (!path || path === '') continue; // Skip root
        // Extract package name from path like "node_modules/@scope/name"
        // Also handle nested: "node_modules/foo/node_modules/bar"
        const parts = path.split('node_modules/');
        const name = parts[parts.length - 1];
        const version = pkg.version;
        const key = `${name}@${version}`;
        if (name && version && compromisedMap.has(name) && !seen.has(key)) {
          const badVersions = compromisedMap.get(name);
          if (badVersions.has(version)) {
            seen.add(key);
            matches.push({ name, version });
          }
        }
      }
    }

    // npm lockfile v1 format (dependencies field, recursive)
    if (lockfile.dependencies) {
      this.#checkLockfileDepsV1(lockfile.dependencies, compromisedMap, matches, seen);
    }

    return matches;
  }

  #checkLockfileDepsV1(deps, compromisedMap, matches, seen) {
    for (const [name, info] of Object.entries(deps)) {
      const version = info.version;
      const key = `${name}@${version}`;
      if (version && compromisedMap.has(name) && !seen.has(key)) {
        const badVersions = compromisedMap.get(name);
        if (badVersions.has(version)) {
          seen.add(key);
          matches.push({ name, version });
        }
      }
      // Recurse into nested dependencies
      if (info.dependencies) {
        this.#checkLockfileDepsV1(info.dependencies, compromisedMap, matches, seen);
      }
    }
  }

  // Check package.json for both semver matches (DANGER) and name-only matches (CAUTION)
  #checkPackageJsonAllLevels(packageJson, compromisedMap) {
    const danger = [];
    const caution = [];
    const allDeps = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies,
      ...packageJson.optionalDependencies,
      ...packageJson.peerDependencies,
    };

    for (const [name, range] of Object.entries(allDeps)) {
      if (!compromisedMap.has(name)) continue;
      const badVersions = compromisedMap.get(name);

      let semverMatched = false;
      let matchedVersion = null;

      // Check if any compromised version satisfies the semver range
      for (const badVersion of badVersions) {
        try {
          if (valid(badVersion) && satisfies(badVersion, range)) {
            semverMatched = true;
            matchedVersion = badVersion;
            break;
          }
        } catch {
          // Invalid semver range, skip
        }
      }

      if (semverMatched) {
        danger.push({ name, range, matchedVersion });
      } else {
        // Name matches but semver doesn't - CAUTION level
        caution.push({ name, range, compromisedVersions: Array.from(badVersions).slice(0, 3).join(', ') });
      }
    }

    return { danger, caution };
  }

  // Scan entire org
  async scanOrg(compromisedSpecs, onProgress) {
    // Build a map: packageName -> Set of compromised versions
    const compromisedMap = new Map();
    for (const spec of compromisedSpecs) {
      const atIndex = spec.lastIndexOf('@');
      if (atIndex <= 0) continue;
      const name = spec.slice(0, atIndex);
      const version = spec.slice(atIndex + 1);
      if (!compromisedMap.has(name)) {
        compromisedMap.set(name, new Set());
      }
      compromisedMap.get(name).add(version);
    }

    const results = [];
    const repos = await this.listRepos();

    for (const repo of repos) {
      if (onProgress) onProgress({ type: 'repo', name: repo.name });
      
      const branches = await this.listMatchingBranches(repo.name);
      for (const branch of branches) {
        if (onProgress) onProgress({ type: 'branch', repo: repo.name, branch });
        
        const branchResults = await this.scanBranch(repo.name, branch, compromisedMap);
        results.push(...branchResults);
      }
    }

    return results;
  }
}

// Build a compromised package map from specs
export function buildCompromisedMap(specs) {
  const map = new Map();
  for (const spec of specs) {
    const atIndex = spec.lastIndexOf('@');
    if (atIndex <= 0) continue;
    const name = spec.slice(0, atIndex);
    const version = spec.slice(atIndex + 1);
    if (!map.has(name)) {
      map.set(name, new Set());
    }
    map.get(name).add(version);
  }
  return map;
}
