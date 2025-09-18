#!/usr/bin/env node
import { Command } from 'commander';
import { ArtifactoryClient } from './artifactoryClient.js';

function parsePackageList(input) {
  return input
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((spec) => {
      const atIndex = spec.lastIndexOf('@');
      if (atIndex <= 0) {
        throw new Error(`Invalid package specifier: ${spec}. Use name@version`);
      }
      const name = spec.slice(0, atIndex);
      const version = spec.slice(atIndex + 1);
      if (!version) throw new Error(`Missing version in specifier: ${spec}`);
      return { name, version };
    });
}

async function main() {
  const program = new Command();
  program
    .name('jfrog-scan')
    .description('Audit Artifactory npm proxy cache for package versions and last-download time')
    .option('-u, --base-url <url>', 'Artifactory base URL (e.g., https://host/artifactory)', process.env.ARTIFACTORY_BASE_URL)
    .option('-r, --repo <name>', 'Artifactory repository key (npm remote/virtual)', process.env.ARTIFACTORY_REPOSITORY)
    .option('--username <name>', 'Artifactory username', process.env.ARTIFACTORY_USERNAME)
    .option('--password <pwd>', 'Artifactory password', process.env.ARTIFACTORY_PASSWORD)
    .option('--token <token>', 'Artifactory access token (preferred)', process.env.ARTIFACTORY_ACCESS_TOKEN)
    .option('--scrape-url <url>', 'Fetch a web page and extract impacted packages')
    .option('--file <path>', 'Path to read/write a list (name@version per line)')
    .option('--json', 'Output JSON instead of table', false)
    .parse(process.argv);

  const opts = program.opts();

  // Build the package list according to input precedence and requested behavior
  let specs = [];
  let scraped = [];
  if (opts.scrapeUrl) {
    scraped = await scrapeImpactedPackages(opts.scrapeUrl);
    if (!scraped.length) {
      console.error('No packages extracted from the provided URL.');
      process.exit(1);
    }
    // If no file and no Artifactory details, output to stdout and exit
    if (!opts.file && (!opts.baseUrl || !opts.repo)) {
      const lines = scraped.map((s) => `${s.name}@${s.version}`).join('\n');
      console.log(lines);
      return;
    }
    // If a --file is provided, write the scraped list to disk, but still prefer in-memory for scanning
    if (opts.file) {
      const fs = await import('node:fs/promises');
      const lines = scraped.map((s) => `${s.name}@${s.version}`).join('\n') + '\n';
      await fs.writeFile(opts.file, lines, 'utf8');
      console.log(`Wrote ${scraped.length} entries to ${opts.file}`);
      // If base-url/repo are missing, exit after writing without scanning
      if (!opts.baseUrl || !opts.repo) {
        return;
      }
    }
    // Use scraped list in memory for scanning if base/repo provided
    specs = scraped;
  } else if (opts.file) {
    const fs = await import('node:fs/promises');
    const raw = await fs.readFile(opts.file, 'utf8');
    specs = raw
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .map((line) => parsePackageList(line)[0]);
  } else {
    // Read from stdin
    const stdin = await readStdin();
    if (!stdin.trim()) {
      console.error('No input provided. Use --scrape-url, --file, or pipe a list via stdin.');
      process.exit(1);
    }
    specs = stdin
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .map((line) => parsePackageList(line)[0]);
  }

  // If we reached here intending to scan, ensure base-url and repo are provided
  if (!opts.baseUrl || !opts.repo) {
    console.error('Error: base-url and repo are required to perform a scan.');
    process.exit(1);
  }

  const config = {
    baseUrl: opts.baseUrl,
    repository: opts.repo,
    username: opts.username,
    password: opts.password,
    accessToken: opts.token,
  };
  const client = new ArtifactoryClient(config);

  const results = await Promise.all(
    specs.map((s) => client.checkCache(s.name, s.version)),
  );

  if (opts.json) {
    console.log(JSON.stringify(results, null, 2));
    return;
  }

  const rows = results.map((r) => [
    `${r.package}@${r.version}`,
    r.existsInCache ? 'yes' : 'no',
    r.lastDownloaded ?? '-',
    r.additional?.downloadCount ?? '-',
    r.error ?? '-',
  ]);

  const header = ['package', 'inCache', 'lastDownloaded', 'downloadCount', 'error'];
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((row) => String(row[i]).length)));
  const printRow = (cols) =>
    cols
      .map((c, i) => String(c).padEnd(widths[i]))
      .join('  ');

  console.log(printRow(header));
  console.log(widths.map((w) => '-'.repeat(w)).join('  '));
  for (const row of rows) console.log(printRow(row));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

// Extract package names and versions from a web page's text.
// Tailored for the Wiz blog "Shai-Hulud" appendix formatting where items look like:
// "@operato/utils (9.0.22, 9.0.35, ...)" or "thangved-react-grid (1.0.3)".
async function scrapeImpactedPackages(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status} ${res.statusText}`);
    const html = await res.text();
    const text = stripHtml(html);
    // Narrow to the Appendix section if possible
    const startIdx = text.toLowerCase().indexOf('appendix: impacted packages');
    const endIdx = text.toLowerCase().indexOf('references', startIdx + 1);
    const scope = startIdx >= 0 && endIdx > startIdx ? text.slice(startIdx, endIdx) : text;

    // Regex: package then versions in parentheses, versions comma-separated
    const re = /([@a-z0-9._/-]+)\s*\(([^)]+)\)/gi;
    const results = [];
    for (const m of scope.matchAll(re)) {
      const name = m[1].trim();
      const versionList = m[2]
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean);
      for (const v of versionList) {
        // basic version guard: starts with digit
        if (/^[0-9]/.test(v)) results.push({ name, version: v });
      }
    }
    // Dedupe
    const seen = new Set();
    return results.filter((r) => {
      const key = `${r.name}@${r.version}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  } finally {
    clearTimeout(timeout);
  }
}

function stripHtml(html) {
  // Replace tags with spaces, collapse whitespace; decode a few common entities
  const noTags = html.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ');
  const decoded = noTags
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"');
  return decoded.replace(/\s+/g, ' ').trim();
}

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    if (process.stdin.isTTY) return resolve('');
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
  });
}


