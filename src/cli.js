#!/usr/bin/env node
import { Command } from 'commander';
import { text } from 'node:stream/consumers';
import { ArtifactoryClient } from './artifactoryClient.js';

// Central list of suggested sources (also shown in --help)
const SUGGESTED_SOURCES = [
  'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack',
  'https://security.snyk.io/shai-hulud-npm-supply-chain-attack-sep-2025',
  'https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/',
];

const helpDescription = [
  'Audit Artifactory npm proxy cache for package versions and last-download time',
  '',
  'Suggested sources for --scrape-url / --scrape-all:',
  ...SUGGESTED_SOURCES.map((u) => `  - ${u}`),
].join('\n');

const main = async () => {
  const opts = new Command('jfrog-scan')
    .description(helpDescription)
    .option('-u, --base-url <url>', 'Artifactory base URL (e.g., https://host/artifactory)', process.env.ARTIFACTORY_BASE_URL)
    .option('-r, --repo <name>', 'Artifactory repository key (npm remote/virtual)', process.env.ARTIFACTORY_REPOSITORY)
    .option('--username <name>', 'Artifactory username', process.env.ARTIFACTORY_USERNAME)
    .option('--password <pwd>', 'Artifactory password', process.env.ARTIFACTORY_PASSWORD)
    .option('--token <token>', 'Artifactory access token (preferred)', process.env.ARTIFACTORY_ACCESS_TOKEN)
    .option('--scrape-url <url>', 'Fetch a web page and extract impacted packages', (val, acc) => { (acc ||= []).push(val); return acc; }, [])
    .option('--scrape-all', 'Scrape and combine from all suggested sources', false)
    .option('--json', 'Output JSON instead of table', false)
    .parse(process.argv)
    .opts();

  // Build the package list
  let specs;
  if (opts.scrapeAll) {
    const combined = new Set();
    for (const src of SUGGESTED_SOURCES) {
      const entries = await scrapeImpactedPackages(src);
      entries.forEach((e) => combined.add(e));
    }
    specs = Array.from(combined);
  } else if (Array.isArray(opts.scrapeUrl) && opts.scrapeUrl.length > 0) {
    const combined = new Set();
    for (const src of opts.scrapeUrl) {
      const entries = await scrapeImpactedPackages(src);
      entries.forEach((e) => combined.add(e));
    }
    specs = Array.from(combined);
  } else {
    specs = await readStdinImpactedPackages();
  }

  if (!specs.length) {
    throw new Error('No packages specified.');
  }

  // Output only if no Artifactory details
  if (!opts.baseUrl || !opts.repo) {
    console.log(specs.join('\n'));
    return;
  }

  const results = await Promise.all(
    specs.map((spec) =>
      new ArtifactoryClient({
        baseUrl: opts.baseUrl,
        repository: opts.repo,
        username: opts.username,
        password: opts.password,
        accessToken: opts.token,
      }).checkCache(spec),
    ),
  );

  if (opts.json) {
    console.log(JSON.stringify(results, null, 2));
    return;
  }

  const header = ['package', 'inCache', 'lastDownloaded', 'downloadCount', 'error'];
  const rows = results.map((r) => [
    `${r.package}@${r.version}`,
    r.existsInCache ? 'yes' : 'no',
    r.lastDownloaded ?? '-',
    r.additional?.downloadCount ?? '-',
    r.error ?? '-',
  ]);
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((row) => String(row[i]).length)));
  const printRow = (cols) => cols.map((c, i) => String(c).padEnd(widths[i])).join('  ');

  console.log(printRow(header));
  console.log(widths.map((w) => '-'.repeat(w)).join('  '));
  rows.forEach((row) => console.log(printRow(row)));
};

// Extract package names and versions from text content (supports Wiz, Snyk text, and JFrog list formats)
const extractImpactedFromText = (textContent) => {
  const results = [];

  // Wiz format: "<name> (v1, v2, ...)"
  const wizRe = /([@a-z0-9._/-]+)\s*\(([^)]+)\)/gi;
  for (const m of textContent.matchAll(wizRe)) {
    const name = m[1].trim();
    m[2]
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean)
      .forEach((v) => {
        if (/^[0-9]/.test(v)) results.push(`${name}@${v}`);
      });
  }

  // Snyk text format: "in <name> (npm) Versions: v1, v2, ..."
  const snykRe = /\bin\s+([@a-z0-9._/-]+)\s*\(npm\)\s*versions?:\s*([0-9a-zA-Z._-]+(?:\s*,\s*[0-9a-zA-Z._-]+)*)/gi;
  for (const m of textContent.matchAll(snykRe)) {
    const name = m[1].trim();
    m[2]
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean)
      .forEach((v) => {
        if (/^[0-9]/.test(v)) results.push(`${name}@${v}`);
      });
  }

  // JFrog simple list format: tokens like "name@version"
  const jfrogTokenRe = /([@a-z0-9._/-]+)@([0-9][0-9a-zA-Z._-]*)/gi;
  for (const m of textContent.matchAll(jfrogTokenRe)) {
    const name = m[1].trim();
    const v = m[2].trim();
    if (name && v) results.push(`${name}@${v}`);
  }

  // Dedupe
  const seen = new Set();
  return results.filter((spec) => (seen.has(spec) ? false : (seen.add(spec), true)));
};

// Decode a single-quoted JS string literal into raw string
const decodeJsSingleQuoted = (src) => {
  return src
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\\\/g, '\\')
    .replace(/\\\'/g, "'")
    .replace(/\\\"/g, '"')
    .replace(/\\([\[\]{}])/g, '$1');
};

// Extract package names and versions from a web page
const scrapeImpactedPackages = async (url) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  try {
    // First attempt: Wiz/JFrog-style extraction directly from page HTML
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status} ${res.statusText}`);
    const html = await res.text();
    const firstPass = extractImpactedFromText(stripHtml(html));
    if (firstPass.length) return firstPass;

    // Second attempt: Snyk bundle JSON embedded in modulepreload/module scripts
    const scriptHrefs = [];
    const base = new URL(url);
    const modulePreloadRe = /<link[^>]+rel=["']modulepreload["'][^>]+href=["']([^"']+)["'][^>]*>/gi;
    const moduleScriptRe = /<script[^>]+type=["']module["'][^>]+src=["']([^"']+)["'][^>]*><\/script>/gi;
    let m;
    while ((m = modulePreloadRe.exec(html))) scriptHrefs.push(new URL(m[1], base).toString());
    while ((m = moduleScriptRe.exec(html))) scriptHrefs.push(new URL(m[1], base).toString());

    const marker = 'class:"vue--zero-day-packages"';
    const jsonParseRe = /JSON\.parse\('([\s\S]*?)'\)/;
    const aggregated = [];
    const seen = new Set();

    for (const srcUrl of scriptHrefs) {
      try {
        const jsRes = await fetch(srcUrl, { signal: controller.signal });
        if (!jsRes.ok) continue;
        const js = await jsRes.text();
        if (!js.includes(marker)) continue;
        const j = js.match(jsonParseRe);
        if (!j) continue;
        const decoded = decodeJsSingleQuoted(j[1]);
        const arr = JSON.parse(decoded);
        for (const item of arr) {
          const name = String(item.package_name || '').trim();
          const vuln = String(item.vulnerable || '');
          const versions = vuln.match(/[0-9][0-9A-Za-z._-]*/g) || [];
          for (const v of versions) {
            const spec = `${name}@${v}`;
            if (name && v && !seen.has(spec)) {
              seen.add(spec);
              aggregated.push(spec);
            }
          }
        }
        if (aggregated.length) return aggregated;
      } catch {}
    }

    throw new Error('Failed to locate Snyk data bundle in scripts.');
  } finally {
    clearTimeout(timeout);
  }
};

const stripHtml = (html) => {
  // Replace tags with spaces, collapse whitespace; decode a few common entities
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/\s+/g, ' ').trim();
};

const readStdinImpactedPackages = async () => {
  return (await text(process.stdin))
    .trim()
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((spec) => {
      const atIndex = spec.lastIndexOf('@');
      if (atIndex <= 0) throw new Error(`Invalid package specifier: ${spec}. Use name@version`);
      const name = spec.slice(0, atIndex);
      const version = spec.slice(atIndex + 1);
      if (!version) throw new Error(`Missing version in specifier: ${spec}`);
      return `${name}@${version}`;
    });
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
