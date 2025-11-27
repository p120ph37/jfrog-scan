#!/usr/bin/env node
import { Command } from 'commander';
import { text } from 'node:stream/consumers';
import { ArtifactoryClient } from './artifactoryClient.js';

// Central list of suggested sources (also shown in --help)
const SUGGESTED_SOURCES = [
//  'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack',
//  'https://security.snyk.io/shai-hulud-npm-supply-chain-attack-sep-2025',
//  'https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/',
  'https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack',
  'https://research.jfrog.com/shai_hulud_2_packages.csv',
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

// Extract package names and versions from JFrog CSV format
// Format: package_name,package_type,versions,xray_ids
// Example: @posthog/agent,npm,[1.24.1],XRAY-898290
// Example: @asyncapi/cli,npm,"[4.1.2], [4.1.3]",XRAY-898365
const extractImpactedFromCsv = (csvContent) => {
  const results = [];
  const lines = csvContent.split('\n');
  
  for (const line of lines) {
    // Skip header and empty lines
    if (!line.trim() || line.startsWith('package_name,')) continue;
    
    // Parse CSV line (handles quoted fields with commas)
    const match = line.match(/^([^,]+),([^,]+),("?\[.+?\]"?),/);
    if (!match) continue;
    
    const name = match[1].trim();
    const packageType = match[2].trim();
    let versionsStr = match[3].trim();
    
    // Only process npm packages
    if (packageType !== 'npm') continue;
    
    // Remove surrounding quotes if present
    if (versionsStr.startsWith('"') && versionsStr.endsWith('"')) {
      versionsStr = versionsStr.slice(1, -1);
    }
    
    // Extract versions from format like "[1.0.1], [1.0.2]" or "[1.0.1]"
    const versionMatches = versionsStr.match(/\[([^\]]+)\]/g);
    if (versionMatches) {
      versionMatches.forEach((vm) => {
        const v = vm.replace(/^\[|\]$/g, '').trim();
        if (v && /^[0-9]/.test(v)) {
          results.push(`${name}@${v}`);
        }
      });
    }
  }
  
  // Dedupe
  const seen = new Set();
  return results.filter((spec) => (seen.has(spec) ? false : (seen.add(spec), true)));
};

// Extract package names and versions from raw HTML (handles JSON and HTML table formats)
const extractImpactedFromHtml = (html) => {
  const results = [];

  // Wiz 2.0 JSON format embedded in page: {"Package":"name","Version":"= X.X.X || = Y.Y.Y"}
  const jsonPackageRe = /\{"Package":"([^"]+)","Version":"([^"]*)"\}/g;
  for (const m of html.matchAll(jsonPackageRe)) {
    const name = m[1].trim();
    const versionStr = m[2].trim();
    if (!name || !versionStr) continue;
    
    // Extract versions from format like "= 1.0.1 || = 1.0.2" or "= 1.0.1"
    const versionMatches = versionStr.match(/=\s*([0-9][0-9a-zA-Z._-]*)/g);
    if (versionMatches) {
      versionMatches.forEach((vm) => {
        const v = vm.replace(/^=\s*/, '').trim();
        if (v && /^[0-9]/.test(v)) {
          results.push(`${name}@${v}`);
        }
      });
    }
  }

  // JFrog research HTML table format: <td>package-name</td><td>[version]</td> or <td>[version, version2]</td>
  const jfrogTableRe = /<td>([@a-z0-9._/-]+)<\/td>\s*<td>\[([^\]]+)\]<\/td>/gi;
  for (const m of html.matchAll(jfrogTableRe)) {
    const name = m[1].trim();
    const versionStr = m[2].trim();
    if (!name) continue;
    
    // Split on comma for multiple versions like "[1.0.1, 1.0.2]"
    versionStr.split(',').forEach((v) => {
      const ver = v.trim();
      if (ver && /^[0-9]/.test(ver)) {
        results.push(`${name}@${ver}`);
      }
    });
  }

  // Dedupe
  const seen = new Set();
  return results.filter((spec) => (seen.has(spec) ? false : (seen.add(spec), true)));
};

// Extract package names and versions from text content (supports Wiz, Snyk text, JFrog list formats)
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

// Extract package names and versions from a web page or CSV file
const scrapeImpactedPackages = async (url) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status} ${res.statusText}`);
    const content = await res.text();

    // Check if this is a CSV file (by URL or content)
    if (url.endsWith('.csv') || content.startsWith('package_name,')) {
      const csvPass = extractImpactedFromCsv(content);
      if (csvPass.length) return csvPass;
    }

    // First attempt: Extract from raw HTML (JSON objects and HTML tables)
    const htmlPass = extractImpactedFromHtml(content);
    if (htmlPass.length) return htmlPass;

    // Second attempt: Extract from stripped text (older formats)
    const textPass = extractImpactedFromText(stripHtml(content));
    if (textPass.length) return textPass;

    // Third attempt: Snyk bundle JSON embedded in modulepreload/module scripts
    const scriptHrefs = [];
    const base = new URL(url);
    const modulePreloadRe = /<link[^>]+rel=["']modulepreload["'][^>]+href=["']([^"']+)["'][^>]*>/gi;
    const moduleScriptRe = /<script[^>]+type=["']module["'][^>]+src=["']([^"']+)["'][^>]*><\/script>/gi;
    let m;
    while ((m = modulePreloadRe.exec(content))) scriptHrefs.push(new URL(m[1], base).toString());
    while ((m = moduleScriptRe.exec(content))) scriptHrefs.push(new URL(m[1], base).toString());

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

    throw new Error(`Failed to extract package data from ${url}`);
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
