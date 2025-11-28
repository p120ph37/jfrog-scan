#!/usr/bin/env node
import { Command } from 'commander';
import { text } from 'node:stream/consumers';
import { ArtifactoryClient } from './artifactoryClient.js';

// Central list of suggested sources (also shown in --help)
const SUGGESTED_SOURCES = [
  // Shai-Hulud 1.0 (September 2025)
  'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack',
  'https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/',
  // Shai-Hulud 2.0 (November 2025)
  'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv',
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

// Extract package names and versions from CSV format (supports both Wiz and JFrog formats)
// JFrog format: package_name,package_type,versions,xray_ids
//   Example: @posthog/agent,npm,[1.24.1],XRAY-898290
// Wiz format: Package,Version
//   Example: @posthog/agent,= 1.24.1 || = 1.24.2
const extractImpactedFromCsv = (csvContent) => {
  const results = [];
  const lines = csvContent.split('\n');
  
  for (const line of lines) {
    const trimmed = line.trim();
    // Skip header and empty lines
    if (!trimmed || trimmed.startsWith('package_name,') || trimmed.startsWith('Package,')) continue;
    
    // Try JFrog format first: package_name,npm,[versions],xray_id
    const jfrogMatch = trimmed.match(/^([^,]+),([^,]+),("?\[.+?\]"?),/);
    if (jfrogMatch) {
      const name = jfrogMatch[1].trim();
      const packageType = jfrogMatch[2].trim();
      let versionsStr = jfrogMatch[3].trim();
      
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
      continue;
    }
    
    // Try Wiz format: Package,= version || = version2
    const wizMatch = trimmed.match(/^([^,]+),(.+)$/);
    if (wizMatch) {
      const name = wizMatch[1].trim();
      const versionsStr = wizMatch[2].trim();
      
      // Extract versions from format like "= 1.0.1 || = 1.0.2" or "= 1.0.1"
      const versionMatches = versionsStr.match(/=\s*([0-9][0-9a-zA-Z._-]*)/g);
      if (versionMatches) {
        versionMatches.forEach((vm) => {
          const v = vm.replace(/^=\s*/, '').trim();
          if (v && /^[0-9]/.test(v)) {
            results.push(`${name}@${v}`);
          }
        });
      }
    }
  }
  
  // Dedupe
  const seen = new Set();
  return results.filter((spec) => (seen.has(spec) ? false : (seen.add(spec), true)));
};

// Extract package names and versions from text content (supports Wiz and JFrog list formats)
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

// Extract package names and versions from a web page or CSV file
const scrapeImpactedPackages = async (url) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status} ${res.statusText}`);
    const content = await res.text();

    // Check if this is a CSV file (by URL or content)
    if (url.endsWith('.csv') || content.startsWith('package_name,') || content.startsWith('Package,')) {
      const csvPass = extractImpactedFromCsv(content);
      if (csvPass.length) return csvPass;
    }

    // Extract from stripped text (older Wiz/JFrog blog formats)
    const textPass = extractImpactedFromText(stripHtml(content));
    if (textPass.length) return textPass;

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
