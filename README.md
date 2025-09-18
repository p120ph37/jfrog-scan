## jFrog Artifactory npm proxy cache auditor

Check if npm packages exist in an Artifactory npm proxy cache and when they were last downloaded (uses Storage/Stats APIs; does not pull artifacts).

### Install

```bash
npm install
```

### Usage

- Reference: [Wiz blog Shai-Hulud impacted packages](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack#appendix-impacted-packages-41)

1) Scrape Wiz blog to stdout (no scan):
```bash
npm start -- --scrape-url https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack
```

2) Scrape Wiz blog and scan Artifactory:
```bash
npm start -- \
  --scrape-url https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack \
  -u https://your-artifactory.example.com/artifactory -r npm-remote --token XXXXX
```

3) Scan from a file:
```bash
npm start -- --file packages.txt \
  -u https://your-artifactory.example.com/artifactory -r npm-remote --token XXXXX
```

4) Positive-hit example:
```bash
echo 'babel-core@6.26.3' | npm start -- \
  -u https://your-artifactory.example.com/artifactory -r npm-remote \
  --username user --password XXXXX

# Sample output
package               inCache  lastDownloaded              downloadCount  error
---------------------  -------  -------------------------  -------------  -----
babel-core@6.26.3     yes      2025-04-10T12:34:56.000Z   123            -
```


