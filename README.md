## jFrog Artifactory npm proxy cache auditor

Check if npm packages exist in an Artifactory npm proxy cache and when they were last downloaded (uses Storage/Stats APIs; does not pull artifacts).

### Install

```bash
npm install
```

### Usage

1) Scrape all suggested sources to stdout (no scan):
```bash
npm start -- --scrape-all
```

2) Scrape a specific source to stdout (no scan):
```bash
npm start -- --scrape-url https://example.com/some-list
```

3) Scrape all and scan Artifactory:
```bash
npm start -- \
  --scrape-all \
  -u https://your-artifactory.example.com/artifactory -r npm-remote --token XXXXX
```

4) Scan from stdin:
```bash
npm start -- \
  -u https://your-artifactory.example.com/artifactory -r npm-remote --token XXXXX \
  < packages.txt
```

5) Positive-hit (stdin) example:
```bash
echo 'babel-core@6.26.3' | npm start -- \
  -u https://your-artifactory.example.com/artifactory -r npm-remote \
  --username user --password XXXXX

# Sample output
package               inCache  lastDownloaded              downloadCount  error
---------------------  -------  -------------------------  -------------  -----
babel-core@6.26.3     yes      2025-04-10T12:34:56.000Z   123            -
```


