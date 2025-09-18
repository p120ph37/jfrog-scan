function buildAuthHeader(config) {
  if (config.accessToken) {
    return { Authorization: `Bearer ${config.accessToken}` };
  }
  if (config.username && config.password) {
    const encoded = Buffer.from(`${config.username}:${config.password}`).toString('base64');
    return { Authorization: `Basic ${encoded}` };
  }
  return {};
}

export class ArtifactoryClient {
  baseUrl;
  repository;
  headers;

  constructor(config) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.repository = config.repository;
    this.headers = {
      Accept: 'application/json',
      ...buildAuthHeader(config),
    };
  }

  // Compute path to npm tarball in Artifactory remote/virtual repo cache layout
  // Unscoped: <name>/-/<name>-<version>.tgz
  // Scoped: @<scope>/<name>/-/<name>-<version>.tgz
  tarballPath(pkgName, version) {
    if (pkgName.startsWith('@')) {
      const [scope, name] = pkgName.split('/');
      return `${scope}/${name}/-/${name}-${version}.tgz`;
    }
    return `${pkgName}/-/${pkgName}-${version}.tgz`;
  }

  async checkCache(pkgName, version) {
    const path = this.tarballPath(pkgName, version);
    // Encode each segment to safely handle '@' in scopes, spaces, etc.
    const encodedPath = path
      .split('/')
      .map((seg) => encodeURIComponent(seg))
      .join('/');
    const storageUrl = `${this.baseUrl}/api/storage/${this.repository}/${encodedPath}`;
    const statsUrl = `${storageUrl}?stats`;

    try {
      const storageResp = await this.#getJson(storageUrl);
      const exists = Boolean(storageResp && storageResp.repo);
      if (!exists) {
        return { package: pkgName, version, existsInCache: false };
      }

      const statsResp = await this.#getJson(statsUrl);
      const lastDownloadedIso = statsResp?.lastDownloaded ? new Date(statsResp.lastDownloaded).toISOString() : undefined;

      return {
        package: pkgName,
        version,
        existsInCache: true,
        lastDownloaded: lastDownloadedIso,
        additional: {
          downloadCount: statsResp?.downloadCount,
          lastDownloadedBy: statsResp?.lastDownloadedBy,
          size: storageResp?.size,
          checksums: storageResp?.checksums,
          remoteUrl: storageResp?.remoteUrl,
          uri: storageResp?.uri,
        },
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return { package: pkgName, version, existsInCache: false, error: message };
    }
  }

  async #getJson(url) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      const res = await fetch(url, { headers: this.headers, signal: controller.signal });
      if (res.status === 404) return {};
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`${res.status} ${res.statusText}${text ? ` - ${text}` : ''}`);
      }
      const ct = res.headers.get('content-type') || '';
      if (!ct.includes('application/json')) {
        const text = await res.text().catch(() => '');
        try {
          return JSON.parse(text);
        } catch {
          return {};
        }
      }
      return await res.json();
    } finally {
      clearTimeout(timeout);
    }
  }
}


