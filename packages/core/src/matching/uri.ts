export enum UriMatchType {
  Domain = 0,
  Host = 1,
  StartsWith = 2,
  Exact = 3,
  Regex = 4,
  Never = 5,
}

export interface MatchCandidate {
  uri: string;
  match?: UriMatchType | null;
}

const MULTI_PART_TLDS = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'co.jp',
  'ne.jp',
  'or.jp',
  'com.cn',
  'net.cn',
  'org.cn',
  'gov.cn',
  'com.au',
  'net.au',
  'org.au',
  'com.br',
  'co.nz',
  'co.kr',
  'co.in',
  'com.tw',
  'com.hk',
  'com.sg',
]);

function tryParseUrl(raw: string): URL | null {
  try {
    if (/^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(raw)) {
      return new URL(raw);
    }
    return new URL(`https://${raw}`);
  } catch {
    return null;
  }
}

export function extractBaseDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.+$/, '');
  if (!host) return '';
  // IPv4, IPv6, or single-label host (e.g. localhost)
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':') || !host.includes('.')) {
    return host;
  }

  const parts = host.split('.');
  if (parts.length <= 2) {
    return host;
  }

  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
}

function normalizedHostPort(url: URL): string {
  const port = url.port;
  const host = url.hostname.toLowerCase();
  return port ? `${host}:${port}` : host;
}

/**
 * Score how well a stored URI matches the active tab URL.
 * Returns 0 for no match, or a positive specificity score (higher = stronger match).
 */
export function scoreUriMatch(
  tabUrlStr: string,
  candidate: MatchCandidate,
): number {
  const matchType = candidate.match ?? UriMatchType.Domain;
  if (matchType === UriMatchType.Never || !candidate.uri) {
    return 0;
  }

  const tabUrl = tryParseUrl(tabUrlStr);
  if (!tabUrl) {
    return 0;
  }

  // Only match web URLs against web/host URIs
  if (tabUrl.protocol !== 'http:' && tabUrl.protocol !== 'https:') {
    return 0;
  }

  switch (matchType) {
    case UriMatchType.Exact: {
      return tabUrlStr === candidate.uri ? 100 : 0;
    }
    case UriMatchType.Host: {
      const candUrl = tryParseUrl(candidate.uri);
      if (!candUrl) return 0;
      return normalizedHostPort(tabUrl) === normalizedHostPort(candUrl) ? 80 : 0;
    }
    case UriMatchType.Domain: {
      const candUrl = tryParseUrl(candidate.uri);
      if (!candUrl) return 0;
      const tabDomain = extractBaseDomain(tabUrl.hostname);
      const candDomain = extractBaseDomain(candUrl.hostname);
      if (!tabDomain || tabDomain !== candDomain) return 0;
      // Bonus if exact hostname also matches (e.g. app.example.com vs login.example.com)
      return tabUrl.hostname.toLowerCase() === candUrl.hostname.toLowerCase()
        ? 65
        : 55;
    }
    case UriMatchType.StartsWith: {
      return tabUrlStr.startsWith(candidate.uri) ? 40 : 0;
    }
    case UriMatchType.Regex: {
      try {
        const re = new RegExp(candidate.uri, 'i');
        return re.test(tabUrlStr) ? 30 : 0;
      } catch {
        return 0;
      }
    }
    default:
      return 0;
  }
}

export function scoreItemUriMatches(
  tabUrlStr: string,
  uris: MatchCandidate[] | undefined,
): number {
  if (!uris || uris.length === 0) return 0;
  let best = 0;
  for (const u of uris) {
    const score = scoreUriMatch(tabUrlStr, u);
    if (score > best) best = score;
  }
  return best;
}
