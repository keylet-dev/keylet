import { describe, expect, it } from 'vitest';
import {
  extractBaseDomain,
  scoreItemUriMatches,
  scoreUriMatch,
  UriMatchType,
} from '../src/matching/uri';

describe('URI Matching', () => {
  it('extracts base domains including multi-part TLDs and localhost', () => {
    expect(extractBaseDomain('login.github.com')).toBe('github.com');
    expect(extractBaseDomain('auth.service.co.uk')).toBe('service.co.uk');
    expect(extractBaseDomain('localhost')).toBe('localhost');
    expect(extractBaseDomain('127.0.0.1')).toBe('127.0.0.1');
  });

  it('scores Domain, Host, Exact, StartsWith, Regex, and Never correctly', () => {
    const tabUrl = 'https://app.example.com:8443/login?next=/home';

    expect(
      scoreUriMatch(tabUrl, { uri: tabUrl, match: UriMatchType.Exact }),
    ).toBe(100);
    expect(
      scoreUriMatch(tabUrl, {
        uri: 'https://app.example.com:8443/other',
        match: UriMatchType.Host,
      }),
    ).toBe(80);
    expect(
      scoreUriMatch(tabUrl, {
        uri: 'https://auth.example.com',
        match: UriMatchType.Domain,
      }),
    ).toBe(55);
    expect(
      scoreUriMatch(tabUrl, {
        uri: 'https://app.example.com:8443/login',
        match: UriMatchType.StartsWith,
      }),
    ).toBe(40);
    expect(
      scoreUriMatch(tabUrl, {
        uri: '^https://app\\.example\\.com',
        match: UriMatchType.Regex,
      }),
    ).toBe(30);
    expect(
      scoreUriMatch(tabUrl, { uri: tabUrl, match: UriMatchType.Never }),
    ).toBe(0);
  });

  it('picks the highest-scoring URI among multiple URIs on a cipher', () => {
    const score = scoreItemUriMatches('https://vault.example.com/login', [
      { uri: 'https://other.org' },
      { uri: 'https://vault.example.com/login', match: UriMatchType.Exact },
    ]);
    expect(score).toBe(100);
  });
});
