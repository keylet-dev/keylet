import { afterEach, describe, expect, it, vi } from 'vitest';
import { createCipher, updateCipher } from '../src/api/client.js';

function makeJwt(sub: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ sub })).toString('base64url');
  return `${header}.${payload}.sig`;
}

describe('API client cipher requests & errors', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('auto-populates encryptedFor from accessToken JWT sub in createCipher and updateCipher', async () => {
    const calls: { url: string; body: Record<string, unknown> }[] = [];
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({
        url: String(input),
        body: JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>,
      });
      return new Response(JSON.stringify({ id: 'c-1', type: 2, name: '2.a|b|c', favorite: false }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    const token = makeJwt('user-uuid-1234');
    await createCipher('https://vaultwarden.example.com', token, {
      type: 2,
      name: '2.a|b|c',
      secureNote: { type: 0 },
    });
    await updateCipher('https://vaultwarden.example.com', token, 'c-1', {
      type: 2,
      name: '2.a|b|c',
      secureNote: { type: 0 },
      encryptedFor: 'custom-uuid',
    });

    expect(calls).toHaveLength(2);
    expect(calls[0].body.encryptedFor).toBe('user-uuid-1234');
    expect(calls[1].body.encryptedFor).toBe('custom-uuid');
  });

  it('surfaces Rocket 422 JSON error descriptions and ValidationErrors instead of generic status text', async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(
        JSON.stringify({
          error: {
            code: 422,
            reason: 'Unprocessable Entity',
            description: 'missing field `encryptedFor`',
          },
        }),
        { status: 422, headers: { 'Content-Type': 'application/json' } },
      ),
    ) as typeof fetch;

    await expect(
      createCipher('https://vaultwarden.example.com', 'not-a-jwt', {
        type: 2,
        name: '2.a|b|c',
      }),
    ).rejects.toThrow('missing field `encryptedFor`');

    globalThis.fetch = vi.fn(async () =>
      new Response(
        JSON.stringify({
          Message: 'The model state is invalid.',
          ValidationErrors: { encryptedFor: ['Required'] },
        }),
        { status: 422, headers: { 'Content-Type': 'application/json' } },
      ),
    ) as typeof fetch;

    await expect(
      createCipher('https://vaultwarden.example.com', 'not-a-jwt', {
        type: 2,
        name: '2.a|b|c',
      }),
    ).rejects.toThrow(/The model state is invalid.*encryptedFor/);
  });
});
