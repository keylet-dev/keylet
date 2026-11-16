import { describe, expect, it } from 'vitest';
import { CipherType, type DecryptedCipher } from '@keylet/core';
import {
  extractCipherField,
  findCipherByQuery,
  resolveRunEnvironment,
} from '../src/run.js';

const MOCK_CIPHERS: DecryptedCipher[] = [
  {
    id: '1',
    folderId: null,
    type: CipherType.Login,
    name: 'Production Postgres',
    notes: 'Primary DB',
    favorite: false,
    fields: [{ name: 'DB_HOST', value: 'db.internal', type: 0 }],
    login: {
      username: 'pgadmin',
      password: 'super-secret-db-password',
      totp: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
      uris: [{ uri: 'https://db.internal', match: null }],
    },
  },
  {
    id: '2',
    folderId: null,
    type: CipherType.SecureNote,
    name: 'App Env',
    notes: '# comment\nSTRIPE_KEY=sk_test_123\nJWT_SECRET=jwt_abc',
    favorite: false,
    fields: [],
  },
];

describe('@keylet/cli run & query helpers', () => {
  it('finds ciphers by exact or partial name and extracts fields', async () => {
    const item = findCipherByQuery(MOCK_CIPHERS, 'postgres');
    expect(item.id).toBe('1');
    expect(await extractCipherField(item, 'password')).toBe(
      'super-secret-db-password',
    );
    expect(await extractCipherField(item, 'DB_HOST')).toBe('db.internal');
    const totp = await extractCipherField(item, 'totp');
    expect(totp).toMatch(/^\d{6}$/);
  });

  it('resolves keylet:// references and --from SecureNote KEY=VALUE pairs', async () => {
    const env = await resolveRunEnvironment(
      MOCK_CIPHERS,
      {
        PATH: '/usr/bin',
        PGPASSWORD: 'keylet://Production Postgres/password',
        PGUSER: 'keylet://Production Postgres/username',
      },
      { fromItem: 'App Env' },
    );

    expect(env.PATH).toBe('/usr/bin');
    expect(env.PGPASSWORD).toBe('super-secret-db-password');
    expect(env.PGUSER).toBe('pgadmin');
    expect(env.STRIPE_KEY).toBe('sk_test_123');
    expect(env.JWT_SECRET).toBe('jwt_abc');
  });
});
