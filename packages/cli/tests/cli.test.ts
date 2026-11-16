import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  CipherType,
  type DecryptedCipher,
  generateEd25519SshKeyPair,
} from '@keylet/core';
import { KeyletSshAgent, parseOpenSshEd25519 } from '../src/sshAgent.js';
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

  it('loads Ed25519 SSH keys and responds to SSH_AGENTC_REQUEST_IDENTITIES & SIGN_REQUEST', async () => {
    const kp = await generateEd25519SshKeyPair('dev@keylet');
    const parsed = parseOpenSshEd25519(kp.privateKey, 'My Ed25519');
    expect(parsed).not.toBeNull();

    const sock = path.join(os.tmpdir(), `keylet-ssh-test-${Date.now()}.sock`);
    const agent = new KeyletSshAgent(sock);
    const ciphers: DecryptedCipher[] = [
      {
        id: 'ssh-1',
        folderId: null,
        type: CipherType.SshKey,
        name: 'My Ed25519',
        notes: null,
        favorite: false,
        fields: [],
        sshKey: kp,
      },
    ];
    agent.updateKeys(ciphers);

    // SSH_AGENTC_REQUEST_IDENTITIES (11)
    const idReply = agent.handlePacket(Buffer.from([11]));
    expect(idReply.readUInt8(4)).toBe(12); // SSH_AGENT_IDENTITIES_ANSWER
    expect(idReply.readUInt32BE(5)).toBe(1); // 1 key

    // SSH_AGENTC_SIGN_REQUEST (13)
    const challenge = Buffer.from('sign-this-challenge');
    const encodeStr = (b: Buffer) => {
      const out = Buffer.alloc(4 + b.length);
      out.writeUInt32BE(b.length, 0);
      b.copy(out, 4);
      return out;
    };
    const signReq = Buffer.concat([
      Buffer.from([13]),
      encodeStr(parsed!.pubBlob),
      encodeStr(challenge),
      Buffer.alloc(4),
    ]);
    const signReply = agent.handlePacket(signReq);
    expect(signReply.readUInt8(4)).toBe(14); // SSH_AGENT_SIGN_RESPONSE

    // Verify signature using Node crypto
    const sigBlobLen = signReply.readUInt32BE(5);
    const sigBlob = signReply.subarray(9, 9 + sigBlobLen);
    const algoLen = sigBlob.readUInt32BE(0);
    const rawSigLen = sigBlob.readUInt32BE(4 + algoLen);
    const rawSig = sigBlob.subarray(8 + algoLen, 8 + algoLen + rawSigLen);
    const pubKeyObj = crypto.createPublicKey(parsed!.privateKey);
    expect(crypto.verify(null, challenge, pubKeyObj, rawSig)).toBe(true);
  });
});
