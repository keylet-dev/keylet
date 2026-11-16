import { describe, expect, it } from 'vitest';
import {
  CipherType,
  decryptSyncResponse,
  encryptBytes,
  encryptCipherPayload,
  encryptString,
  generateEd25519SshKeyPair,
  symmetricKeyFromBytes,
} from '../src/index.js';

describe('SSH Keys & RSA Organization Decryption', () => {
  it('generates valid OpenSSH Ed25519 keypair and encrypts/decrypts CipherType.SshKey', async () => {
    const kp = await generateEd25519SshKeyPair('alice@keylet');
    expect(kp.publicKey.startsWith('ssh-ed25519 ')).toBe(true);
    expect(kp.privateKey).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');
    expect(kp.keyFingerprint.startsWith('SHA256:')).toBe(true);

    const userKey = symmetricKeyFromBytes(crypto.getRandomValues(new Uint8Array(64)));
    const payload = await encryptCipherPayload(
      {
        type: CipherType.SshKey,
        name: 'GitHub SSH',
        sshKey: kp,
      },
      userKey,
    );

    const decrypted = await decryptSyncResponse(
      {
        profile: { id: 'u1', email: 'alice@keylet.test', key: '' },
        ciphers: [
          {
            id: 'ssh1',
            type: CipherType.SshKey,
            name: payload.name,
            favorite: false,
            sshKey: payload.sshKey,
          },
        ],
      },
      userKey,
    );

    expect(decrypted.ciphers).toHaveLength(1);
    expect(decrypted.ciphers[0]?.sshKey?.publicKey).toBe(kp.publicKey);
    expect(decrypted.ciphers[0]?.sshKey?.privateKey).toBe(kp.privateKey);
    expect(decrypted.ciphers[0]?.sshKey?.keyFingerprint).toBe(kp.keyFingerprint);
  });

  it('decrypts RSA-OAEP-SHA1 organization keys and shared org ciphers', async () => {
    const userKey = symmetricKeyFromBytes(crypto.getRandomValues(new Uint8Array(64)));
    const orgKey = symmetricKeyFromBytes(crypto.getRandomValues(new Uint8Array(64)));

    const rsaPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-1',
      },
      true,
      ['encrypt', 'decrypt'],
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', rsaPair.privateKey));
    const encPrivateKey = await encryptBytes(pkcs8, userKey);

    const wrappedOrgKey = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaPair.publicKey, orgKey.raw),
    );
    const encOrgKey = `4.${Buffer.from(wrappedOrgKey).toString('base64')}`;

    const syncRes = {
      profile: {
        id: 'u1',
        email: 'alice@keylet.test',
        key: '',
        privateKey: encPrivateKey,
        organizations: [{ id: 'org1', name: 'Acme Corp', key: encOrgKey }],
      },
      collections: [
        {
          id: 'col1',
          organizationId: 'org1',
          name: await encryptString('Infra', orgKey),
        },
      ],
      ciphers: [
        {
          id: 'org-c1',
          organizationId: 'org1',
          collectionIds: ['col1'],
          type: CipherType.Login,
          name: await encryptString('Prod Bastion', orgKey),
          favorite: false,
          login: {
            username: await encryptString('root', orgKey),
            password: await encryptString('org-secret', orgKey),
          },
        },
      ],
    };

    const dec = await decryptSyncResponse(syncRes, userKey);
    expect(dec.organizations).toEqual([{ id: 'org1', name: 'Acme Corp' }]);
    expect(dec.collections).toEqual([
      { id: 'col1', organizationId: 'org1', name: 'Infra' },
    ]);
    expect(dec.ciphers[0]?.name).toBe('Prod Bastion');
    expect(dec.ciphers[0]?.login?.password).toBe('org-secret');
  });
});
