import { describe, expect, it } from 'vitest';
import { CipherType, parseImportFile } from '../src/index.js';

describe('Vault Import Parsers', () => {
  it('parses Bitwarden JSON exports', () => {
    const json = JSON.stringify({
      items: [
        {
          type: 1,
          name: 'GitHub',
          favorite: true,
          login: {
            username: 'alice',
            password: 'pw1',
            totp: 'JBSWY3DPEHPK3PXP',
            uris: [{ uri: 'https://github.com' }],
          },
        },
        {
          type: 2,
          name: 'SSH Recovery',
          notes: 'backup-key',
        },
      ],
    });

    const res = parseImportFile(json);
    expect(res.format).toBe('bitwarden-json');
    expect(res.items).toHaveLength(2);
    expect(res.items[0]?.type).toBe(CipherType.Login);
    expect(res.items[0]?.login?.totp).toBe('JBSWY3DPEHPK3PXP');
    expect(res.items[1]?.type).toBe(CipherType.SecureNote);
  });

  it('parses Bitwarden CSV exports with quoted multiline notes', () => {
    const csv = [
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp',
      ',1,login,Example,"line1\n""quoted""", ,0,https://example.com,bob,s3cr3t,ABCDEF',
      ',0,note,My Note,hello,,,,,,',
    ].join('\n');

    const res = parseImportFile(csv);
    expect(res.format).toBe('bitwarden-csv');
    expect(res.items).toHaveLength(2);
    expect(res.items[0]?.favorite).toBe(true);
    expect(res.items[0]?.notes).toBe('line1\n"quoted"');
    expect(res.items[1]?.type).toBe(CipherType.SecureNote);
  });

  it('parses Chrome/Edge Passwords CSV exports', () => {
    const csv = [
      'name,url,username,password,note',
      'Vaultwarden,https://vault.example.com,alice@example.com,pass123,self-hosted',
    ].join('\n');

    const res = parseImportFile(csv);
    expect(res.format).toBe('chrome-csv');
    expect(res.items).toHaveLength(1);
    expect(res.items[0]?.login?.username).toBe('alice@example.com');
    expect(res.items[0]?.login?.uris[0]?.uri).toBe('https://vault.example.com');
  });

  it('parses 1Password CSV exports', () => {
    const csv = [
      'Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes',
      'AWS Console,https://aws.amazon.com,devops,aws-pass,otpauth://totp/AWS?secret=JBSWY3DPEHPK3PXP,true,false,cloud,prod account',
    ].join('\n');

    const res = parseImportFile(csv);
    expect(res.format).toBe('1password-csv');
    expect(res.items).toHaveLength(1);
    expect(res.items[0]?.favorite).toBe(true);
    expect(res.items[0]?.login?.totp).toBe('otpauth://totp/AWS?secret=JBSWY3DPEHPK3PXP');
  });

  it('parses 1Password 1PUX export.data JSON', () => {
    const json = JSON.stringify({
      accounts: [
        {
          vaults: [
            {
              items: [
                {
                  categoryUuid: '001',
                  favIndex: 1,
                  overview: { title: 'Linear', url: 'https://linear.app' },
                  details: {
                    notesPlain: 'workspace',
                    loginFields: [
                      { designation: 'username', value: 'liu@example.com' },
                      { designation: 'password', value: 'lin-pass' },
                    ],
                    sections: [
                      { fields: [{ title: 'one-time password', value: { totp: 'otpauth://totp/Linear?secret=ABCDEF' } }] },
                    ],
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    const res = parseImportFile(json);
    expect(res.format).toBe('1password-json');
    expect(res.items).toHaveLength(1);
    expect(res.items[0]?.name).toBe('Linear');
    expect(res.items[0]?.login?.username).toBe('liu@example.com');
    expect(res.items[0]?.login?.totp).toBe('otpauth://totp/Linear?secret=ABCDEF');
  });
});
