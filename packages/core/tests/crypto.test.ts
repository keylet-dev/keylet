import { describe, expect, it } from 'vitest';
import {
  bytesToBase64,
  decryptProtectedSymmetricKey,
  decryptToString,
  deriveMasterKey,
  deriveMasterPasswordHash,
  encryptString,
  generatePassword,
  generateTotp,
  KdfType,
  parseEncString,
  stretchKey,
  symmetricKeyFromBytes,
} from '../src/crypto';

describe('Keylet Crypto Layer', () => {
  it('derives deterministic PBKDF2 master key, password hash, and stretched keys', async () => {
    const email = '  User@Example.COM ';
    const password = 'correct-horse-battery-staple';
    const masterKey = await deriveMasterKey(password, email, {
      kdf: KdfType.PBKDF2_SHA256,
      kdfIterations: 1000,
    });

    expect(masterKey).toHaveLength(32);

    // Same email normalized should yield identical key
    const masterKey2 = await deriveMasterKey(password, 'user@example.com', {
      kdf: KdfType.PBKDF2_SHA256,
      kdfIterations: 1000,
    });
    expect(bytesToBase64(masterKey)).toBe(bytesToBase64(masterKey2));

    const pwHash = await deriveMasterPasswordHash(masterKey, password);
    expect(pwHash).toMatch(/^[A-Za-z0-9+/=]{44}$/);

    const stretched = await stretchKey(masterKey);
    expect(stretched.encKey).toHaveLength(32);
    expect(stretched.macKey).toHaveLength(32);
    expect(stretched.raw).toHaveLength(64);
    expect(bytesToBase64(stretched.encKey)).not.toBe(
      bytesToBase64(stretched.macKey),
    );
  });

  it('derives Argon2id master key with normalized email SHA-256 salt', async () => {
    const masterKey = await deriveMasterKey('vault-pass', 'Alice@Example.com', {
      kdf: KdfType.Argon2id,
      kdfIterations: 1,
      kdfMemory: 8, // 8 MiB for fast unit test
      kdfParallelism: 1,
    });
    expect(masterKey).toHaveLength(32);

    const masterKeySame = await deriveMasterKey('vault-pass', 'alice@example.com', {
      kdf: KdfType.Argon2id,
      kdfIterations: 1,
      kdfMemory: 8,
      kdfParallelism: 1,
    });
    expect(bytesToBase64(masterKey)).toBe(bytesToBase64(masterKeySame));
  });

  it('encrypts, parses, and decrypts EncType 2 (AesCbc256_HmacSha256_B64)', async () => {
    const rawKey = crypto.getRandomValues(new Uint8Array(64));
    const key = symmetricKeyFromBytes(rawKey);

    const plaintext = 'Super secret vault entry 🔐';
    const encString = await encryptString(plaintext, key);

    expect(encString.startsWith('2.')).toBe(true);
    const parsed = parseEncString(encString);
    expect(parsed.encType).toBe(2);
    expect(parsed.iv).toHaveLength(16);
    expect(parsed.mac).toHaveLength(32);

    const decrypted = await decryptToString(encString, key);
    expect(decrypted).toBe(plaintext);
  });

  it('rejects tampered ciphertext or MAC before decryption (Encrypt-then-MAC)', async () => {
    const key = symmetricKeyFromBytes(crypto.getRandomValues(new Uint8Array(64)));
    const encString = await encryptString('integrity-protected', key);
    const [prefix, rest = ''] = encString.split('.');
    const [iv = '', ct = '', mac = ''] = rest.split('|');

    // Flip last character of MAC
    const tamperedMac =
      mac.slice(0, -2) + (mac.endsWith('AA') ? 'BB' : 'AA');
    const tamperedEnc = `${prefix}.${iv}|${ct}|${tamperedMac}`;

    await expect(decryptToString(tamperedEnc, key)).rejects.toThrow(
      'MAC verification failed',
    );
  });

  it('encrypts and decrypts a 64-byte protected symmetric key', async () => {
    const masterKey = await deriveMasterKey('master-pw', 'test@vault.local', {
      kdf: KdfType.PBKDF2_SHA256,
      kdfIterations: 1000,
    });
    const stretched = await stretchKey(masterKey);

    const userSymKey = symmetricKeyFromBytes(
      crypto.getRandomValues(new Uint8Array(64)),
    );
    // Encrypt raw 64-byte symmetric key with stretched master key
    const { encryptBytes } = await import('../src/crypto');
    const protectedKey = await encryptBytes(userSymKey.raw, stretched);

    const recovered = await decryptProtectedSymmetricKey(protectedKey, stretched);
    expect(bytesToBase64(recovered.raw)).toBe(bytesToBase64(userSymKey.raw));
  });

  it('generates RFC 6238 compliant TOTP codes from Base32 and otpauth URI', async () => {
    // RFC 6238 SHA-1 test secret: "12345678901234567890" -> Base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    const uri =
      'otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1';
    const res = await generateTotp(uri, 59_000);
    expect(res.code).toBe('94287082');
    expect(res.period).toBe(30);
    expect(res.remainingSeconds).toBe(1);

    const rawRes = await generateTotp('JBSWY3DPEHPK3PXP', 59_000);
    expect(rawRes.code).toHaveLength(6);
    expect(rawRes.code).toMatch(/^\d{6}$/);
  });

  it('generates passwords respecting character sets and entropy', () => {
    const { password, entropyBits } = generatePassword({
      length: 24,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: false,
      excludeAmbiguous: true,
    });

    expect(password).toHaveLength(24);
    expect(password).not.toMatch(/[Il1O0o]/);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/[0-9]/);
    expect(entropyBits).toBeGreaterThan(100);
  });
});
