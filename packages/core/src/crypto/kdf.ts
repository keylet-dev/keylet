import { argon2id as wasmArgon2id } from 'hash-wasm';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  bytesToBase64,
  concatBytes,
  toBuffer,
  utf8ToBytes,
} from './encoding.js';
import { KdfType, type KdfConfig, type SymmetricKey } from './types.js';

async function pbkdf2Sha256(
  passwordBytes: Uint8Array,
  saltBytes: Uint8Array,
  iterations: number,
  lengthBytes: number,
): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    toBuffer(passwordBytes),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: toBuffer(saltBytes),
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

/**
 * RFC 5869 HKDF-Expand (without Extract) using HMAC-SHA256.
 * Bitwarden uses PRK = 32-byte masterKey directly.
 */
export async function hkdfExpandSha256(
  prk: Uint8Array,
  info: Uint8Array,
  lengthBytes: number,
): Promise<Uint8Array> {
  const hashLen = 32;
  const n = Math.ceil(lengthBytes / hashLen);
  if (n > 255) {
    throw new Error('HKDF-Expand output length too large');
  }

  const hmacKey = await crypto.subtle.importKey(
    'raw',
    toBuffer(prk),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  let prev = new Uint8Array(0);
  const blocks: Uint8Array[] = [];

  for (let i = 1; i <= n; i++) {
    const input = concatBytes(prev, info, new Uint8Array([i]));
    const sig = await crypto.subtle.sign('HMAC', hmacKey, toBuffer(input));
    prev = new Uint8Array(sig);
    blocks.push(prev);
  }

  return concatBytes(...blocks).slice(0, lengthBytes);
}

/** Derive the 32-byte Master Key from master password, email, and KDF config. */
export async function deriveMasterKey(
  masterPassword: string,
  email: string,
  kdfConfig: KdfConfig,
): Promise<Uint8Array> {
  const normalizedEmail = email.trim().toLowerCase();
  const passwordBytes = utf8ToBytes(masterPassword);
  const emailBytes = utf8ToBytes(normalizedEmail);

  if (kdfConfig.kdf === KdfType.PBKDF2_SHA256) {
    const iterations = kdfConfig.kdfIterations;
    if (!Number.isFinite(iterations) || iterations < 1) {
      throw new Error(`Invalid PBKDF2 iterations: ${iterations}`);
    }
    return pbkdf2Sha256(passwordBytes, emailBytes, iterations, 32);
  }

  if (kdfConfig.kdf === KdfType.Argon2id) {
    const salt = sha256(emailBytes);
    const t = kdfConfig.kdfIterations || 3;
    const memoryMiB = kdfConfig.kdfMemory ?? 64;
    const p = kdfConfig.kdfParallelism ?? 4;
    try {
      return await wasmArgon2id({
        password: passwordBytes,
        salt,
        iterations: t,
        parallelism: p,
        memorySize: memoryMiB * 1024,
        hashLength: 32,
        outputType: 'binary',
      });
    } catch {
      return argon2idAsync(passwordBytes, salt, {
        t,
        m: memoryMiB * 1024,
        p,
        dkLen: 32,
      });
    }
  }

  throw new Error(`Unsupported KDF type: ${String(kdfConfig.kdf)}`);
}

/**
 * Derive the Master Password Hash sent to `/identity/connect/token`.
 * Bitwarden runs 1 iteration of PBKDF2-SHA256 with masterKey as key and password as salt.
 */
export async function deriveMasterPasswordHash(
  masterKey: Uint8Array,
  masterPassword: string,
): Promise<string> {
  const hashBytes = await pbkdf2Sha256(
    masterKey,
    utf8ToBytes(masterPassword),
    1,
    32,
  );
  return bytesToBase64(hashBytes);
}

/** Stretch the 32-byte Master Key into a 64-byte SymmetricKey (encKey + macKey). */
export async function stretchKey(masterKey: Uint8Array): Promise<SymmetricKey> {
  const encKey = await hkdfExpandSha256(masterKey, utf8ToBytes('enc'), 32);
  const macKey = await hkdfExpandSha256(masterKey, utf8ToBytes('mac'), 32);
  return {
    encKey,
    macKey,
    raw: concatBytes(encKey, macKey),
  };
}

/** Construct a SymmetricKey from a 64-byte raw key (32B encKey + 32B macKey). */
export function symmetricKeyFromBytes(raw: Uint8Array): SymmetricKey {
  if (raw.length !== 64) {
    throw new Error(`Expected 64-byte symmetric key, got ${raw.length}`);
  }
  return {
    encKey: raw.slice(0, 32),
    macKey: raw.slice(32, 64),
    raw: raw.slice(),
  };
}

/** Derive a 64-byte wrapping key from a user PIN and random 16-byte salt. */
export async function derivePinWrappingKey(
  pin: string,
  salt: Uint8Array,
): Promise<SymmetricKey> {
  const keyMaterial = await pbkdf2Sha256(utf8ToBytes(pin), salt, 100_000, 32);
  return stretchKey(keyMaterial);
}
