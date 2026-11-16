import {
  base64ToBytes,
  bytesToBase64,
  bytesToUtf8,
  concatBytes,
  constantTimeEqual,
  toBuffer,
  utf8ToBytes,
} from './encoding.js';
import { symmetricKeyFromBytes } from './kdf.js';
import { EncType, type ParsedEncString, type SymmetricKey } from './types.js';

/** Parse a Bitwarden EncString (`<encType>.<iv>|<data>[|<mac>]`). */
export function parseEncString(encStr: string): ParsedEncString {
  const dotIdx = encStr.indexOf('.');
  if (dotIdx === -1) {
    throw new Error('Invalid EncString: missing encType prefix');
  }

  const encTypeNum = Number(encStr.slice(0, dotIdx));
  const payload = encStr.slice(dotIdx + 1);
  const parts = payload.split('|');

  if (encTypeNum === EncType.AesCbc256_B64) {
    const [ivB64, dataB64] = parts;
    if (parts.length !== 2 || !ivB64 || !dataB64) {
      throw new Error('Invalid AesCbc256_B64 EncString format');
    }
    return {
      encType: EncType.AesCbc256_B64,
      iv: base64ToBytes(ivB64),
      data: base64ToBytes(dataB64),
    };
  }

  if (encTypeNum === EncType.AesCbc256_HmacSha256_B64) {
    const [ivB64, dataB64, macB64] = parts;
    if (parts.length !== 3 || !ivB64 || !dataB64 || !macB64) {
      throw new Error('Invalid AesCbc256_HmacSha256_B64 EncString format');
    }
    return {
      encType: EncType.AesCbc256_HmacSha256_B64,
      iv: base64ToBytes(ivB64),
      data: base64ToBytes(dataB64),
      mac: base64ToBytes(macB64),
    };
  }

  throw new Error(`Unsupported EncType: ${encTypeNum}`);
}

async function computeHmacSha256(
  macKey: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    toBuffer(macKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const macInput = concatBytes(iv, data);
  const sig = await crypto.subtle.sign('HMAC', key, toBuffer(macInput));
  return new Uint8Array(sig);
}

/**
 * Decrypt a Bitwarden EncString to raw bytes.
 * Enforces Encrypt-then-MAC: verifies HMAC-SHA256 before AES-CBC decryption.
 */
export async function decryptToBytes(
  encStr: string,
  key: SymmetricKey,
): Promise<Uint8Array> {
  const parsed = parseEncString(encStr);

  if (parsed.encType === EncType.AesCbc256_HmacSha256_B64) {
    if (!parsed.mac) {
      throw new Error('Missing MAC in AesCbc256_HmacSha256_B64 EncString');
    }
    const expectedMac = await computeHmacSha256(
      key.macKey,
      parsed.iv,
      parsed.data,
    );
    if (!constantTimeEqual(parsed.mac, expectedMac)) {
      throw new Error('MAC verification failed');
    }
  }

  const aesKey = await crypto.subtle.importKey(
    'raw',
    toBuffer(key.encKey),
    { name: 'AES-CBC' },
    false,
    ['decrypt'],
  );

  const plainBuffer = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: toBuffer(parsed.iv) },
    aesKey,
    toBuffer(parsed.data),
  );

  return new Uint8Array(plainBuffer);
}

export async function decryptToString(
  encStr: string | null | undefined,
  key: SymmetricKey,
): Promise<string | null> {
  if (!encStr) {
    return null;
  }
  const bytes = await decryptToBytes(encStr, key);
  return bytesToUtf8(bytes);
}

/** Encrypt raw bytes using AesCbc256_HmacSha256_B64 (EncType 2). */
export async function encryptBytes(
  plain: Uint8Array,
  key: SymmetricKey,
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const aesKey = await crypto.subtle.importKey(
    'raw',
    toBuffer(key.encKey),
    { name: 'AES-CBC' },
    false,
    ['encrypt'],
  );

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: toBuffer(iv) },
    aesKey,
    toBuffer(plain),
  );
  const data = new Uint8Array(cipherBuffer);
  const mac = await computeHmacSha256(key.macKey, iv, data);

  return `${EncType.AesCbc256_HmacSha256_B64}.${bytesToBase64(iv)}|${bytesToBase64(data)}|${bytesToBase64(mac)}`;
}

export async function encryptString(
  plain: string,
  key: SymmetricKey,
): Promise<string> {
  return encryptBytes(utf8ToBytes(plain), key);
}

/** Decrypt the user's protected symmetric key using the stretched Master Key. */
export async function decryptProtectedSymmetricKey(
  protectedKeyStr: string,
  stretchedMasterKey: SymmetricKey,
): Promise<SymmetricKey> {
  const raw = await decryptToBytes(protectedKeyStr, stretchedMasterKey);
  return symmetricKeyFromBytes(raw);
}
