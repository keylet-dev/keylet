import { toBuffer } from './encoding.js';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export interface TotpParams {
  secret: Uint8Array;
  period: number;
  digits: number;
  algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512';
}

export interface TotpResult {
  code: string;
  remainingSeconds: number;
  period: number;
}

export function decodeBase32(input: string): Uint8Array {
  const cleaned = input.replace(/[\s\-=]+/g, '').toUpperCase();
  if (cleaned.length === 0) {
    throw new Error('Empty Base32 secret');
  }

  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned.charAt(i);
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character: ${ch}`);
    }
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

export function parseTotpInput(secretOrUri: string): TotpParams {
  const trimmed = secretOrUri.trim();
  if (trimmed.toLowerCase().startsWith('otpauth://')) {
    const url = new URL(trimmed);
    const secretParam = url.searchParams.get('secret');
    if (!secretParam) {
      throw new Error('otpauth URI missing secret parameter');
    }
    const period = Math.max(1, Number(url.searchParams.get('period') ?? '30') || 30);
    const digits = Math.min(10, Math.max(4, Number(url.searchParams.get('digits') ?? '6') || 6));
    const algoRaw = (url.searchParams.get('algorithm') ?? 'SHA1').toUpperCase();
    const algorithm: TotpParams['algorithm'] =
      algoRaw === 'SHA256' || algoRaw === 'SHA-256'
        ? 'SHA-256'
        : algoRaw === 'SHA512' || algoRaw === 'SHA-512'
          ? 'SHA-512'
          : 'SHA-1';

    return {
      secret: decodeBase32(secretParam),
      period,
      digits,
      algorithm,
    };
  }

  return {
    secret: decodeBase32(trimmed),
    period: 30,
    digits: 6,
    algorithm: 'SHA-1',
  };
}

/** Generate an RFC 6238 TOTP code using Web Crypto HMAC. */
export async function generateTotp(
  secretOrUri: string,
  timestampMs: number = Date.now(),
): Promise<TotpResult> {
  const { secret, period, digits, algorithm } = parseTotpInput(secretOrUri);
  const epochSeconds = Math.floor(timestampMs / 1000);
  const counter = Math.floor(epochSeconds / period);
  const remainingSeconds = period - (epochSeconds % period);

  const counterBytes = new Uint8Array(8);
  const view = new DataView(counterBytes.buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);

  const key = await crypto.subtle.importKey(
    'raw',
    toBuffer(secret),
    { name: 'HMAC', hash: algorithm },
    false,
    ['sign'],
  );

  const hmacBuffer = await crypto.subtle.sign('HMAC', key, toBuffer(counterBytes));
  const hmac = new Uint8Array(hmacBuffer);

  const offset = hmac[hmac.length - 1]! & 0x0f;
  const binary =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);

  const modulo = 10 ** digits;
  const code = String(binary % modulo).padStart(digits, '0');

  return { code, remainingSeconds, period };
}
