export interface PasswordOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

export const DEFAULT_PASSWORD_OPTIONS: PasswordOptions = {
  length: 20,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
  excludeAmbiguous: false,
};

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const NUMBERS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';
const AMBIGUOUS_CHARS = new Set(['I', 'l', '1', 'O', '0', 'o']);

function filterAmbiguous(chars: string, exclude: boolean): string {
  if (!exclude) return chars;
  return [...chars].filter((c) => !AMBIGUOUS_CHARS.has(c)).join('');
}

/** Unbiased random integer in [0, max) using rejection sampling. */
function randomInt(max: number): number {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  while (true) {
    crypto.getRandomValues(buf);
    const val = buf[0]!;
    if (val < limit) {
      return val % max;
    }
  }
}

export function generatePassword(options: PasswordOptions): {
  password: string;
  entropyBits: number;
} {
  const pools: string[] = [];
  if (options.uppercase) pools.push(filterAmbiguous(UPPERCASE, options.excludeAmbiguous));
  if (options.lowercase) pools.push(filterAmbiguous(LOWERCASE, options.excludeAmbiguous));
  if (options.numbers) pools.push(filterAmbiguous(NUMBERS, options.excludeAmbiguous));
  if (options.symbols) pools.push(SYMBOLS);

  if (pools.length === 0) {
    pools.push(filterAmbiguous(LOWERCASE, options.excludeAmbiguous));
  }

  const length = Math.max(4, Math.min(128, Math.floor(options.length)));
  const combined = pools.join('');
  const chars: string[] = [];

  // Ensure at least one char from each selected pool when length allows
  for (let i = 0; i < pools.length && i < length; i++) {
    const pool = pools[i]!;
    chars.push(pool.charAt(randomInt(pool.length)));
  }

  while (chars.length < length) {
    chars.push(combined.charAt(randomInt(combined.length)));
  }

  // Fisher-Yates shuffle
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    const tmp = chars[i]!;
    chars[i] = chars[j]!;
    chars[j] = tmp;
  }

  const entropyBits = Math.round(length * Math.log2(combined.length));
  return {
    password: chars.join(''),
    entropyBits,
  };
}
