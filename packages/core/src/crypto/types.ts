export enum KdfType {
  PBKDF2_SHA256 = 0,
  Argon2id = 1,
}

export interface KdfConfig {
  kdf: KdfType;
  kdfIterations: number;
  /** Argon2id memory in MiB (Bitwarden prelogin returns MiB, e.g. 64). */
  kdfMemory?: number | null;
  /** Argon2id parallelism (e.g. 4). */
  kdfParallelism?: number | null;
}

export enum EncType {
  AesCbc256_B64 = 0,
  AesCbc256_HmacSha256_B64 = 2,
  Rsa2048_OaepSha256_B64 = 3,
  Rsa2048_OaepSha1_B64 = 4,
}

export interface SymmetricKey {
  /** 32-byte AES-256-CBC encryption key. */
  encKey: Uint8Array;
  /** 32-byte HMAC-SHA256 authentication key. */
  macKey: Uint8Array;
  /** Combined 64-byte raw key (encKey || macKey). */
  raw: Uint8Array;
}

export interface ParsedEncString {
  encType: EncType;
  iv: Uint8Array;
  data: Uint8Array;
  mac?: Uint8Array;
}
