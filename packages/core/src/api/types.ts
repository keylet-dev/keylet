import type { KdfConfig, KdfType } from '../crypto/types.js';
import type { UriMatchType } from '../matching/uri.js';

export enum CipherType {
  Login = 1,
  SecureNote = 2,
  Card = 3,
  Identity = 4,
}

export interface ServerPreset {
  id: 'us' | 'eu' | 'custom';
  label: string;
  url: string;
}

export const SERVER_PRESETS: ServerPreset[] = [
  { id: 'us', label: 'Bitwarden (US)', url: 'https://vault.bitwarden.com' },
  { id: 'eu', label: 'Bitwarden (EU)', url: 'https://vault.bitwarden.eu' },
  { id: 'custom', label: 'Self-hosted / Vaultwarden', url: '' },
];

export interface PreloginResponse extends KdfConfig {}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
  Key: string;
  PrivateKey?: string;
  Kdf?: KdfType;
  KdfIterations?: number;
  KdfMemory?: number | null;
  KdfParallelism?: number | null;
}

export interface TwoFactorParams {
  provider: number;
  token: string;
  remember?: boolean;
}

export interface EncryptedUri {
  uri: string | null;
  match?: UriMatchType | null;
}

export interface EncryptedField {
  name: string | null;
  value: string | null;
  type: number;
}

export interface EncryptedCipher {
  id: string;
  organizationId?: string | null;
  folderId?: string | null;
  type: CipherType;
  name: string | null;
  notes?: string | null;
  favorite: boolean;
  deletedDate?: string | null;
  revisionDate?: string;
  fields?: EncryptedField[] | null;
  login?: {
    username?: string | null;
    password?: string | null;
    totp?: string | null;
    uris?: EncryptedUri[] | null;
  } | null;
  card?: {
    cardholderName?: string | null;
    brand?: string | null;
    number?: string | null;
    expMonth?: string | null;
    expYear?: string | null;
    code?: string | null;
  } | null;
  identity?: {
    firstName?: string | null;
    lastName?: string | null;
    email?: string | null;
    phone?: string | null;
    username?: string | null;
  } | null;
  secureNote?: {
    type: number;
  } | null;
}

export interface EncryptedFolder {
  id: string;
  name: string | null;
}

export interface EncryptedSyncResponse {
  profile: {
    id: string;
    email: string;
    name?: string | null;
    key: string;
  };
  folders?: EncryptedFolder[];
  ciphers?: EncryptedCipher[];
}

export interface DecryptedUri {
  uri: string;
  match?: UriMatchType | null;
}

export interface DecryptedField {
  name: string;
  value: string;
  type: number;
}

export interface DecryptedCipher {
  id: string;
  folderId: string | null;
  type: CipherType;
  name: string;
  notes: string | null;
  favorite: boolean;
  revisionDate?: string;
  fields: DecryptedField[];
  login?: {
    username: string | null;
    password: string | null;
    totp: string | null;
    uris: DecryptedUri[];
  };
  card?: {
    cardholderName: string | null;
    brand: string | null;
    number: string | null;
    expMonth: string | null;
    expYear: string | null;
    code: string | null;
  };
  identity?: {
    firstName: string | null;
    lastName: string | null;
    email: string | null;
    phone: string | null;
    username: string | null;
  };
}

export interface DecryptedFolder {
  id: string;
  name: string;
}
