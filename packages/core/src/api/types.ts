import type { KdfConfig, KdfType } from '../crypto/types.js';
import type { UriMatchType } from '../matching/uri.js';

export enum CipherType {
  Login = 1,
  SecureNote = 2,
  Card = 3,
  Identity = 4,
  SshKey = 5,
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

export interface EncryptedIdentity {
  title?: string | null;
  firstName?: string | null;
  middleName?: string | null;
  lastName?: string | null;
  company?: string | null;
  ssn?: string | null;
  passportNumber?: string | null;
  licenseNumber?: string | null;
  email?: string | null;
  phone?: string | null;
  username?: string | null;
  address1?: string | null;
  address2?: string | null;
  address3?: string | null;
  city?: string | null;
  state?: string | null;
  postalCode?: string | null;
  country?: string | null;
}

export interface EncryptedSshKey {
  privateKey?: string | null;
  publicKey?: string | null;
  keyFingerprint?: string | null;
}

export interface EncryptedCipher {
  id: string;
  organizationId?: string | null;
  folderId?: string | null;
  collectionIds?: string[] | null;
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
  identity?: EncryptedIdentity | null;
  secureNote?: {
    type: number;
  } | null;
  sshKey?: EncryptedSshKey | null;
}

export interface EncryptedFolder {
  id: string;
  name: string | null;
}

export interface EncryptedOrganization {
  id: string;
  name: string;
  key: string;
  enabled?: boolean;
}

export interface EncryptedCollection {
  id: string;
  organizationId: string;
  name: string | null;
}

export interface EncryptedSyncResponse {
  profile: {
    id: string;
    email: string;
    name?: string | null;
    key: string;
    privateKey?: string | null;
    organizations?: EncryptedOrganization[];
  };
  folders?: EncryptedFolder[];
  collections?: EncryptedCollection[];
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
  organizationId?: string | null;
  folderId: string | null;
  collectionIds?: string[];
  type: CipherType;
  name: string;
  notes: string | null;
  favorite: boolean;
  deletedDate?: string | null;
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
    title: string | null;
    firstName: string | null;
    middleName: string | null;
    lastName: string | null;
    company: string | null;
    ssn: string | null;
    passportNumber: string | null;
    licenseNumber: string | null;
    email: string | null;
    phone: string | null;
    username: string | null;
    address1: string | null;
    city: string | null;
    state: string | null;
    postalCode: string | null;
    country: string | null;
  };
  sshKey?: {
    privateKey: string | null;
    publicKey: string | null;
    keyFingerprint: string | null;
  };
}

export interface DecryptedFolder {
  id: string;
  name: string;
}

export interface DecryptedCollection {
  id: string;
  organizationId: string;
  name: string;
}

export interface DecryptedOrganization {
  id: string;
  name: string;
}
