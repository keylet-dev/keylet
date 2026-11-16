import type { DecryptedCipher, DecryptedFolder } from '../api/types.js';
import type { CipherInput } from './decrypt.js';

export type VaultAuthState = 'logged_out' | 'locked' | 'unlocked';

export interface VaultStatus {
  state: VaultAuthState;
  serverUrl: string | null;
  email: string | null;
  lastSyncAt: number | null;
  autoLockMinutes: number;
  clipboardClearSeconds: number;
  hasPin: boolean;
  cipherCount: number;
}

export interface MatchedCipher extends DecryptedCipher {
  matchScore: number;
}

export type RuntimeRequest =
  | { type: 'GET_STATUS' }
  | {
      type: 'LOGIN';
      serverUrl: string;
      email: string;
      masterPassword: string;
      twoFactorProvider?: number;
      twoFactorToken?: string;
    }
  | { type: 'UNLOCK'; masterPassword: string }
  | { type: 'UNLOCK_PIN'; pin: string }
  | { type: 'SET_PIN'; pin: string }
  | { type: 'CLEAR_PIN' }
  | { type: 'LOCK' }
  | { type: 'LOGOUT' }
  | { type: 'SYNC_VAULT' }
  | { type: 'GET_VAULT_DATA'; tabUrl?: string | null }
  | { type: 'GET_TAB_MATCHES'; tabUrl: string }
  | { type: 'AUTOFILL_CIPHER'; cipherId: string; tabId?: number }
  | {
      type: 'UPDATE_SETTINGS';
      autoLockMinutes?: number;
      clipboardClearSeconds?: number;
    }
  | { type: 'CREATE_CIPHER'; cipher: CipherInput }
  | { type: 'UPDATE_CIPHER'; cipherId: string; cipher: CipherInput }
  | { type: 'DELETE_CIPHER'; cipherId: string }
  | { type: 'IMPORT_CIPHERS'; items: CipherInput[] }
  | {
      type: 'SAVE_LOGIN';
      name: string;
      username: string;
      password: string;
      uri: string;
    };

export type RuntimeResponse<T = unknown> =
  | { ok: true; data: T }
  | { ok: false; error: string; twoFactorProviders?: number[] };

export interface VaultDataPayload {
  ciphers: MatchedCipher[];
  folders: DecryptedFolder[];
  tabUrl: string | null;
}
