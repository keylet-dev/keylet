import type { DecryptedCipher, DecryptedFolder } from '../api/types.js';
import type { CipherInput } from './decrypt.js';

export type VaultAuthState = 'logged_out' | 'locked' | 'unlocked';

export interface AccountSummary {
  id: string;
  serverUrl: string;
  email: string;
}

export interface VaultStatus {
  state: VaultAuthState;
  activeAccountId: string | null;
  accounts: AccountSummary[];
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
  | { type: 'LOGOUT'; accountId?: string }
  | { type: 'SWITCH_ACCOUNT'; accountId: string }
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
    }
  | {
      type: 'STAGE_SAVE_LOGIN';
      name: string;
      username: string;
      password: string;
      uri: string;
    }
  | { type: 'GET_PENDING_SAVE'; uri: string }
  | { type: 'DISMISS_SAVE_LOGIN' };

export type RuntimeResponse<T = unknown> =
  | { ok: true; data: T }
  | { ok: false; error: string; twoFactorProviders?: number[] };

export interface VaultDataPayload {
  ciphers: MatchedCipher[];
  folders: DecryptedFolder[];
  tabUrl: string | null;
}
