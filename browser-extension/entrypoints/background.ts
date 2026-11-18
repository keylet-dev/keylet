import { browser } from 'wxt/browser';
import { defineBackground } from 'wxt/utils/define-background';
import {
  CipherType,
  type DecryptedCipher,
  type DecryptedFolder,
  type EncryptedSyncResponse,
} from '@keylet/core';
import {
  ApiError,
  createCipher,
  deleteCipher,
  loginWithPassword,
  normalizeServerUrl,
  prelogin,
  refreshAccessToken,
  syncVault,
  TwoFactorRequiredError,
  updateCipher,
} from '@keylet/core';
import {
  base64ToBytes,
  bytesToBase64,
  decryptProtectedSymmetricKey,
  decryptToBytes,
  deriveMasterKey,
  deriveMasterPasswordHash,
  derivePinWrappingKey,
  encryptBytes,
  generateTotp,
  type KdfConfig,
  stretchKey,
  type SymmetricKey,
  symmetricKeyFromBytes,
} from '@keylet/core';
import { scoreItemUriMatches } from '@keylet/core';
import {
  decryptSyncResponse,
  encryptCipherPayload,
  encryptNewLoginCipher,
} from '@keylet/core';
import type {
  AccountSummary,
  MatchedCipher,
  RuntimeRequest,
  RuntimeResponse,
  VaultDataPayload,
  VaultStatus,
} from '@keylet/core';

const LOCAL_ACCOUNTS_KEY = 'keylet_accounts';
const LOCAL_ACTIVE_ACCOUNT_KEY = 'keylet_active_account';
const LEGACY_ACCOUNT_KEY = 'keylet_account';
const LEGACY_SNAPSHOT_KEY = 'keylet_sync_snapshot';
const SESSION_KEY = 'keylet_session';
const AUTOLOCK_ALARM = 'keylet-autolock';

function makeAccountId(serverUrl: string, email: string): string {
  return `${serverUrl}|${email.trim().toLowerCase()}`;
}

function snapshotStorageKey(accountId: string): string {
  return `keylet_snapshot_${accountId}`;
}

interface StoredAccount {
  serverUrl: string;
  email: string;
  deviceId: string;
  kdfConfig: KdfConfig;
  protectedKey: string;
  lastSyncAt: number | null;
  autoLockMinutes: number;
  clipboardClearSeconds?: number;
  pinSaltB64?: string;
  pinProtectedKey?: string;
  pinFailedAttempts?: number;
}

interface SessionState {
  symKeyB64: string;
  accessToken: string;
  refreshToken: string | null;
  ciphers: DecryptedCipher[];
  folders: DecryptedFolder[];
}

// In-memory service worker cache for sub-10ms popup reads
let memSymKey: SymmetricKey | null = null;
let memAccessToken: string | null = null;
let memRefreshToken: string | null = null;
let memCiphers: DecryptedCipher[] = [];
let memFolders: DecryptedFolder[] = [];

async function getAccountStore(): Promise<{
  accounts: Record<string, StoredAccount>;
  activeId: string | null;
}> {
  const res = await browser.storage.local.get([
    LOCAL_ACCOUNTS_KEY,
    LOCAL_ACTIVE_ACCOUNT_KEY,
    LEGACY_ACCOUNT_KEY,
    LEGACY_SNAPSHOT_KEY,
  ]);

  let accounts =
    (res[LOCAL_ACCOUNTS_KEY] as Record<string, StoredAccount> | undefined) ?? {};
  let activeId =
    (res[LOCAL_ACTIVE_ACCOUNT_KEY] as string | undefined) ?? null;

  // Migrate legacy single-account storage automatically
  const legacy = res[LEGACY_ACCOUNT_KEY] as StoredAccount | undefined;
  if (legacy && Object.keys(accounts).length === 0) {
    const id = makeAccountId(legacy.serverUrl, legacy.email);
    accounts = { [id]: legacy };
    activeId = id;
    const toSet: Record<string, unknown> = {
      [LOCAL_ACCOUNTS_KEY]: accounts,
      [LOCAL_ACTIVE_ACCOUNT_KEY]: activeId,
    };
    if (res[LEGACY_SNAPSHOT_KEY]) {
      toSet[snapshotStorageKey(id)] = res[LEGACY_SNAPSHOT_KEY];
    }
    await browser.storage.local.set(toSet);
    await browser.storage.local.remove([LEGACY_ACCOUNT_KEY, LEGACY_SNAPSHOT_KEY]);
  }

  return { accounts, activeId };
}

async function getStoredAccount(): Promise<StoredAccount | null> {
  const { accounts, activeId } = await getAccountStore();
  if (!activeId) return null;
  return accounts[activeId] ?? null;
}

async function saveStoredAccount(
  account: StoredAccount,
  makeActive = true,
): Promise<void> {
  const { accounts, activeId } = await getAccountStore();
  const id = makeAccountId(account.serverUrl, account.email);
  accounts[id] = account;
  await browser.storage.local.set({
    [LOCAL_ACCOUNTS_KEY]: accounts,
    [LOCAL_ACTIVE_ACCOUNT_KEY]: makeActive ? id : activeId ?? id,
  });
}

async function getSyncSnapshot(): Promise<EncryptedSyncResponse | null> {
  const { activeId } = await getAccountStore();
  if (!activeId) return null;
  const key = snapshotStorageKey(activeId);
  const res = await browser.storage.local.get(key);
  return (res[key] as EncryptedSyncResponse | undefined) ?? null;
}

async function persistSession(): Promise<void> {
  if (!memSymKey || !memAccessToken) return;
  const session: SessionState = {
    symKeyB64: bytesToBase64(memSymKey.raw),
    accessToken: memAccessToken,
    refreshToken: memRefreshToken,
    ciphers: memCiphers,
    folders: memFolders,
  };
  await browser.storage.session.set({ [SESSION_KEY]: session });
}

async function restoreSessionIfNeeded(): Promise<boolean> {
  if (memSymKey) return true;
  const res = await browser.storage.session.get(SESSION_KEY);
  const session = res[SESSION_KEY] as SessionState | undefined;
  if (!session?.symKeyB64) return false;

  memSymKey = symmetricKeyFromBytes(base64ToBytes(session.symKeyB64));
  memAccessToken = session.accessToken;
  memRefreshToken = session.refreshToken;
  memCiphers = session.ciphers ?? [];
  memFolders = session.folders ?? [];
  return true;
}

async function lockVault(): Promise<void> {
  if (memSymKey) {
    memSymKey.raw.fill(0);
    memSymKey.encKey.fill(0);
    memSymKey.macKey.fill(0);
  }
  memSymKey = null;
  memAccessToken = null;
  memRefreshToken = null;
  memCiphers = [];
  memFolders = [];
  await browser.storage.session.remove(SESSION_KEY);
  await browser.alarms.clear(AUTOLOCK_ALARM);
}

async function resetAutoLockAlarm(minutes: number): Promise<void> {
  await browser.alarms.clear(AUTOLOCK_ALARM);
  if (minutes > 0 && memSymKey) {
    await browser.alarms.create(AUTOLOCK_ALARM, { delayInMinutes: minutes });
  }
}

async function touchActivity(): Promise<void> {
  const account = await getStoredAccount();
  if (account && memSymKey) {
    await resetAutoLockAlarm(account.autoLockMinutes);
  }
}

async function getActiveTabInfo(): Promise<{ id?: number; url: string | null }> {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  return { id: tab?.id, url: tab?.url ?? null };
}

function rankCiphersForUrl(
  ciphers: DecryptedCipher[],
  tabUrl: string | null,
): MatchedCipher[] {
  return ciphers
    .map((c) => ({
      ...c,
      matchScore:
        tabUrl && c.type === CipherType.Login
          ? scoreItemUriMatches(tabUrl, c.login?.uris)
          : 0,
    }))
    .sort((a, b) => {
      if (b.matchScore !== a.matchScore) return b.matchScore - a.matchScore;
      if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
}

async function performSync(account: StoredAccount): Promise<void> {
  if (!memSymKey || !memAccessToken) {
    throw new Error('Vault is locked');
  }

  let syncRes: EncryptedSyncResponse;
  try {
    syncRes = await syncVault(account.serverUrl, memAccessToken);
  } catch (err) {
    // Attempt token refresh once if access token expired
    if (memRefreshToken) {
      const refreshed = await refreshAccessToken(
        account.serverUrl,
        memRefreshToken,
      );
      memAccessToken = refreshed.access_token;
      if (refreshed.refresh_token) {
        memRefreshToken = refreshed.refresh_token;
      }
      syncRes = await syncVault(account.serverUrl, memAccessToken);
    } else {
      throw err;
    }
  }

  const decrypted = await decryptSyncResponse(syncRes, memSymKey);
  memCiphers = decrypted.ciphers;
  memFolders = decrypted.folders;

  account.lastSyncAt = Date.now();
  const id = makeAccountId(account.serverUrl, account.email);
  const { accounts } = await getAccountStore();
  accounts[id] = account;
  await browser.storage.local.set({
    [LOCAL_ACCOUNTS_KEY]: accounts,
    [snapshotStorageKey(id)]: syncRes,
  });
  await persistSession();
}

async function handleLogin(
  req: Extract<RuntimeRequest, { type: 'LOGIN' }>,
): Promise<VaultStatus> {
  const serverUrl = normalizeServerUrl(req.serverUrl);
  const email = req.email.trim().toLowerCase();
  const { accounts } = await getAccountStore();
  const existing = accounts[makeAccountId(serverUrl, email)] ?? null;
  const deviceId = existing?.deviceId ?? crypto.randomUUID();

  const kdfConfig = await prelogin(serverUrl, email);
  const masterKey = await deriveMasterKey(req.masterPassword, email, kdfConfig);
  const passwordHash = await deriveMasterPasswordHash(
    masterKey,
    req.masterPassword,
  );

  const twoFactor =
    req.twoFactorProvider != null && req.twoFactorToken
      ? {
          provider: req.twoFactorProvider,
          token: req.twoFactorToken,
          remember: true,
        }
      : undefined;

  const tokenRes = await loginWithPassword(
    serverUrl,
    email,
    passwordHash,
    deviceId,
    twoFactor,
  );

  const stretched = await stretchKey(masterKey);
  const symKey = await decryptProtectedSymmetricKey(tokenRes.Key, stretched);

  memSymKey = symKey;
  memAccessToken = tokenRes.access_token;
  memRefreshToken = tokenRes.refresh_token ?? null;

  const account: StoredAccount = {
    serverUrl,
    email,
    deviceId,
    kdfConfig,
    protectedKey: tokenRes.Key,
    lastSyncAt: null,
    autoLockMinutes: existing?.autoLockMinutes ?? 15,
    clipboardClearSeconds: existing?.clipboardClearSeconds ?? 30,
  };

  await saveStoredAccount(account);
  await performSync(account);
  await resetAutoLockAlarm(account.autoLockMinutes);

  return getStatus();
}

async function handleUnlock(masterPassword: string): Promise<VaultStatus> {
  const account = await getStoredAccount();
  if (!account) {
    throw new Error('No logged-in account found');
  }

  const masterKey = await deriveMasterKey(
    masterPassword,
    account.email,
    account.kdfConfig,
  );
  const stretched = await stretchKey(masterKey);
  const symKey = await decryptProtectedSymmetricKey(
    account.protectedKey,
    stretched,
  );

  memSymKey = symKey;

  const snapshot = await getSyncSnapshot();
  if (snapshot) {
    const decrypted = await decryptSyncResponse(snapshot, symKey);
    memCiphers = decrypted.ciphers;
    memFolders = decrypted.folders;
  }

  // Re-authenticate silently to obtain a fresh access token if needed
  if (!memAccessToken) {
    try {
      const pwHash = await deriveMasterPasswordHash(masterKey, masterPassword);
      const tokenRes = await loginWithPassword(
        account.serverUrl,
        account.email,
        pwHash,
        account.deviceId,
      );
      memAccessToken = tokenRes.access_token;
      memRefreshToken = tokenRes.refresh_token ?? null;
    } catch {
      // Offline unlock still succeeds using cached encrypted snapshot
      memAccessToken = memAccessToken ?? 'offline';
    }
  }

  await persistSession();
  await resetAutoLockAlarm(account.autoLockMinutes);
  return getStatus();
}

async function handleUnlockWithPin(pin: string): Promise<VaultStatus> {
  const account = await getStoredAccount();
  if (!account || !account.pinSaltB64 || !account.pinProtectedKey) {
    throw new Error('PIN unlock is not configured');
  }

  try {
    const pinKey = await derivePinWrappingKey(pin, base64ToBytes(account.pinSaltB64));
    const rawSym = await decryptToBytes(account.pinProtectedKey, pinKey);
    memSymKey = symmetricKeyFromBytes(rawSym);
    account.pinFailedAttempts = 0;
    await saveStoredAccount(account);
  } catch {
    const fails = (account.pinFailedAttempts ?? 0) + 1;
    if (fails >= 5) {
      delete account.pinSaltB64;
      delete account.pinProtectedKey;
      account.pinFailedAttempts = 0;
      await saveStoredAccount(account);
      throw new Error('Too many failed PIN attempts. Please use your Master Password.');
    }
    account.pinFailedAttempts = fails;
    await saveStoredAccount(account);
    throw new Error(`Invalid PIN (${5 - fails} attempts left)`);
  }

  const snapshot = await getSyncSnapshot();
  if (snapshot) {
    const decrypted = await decryptSyncResponse(snapshot, memSymKey);
    memCiphers = decrypted.ciphers;
    memFolders = decrypted.folders;
  }

  memAccessToken = memAccessToken ?? 'offline';
  await persistSession();
  await resetAutoLockAlarm(account.autoLockMinutes);
  return getStatus();
}

async function getStatus(): Promise<VaultStatus> {
  await restoreSessionIfNeeded();
  const { accounts, activeId } = await getAccountStore();
  const accountList: AccountSummary[] = Object.entries(accounts).map(
    ([id, acc]) => ({
      id,
      serverUrl: acc.serverUrl,
      email: acc.email,
    }),
  );
  const account = activeId ? accounts[activeId] ?? null : null;

  if (!account) {
    return {
      state: 'logged_out',
      activeAccountId: null,
      accounts: accountList,
      serverUrl: null,
      email: null,
      lastSyncAt: null,
      autoLockMinutes: 15,
      clipboardClearSeconds: 30,
      hasPin: false,
      cipherCount: 0,
    };
  }

  return {
    state: memSymKey ? 'unlocked' : 'locked',
    activeAccountId: activeId,
    accounts: accountList,
    serverUrl: account.serverUrl,
    email: account.email,
    lastSyncAt: account.lastSyncAt,
    autoLockMinutes: account.autoLockMinutes,
    clipboardClearSeconds: account.clipboardClearSeconds ?? 30,
    hasPin: Boolean(account.pinProtectedKey),
    cipherCount: memCiphers.length,
  };
}

async function autofillCipherInTab(
  cipherId: string,
  explicitTabId?: number,
): Promise<void> {
  await restoreSessionIfNeeded();
  if (!memSymKey) throw new Error('Vault is locked');

  const cipher = memCiphers.find((c) => c.id === cipherId);
  if (!cipher?.login) throw new Error('Login item not found');

  let tabId = explicitTabId;
  if (tabId == null) {
    const active = await getActiveTabInfo();
    tabId = active.id;
  }
  if (tabId == null) throw new Error('No active tab');

  let totpCode = '';
  if (cipher.login.totp) {
    try {
      const res = await generateTotp(cipher.login.totp);
      totpCode = res.code;
    } catch {
      // ignore invalid TOTP secret
    }
  }

  await browser.tabs.sendMessage(tabId, {
    type: 'KEYLET_FILL',
    username: cipher.login.username ?? '',
    password: cipher.login.password ?? '',
    totp: totpCode,
  });
  await touchActivity();
}

const PENDING_SAVE_KEY = 'keylet_pending_saves';
const PENDING_SAVE_TTL_MS = 2 * 60 * 1000;

interface PendingSaveLogin {
  name: string;
  username: string;
  password: string;
  uri: string;
  host: string;
  expiresAt: number;
}

async function readPendingSaves(): Promise<Record<string, PendingSaveLogin>> {
  const sessionApi = (browser.storage as unknown as {
    session?: typeof browser.storage.local;
  }).session;
  if (!sessionApi) return {};
  const raw = await sessionApi.get(PENDING_SAVE_KEY);
  const map = (raw[PENDING_SAVE_KEY] as Record<string, PendingSaveLogin> | undefined) ?? {};
  const now = Date.now();
  const pruned: Record<string, PendingSaveLogin> = {};
  for (const [k, v] of Object.entries(map)) {
    if (v && v.expiresAt > now) pruned[k] = v;
  }
  return pruned;
}

async function writePendingSaves(map: Record<string, PendingSaveLogin>): Promise<void> {
  const sessionApi = (browser.storage as unknown as {
    session?: typeof browser.storage.local;
  }).session;
  if (!sessionApi) return;
  await sessionApi.set({ [PENDING_SAVE_KEY]: map });
}

function getHostname(uri: string): string {
  try {
    return new URL(uri).hostname.toLowerCase();
  } catch {
    return '';
  }
}

async function withAccessTokenRetry<T>(
  account: StoredAccount,
  fn: (token: string) => Promise<T>,
): Promise<T> {
  if (!memAccessToken) throw new Error('Vault is locked');
  try {
    return await fn(memAccessToken);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401 && memRefreshToken) {
      const tokens = await refreshAccessToken(account.serverUrl, memRefreshToken);
      const nextToken = tokens.access_token;
      memAccessToken = nextToken;
      if (tokens.refresh_token) memRefreshToken = tokens.refresh_token;
      await persistSession();
      return await fn(nextToken);
    }
    throw err;
  }
}

async function handleMessage(
  req: RuntimeRequest,
  senderTabId?: number,
): Promise<RuntimeResponse<unknown>> {
  try {
    switch (req.type) {
      case 'GET_STATUS': {
        return { ok: true, data: await getStatus() };
      }
      case 'LOGIN': {
        return { ok: true, data: await handleLogin(req) };
      }
      case 'UNLOCK': {
        return { ok: true, data: await handleUnlock(req.masterPassword) };
      }
      case 'UNLOCK_PIN': {
        return { ok: true, data: await handleUnlockWithPin(req.pin) };
      }
      case 'SET_PIN': {
        await restoreSessionIfNeeded();
        const account = await getStoredAccount();
        if (!account || !memSymKey) throw new Error('Vault is locked');
        if (req.pin.trim().length < 4) throw new Error('PIN must be at least 4 characters');
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const pinKey = await derivePinWrappingKey(req.pin.trim(), salt);
        account.pinSaltB64 = bytesToBase64(salt);
        account.pinProtectedKey = await encryptBytes(memSymKey.raw, pinKey);
        account.pinFailedAttempts = 0;
        await saveStoredAccount(account);
        return { ok: true, data: await getStatus() };
      }
      case 'CLEAR_PIN': {
        const account = await getStoredAccount();
        if (!account) throw new Error('Not logged in');
        delete account.pinSaltB64;
        delete account.pinProtectedKey;
        account.pinFailedAttempts = 0;
        await saveStoredAccount(account);
        return { ok: true, data: await getStatus() };
      }
      case 'LOCK': {
        await lockVault();
        return { ok: true, data: await getStatus() };
      }
      case 'LOGOUT': {
        await lockVault();
        const { accounts, activeId } = await getAccountStore();
        const targetId = req.accountId ?? activeId;
        if (targetId && accounts[targetId]) {
          delete accounts[targetId];
          await browser.storage.local.remove(snapshotStorageKey(targetId));
        }
        const remainingIds = Object.keys(accounts);
        const nextActive =
          targetId === activeId ? remainingIds[0] ?? null : activeId;
        await browser.storage.local.set({
          [LOCAL_ACCOUNTS_KEY]: accounts,
          [LOCAL_ACTIVE_ACCOUNT_KEY]: nextActive,
        });
        return { ok: true, data: await getStatus() };
      }
      case 'SWITCH_ACCOUNT': {
        await lockVault();
        const { accounts } = await getAccountStore();
        if (!accounts[req.accountId]) {
          throw new Error('Account not found');
        }
        await browser.storage.local.set({
          [LOCAL_ACTIVE_ACCOUNT_KEY]: req.accountId,
        });
        return { ok: true, data: await getStatus() };
      }
      case 'SYNC_VAULT': {
        await restoreSessionIfNeeded();
        const account = await getStoredAccount();
        if (!account) throw new Error('Not logged in');
        await performSync(account);
        await touchActivity();
        return { ok: true, data: await getStatus() };
      }
      case 'GET_VAULT_DATA': {
        await restoreSessionIfNeeded();
        if (!memSymKey) throw new Error('Vault is locked');
        const active =
          req.tabUrl !== undefined
            ? { url: req.tabUrl }
            : await getActiveTabInfo();
        const payload: VaultDataPayload = {
          ciphers: rankCiphersForUrl(memCiphers, active.url),
          folders: memFolders,
          tabUrl: active.url,
        };
        await touchActivity();
        return { ok: true, data: payload };
      }
      case 'GET_TAB_MATCHES': {
        await restoreSessionIfNeeded();
        if (!memSymKey) {
          return { ok: true, data: [] };
        }
        const matches = rankCiphersForUrl(memCiphers, req.tabUrl).filter(
          (c) => c.matchScore > 0,
        );
        return { ok: true, data: matches };
      }
      case 'AUTOFILL_CIPHER': {
        await autofillCipherInTab(req.cipherId, req.tabId);
        return { ok: true, data: true };
      }
      case 'UPDATE_SETTINGS': {
        const account = await getStoredAccount();
        if (!account) throw new Error('Not logged in');
        if (req.autoLockMinutes !== undefined) {
          account.autoLockMinutes = req.autoLockMinutes;
          await resetAutoLockAlarm(account.autoLockMinutes);
        }
        if (req.clipboardClearSeconds !== undefined) {
          account.clipboardClearSeconds = req.clipboardClearSeconds;
        }
        await saveStoredAccount(account);
        return { ok: true, data: await getStatus() };
      }
      case 'CREATE_CIPHER': {
        await restoreSessionIfNeeded();
        const account = await getStoredAccount();
        if (!account || !memSymKey || !memAccessToken) {
          throw new Error('Vault is locked');
        }
        const payload = await encryptCipherPayload(req.cipher, memSymKey);
        await createCipher(account.serverUrl, memAccessToken, payload);
        await performSync(account);
        await touchActivity();
        return { ok: true, data: await getStatus() };
      }
      case 'UPDATE_CIPHER': {
        await restoreSessionIfNeeded();
        const account = await getStoredAccount();
        if (!account || !memSymKey || !memAccessToken) {
          throw new Error('Vault is locked');
        }
        const payload = await encryptCipherPayload(req.cipher, memSymKey);
        await updateCipher(account.serverUrl, memAccessToken, req.cipherId, payload);
        await performSync(account);
        await touchActivity();
        return { ok: true, data: await getStatus() };
      }
      case 'DELETE_CIPHER': {
        await restoreSessionIfNeeded();
        const account = await getStoredAccount();
        if (!account || !memSymKey || !memAccessToken) {
          throw new Error('Vault is locked');
        }
        await deleteCipher(account.serverUrl, memAccessToken, req.cipherId);
        await performSync(account);
        await touchActivity();
        return { ok: true, data: await getStatus() };
      }
      case 'IMPORT_CIPHERS': {
        await restoreSessionIfNeeded();
        const account = await getStoredAccount();
        if (!account || !memSymKey || !memAccessToken) {
          throw new Error('Vault is locked');
        }
        const batchSize = 4;
        for (let i = 0; i < req.items.length; i += batchSize) {
          const slice = req.items.slice(i, i + batchSize);
          await Promise.all(
            slice.map(async (item) => {
              const payload = await encryptCipherPayload(item, memSymKey!);
              await createCipher(account.serverUrl, memAccessToken!, payload);
            }),
          );
        }
        await performSync(account);
        await touchActivity();
        return { ok: true, data: await getStatus() };
      }
      case 'STAGE_SAVE_LOGIN': {
        await restoreSessionIfNeeded();
        if (!memSymKey || !memAccessToken || senderTabId == null) {
          return { ok: true, data: { shouldPrompt: false } };
        }
        const matches = rankCiphersForUrl(memCiphers, req.uri);
        const alreadySaved = matches.some(
          (m) =>
            m.matchScore > 0 &&
            m.type === CipherType.Login &&
            m.login?.password === req.password &&
            (!req.username || m.login?.username === req.username),
        );
        if (alreadySaved) {
          const map = await readPendingSaves();
          delete map[String(senderTabId)];
          await writePendingSaves(map);
          return { ok: true, data: { shouldPrompt: false } };
        }
        const host = getHostname(req.uri) || req.name;
        const map = await readPendingSaves();
        map[String(senderTabId)] = {
          name: req.name,
          username: req.username,
          password: req.password,
          uri: req.uri,
          host,
          expiresAt: Date.now() + PENDING_SAVE_TTL_MS,
        };
        await writePendingSaves(map);
        return { ok: true, data: { shouldPrompt: true } };
      }
      case 'GET_PENDING_SAVE': {
        await restoreSessionIfNeeded();
        if (!memSymKey || senderTabId == null) {
          return { ok: true, data: null };
        }
        const map = await readPendingSaves();
        const pending = map[String(senderTabId)];
        if (!pending) return { ok: true, data: null };
        const currentHost = getHostname(req.uri);
        if (
          currentHost &&
          pending.host &&
          currentHost !== pending.host &&
          !currentHost.endsWith(`.${pending.host}`) &&
          !pending.host.endsWith(`.${currentHost}`)
        ) {
          return { ok: true, data: null };
        }
        return { ok: true, data: pending };
      }
      case 'DISMISS_SAVE_LOGIN': {
        if (senderTabId != null) {
          const map = await readPendingSaves();
          delete map[String(senderTabId)];
          await writePendingSaves(map);
        }
        return { ok: true, data: true };
      }
      case 'SAVE_LOGIN': {
        await restoreSessionIfNeeded();
        const account = await getStoredAccount();
        if (!account || !memSymKey || !memAccessToken) {
          throw new Error('Vault is locked');
        }
        const existing = rankCiphersForUrl(memCiphers, req.uri).find(
          (m) =>
            m.matchScore > 0 &&
            m.type === CipherType.Login &&
            (req.username
              ? (m.login?.username ?? '').toLowerCase() === req.username.toLowerCase()
              : !m.login?.username),
        );
        if (existing) {
          const payload = await encryptCipherPayload(
            {
              type: CipherType.Login,
              name: existing.name,
              notes: existing.notes,
              favorite: existing.favorite,
              folderId: existing.folderId,
              fields: existing.fields,
              login: {
                username: req.username || existing.login?.username || null,
                password: req.password,
                totp: existing.login?.totp ?? null,
                uris: existing.login?.uris?.length
                  ? existing.login.uris
                  : [{ uri: req.uri, match: null }],
              },
            },
            memSymKey,
          );
          await withAccessTokenRetry(account, (token) =>
            updateCipher(account.serverUrl, token, existing.id, payload),
          );
        } else {
          const payload = await encryptNewLoginCipher(
            {
              name: req.name,
              username: req.username,
              password: req.password,
              uri: req.uri,
            },
            memSymKey,
          );
          await withAccessTokenRetry(account, (token) =>
            createCipher(account.serverUrl, token, payload),
          );
        }
        if (senderTabId != null) {
          const map = await readPendingSaves();
          delete map[String(senderTabId)];
          await writePendingSaves(map);
        }
        await performSync(account);
        await touchActivity();
        return { ok: true, data: true };
      }
      default:
        return { ok: false, error: 'Unknown message type' };
    }
  } catch (err) {
    if (err instanceof TwoFactorRequiredError) {
      return {
        ok: false,
        error: err.message,
        twoFactorProviders: err.providers,
      };
    }
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export default defineBackground(() => {
  browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    handleMessage(msg as RuntimeRequest, sender.tab?.id).then(sendResponse);
    return true;
  });

  browser.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === AUTOLOCK_ALARM) {
      void lockVault();
    }
  });

  browser.commands.onCommand.addListener(async (command) => {
    if (command !== 'autofill') return;
    await restoreSessionIfNeeded();
    if (!memSymKey) return;

    const active = await getActiveTabInfo();
    if (!active.id || !active.url) return;

    const matches = rankCiphersForUrl(memCiphers, active.url).filter(
      (c) => c.matchScore > 0,
    );
    const best = matches[0];
    if (best) {
      await autofillCipherInTab(best.id, active.id);
    }
  });

  browser.runtime.onInstalled.addListener(() => {
    browser.contextMenus.create({
      id: 'keylet-autofill',
      title: 'Keylet: Autofill matching login',
      contexts: ['editable', 'page'],
    });
  });

  browser.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId !== 'keylet-autofill' || !tab?.id || !tab.url) return;
    await restoreSessionIfNeeded();
    if (!memSymKey) return;
    const matches = rankCiphersForUrl(memCiphers, tab.url).filter(
      (c) => c.matchScore > 0,
    );
    const best = matches[0];
    if (best) {
      await autofillCipherInTab(best.id, tab.id);
    }
  });
});
