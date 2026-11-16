import fs from 'node:fs';
import http from 'node:http';
import {
  base64ToBytes,
  type DecryptedCipher,
  type DecryptedFolder,
  decryptProtectedSymmetricKey,
  decryptSyncResponse,
  deriveMasterKey,
  deriveMasterPasswordHash,
  type EncryptedSyncResponse,
  loginWithPassword,
  refreshAccessToken,
  stretchKey,
  type SymmetricKey,
  symmetricKeyFromBytes,
  syncVault,
} from '@keylet/core';
import {
  type CliAccount,
  ensureConfigDir,
  getSocketPath,
  readAccount,
  readSnapshot,
  writeAccount,
  writeSnapshot,
} from './config.js';

export function startDaemon(): void {
  const dir = ensureConfigDir();
  const sockPath = getSocketPath(dir);
  if (fs.existsSync(sockPath)) {
    fs.unlinkSync(sockPath);
  }

  let memSymKey: SymmetricKey | null = null;
  let memAccessToken: string | null = null;
  let memRefreshToken: string | null = null;
  let memCiphers: DecryptedCipher[] = [];
  let memFolders: DecryptedFolder[] = [];
  let idleTimer: ReturnType<typeof setTimeout> | null = null;

  function wipeAndExit() {
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
    if (idleTimer) clearTimeout(idleTimer);
    server.close(() => {
      if (fs.existsSync(sockPath)) fs.unlinkSync(sockPath);
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 200).unref();
  }

  function resetIdleTimer(minutes: number) {
    if (idleTimer) clearTimeout(idleTimer);
    if (minutes > 0) {
      idleTimer = setTimeout(wipeAndExit, minutes * 60_000);
      idleTimer.unref();
    }
  }

  async function performSync(account: CliAccount): Promise<void> {
    if (!memSymKey || !memAccessToken) throw new Error('Vault is locked');
    let syncRes: EncryptedSyncResponse;
    try {
      syncRes = await syncVault(account.serverUrl, memAccessToken);
    } catch (err) {
      if (memRefreshToken) {
        const refreshed = await refreshAccessToken(
          account.serverUrl,
          memRefreshToken,
        );
        memAccessToken = refreshed.access_token;
        if (refreshed.refresh_token) memRefreshToken = refreshed.refresh_token;
        syncRes = await syncVault(account.serverUrl, memAccessToken);
      } else {
        throw err;
      }
    }

    const decrypted = await decryptSyncResponse(syncRes, memSymKey);
    memCiphers = decrypted.ciphers;
    memFolders = decrypted.folders;
    account.lastSyncAt = Date.now();
    writeAccount(account, dir);
    writeSnapshot(syncRes, dir);
  }

  const server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const bodyText = Buffer.concat(chunks).toString('utf8');
    const body = bodyText ? (JSON.parse(bodyText) as Record<string, unknown>) : {};

    const reply = (status: number, data: unknown) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    };

    try {
      const url = req.url ?? '/';
      if (req.method === 'GET' && url === '/ping') {
        reply(200, { ok: true, unlocked: Boolean(memSymKey) });
        return;
      }

      if (req.method === 'GET' && url === '/status') {
        const account = readAccount(dir);
        reply(200, {
          ok: true,
          unlocked: Boolean(memSymKey),
          account,
          cipherCount: memCiphers.length,
        });
        return;
      }

      if (req.method === 'POST' && url === '/session') {
        const symKeyB64 = String(body.symKeyB64 ?? '');
        memSymKey = symmetricKeyFromBytes(base64ToBytes(symKeyB64));
        memAccessToken = String(body.accessToken ?? '');
        memRefreshToken =
          typeof body.refreshToken === 'string' ? body.refreshToken : null;
        const account = readAccount(dir);
        if (!account) throw new Error('Account not initialized');
        await performSync(account);
        resetIdleTimer(account.autoLockMinutes);
        reply(200, { ok: true, cipherCount: memCiphers.length });
        return;
      }

      if (req.method === 'POST' && url === '/unlock') {
        const masterPassword = String(body.masterPassword ?? '');
        const account = readAccount(dir);
        if (!account) throw new Error('Not logged in. Run `keylet login` first.');

        const masterKey = await deriveMasterKey(
          masterPassword,
          account.email,
          account.kdfConfig,
        );
        const stretched = await stretchKey(masterKey);
        memSymKey = await decryptProtectedSymmetricKey(
          account.protectedKey,
          stretched,
        );

        const snapshot = readSnapshot(dir);
        if (snapshot) {
          const dec = await decryptSyncResponse(snapshot, memSymKey);
          memCiphers = dec.ciphers;
          memFolders = dec.folders;
        }

        if (!memAccessToken) {
          try {
            const pwHash = await deriveMasterPasswordHash(
              masterKey,
              masterPassword,
            );
            const tok = await loginWithPassword(
              account.serverUrl,
              account.email,
              pwHash,
              account.deviceId,
            );
            memAccessToken = tok.access_token;
            memRefreshToken = tok.refresh_token ?? null;
          } catch {
            memAccessToken = memAccessToken ?? 'offline';
          }
        }

        resetIdleTimer(account.autoLockMinutes);
        reply(200, { ok: true, cipherCount: memCiphers.length });
        return;
      }

      if (req.method === 'POST' && url === '/sync') {
        const account = readAccount(dir);
        if (!account || !memSymKey) throw new Error('Vault is locked');
        await performSync(account);
        resetIdleTimer(account.autoLockMinutes);
        reply(200, { ok: true, cipherCount: memCiphers.length });
        return;
      }

      if (req.method === 'GET' && url === '/items') {
        if (!memSymKey) throw new Error('Vault is locked');
        const account = readAccount(dir);
        if (account) resetIdleTimer(account.autoLockMinutes);
        reply(200, { ok: true, ciphers: memCiphers, folders: memFolders });
        return;
      }

      if (req.method === 'POST' && url === '/lock') {
        reply(200, { ok: true });
        wipeAndExit();
        return;
      }

      reply(404, { ok: false, error: 'Not found' });
    } catch (err) {
      reply(400, {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  });

  server.listen(sockPath, () => {
    fs.chmodSync(sockPath, 0o600);
  });

  process.on('SIGINT', wipeAndExit);
  process.on('SIGTERM', wipeAndExit);
}
