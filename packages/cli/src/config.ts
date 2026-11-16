import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { EncryptedSyncResponse, KdfConfig } from '@keylet/core';

export interface CliAccount {
  serverUrl: string;
  email: string;
  deviceId: string;
  kdfConfig: KdfConfig;
  protectedKey: string;
  lastSyncAt: number | null;
  autoLockMinutes: number;
}

export function getConfigDir(): string {
  return (
    process.env.KEYLET_CONFIG_DIR ||
    path.join(os.homedir(), '.config', 'keylet')
  );
}

export function ensureConfigDir(dir = getConfigDir()): string {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

export function makeAccountId(serverUrl: string, email: string): string {
  const hash = crypto
    .createHash('sha256')
    .update(`${serverUrl}|${email.trim().toLowerCase()}`)
    .digest('hex')
    .slice(0, 12);
  return hash;
}

function getAccountsDir(dir = getConfigDir()): string {
  return path.join(dir, 'accounts');
}

function getActiveFilePath(dir = getConfigDir()): string {
  return path.join(dir, 'active.txt');
}

export function getSocketPath(dir = getConfigDir()): string {
  return path.join(dir, 'agent.sock');
}

export function getSshSocketPath(dir = getConfigDir()): string {
  return process.env.KEYLET_SSH_SOCK || path.join(dir, 'ssh.sock');
}

function migrateLegacyIfNeeded(dir = getConfigDir()): void {
  const legacyAcc = path.join(dir, 'account.json');
  if (!fs.existsSync(legacyAcc)) return;
  try {
    const acc = JSON.parse(fs.readFileSync(legacyAcc, 'utf8')) as CliAccount;
    const id = makeAccountId(acc.serverUrl, acc.email);
    const accDir = path.join(getAccountsDir(dir), id);
    fs.mkdirSync(accDir, { recursive: true, mode: 0o700 });
    fs.renameSync(legacyAcc, path.join(accDir, 'account.json'));
    const legacySnap = path.join(dir, 'snapshot.json');
    if (fs.existsSync(legacySnap)) {
      fs.renameSync(legacySnap, path.join(accDir, 'snapshot.json'));
    }
    fs.writeFileSync(getActiveFilePath(dir), id, { mode: 0o600 });
  } catch {
    // ignore migration error
  }
}

export function listAccounts(
  dir = getConfigDir(),
): Array<{ id: string; account: CliAccount; active: boolean }> {
  migrateLegacyIfNeeded(dir);
  const accsDir = getAccountsDir(dir);
  if (!fs.existsSync(accsDir)) return [];
  const activeId = getActiveAccountId(dir);
  const out: Array<{ id: string; account: CliAccount; active: boolean }> = [];
  for (const entry of fs.readdirSync(accsDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const accFile = path.join(accsDir, entry.name, 'account.json');
    if (!fs.existsSync(accFile)) continue;
    try {
      const account = JSON.parse(fs.readFileSync(accFile, 'utf8')) as CliAccount;
      out.push({ id: entry.name, account, active: entry.name === activeId });
    } catch {
      // ignore corrupt entry
    }
  }
  return out;
}

export function getActiveAccountId(dir = getConfigDir()): string | null {
  migrateLegacyIfNeeded(dir);
  const p = getActiveFilePath(dir);
  if (!fs.existsSync(p)) return null;
  const id = fs.readFileSync(p, 'utf8').trim();
  return id || null;
}

export function setActiveAccountId(id: string | null, dir = getConfigDir()): void {
  ensureConfigDir(dir);
  const p = getActiveFilePath(dir);
  if (!id) {
    if (fs.existsSync(p)) fs.unlinkSync(p);
    return;
  }
  fs.writeFileSync(p, id, { mode: 0o600 });
}

export function readAccount(dir = getConfigDir()): CliAccount | null {
  const id = getActiveAccountId(dir);
  if (!id) return null;
  const p = path.join(getAccountsDir(dir), id, 'account.json');
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, 'utf8')) as CliAccount;
}

export function writeAccount(account: CliAccount, dir = getConfigDir()): void {
  ensureConfigDir(dir);
  const id = makeAccountId(account.serverUrl, account.email);
  const accDir = path.join(getAccountsDir(dir), id);
  fs.mkdirSync(accDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(accDir, 'account.json'), JSON.stringify(account, null, 2), {
    mode: 0o600,
  });
  setActiveAccountId(id, dir);
}

export function readSnapshot(dir = getConfigDir()): EncryptedSyncResponse | null {
  const id = getActiveAccountId(dir);
  if (!id) return null;
  const p = path.join(getAccountsDir(dir), id, 'snapshot.json');
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, 'utf8')) as EncryptedSyncResponse;
}

export function writeSnapshot(
  snapshot: EncryptedSyncResponse,
  dir = getConfigDir(),
): void {
  ensureConfigDir(dir);
  const id = getActiveAccountId(dir);
  if (!id) return;
  const accDir = path.join(getAccountsDir(dir), id);
  fs.mkdirSync(accDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(accDir, 'snapshot.json'), JSON.stringify(snapshot), {
    mode: 0o600,
  });
}

export function clearStoredAccount(dir = getConfigDir()): void {
  const id = getActiveAccountId(dir);
  if (id) {
    const accDir = path.join(getAccountsDir(dir), id);
    if (fs.existsSync(accDir)) {
      fs.rmSync(accDir, { recursive: true, force: true });
    }
  }
  const remaining = listAccounts(dir);
  setActiveAccountId(remaining[0]?.id ?? null, dir);
}
