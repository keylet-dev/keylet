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

export function getAccountPath(dir = getConfigDir()): string {
  return path.join(dir, 'account.json');
}

export function getSnapshotPath(dir = getConfigDir()): string {
  return path.join(dir, 'snapshot.json');
}

export function getSocketPath(dir = getConfigDir()): string {
  return path.join(dir, 'agent.sock');
}

export function getSshSocketPath(dir = getConfigDir()): string {
  return process.env.KEYLET_SSH_SOCK || path.join(dir, 'ssh.sock');
}

export function readAccount(dir = getConfigDir()): CliAccount | null {
  const p = getAccountPath(dir);
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, 'utf8')) as CliAccount;
}

export function writeAccount(account: CliAccount, dir = getConfigDir()): void {
  ensureConfigDir(dir);
  fs.writeFileSync(getAccountPath(dir), JSON.stringify(account, null, 2), {
    mode: 0o600,
  });
}

export function readSnapshot(dir = getConfigDir()): EncryptedSyncResponse | null {
  const p = getSnapshotPath(dir);
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, 'utf8')) as EncryptedSyncResponse;
}

export function writeSnapshot(
  snapshot: EncryptedSyncResponse,
  dir = getConfigDir(),
): void {
  ensureConfigDir(dir);
  fs.writeFileSync(getSnapshotPath(dir), JSON.stringify(snapshot), {
    mode: 0o600,
  });
}

export function clearStoredAccount(dir = getConfigDir()): void {
  for (const p of [getAccountPath(dir), getSnapshotPath(dir)]) {
    if (fs.existsSync(p)) fs.unlinkSync(p);
  }
}
