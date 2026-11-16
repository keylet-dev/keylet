#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import {
  bytesToBase64,
  type CipherInput,
  CipherType,
  type DecryptedCipher,
  type DecryptedFolder,
  decryptProtectedSymmetricKey,
  DEFAULT_PASSWORD_OPTIONS,
  deriveMasterKey,
  deriveMasterPasswordHash,
  generateEd25519SshKeyPair,
  generatePassword,
  generateTotp,
  loginWithPassword,
  normalizeServerUrl,
  parseImportBytes,
  prelogin,
  stretchKey,
  TwoFactorRequiredError,
} from '@keylet/core';
import { ensureDaemon, ipcRequest, isDaemonRunning } from './client.js';
import {
  type CliAccount,
  clearStoredAccount,
  readAccount,
  writeAccount,
} from './config.js';
import { startDaemon } from './daemon.js';
import {
  extractCipherField,
  findCipherByQuery,
  resolveRunEnvironment,
} from './run.js';
import { renderTable, resolveOutputFormat, toYaml } from './format.js';
import {
  installSkill,
  KEYLET_SKILL_MD,
  resolveSkillTargetDir,
} from './skills.js';

const BIN_PATH = fileURLToPath(import.meta.url);

function printRootHelp(): void {
  console.log(`keylet - Keyboard-first Bitwarden & Vaultwarden CLI

Usage:
  keylet <group|command> [options]

Command Groups:
  auth      Authentication & session lock (login, unlock, lock, logout, status)
  item      Manage vault items (list, get, add, rm, totp)
  folder    Manage folders (list, add, rm)
  vault     Sync & import vault data (sync, import)
  ssh       SSH keys & in-memory agent (agent, add, list)
  skills    Install or inspect the Keylet AI Agent Skill (install, show, path)

Standalone Commands:
  run       Run a command with vault secrets injected into env
  generate  Generate a strong random password

Run \`keylet <group> --help\` for subcommand details.`);
}

function printGroupHelp(group: string): void {
  switch (group) {
    case 'auth':
      console.log(`Usage: keylet auth <subcommand>

Subcommands:
  login [--server <url>] [--email <email>] [--password-env <VAR>] [--2fa <code>]
  unlock [--password-env <VAR>]
  lock
  logout
  status`);
      break;
    case 'item':
      console.log(`Usage: keylet item <subcommand>

Subcommands:
  list [--type login|note|card|ssh] [--format table|json|yaml] [--json] [query]
  get <query> [--field password|username|totp|public|private|notes|all] [--json]
  add --name <name> [--type login|note|ssh] [--username <u>] [--password <p>] [--uri <url>] [--totp <secret>] [--generate-ssh]
  rm <query> [--permanent]
  totp <query>`);
      break;
    case 'folder':
      console.log(`Usage: keylet folder <subcommand>

Subcommands:
  list [--format table|json|yaml] [--json]
  add <name>
  rm <nameOrId>`);
      break;
    case 'vault':
      console.log(`Usage: keylet vault <subcommand>

Subcommands:
  sync
  import <file.json|file.csv>   (Bitwarden JSON/CSV, 1Password CSV/1PUX, Chrome CSV)`);
      break;
    case 'ssh':
      console.log(`Usage: keylet ssh <subcommand>

Subcommands:
  agent                               Start in-memory SSH agent & print SSH_AUTH_SOCK export
  add --name <name> [--generate]        Add or generate an Ed25519 SSH key item
  list [--format table|json|yaml] [--json]  List SSH key items in vault`);
      break;
    case 'skills':
      console.log(`Usage: keylet skills <subcommand>

Subcommands:
  install [--global] [--dir <path>]  Install Keylet SKILL.md for AI coding agents
  show                               Print bundled SKILL.md to stdout
  path [--global] [--dir <path>]     Print target skill directory path`);
      break;
  }
}

async function promptLine(label: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
  });
  return new Promise((resolve) => {
    rl.question(label, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function promptPassword(label: string): Promise<string> {
  if (!process.stdin.isTTY) {
    return promptLine('');
  }
  return new Promise((resolve) => {
    process.stderr.write(label);
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    let value = '';
    const onData = (buf: Buffer) => {
      const ch = buf.toString('utf8');
      if (ch === '\r' || ch === '\n') {
        stdin.setRawMode(Boolean(wasRaw));
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stderr.write('\n');
        resolve(value);
      } else if (ch === '\u0003') {
        stdin.setRawMode(Boolean(wasRaw));
        process.exit(130);
      } else if (ch === '\u007f' || ch === '\b') {
        value = value.slice(0, -1);
      } else {
        value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

function getFlag(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

function hasFlag(args: string[], name: string): boolean {
  return args.includes(name);
}

function wantsHelp(args: string[]): boolean {
  return args.includes('--help') || args.includes('-h');
}

async function getUnlockedItems(): Promise<DecryptedCipher[]> {
  if (!(await isDaemonRunning())) {
    throw new Error('Vault is locked. Run `keylet auth unlock` first.');
  }
  const res = await ipcRequest<{ ok: boolean; ciphers: DecryptedCipher[] }>(
    'GET',
    '/items',
  );
  return res.ciphers;
}

// --- Auth commands ---
async function cmdLogin(args: string[]): Promise<void> {
  const serverRaw =
    getFlag(args, '--server') ||
    (await promptLine('Server URL (default https://vault.bitwarden.com): ')) ||
    'https://vault.bitwarden.com';
  const serverUrl = normalizeServerUrl(serverRaw);
  const email = (getFlag(args, '--email') || (await promptLine('Email: ')))
    .trim()
    .toLowerCase();

  const pwEnvVar = getFlag(args, '--password-env');
  const password =
    (pwEnvVar && process.env[pwEnvVar]) ||
    (await promptPassword('Master Password: '));

  const existing = readAccount();
  const deviceId = existing?.deviceId ?? crypto.randomUUID();
  const kdfConfig = await prelogin(serverUrl, email);
  const masterKey = await deriveMasterKey(password, email, kdfConfig);
  const passwordHash = await deriveMasterPasswordHash(masterKey, password);

  let twoFactorToken = getFlag(args, '--2fa');
  let tokenRes;
  try {
    tokenRes = await loginWithPassword(
      serverUrl,
      email,
      passwordHash,
      deviceId,
      twoFactorToken
        ? { provider: 0, token: twoFactorToken, remember: true }
        : undefined,
    );
  } catch (err) {
    if (err instanceof TwoFactorRequiredError) {
      twoFactorToken = await promptLine('2FA Code: ');
      tokenRes = await loginWithPassword(
        serverUrl,
        email,
        passwordHash,
        deviceId,
        {
          provider: err.providers[0] ?? 0,
          token: twoFactorToken,
          remember: true,
        },
      );
    } else {
      throw err;
    }
  }

  const stretched = await stretchKey(masterKey);
  const symKey = await decryptProtectedSymmetricKey(tokenRes.Key, stretched);

  const account: CliAccount = {
    serverUrl,
    email,
    deviceId,
    kdfConfig,
    protectedKey: tokenRes.Key,
    lastSyncAt: null,
    autoLockMinutes: existing?.autoLockMinutes ?? 15,
  };
  writeAccount(account);

  await ensureDaemon(BIN_PATH);
  const res = await ipcRequest<{ ok: boolean; cipherCount: number }>(
    'POST',
    '/session',
    {
      symKeyB64: bytesToBase64(symKey.raw),
      accessToken: tokenRes.access_token,
      refreshToken: tokenRes.refresh_token ?? null,
    },
  );
  console.log(`Logged in to ${serverUrl} (${res.cipherCount} items synced).`);
}

async function cmdUnlock(args: string[]): Promise<void> {
  const account = readAccount();
  if (!account) {
    throw new Error('No account configured. Run `keylet auth login` first.');
  }
  const pwEnvVar = getFlag(args, '--password-env');
  const masterPassword =
    (pwEnvVar && process.env[pwEnvVar]) ||
    (await promptPassword(`Master Password for ${account.email}: `));

  await ensureDaemon(BIN_PATH);
  const res = await ipcRequest<{ ok: boolean; cipherCount: number }>(
    'POST',
    '/unlock',
    { masterPassword },
  );
  console.log(`Vault unlocked (${res.cipherCount} items).`);
}

async function cmdLock(): Promise<void> {
  if (await isDaemonRunning()) {
    await ipcRequest('POST', '/lock');
  }
  console.log('Vault locked.');
}

async function cmdLogout(): Promise<void> {
  if (await isDaemonRunning()) {
    await ipcRequest('POST', '/lock').catch(() => {});
  }
  clearStoredAccount();
  console.log('Logged out and local vault data cleared.');
}

async function cmdStatus(): Promise<void> {
  const account = readAccount();
  if (!account) {
    console.log('Status: logged_out');
    return;
  }
  const running = await isDaemonRunning();
  if (!running) {
    console.log(`Status: locked\nServer: ${account.serverUrl}\nEmail:  ${account.email}`);
    return;
  }
  const st = await ipcRequest<{ unlocked: boolean; cipherCount: number }>(
    'GET',
    '/status',
  );
  console.log(
    `Status: ${st.unlocked ? 'unlocked' : 'locked'}\nServer: ${account.serverUrl}\nEmail:  ${account.email}\nItems:  ${st.cipherCount}`,
  );
}

// --- Vault commands ---
async function cmdSync(): Promise<void> {
  if (!(await isDaemonRunning())) {
    throw new Error('Vault is locked. Run `keylet auth unlock` first.');
  }
  const res = await ipcRequest<{ cipherCount: number }>('POST', '/sync');
  console.log(`Synced ${res.cipherCount} items.`);
}

async function cmdImport(args: string[]): Promise<void> {
  const filePath = args[0];
  if (!filePath) throw new Error('Usage: keylet vault import <file.1pux|file.json|file.csv>');
  if (!(await isDaemonRunning())) {
    throw new Error('Vault is locked. Run `keylet auth unlock` first.');
  }
  const bytes = new Uint8Array(fs.readFileSync(filePath));
  const parsed = await parseImportBytes(bytes);
  if (parsed.items.length === 0) {
    throw new Error('No importable items found');
  }
  const res = await ipcRequest<{ imported: number; cipherCount: number }>(
    'POST',
    '/import',
    { items: parsed.items },
  );
  console.log(
    `Imported ${res.imported} items (${parsed.format}, skipped ${parsed.skipped}). Total items: ${res.cipherCount}.`,
  );
}

// --- Item commands ---
function cipherTypeLabel(type: CipherType): string {
  switch (type) {
    case CipherType.Login:
      return 'login';
    case CipherType.SecureNote:
      return 'note';
    case CipherType.Card:
      return 'card';
    case CipherType.Identity:
      return 'identity';
    case CipherType.SshKey:
      return 'ssh';
    default:
      return String(type);
  }
}

async function cmdList(args: string[]): Promise<void> {
  const ciphers = await getUnlockedItems();
  const typeFilter = getFlag(args, '--type')?.toLowerCase();
  const format = resolveOutputFormat(args, 'table');
  const positional = args.filter(
    (a, i) =>
      !a.startsWith('--') &&
      args[i - 1] !== '--type' &&
      args[i - 1] !== '--format',
  );
  const query = positional.join(' ').trim().toLowerCase();

  const filtered = ciphers.filter((c) => {
    if (typeFilter === 'login' && c.type !== CipherType.Login) return false;
    if (typeFilter === 'note' && c.type !== CipherType.SecureNote) return false;
    if (typeFilter === 'card' && c.type !== CipherType.Card) return false;
    if (typeFilter === 'ssh' && c.type !== CipherType.SshKey) return false;
    if (!query) return true;
    const hay = `${c.name} ${c.login?.username ?? ''} ${c.sshKey?.keyFingerprint ?? ''}`.toLowerCase();
    return hay.includes(query);
  });

  if (format === 'json') {
    console.log(JSON.stringify(filtered, null, 2));
    return;
  }
  if (format === 'yaml') {
    console.log(toYaml(filtered));
    return;
  }

  console.log(
    renderTable(filtered, [
      { header: 'ID', maxWidth: 10, value: (c) => c.id },
      { header: 'TYPE', value: (c) => cipherTypeLabel(c.type) },
      { header: 'NAME', maxWidth: 28, value: (c) => c.name },
      {
        header: 'USERNAME / DETAIL',
        maxWidth: 28,
        value: (c) =>
          c.login?.username ??
          c.sshKey?.keyFingerprint ??
          (c.card?.number ? `•••• ${c.card.number.slice(-4)}` : c.identity?.email ?? ''),
      },
      {
        header: 'URI / TOTP',
        maxWidth: 32,
        value: (c) =>
          c.login?.uris[0]?.uri ??
          (c.login?.totp ? '[totp]' : c.sshKey?.publicKey ?? ''),
      },
      { header: 'FAV', value: (c) => (c.favorite ? '*' : '') },
    ]),
  );
}

async function cmdGet(args: string[]): Promise<void> {
  const ciphers = await getUnlockedItems();
  const field = getFlag(args, '--field') ?? 'password';
  const asJson = hasFlag(args, '--json');
  const query = args
    .filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--field')
    .join(' ')
    .trim();
  if (!query) throw new Error('Usage: keylet item get <query> [--field <name>]');

  const item = findCipherByQuery(ciphers, query);
  if (asJson || field === 'all') {
    console.log(JSON.stringify(item, null, 2));
    return;
  }
  const value = await extractCipherField(item, field);
  process.stdout.write(value + (process.stdout.isTTY ? '\n' : ''));
}

async function cmdTotp(args: string[]): Promise<void> {
  const ciphers = await getUnlockedItems();
  const query = args.join(' ').trim();
  if (!query) throw new Error('Usage: keylet item totp <query>');
  const item = findCipherByQuery(ciphers, query);
  if (!item.login?.totp) {
    throw new Error(`Item "${item.name}" has no TOTP secret`);
  }
  const { code, remainingSeconds } = await generateTotp(item.login.totp);
  console.log(
    process.stdout.isTTY ? `${code} (${remainingSeconds}s remaining)` : code,
  );
}

async function cmdAdd(args: string[]): Promise<void> {
  if (!(await isDaemonRunning())) {
    throw new Error('Vault is locked. Run `keylet auth unlock` first.');
  }
  const name = getFlag(args, '--name') || (await promptLine('Item Name: '));
  const rawType = (getFlag(args, '--type') ?? 'login').toLowerCase();

  let cipher: CipherInput;
  if (rawType === 'ssh') {
    const sshKey =
      hasFlag(args, '--generate-ssh') || hasFlag(args, '--generate')
        ? await generateEd25519SshKeyPair(name)
        : {
            privateKey: getFlag(args, '--private-key') ?? '',
            publicKey: getFlag(args, '--public-key') ?? '',
            keyFingerprint: getFlag(args, '--fingerprint') ?? null,
          };
    cipher = {
      type: CipherType.SshKey,
      name,
      notes: getFlag(args, '--notes') ?? null,
      sshKey,
    };
  } else if (rawType === 'note') {
    cipher = {
      type: CipherType.SecureNote,
      name,
      notes: getFlag(args, '--notes') ?? (await promptLine('Notes: ')),
    };
  } else {
    const uri = getFlag(args, '--uri');
    cipher = {
      type: CipherType.Login,
      name,
      notes: getFlag(args, '--notes') ?? null,
      login: {
        username: getFlag(args, '--username') ?? null,
        password: getFlag(args, '--password') ?? null,
        totp: getFlag(args, '--totp') ?? null,
        uris: uri ? [{ uri, match: null }] : [],
      },
    };
  }

  const res = await ipcRequest<{ cipherCount: number }>('POST', '/ciphers/create', {
    cipher,
  });
  console.log(`Added "${name}". Total items: ${res.cipherCount}.`);
}

async function cmdRm(args: string[]): Promise<void> {
  const ciphers = await getUnlockedItems();
  const permanent = hasFlag(args, '--permanent');
  const query = args.filter((a) => !a.startsWith('--')).join(' ').trim();
  if (!query) throw new Error('Usage: keylet item rm <query> [--permanent]');
  const item = findCipherByQuery(ciphers, query);
  const res = await ipcRequest<{ cipherCount: number }>('POST', '/ciphers/delete', {
    cipherId: item.id,
    permanent,
  });
  console.log(`Deleted "${item.name}". Total items: ${res.cipherCount}.`);
}

// --- Folder commands ---
async function cmdFolder(args: string[]): Promise<void> {
  if (wantsHelp(args)) {
    printGroupHelp('folder');
    return;
  }
  if (!(await isDaemonRunning())) {
    throw new Error('Vault is locked. Run `keylet auth unlock` first.');
  }
  const sub = args[0] ?? 'list';
  if (sub === 'list') {
    const rest = args.slice(1);
    const format = resolveOutputFormat(rest, 'table');
    const res = await ipcRequest<{ folders: DecryptedFolder[] }>('GET', '/items');
    if (format === 'json') {
      console.log(JSON.stringify(res.folders, null, 2));
      return;
    }
    if (format === 'yaml') {
      console.log(toYaml(res.folders));
      return;
    }
    console.log(
      renderTable(res.folders, [
        { header: 'ID', value: (f) => f.id },
        { header: 'NAME', value: (f) => f.name },
      ]),
    );
    return;
  }
  if (sub === 'add') {
    const name = args.slice(1).join(' ').trim();
    if (!name) throw new Error('Usage: keylet folder add <name>');
    const res = await ipcRequest<{ folders: DecryptedFolder[] }>(
      'POST',
      '/folders/create',
      { name },
    );
    console.log(`Created folder "${name}". Total folders: ${res.folders.length}.`);
    return;
  }
  if (sub === 'rm') {
    const query = args.slice(1).join(' ').trim();
    if (!query) throw new Error('Usage: keylet folder rm <nameOrId>');
    const items = await ipcRequest<{ folders: DecryptedFolder[] }>('GET', '/items');
    const folder = items.folders.find(
      (f) => f.id === query || f.name.toLowerCase() === query.toLowerCase(),
    );
    if (!folder) throw new Error(`Folder not found: ${query}`);
    await ipcRequest('POST', '/folders/delete', { folderId: folder.id });
    console.log(`Deleted folder "${folder.name}".`);
    return;
  }
  throw new Error(`Unknown folder subcommand: ${sub}`);
}

// --- SSH commands ---
async function cmdSshAgent(): Promise<void> {
  if (!(await isDaemonRunning())) {
    throw new Error('Vault is locked. Run `keylet auth unlock` first.');
  }
  const res = await ipcRequest<{ socketPath: string; keyCount: number }>(
    'POST',
    '/ssh-agent/start',
  );
  console.log(`SSH_AUTH_SOCK=${res.socketPath}; export SSH_AUTH_SOCK;`);
  console.error(`# Keylet SSH agent active with ${res.keyCount} key(s).`);
}

async function handleAuthGroup(args: string[]): Promise<void> {
  const [sub, ...rest] = args;
  if (!sub || wantsHelp([sub])) {
    printGroupHelp('auth');
    return;
  }
  switch (sub) {
    case 'login':
      await cmdLogin(rest);
      break;
    case 'unlock':
      await cmdUnlock(rest);
      break;
    case 'lock':
      await cmdLock();
      break;
    case 'logout':
      await cmdLogout();
      break;
    case 'status':
      await cmdStatus();
      break;
    default:
      throw new Error(`Unknown auth subcommand: ${sub}`);
  }
}

async function handleItemGroup(args: string[]): Promise<void> {
  const [sub, ...rest] = args;
  if (!sub || wantsHelp([sub])) {
    printGroupHelp('item');
    return;
  }
  switch (sub) {
    case 'list':
      await cmdList(rest);
      break;
    case 'get':
      await cmdGet(rest);
      break;
    case 'add':
      await cmdAdd(rest);
      break;
    case 'rm':
      await cmdRm(rest);
      break;
    case 'totp':
      await cmdTotp(rest);
      break;
    default:
      throw new Error(`Unknown item subcommand: ${sub}`);
  }
}

async function handleVaultGroup(args: string[]): Promise<void> {
  const [sub, ...rest] = args;
  if (!sub || wantsHelp([sub])) {
    printGroupHelp('vault');
    return;
  }
  switch (sub) {
    case 'sync':
      await cmdSync();
      break;
    case 'import':
      await cmdImport(rest);
      break;
    default:
      throw new Error(`Unknown vault subcommand: ${sub}`);
  }
}

async function handleSshGroup(args: string[]): Promise<void> {
  const [sub, ...rest] = args;
  if (!sub || wantsHelp([sub])) {
    printGroupHelp('ssh');
    return;
  }
  switch (sub) {
    case 'agent':
      await cmdSshAgent();
      break;
    case 'list':
      await cmdList(['--type', 'ssh', ...rest]);
      break;
    case 'add':
      await cmdAdd(['--type', 'ssh', ...rest]);
      break;
    default:
      throw new Error(`Unknown ssh subcommand: ${sub}`);
  }
}

function handleSkillsGroup(args: string[]): void {
  const [sub, ...rest] = args;
  if (!sub || wantsHelp([sub])) {
    printGroupHelp('skills');
    return;
  }
  const dir = getFlag(rest, '--dir');
  const global = hasFlag(rest, '--global');
  switch (sub) {
    case 'install': {
      const filePath = installSkill({ dir, global });
      console.log(`Installed Keylet skill to ${filePath}`);
      break;
    }
    case 'show':
      process.stdout.write(KEYLET_SKILL_MD);
      break;
    case 'path':
      console.log(resolveSkillTargetDir({ dir, global }));
      break;
    default:
      throw new Error(`Unknown skills subcommand: ${sub}`);
  }
}

// --- Standalone commands ---
function cmdGenerate(args: string[]): void {
  const lenRaw = getFlag(args, '--length');
  const length = lenRaw ? Number(lenRaw) : DEFAULT_PASSWORD_OPTIONS.length;
  const { password } = generatePassword({
    length,
    uppercase: !hasFlag(args, '--no-uppercase'),
    lowercase: !hasFlag(args, '--no-lowercase'),
    numbers: !hasFlag(args, '--no-numbers'),
    symbols: !hasFlag(args, '--no-symbols'),
    excludeAmbiguous: hasFlag(args, '--avoid-ambiguous'),
  });
  console.log(password);
}

async function cmdRun(args: string[]): Promise<void> {
  const sepIdx = args.indexOf('--');
  const flagArgs = sepIdx === -1 ? args : args.slice(0, sepIdx);
  const cmdArgs =
    sepIdx === -1
      ? args.filter(
          (a, i) =>
            !a.startsWith('--') &&
            args[i - 1] !== '--from' &&
            args[i - 1] !== '--env-file',
        )
      : args.slice(sepIdx + 1);

  if (cmdArgs.length === 0) {
    throw new Error('Usage: keylet run [--from <item>] [--env-file <file>] -- <command...>');
  }

  const ciphers = await getUnlockedItems();
  const env = await resolveRunEnvironment(ciphers, process.env, {
    fromItem: getFlag(flagArgs, '--from'),
    envFile: getFlag(flagArgs, '--env-file'),
  });

  const [cmd, ...rest] = cmdArgs;
  const child = spawn(cmd!, rest, { stdio: 'inherit', env });
  child.on('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code ?? 0);
  });
}

async function main(): Promise<void> {
  const [, , subcommand, ...rest] = process.argv;
  if (subcommand === '__daemon') {
    startDaemon();
    return;
  }

  switch (subcommand) {
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      printRootHelp();
      break;

    // Primary 2-level command groups
    case 'auth':
      await handleAuthGroup(rest);
      break;
    case 'item':
      await handleItemGroup(rest);
      break;
    case 'folder':
      await cmdFolder(rest);
      break;
    case 'vault':
      await handleVaultGroup(rest);
      break;
    case 'ssh':
      await handleSshGroup(rest);
      break;
    case 'skills':
      handleSkillsGroup(rest);
      break;

    // Standalone commands
    case 'generate':
      cmdGenerate(rest);
      break;
    case 'run':
      await cmdRun(rest);
      break;

    // Backwards-compatible aliases
    case 'login':
      await cmdLogin(rest);
      break;
    case 'unlock':
      await cmdUnlock(rest);
      break;
    case 'lock':
      await cmdLock();
      break;
    case 'logout':
      await cmdLogout();
      break;
    case 'status':
      await cmdStatus();
      break;
    case 'sync':
      await cmdSync();
      break;
    case 'import':
      await cmdImport(rest);
      break;
    case 'list':
      await cmdList(rest);
      break;
    case 'get':
      await cmdGet(rest);
      break;
    case 'totp':
      await cmdTotp(rest);
      break;
    case 'add':
      await cmdAdd(rest);
      break;
    case 'rm':
      await cmdRm(rest);
      break;
    case 'ssh-agent':
      await cmdSshAgent();
      break;

    default:
      console.error(`Unknown command: ${subcommand}`);
      printRootHelp();
      process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error('Error:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
