import fs from 'node:fs';
import {
  CipherType,
  type DecryptedCipher,
  generateTotp,
} from '@keylet/core';

const KEYLET_REF_RE = /^keylet:\/\/([^/]+)\/(.+)$/;

export function findCipherByQuery(
  ciphers: DecryptedCipher[],
  query: string,
): DecryptedCipher {
  const q = query.trim().toLowerCase();
  const exactId = ciphers.find((c) => c.id.toLowerCase() === q);
  if (exactId) return exactId;

  const exactName = ciphers.filter((c) => c.name.toLowerCase() === q);
  if (exactName.length === 1) return exactName[0]!;
  if (exactName.length > 1) {
    throw new Error(
      `Multiple items match "${query}". Specify by ID: ${exactName.map((c) => c.id).join(', ')}`,
    );
  }

  const partial = ciphers.filter((c) => c.name.toLowerCase().includes(q));
  if (partial.length === 1) return partial[0]!;
  if (partial.length > 1) {
    throw new Error(
      `Ambiguous query "${query}" matched ${partial.length} items: ${partial.map((c) => c.name).join(', ')}`,
    );
  }
  throw new Error(`No vault item found matching "${query}"`);
}

export async function extractCipherField(
  cipher: DecryptedCipher,
  field: string,
): Promise<string> {
  const f = field.trim().toLowerCase();
  if (f === 'username' && cipher.login?.username) return cipher.login.username;
  if (f === 'password' && cipher.login?.password) return cipher.login.password;
  if (f === 'totp' && cipher.login?.totp) {
    const res = await generateTotp(cipher.login.totp);
    return res.code;
  }
  if (f === 'notes' && cipher.notes) return cipher.notes;
  if (f === 'uri' && cipher.login?.uris[0]?.uri) return cipher.login.uris[0].uri;
  if (f === 'number' && cipher.card?.number) return cipher.card.number;
  if (f === 'cvv' && cipher.card?.code) return cipher.card.code;
  if ((f === 'publickey' || f === 'public') && cipher.sshKey?.publicKey) return cipher.sshKey.publicKey;
  if ((f === 'privatekey' || f === 'private') && cipher.sshKey?.privateKey) return cipher.sshKey.privateKey;
  if (f === 'fingerprint' && cipher.sshKey?.keyFingerprint) return cipher.sshKey.keyFingerprint;

  const custom = cipher.fields.find((cf) => cf.name.toLowerCase() === f);
  if (custom) return custom.value;

  throw new Error(`Field "${field}" not found on item "${cipher.name}"`);
}

export function parseEnvFile(filePath: string): Record<string, string> {
  const content = fs.readFileSync(filePath, 'utf8');
  const out: Record<string, string> = {};
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    out[key] = val;
  }
  return out;
}

/**
 * Resolve `keylet://<item>/<field>` references and `--from <item>` injections
 * into a clean env map without writing any secrets to disk.
 */
export async function resolveRunEnvironment(
  ciphers: DecryptedCipher[],
  baseEnv: Record<string, string | undefined>,
  options: { fromItem?: string; envFile?: string },
): Promise<Record<string, string>> {
  const merged: Record<string, string> = {};
  for (const [k, v] of Object.entries(baseEnv)) {
    if (v !== undefined) merged[k] = v;
  }

  if (options.envFile) {
    Object.assign(merged, parseEnvFile(options.envFile));
  }

  if (options.fromItem) {
    const item = findCipherByQuery(ciphers, options.fromItem);
    if (item.type === CipherType.Login && item.login) {
      if (item.login.username) merged.KEYLET_USERNAME = item.login.username;
      if (item.login.password) merged.KEYLET_PASSWORD = item.login.password;
      if (item.login.totp) {
        merged.KEYLET_TOTP = (await generateTotp(item.login.totp)).code;
      }
    }
    for (const cf of item.fields) {
      if (cf.name) merged[cf.name] = cf.value;
    }
    if (item.type === CipherType.SecureNote && item.notes) {
      for (const line of item.notes.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eq = trimmed.indexOf('=');
        if (eq > 0) {
          const k = trimmed.slice(0, eq).trim();
          const v = trimmed.slice(eq + 1).trim();
          if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) {
            merged[k] = v;
          }
        }
      }
    }
  }

  // Resolve all keylet://item/field references
  for (const [k, v] of Object.entries(merged)) {
    const match = KEYLET_REF_RE.exec(v);
    if (!match) continue;
    const [, itemQuery, fieldName] = match;
    if (!itemQuery || !fieldName) continue;
    const item = findCipherByQuery(ciphers, itemQuery);
    merged[k] = await extractCipherField(item, fieldName);
  }

  return merged;
}
