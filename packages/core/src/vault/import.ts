import { CipherType } from '../api/types.js';
import { bytesToUtf8 } from '../crypto/encoding.js';
import type { CipherInput } from './decrypt.js';

export type ImportFormat =
  | 'bitwarden-json'
  | 'bitwarden-csv'
  | 'chrome-csv'
  | '1password-csv'
  | '1password-json'
  | '1password-1pux';

export interface ImportParseResult {
  format: ImportFormat;
  items: CipherInput[];
  skipped: number;
}

/** RFC 4180 CSV parser supporting quoted multiline values and escaped quotes. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;

  const normalized = text.replace(/^\uFEFF/, '');
  for (let i = 0; i < normalized.length; i++) {
    const ch = normalized.charAt(i);
    if (inQuotes) {
      if (ch === '"') {
        if (normalized.charAt(i + 1) === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\r' || ch === '\n') {
      if (ch === '\r' && normalized.charAt(i + 1) === '\n') {
        i++;
      }
      row.push(field);
      if (row.some((cell) => cell.length > 0)) {
        rows.push(row);
      }
      row = [];
      field = '';
    } else {
      field += ch;
    }
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field);
    if (row.some((cell) => cell.length > 0)) {
      rows.push(row);
    }
  }
  return rows;
}

function parse1PasswordJson(raw: string): ImportParseResult {
  const parsed = JSON.parse(raw) as {
    accounts?: Array<{
      vaults?: Array<{
        items?: Array<{
          categoryUuid?: string;
          favIndex?: number;
          overview?: {
            title?: string;
            url?: string;
            urls?: Array<{ url?: string }>;
          };
          details?: {
            notesPlain?: string;
            password?: string;
            loginFields?: Array<{
              designation?: string;
              value?: string;
            }>;
            sections?: Array<{
              fields?: Array<{
                title?: string;
                id?: string;
                value?: {
                  totp?: string;
                  string?: string;
                  concealed?: string;
                  creditCardNumber?: string;
                  sshKey?: {
                    privateKey?: string;
                    publicKey?: string;
                    metadata?: {
                      privateKey?: string;
                      publicKey?: string;
                      fingerprint?: string;
                    };
                  };
                };
              }>;
            }>;
          };
        }>;
      }>;
    }>;
  };

  const items: CipherInput[] = [];
  let skipped = 0;

  for (const acc of parsed.accounts ?? []) {
    for (const vault of acc.vaults ?? []) {
      for (const item of vault.items ?? []) {
        const name = item.overview?.title?.trim();
        if (!name) {
          skipped++;
          continue;
        }
        const notes = item.details?.notesPlain || null;
        const favorite = (item.favIndex ?? 0) > 0;

        // 003 = Secure Note in 1PUX
        if (item.categoryUuid === '003') {
          items.push({
            type: CipherType.SecureNote,
            name,
            notes,
            favorite,
          });
          continue;
        }

        // 114 = SSH Key in 1PUX
        if (item.categoryUuid === '114') {
          let priv: string | null = null;
          let pub: string | null = null;
          let fp: string | null = null;
          for (const sec of item.details?.sections ?? []) {
            for (const f of sec.fields ?? []) {
              if (f.value?.sshKey) {
                priv =
                  f.value.sshKey.privateKey ??
                  f.value.sshKey.metadata?.privateKey ??
                  priv;
                pub =
                  f.value.sshKey.publicKey ??
                  f.value.sshKey.metadata?.publicKey ??
                  pub;
                fp = f.value.sshKey.metadata?.fingerprint ?? fp;
              } else if (f.id === 'private_key') {
                priv = f.value?.concealed ?? f.value?.string ?? priv;
              } else if (f.id === 'public_key') {
                pub = f.value?.string ?? pub;
              }
            }
          }
          if (priv || pub) {
            items.push({
              type: CipherType.SshKey,
              name,
              notes,
              favorite,
              sshKey: { privateKey: priv, publicKey: pub, keyFingerprint: fp },
            });
            continue;
          }
        }

        const loginFields = item.details?.loginFields ?? [];
        const username =
          loginFields.find((f) => f.designation === 'username')?.value ?? null;
        const password =
          loginFields.find((f) => f.designation === 'password')?.value ??
          item.details?.password ??
          null;

        let totp: string | null = null;
        for (const sec of item.details?.sections ?? []) {
          for (const f of sec.fields ?? []) {
            if (f.value?.totp) {
              totp = f.value.totp;
              break;
            }
          }
          if (totp) break;
        }

        const uris = [
          ...(item.overview?.url ? [{ url: item.overview.url }] : []),
          ...(item.overview?.urls ?? []),
        ]
          .map((u) => u.url?.trim() ?? '')
          .filter((u) => u.length > 0)
          .filter((u, idx, arr) => arr.indexOf(u) === idx)
          .map((u) => ({ uri: u, match: null }));

        items.push({
          type: CipherType.Login,
          name,
          notes,
          favorite,
          login: { username, password, totp, uris },
        });
      }
    }
  }

  return { format: '1password-json', items, skipped };
}

function parseBitwardenJson(raw: string): ImportParseResult {
  const parsed = JSON.parse(raw) as {
    accounts?: unknown[];
    items?: Array<{
      type?: number;
      name?: string;
      notes?: string | null;
      favorite?: boolean;
      login?: {
        username?: string | null;
        password?: string | null;
        totp?: string | null;
        uris?: Array<{ uri?: string | null; match?: number | null }>;
      };
      card?: {
        cardholderName?: string | null;
        brand?: string | null;
        number?: string | null;
        expMonth?: string | null;
        expYear?: string | null;
        code?: string | null;
      };
    }>;
  };

  if (Array.isArray(parsed.accounts)) {
    return parse1PasswordJson(raw);
  }

  if (!Array.isArray(parsed.items)) {
    throw new Error('Invalid JSON export: missing Bitwarden items or 1Password accounts');
  }

  const items: CipherInput[] = [];
  let skipped = 0;

  for (const item of parsed.items) {
    const name = item.name?.trim();
    if (!name) {
      skipped++;
      continue;
    }
    const type =
      item.type === CipherType.SecureNote
        ? CipherType.SecureNote
        : item.type === CipherType.Card
          ? CipherType.Card
          : item.type === CipherType.Login
            ? CipherType.Login
            : null;

    if (type === null) {
      skipped++;
      continue;
    }

    const input: CipherInput = {
      type,
      name,
      notes: item.notes ?? null,
      favorite: Boolean(item.favorite),
    };

    if (type === CipherType.Login) {
      input.login = {
        username: item.login?.username ?? null,
        password: item.login?.password ?? null,
        totp: item.login?.totp ?? null,
        uris: (item.login?.uris ?? [])
          .filter((u): u is { uri: string; match?: number | null } => Boolean(u.uri?.trim()))
          .map((u) => ({ uri: u.uri.trim(), match: u.match ?? null })),
      };
    } else if (type === CipherType.Card && item.card) {
      input.card = {
        cardholderName: item.card.cardholderName ?? null,
        brand: item.card.brand ?? null,
        number: item.card.number ?? null,
        expMonth: item.card.expMonth ?? null,
        expYear: item.card.expYear ?? null,
        code: item.card.code ?? null,
      };
    }

    items.push(input);
  }

  return { format: 'bitwarden-json', items, skipped };
}

function parseCsvRows(rows: string[][]): ImportParseResult {
  if (rows.length < 2) {
    throw new Error('CSV file has no data rows');
  }
  const headers = rows[0]!.map((h) => h.trim().toLowerCase());
  const col = (name: string) => headers.indexOf(name);

  // Bitwarden CSV format
  if (headers.includes('login_username') || headers.includes('login_password')) {
    const idxType = col('type');
    const idxName = col('name');
    const idxNotes = col('notes');
    const idxFav = col('favorite');
    const idxUri = col('login_uri');
    const idxUser = col('login_username');
    const idxPass = col('login_password');
    const idxTotp = col('login_totp');

    const items: CipherInput[] = [];
    let skipped = 0;

    for (const r of rows.slice(1)) {
      const name = (idxName >= 0 ? r[idxName] : '')?.trim();
      if (!name) {
        skipped++;
        continue;
      }
      const rawType = (idxType >= 0 ? r[idxType] : 'login')?.trim().toLowerCase();
      if (rawType === 'note' || rawType === 'securenote') {
        items.push({
          type: CipherType.SecureNote,
          name,
          notes: idxNotes >= 0 ? r[idxNotes] || null : null,
          favorite: idxFav >= 0 && r[idxFav] === '1',
        });
      } else {
        const uriStr = idxUri >= 0 ? r[idxUri]?.trim() : '';
        items.push({
          type: CipherType.Login,
          name,
          notes: idxNotes >= 0 ? r[idxNotes] || null : null,
          favorite: idxFav >= 0 && r[idxFav] === '1',
          login: {
            username: idxUser >= 0 ? r[idxUser] || null : null,
            password: idxPass >= 0 ? r[idxPass] || null : null,
            totp: idxTotp >= 0 ? r[idxTotp] || null : null,
            uris: uriStr ? [{ uri: uriStr, match: null }] : [],
          },
        });
      }
    }
    return { format: 'bitwarden-csv', items, skipped };
  }

  // 1Password CSV format: Title,Url/Website,Username,Password,OTPAuth,Favorite,...,Notes,Type
  if (headers.includes('title') && (headers.includes('otpauth') || headers.includes('website') || headers.includes('archived'))) {
    const idxTitle = col('title');
    const idxUrl = col('url') !== -1 ? col('url') : col('website');
    const idxUser = col('username');
    const idxPass = col('password');
    const idxOtp = col('otpauth');
    const idxFav = col('favorite');
    const idxNotes = col('notes');
    const idxType = col('type');

    const items: CipherInput[] = [];
    let skipped = 0;

    for (const r of rows.slice(1)) {
      const name = (idxTitle >= 0 ? r[idxTitle] : '')?.trim();
      if (!name) {
        skipped++;
        continue;
      }
      const rawType = (idxType >= 0 ? r[idxType] : 'Login')?.trim().toLowerCase();
      const favVal = (idxFav >= 0 ? r[idxFav] : '')?.trim().toLowerCase();
      const favorite = favVal === 'true' || favVal === '1';
      const notes = idxNotes >= 0 ? r[idxNotes] || null : null;

      if (rawType === 'secure note' || rawType === 'note') {
        items.push({ type: CipherType.SecureNote, name, notes, favorite });
      } else {
        const uriStr = idxUrl >= 0 ? r[idxUrl]?.trim() : '';
        items.push({
          type: CipherType.Login,
          name,
          notes,
          favorite,
          login: {
            username: idxUser >= 0 ? r[idxUser] || null : null,
            password: idxPass >= 0 ? r[idxPass] || null : null,
            totp: idxOtp >= 0 ? r[idxOtp] || null : null,
            uris: uriStr ? [{ uri: uriStr, match: null }] : [],
          },
        });
      }
    }
    return { format: '1password-csv', items, skipped };
  }

  // Chrome / Edge / Brave Passwords CSV format: name,url,username,password[,note]
  const idxName = col('name');
  const idxUrl = col('url');
  const idxUser = col('username');
  const idxPass = col('password');
  const idxNote = col('note');

  if (idxUrl === -1 && idxPass === -1) {
    throw new Error('Unrecognized CSV header format');
  }

  const items: CipherInput[] = [];
  let skipped = 0;

  for (const r of rows.slice(1)) {
    const url = (idxUrl >= 0 ? r[idxUrl] : '')?.trim() ?? '';
    const rawName = (idxName >= 0 ? r[idxName] : '')?.trim() ?? '';
    const name = rawName || url;
    if (!name) {
      skipped++;
      continue;
    }
    items.push({
      type: CipherType.Login,
      name,
      notes: idxNote >= 0 ? r[idxNote] || null : null,
      favorite: false,
      login: {
        username: idxUser >= 0 ? r[idxUser] || null : null,
        password: idxPass >= 0 ? r[idxPass] || null : null,
        uris: url ? [{ uri: url, match: null }] : [],
      },
    });
  }

  return { format: 'chrome-csv', items, skipped };
}

/** Auto-detect and parse Bitwarden JSON, Bitwarden CSV, 1Password CSV/JSON, or Chrome/Edge CSV. */
export function parseImportFile(content: string): ImportParseResult {
  const trimmed = content.trim();
  if (!trimmed) {
    throw new Error('Import file is empty');
  }
  if (trimmed.startsWith('{')) {
    return parseBitwardenJson(trimmed);
  }
  return parseCsvRows(parseCsv(trimmed));
}

async function inflateDeflateRaw(compressed: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(compressed.length);
  copy.set(compressed);
  const stream = new Blob([copy.buffer])
    .stream()
    .pipeThrough(new DecompressionStream('deflate-raw'));
  const ab = await new Response(stream).arrayBuffer();
  return new Uint8Array(ab);
}

/** Minimal dependency-free ZIP extractor using Central Directory + Web DecompressionStream. */
export async function extractFileFromZip(
  zip: Uint8Array,
  targetName: string,
): Promise<Uint8Array> {
  const view = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  // Find End of Central Directory (0x06054b50) scanning backwards from end
  let eocdOffset = -1;
  const minOffset = Math.max(0, zip.length - 65557);
  for (let i = zip.length - 22; i >= minOffset; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset === -1) {
    throw new Error('Invalid ZIP archive: EOCD not found');
  }

  const totalEntries = view.getUint16(eocdOffset + 10, true);
  let cdOffset = view.getUint32(eocdOffset + 16, true);

  for (let i = 0; i < totalEntries; i++) {
    if (view.getUint32(cdOffset, true) !== 0x02014b50) {
      throw new Error('Invalid ZIP central directory entry');
    }
    const method = view.getUint16(cdOffset + 10, true);
    const compSize = view.getUint32(cdOffset + 20, true);
    const nameLen = view.getUint16(cdOffset + 28, true);
    const extraLen = view.getUint16(cdOffset + 30, true);
    const commentLen = view.getUint16(cdOffset + 32, true);
    const localHeaderOffset = view.getUint32(cdOffset + 42, true);

    const fileName = bytesToUtf8(
      zip.subarray(cdOffset + 46, cdOffset + 46 + nameLen),
    );
    cdOffset += 46 + nameLen + extraLen + commentLen;

    if (fileName !== targetName) continue;

    if (view.getUint32(localHeaderOffset, true) !== 0x04034b50) {
      throw new Error('Invalid ZIP local file header');
    }
    const localNameLen = view.getUint16(localHeaderOffset + 26, true);
    const localExtraLen = view.getUint16(localHeaderOffset + 28, true);
    const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen;
    const compressed = zip.subarray(dataStart, dataStart + compSize);

    if (method === 0) return compressed.slice();
    if (method === 8) return inflateDeflateRaw(compressed);
    throw new Error(`Unsupported ZIP compression method: ${method}`);
  }

  throw new Error(`"${targetName}" not found inside .1pux archive`);
}

/**
 * Parse raw import file bytes (supports binary `.1pux` ZIP archives as well as
 * UTF-8 JSON and CSV exports).
 */
export async function parseImportBytes(
  bytes: Uint8Array,
): Promise<ImportParseResult> {
  if (
    bytes.length >= 4 &&
    bytes[0] === 0x50 &&
    bytes[1] === 0x4b &&
    bytes[2] === 0x03 &&
    bytes[3] === 0x04
  ) {
    const exportDataBytes = await extractFileFromZip(bytes, 'export.data');
    const res = parse1PasswordJson(bytesToUtf8(exportDataBytes));
    return { ...res, format: '1password-1pux' };
  }
  return parseImportFile(bytesToUtf8(bytes));
}
