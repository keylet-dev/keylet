import { CipherType } from '../api/types.js';
import type { CipherInput } from './decrypt.js';

export type ImportFormat =
  | 'bitwarden-json'
  | 'bitwarden-csv'
  | 'chrome-csv'
  | '1password-csv'
  | '1password-json';

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
            loginFields?: Array<{
              designation?: string;
              value?: string;
            }>;
            sections?: Array<{
              fields?: Array<{
                title?: string;
                value?: {
                  totp?: string;
                  string?: string;
                  concealed?: string;
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

        const loginFields = item.details?.loginFields ?? [];
        const username =
          loginFields.find((f) => f.designation === 'username')?.value ?? null;
        const password =
          loginFields.find((f) => f.designation === 'password')?.value ?? null;

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

/** Auto-detect and parse Bitwarden JSON, Bitwarden CSV, or Chrome/Edge CSV. */
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
