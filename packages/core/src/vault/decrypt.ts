import {
  CipherType,
  type DecryptedCipher,
  type DecryptedFolder,
  type EncryptedCipher,
  type EncryptedFolder,
  type EncryptedSyncResponse,
} from '../api/types.js';
import type { CreateCipherPayload } from '../api/client.js';
import {
  decryptToString,
  encryptString,
  type SymmetricKey,
} from '../crypto/index.js';

export async function decryptFolder(
  folder: EncryptedFolder,
  key: SymmetricKey,
): Promise<DecryptedFolder> {
  return {
    id: folder.id,
    name: (await decryptToString(folder.name, key)) ?? 'Untitled Folder',
  };
}

export async function decryptCipher(
  cipher: EncryptedCipher,
  key: SymmetricKey,
): Promise<DecryptedCipher> {
  const [name, notes] = await Promise.all([
    decryptToString(cipher.name, key),
    decryptToString(cipher.notes, key),
  ]);

  const fields = cipher.fields
    ? await Promise.all(
        cipher.fields.map(async (f) => ({
          name: (await decryptToString(f.name, key)) ?? '',
          value: (await decryptToString(f.value, key)) ?? '',
          type: f.type,
        })),
      )
    : [];

  const result: DecryptedCipher = {
    id: cipher.id,
    folderId: cipher.folderId ?? null,
    type: cipher.type,
    name: name ?? 'Untitled',
    notes,
    favorite: Boolean(cipher.favorite),
    revisionDate: cipher.revisionDate,
    fields,
  };

  if (cipher.type === CipherType.Login && cipher.login) {
    const [username, password, totp, uris] = await Promise.all([
      decryptToString(cipher.login.username, key),
      decryptToString(cipher.login.password, key),
      decryptToString(cipher.login.totp, key),
      cipher.login.uris
        ? Promise.all(
            cipher.login.uris.map(async (u) => ({
              uri: (await decryptToString(u.uri, key)) ?? '',
              match: u.match ?? null,
            })),
          )
        : Promise.resolve([]),
    ]);

    result.login = {
      username,
      password,
      totp,
      uris: uris.filter((u) => u.uri.length > 0),
    };
  } else if (cipher.type === CipherType.Card && cipher.card) {
    const [cardholderName, brand, number, expMonth, expYear, code] =
      await Promise.all([
        decryptToString(cipher.card.cardholderName, key),
        decryptToString(cipher.card.brand, key),
        decryptToString(cipher.card.number, key),
        decryptToString(cipher.card.expMonth, key),
        decryptToString(cipher.card.expYear, key),
        decryptToString(cipher.card.code, key),
      ]);
    result.card = { cardholderName, brand, number, expMonth, expYear, code };
  } else if (cipher.type === CipherType.Identity && cipher.identity) {
    const [firstName, lastName, email, phone, username] = await Promise.all([
      decryptToString(cipher.identity.firstName, key),
      decryptToString(cipher.identity.lastName, key),
      decryptToString(cipher.identity.email, key),
      decryptToString(cipher.identity.phone, key),
      decryptToString(cipher.identity.username, key),
    ]);
    result.identity = { firstName, lastName, email, phone, username };
  }

  return result;
}

export async function decryptSyncResponse(
  sync: EncryptedSyncResponse,
  key: SymmetricKey,
): Promise<{ ciphers: DecryptedCipher[]; folders: DecryptedFolder[] }> {
  const activeCiphers = (sync.ciphers ?? []).filter((c) => !c.deletedDate);
  const [ciphers, folders] = await Promise.all([
    Promise.all(activeCiphers.map((c) => decryptCipher(c, key))),
    Promise.all((sync.folders ?? []).map((f) => decryptFolder(f, key))),
  ]);
  return { ciphers, folders };
}

export interface CipherInput {
  type: CipherType;
  name: string;
  notes?: string | null;
  favorite?: boolean;
  folderId?: string | null;
  login?: {
    username?: string | null;
    password?: string | null;
    totp?: string | null;
    uris?: { uri: string; match?: number | null }[];
  };
  card?: {
    cardholderName?: string | null;
    brand?: string | null;
    number?: string | null;
    expMonth?: string | null;
    expYear?: string | null;
    code?: string | null;
  };
}

async function encryptOpt(
  value: string | null | undefined,
  key: SymmetricKey,
): Promise<string | null> {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  return encryptString(trimmed, key);
}

export async function encryptCipherPayload(
  input: CipherInput,
  key: SymmetricKey,
): Promise<CreateCipherPayload> {
  const [encName, encNotes] = await Promise.all([
    encryptString(input.name.trim() || 'Untitled', key),
    encryptOpt(input.notes, key),
  ]);

  const payload: CreateCipherPayload = {
    type: input.type,
    name: encName,
    notes: encNotes,
    favorite: Boolean(input.favorite),
    folderId: input.folderId ?? null,
  };

  if (input.type === CipherType.Login) {
    const [encUser, encPass, encTotp, uris] = await Promise.all([
      encryptOpt(input.login?.username, key),
      input.login?.password ? encryptString(input.login.password, key) : Promise.resolve(null),
      encryptOpt(input.login?.totp, key),
      Promise.all(
        (input.login?.uris ?? [])
          .filter((u) => u.uri.trim().length > 0)
          .map(async (u) => ({
            uri: await encryptString(u.uri.trim(), key),
            match: u.match ?? null,
          })),
      ),
    ]);
    payload.login = {
      username: encUser,
      password: encPass,
      totp: encTotp,
      uris,
    };
  } else if (input.type === CipherType.SecureNote) {
    payload.secureNote = { type: 0 };
  } else if (input.type === CipherType.Card) {
    const [cardholderName, brand, number, expMonth, expYear, code] =
      await Promise.all([
        encryptOpt(input.card?.cardholderName, key),
        encryptOpt(input.card?.brand, key),
        encryptOpt(input.card?.number, key),
        encryptOpt(input.card?.expMonth, key),
        encryptOpt(input.card?.expYear, key),
        encryptOpt(input.card?.code, key),
      ]);
    payload.card = { cardholderName, brand, number, expMonth, expYear, code };
  }

  return payload;
}

export async function encryptNewLoginCipher(
  input: {
    name: string;
    username: string;
    password: string;
    uri: string;
  },
  key: SymmetricKey,
): Promise<CreateCipherPayload> {
  return encryptCipherPayload(
    {
      type: CipherType.Login,
      name: input.name,
      login: {
        username: input.username,
        password: input.password,
        uris: input.uri ? [{ uri: input.uri, match: null }] : [],
      },
    },
    key,
  );
}
