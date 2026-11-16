import {
  CipherType,
  type DecryptedCipher,
  type DecryptedCollection,
  type DecryptedFolder,
  type DecryptedOrganization,
  type EncryptedCipher,
  type EncryptedFolder,
  type EncryptedSyncResponse,
} from '../api/types.js';
import type { CreateCipherPayload } from '../api/client.js';
import {
  decryptOrganizationKey,
  decryptPrivateKey,
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
    organizationId: cipher.organizationId ?? null,
    folderId: cipher.folderId ?? null,
    collectionIds: cipher.collectionIds ?? [],
    type: cipher.type,
    name: name ?? 'Untitled',
    notes,
    favorite: Boolean(cipher.favorite),
    deletedDate: cipher.deletedDate ?? null,
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
    const id = cipher.identity;
    const [
      title,
      firstName,
      middleName,
      lastName,
      company,
      ssn,
      passportNumber,
      licenseNumber,
      email,
      phone,
      username,
      address1,
      city,
      state,
      postalCode,
      country,
    ] = await Promise.all([
      decryptToString(id.title, key),
      decryptToString(id.firstName, key),
      decryptToString(id.middleName, key),
      decryptToString(id.lastName, key),
      decryptToString(id.company, key),
      decryptToString(id.ssn, key),
      decryptToString(id.passportNumber, key),
      decryptToString(id.licenseNumber, key),
      decryptToString(id.email, key),
      decryptToString(id.phone, key),
      decryptToString(id.username, key),
      decryptToString(id.address1, key),
      decryptToString(id.city, key),
      decryptToString(id.state, key),
      decryptToString(id.postalCode, key),
      decryptToString(id.country, key),
    ]);
    result.identity = {
      title,
      firstName,
      middleName,
      lastName,
      company,
      ssn,
      passportNumber,
      licenseNumber,
      email,
      phone,
      username,
      address1,
      city,
      state,
      postalCode,
      country,
    };
  } else if (cipher.type === CipherType.SshKey && cipher.sshKey) {
    const [privateKey, publicKey, keyFingerprint] = await Promise.all([
      decryptToString(cipher.sshKey.privateKey, key),
      decryptToString(cipher.sshKey.publicKey, key),
      decryptToString(cipher.sshKey.keyFingerprint, key),
    ]);
    result.sshKey = { privateKey, publicKey, keyFingerprint };
  }

  return result;
}

export async function decryptOrganizationKeys(
  sync: EncryptedSyncResponse,
  userKey: SymmetricKey,
): Promise<Map<string, SymmetricKey>> {
  const orgKeys = new Map<string, SymmetricKey>();
  const encPrivateKey = sync.profile.privateKey;
  const orgs = sync.profile.organizations ?? [];
  if (!encPrivateKey || orgs.length === 0) return orgKeys;

  try {
    const pkcs8 = await decryptPrivateKey(encPrivateKey, userKey);
    for (const org of orgs) {
      if (!org.key) continue;
      try {
        const orgKey = await decryptOrganizationKey(org.key, pkcs8);
        orgKeys.set(org.id, orgKey);
      } catch {
        // Skip orgs whose key cannot be decrypted
      }
    }
  } catch {
    // Private key decryption failed
  }
  return orgKeys;
}

export async function decryptSyncResponse(
  sync: EncryptedSyncResponse,
  key: SymmetricKey,
): Promise<{
  ciphers: DecryptedCipher[];
  folders: DecryptedFolder[];
  collections: DecryptedCollection[];
  organizations: DecryptedOrganization[];
}> {
  const orgKeys = await decryptOrganizationKeys(sync, key);

  const activeCiphers = (sync.ciphers ?? []).filter((c) => !c.deletedDate);
  const [ciphers, folders, collections] = await Promise.all([
    Promise.all(
      activeCiphers.map(async (c) => {
        const itemKey = c.organizationId ? orgKeys.get(c.organizationId) ?? key : key;
        return decryptCipher(c, itemKey);
      }),
    ),
    Promise.all((sync.folders ?? []).map((f) => decryptFolder(f, key))),
    Promise.all(
      (sync.collections ?? []).map(async (col) => {
        const colKey = orgKeys.get(col.organizationId) ?? key;
        return {
          id: col.id,
          organizationId: col.organizationId,
          name: (await decryptToString(col.name, colKey)) ?? 'Collection',
        };
      }),
    ),
  ]);

  const organizations: DecryptedOrganization[] = (sync.profile.organizations ?? []).map(
    (o) => ({ id: o.id, name: o.name }),
  );

  return { ciphers, folders, collections, organizations };
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
  identity?: {
    title?: string | null;
    firstName?: string | null;
    middleName?: string | null;
    lastName?: string | null;
    company?: string | null;
    email?: string | null;
    phone?: string | null;
    username?: string | null;
    address1?: string | null;
    city?: string | null;
    state?: string | null;
    postalCode?: string | null;
    country?: string | null;
  };
  sshKey?: {
    privateKey?: string | null;
    publicKey?: string | null;
    keyFingerprint?: string | null;
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
  } else if (input.type === CipherType.Identity) {
    const id = input.identity;
    const [
      title,
      firstName,
      middleName,
      lastName,
      company,
      email,
      phone,
      username,
      address1,
      city,
      state,
      postalCode,
      country,
    ] = await Promise.all([
      encryptOpt(id?.title, key),
      encryptOpt(id?.firstName, key),
      encryptOpt(id?.middleName, key),
      encryptOpt(id?.lastName, key),
      encryptOpt(id?.company, key),
      encryptOpt(id?.email, key),
      encryptOpt(id?.phone, key),
      encryptOpt(id?.username, key),
      encryptOpt(id?.address1, key),
      encryptOpt(id?.city, key),
      encryptOpt(id?.state, key),
      encryptOpt(id?.postalCode, key),
      encryptOpt(id?.country, key),
    ]);
    payload.identity = {
      title,
      firstName,
      middleName,
      lastName,
      company,
      email,
      phone,
      username,
      address1,
      city,
      state,
      postalCode,
      country,
    };
  } else if (input.type === CipherType.SshKey) {
    const [privateKey, publicKey, keyFingerprint] = await Promise.all([
      input.sshKey?.privateKey ? encryptString(input.sshKey.privateKey, key) : Promise.resolve(null),
      encryptOpt(input.sshKey?.publicKey, key),
      encryptOpt(input.sshKey?.keyFingerprint, key),
    ]);
    payload.sshKey = { privateKey, publicKey, keyFingerprint };
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
