import type {
  EncryptedCipher,
  EncryptedSyncResponse,
  PreloginResponse,
  TokenResponse,
  TwoFactorParams,
} from './types.js';

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export class TwoFactorRequiredError extends Error {
  constructor(public readonly providers: number[]) {
    super('Two-factor authentication required');
    this.name = 'TwoFactorRequiredError';
  }
}

/**
 * Validate and normalize a Bitwarden / Vaultwarden server URL.
 * Enforces https:// except for localhost / 127.0.0.1.
 */
export function normalizeServerUrl(raw: string): string {
  const trimmed = raw.trim().replace(/\/+$/, '');
  if (!trimmed) {
    throw new Error('Server URL is required');
  }

  const withScheme = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(trimmed)
    ? trimmed
    : trimmed.startsWith('localhost') || trimmed.startsWith('127.0.0.1')
      ? `http://${trimmed}`
      : `https://${trimmed}`;

  const url = new URL(withScheme);
  const isLocal =
    url.hostname === 'localhost' || url.hostname === '127.0.0.1';

  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLocal)) {
    throw new Error('Server URL must use https:// (except localhost)');
  }

  return url.origin + (url.pathname === '/' ? '' : url.pathname.replace(/\/+$/, ''));
}

async function parseErrorMessage(res: Response): Promise<string> {
  const text = await res.text().catch(() => '');
  try {
    const data = JSON.parse(text) as Record<string, unknown>;
    if (typeof data.error_description === 'string') return data.error_description;
    if (typeof data.message === 'string') return data.message;
    if (typeof data.Message === 'string') return data.Message;
    const errModel = data.ErrorModel as Record<string, unknown> | undefined;
    if (errModel && typeof errModel.Message === 'string') return errModel.Message;
  } catch {
    if (text && !text.trimStart().startsWith('<')) {
      return text.trim().slice(0, 200);
    }
  }
  return `Request failed with status ${res.status}`;
}

export async function prelogin(
  serverUrl: string,
  email: string,
): Promise<PreloginResponse> {
  const base = normalizeServerUrl(serverUrl);
  const res = await fetch(`${base}/identity/accounts/prelogin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ email: email.trim().toLowerCase() }),
  });

  if (!res.ok) {
    throw new ApiError(await parseErrorMessage(res), res.status);
  }

  const raw = (await res.json()) as Record<string, unknown>;
  return {
    kdf: Number(raw.kdf ?? raw.Kdf ?? 0),
    kdfIterations: Number(raw.kdfIterations ?? raw.KdfIterations ?? 600000),
    kdfMemory:
      (raw.kdfMemory ?? raw.KdfMemory) != null
        ? Number(raw.kdfMemory ?? raw.KdfMemory)
        : null,
    kdfParallelism:
      (raw.kdfParallelism ?? raw.KdfParallelism) != null
        ? Number(raw.kdfParallelism ?? raw.KdfParallelism)
        : null,
  };
}

export async function loginWithPassword(
  serverUrl: string,
  email: string,
  masterPasswordHash: string,
  deviceIdentifier: string,
  twoFactor?: TwoFactorParams,
): Promise<TokenResponse> {
  const base = normalizeServerUrl(serverUrl);
  const params = new URLSearchParams({
    grant_type: 'password',
    username: email.trim().toLowerCase(),
    password: masterPasswordHash,
    scope: 'api offline_access',
    client_id: 'browser',
    deviceType: '9', // ChromeExtension
    deviceIdentifier,
    deviceName: 'Keylet',
  });

  if (twoFactor) {
    params.set('twoFactorProvider', String(twoFactor.provider));
    params.set('twoFactorToken', twoFactor.token.trim());
    params.set('twoFactorRemember', twoFactor.remember ? '1' : '0');
  }

  const res = await fetch(`${base}/identity/connect/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: params.toString(),
  });

  if (!res.ok) {
    let body: Record<string, unknown> | null = null;
    try {
      body = (await res.json()) as Record<string, unknown>;
    } catch {
      // ignore
    }

    if (body && Array.isArray(body.TwoFactorProviders)) {
      throw new TwoFactorRequiredError(
        body.TwoFactorProviders.map((p) => Number(p)),
      );
    }
    if (body && body.TwoFactorProviders2 && typeof body.TwoFactorProviders2 === 'object') {
      const providers = Object.keys(body.TwoFactorProviders2).map((k) => Number(k));
      throw new TwoFactorRequiredError(providers);
    }

    const msg =
      (body && typeof body.error_description === 'string' && body.error_description) ||
      (body && typeof body.message === 'string' && body.message) ||
      `Login failed (${res.status})`;
    throw new ApiError(msg, res.status);
  }

  return (await res.json()) as TokenResponse;
}

export async function refreshAccessToken(
  serverUrl: string,
  refreshToken: string,
): Promise<TokenResponse> {
  const base = normalizeServerUrl(serverUrl);
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: 'browser',
  });

  const res = await fetch(`${base}/identity/connect/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: params.toString(),
  });

  if (!res.ok) {
    throw new ApiError(await parseErrorMessage(res), res.status);
  }

  return (await res.json()) as TokenResponse;
}

export async function syncVault(
  serverUrl: string,
  accessToken: string,
): Promise<EncryptedSyncResponse> {
  const base = normalizeServerUrl(serverUrl);
  const res = await fetch(`${base}/api/sync?excludeDomains=true`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!res.ok) {
    throw new ApiError(await parseErrorMessage(res), res.status);
  }

  return (await res.json()) as EncryptedSyncResponse;
}

export interface CreateCipherPayload {
  type: number;
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
  secureNote?: {
    type: number;
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

export async function createCipher(
  serverUrl: string,
  accessToken: string,
  payload: CreateCipherPayload,
): Promise<EncryptedCipher> {
  const base = normalizeServerUrl(serverUrl);
  const res = await fetch(`${base}/api/ciphers`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    throw new ApiError(await parseErrorMessage(res), res.status);
  }

  return (await res.json()) as EncryptedCipher;
}

export async function updateCipher(
  serverUrl: string,
  accessToken: string,
  cipherId: string,
  payload: CreateCipherPayload,
): Promise<EncryptedCipher> {
  const base = normalizeServerUrl(serverUrl);
  const res = await fetch(`${base}/api/ciphers/${encodeURIComponent(cipherId)}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    throw new ApiError(await parseErrorMessage(res), res.status);
  }

  return (await res.json()) as EncryptedCipher;
}

export async function deleteCipher(
  serverUrl: string,
  accessToken: string,
  cipherId: string,
): Promise<void> {
  const base = normalizeServerUrl(serverUrl);
  const res = await fetch(`${base}/api/ciphers/${encodeURIComponent(cipherId)}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!res.ok) {
    throw new ApiError(await parseErrorMessage(res), res.status);
  }
}
