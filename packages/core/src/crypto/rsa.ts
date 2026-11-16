import { base64ToBytes, toBuffer } from './encoding.js';
import { decryptToBytes } from './cipher.js';
import { symmetricKeyFromBytes } from './kdf.js';
import { EncType, type SymmetricKey } from './types.js';

/**
 * Decrypt a Bitwarden RSA-OAEP EncString (`3.` = SHA-256, `4.` = SHA-1)
 * using a PKCS#8 private key (DER bytes).
 */
export async function rsaDecryptBytes(
  encStr: string,
  privateKeyPkcs8: Uint8Array,
): Promise<Uint8Array> {
  const dotIdx = encStr.indexOf('.');
  if (dotIdx === -1) {
    throw new Error('Invalid RSA EncString: missing encType prefix');
  }
  const encType = Number(encStr.slice(0, dotIdx));
  const payloadB64 = encStr.slice(dotIdx + 1).split('|')[0];
  if (!payloadB64) {
    throw new Error('Invalid RSA EncString: empty payload');
  }

  const hash =
    encType === EncType.Rsa2048_OaepSha256_B64
      ? 'SHA-256'
      : encType === EncType.Rsa2048_OaepSha1_B64
        ? 'SHA-1'
        : null;

  if (!hash) {
    throw new Error(`Unsupported RSA EncType: ${encType}`);
  }

  const key = await crypto.subtle.importKey(
    'pkcs8',
    toBuffer(privateKeyPkcs8),
    { name: 'RSA-OAEP', hash },
    false,
    ['decrypt'],
  );

  const plain = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    key,
    toBuffer(base64ToBytes(payloadB64)),
  );
  return new Uint8Array(plain);
}

/** Decrypt the user's encrypted PKCS#8 private key using their SymmetricKey. */
export async function decryptPrivateKey(
  encPrivateKey: string,
  userKey: SymmetricKey,
): Promise<Uint8Array> {
  return decryptToBytes(encPrivateKey, userKey);
}

/** Decrypt an Organization's 64-byte SymmetricKey using the user's RSA private key. */
export async function decryptOrganizationKey(
  encOrgKey: string,
  privateKeyPkcs8: Uint8Array,
): Promise<SymmetricKey> {
  const raw = await rsaDecryptBytes(encOrgKey, privateKeyPkcs8);
  return symmetricKeyFromBytes(raw);
}
