import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToBase64, concatBytes, utf8ToBytes } from './encoding.js';

export interface SshKeyPairResult {
  privateKey: string;
  publicKey: string;
  keyFingerprint: string;
}

function sshString(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

function wrapBase64(b64: string, width = 70): string {
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += width) {
    lines.push(b64.slice(i, i + width));
  }
  return lines.join('\n');
}

/**
 * Generate an Ed25519 SSH keypair in standard OpenSSH PEM + authorized_keys format
 * using Web Crypto (supported in Node 20+ and Chromium 113+).
 */
export async function generateEd25519SshKeyPair(
  comment = 'keylet',
): Promise<SshKeyPairResult> {
  const kp = (await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  // PKCS#8 for Ed25519 has the 32-byte seed at the last 32 bytes; SPKI has the 32-byte pubkey at the last 32 bytes
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const privSeed = pkcs8.slice(-32);
  const pubRaw = spki.slice(-32);

  const keyType = utf8ToBytes('ssh-ed25519');
  const pubBlob = concatBytes(sshString(keyType), sshString(pubRaw));
  const publicKey = `ssh-ed25519 ${bytesToBase64(pubBlob)} ${comment}`;

  const fpBytes = sha256(pubBlob);
  const keyFingerprint = `SHA256:${bytesToBase64(fpBytes).replace(/=+$/, '')}`;

  // Build OpenSSH private key v1 wire format
  const checkInt = crypto.getRandomValues(new Uint8Array(4));
  const priv64 = concatBytes(privSeed, pubRaw);
  let privBlock = concatBytes(
    checkInt,
    checkInt,
    sshString(keyType),
    sshString(pubRaw),
    sshString(priv64),
    sshString(utf8ToBytes(comment)),
  );
  // Pad to 8-byte cipher block size with 1, 2, 3, ...
  const padLen = (8 - (privBlock.length % 8)) % 8;
  if (padLen > 0) {
    const pad = new Uint8Array(padLen);
    for (let i = 0; i < padLen; i++) pad[i] = i + 1;
    privBlock = concatBytes(privBlock, pad);
  }

  const header = concatBytes(
    utf8ToBytes('openssh-key-v1\0'),
    sshString(utf8ToBytes('none')),
    sshString(utf8ToBytes('none')),
    sshString(new Uint8Array(0)),
    new Uint8Array([0, 0, 0, 1]),
    sshString(pubBlob),
    sshString(privBlock),
  );

  const privateKey = [
    '-----BEGIN OPENSSH PRIVATE KEY-----',
    wrapBase64(bytesToBase64(header)),
    '-----END OPENSSH PRIVATE KEY-----',
  ].join('\n');

  return { privateKey, publicKey, keyFingerprint };
}
