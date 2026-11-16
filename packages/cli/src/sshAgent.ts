import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { CipherType, type DecryptedCipher } from '@keylet/core';

const SSH_AGENT_FAILURE = 5;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;

// ASN.1 PKCS#8 prefix for Ed25519 32-byte seed
const ED25519_PKCS8_PREFIX = Buffer.from(
  '302e020100300506032b657004220420',
  'hex',
);

export interface LoadedSshKey {
  name: string;
  pubBlob: Buffer;
  privateKey: crypto.KeyObject;
}

function readSshString(buf: Buffer, offset: number): [Buffer, number] {
  if (offset + 4 > buf.length) throw new Error('Truncated SSH string');
  const len = buf.readUInt32BE(offset);
  const start = offset + 4;
  const end = start + len;
  if (end > buf.length) throw new Error('SSH string out of bounds');
  return [buf.subarray(start, end), end];
}

function encodeSshString(data: Buffer | string): Buffer {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  const out = Buffer.alloc(4 + buf.length);
  out.writeUInt32BE(buf.length, 0);
  buf.copy(out, 4);
  return out;
}

function wrapAgentPacket(type: number, payload: Buffer): Buffer {
  const len = 1 + payload.length;
  const out = Buffer.alloc(4 + len);
  out.writeUInt32BE(len, 0);
  out.writeUInt8(type, 4);
  payload.copy(out, 5);
  return out;
}

/** Parse an unencrypted OpenSSH Ed25519 private key PEM into a Node KeyObject + public blob. */
export function parseOpenSshEd25519(
  privateKeyPem: string,
  name: string,
): LoadedSshKey | null {
  try {
    const match = privateKeyPem.match(
      /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/,
    );
    if (!match?.[1]) return null;
    const raw = Buffer.from(match[1].replace(/\s+/g, ''), 'base64');
    const magic = Buffer.from('openssh-key-v1\0', 'utf8');
    if (!raw.subarray(0, magic.length).equals(magic)) return null;

    let off = magic.length;
    const [cipherName, o1] = readSshString(raw, off);
    off = o1;
    if (cipherName.toString('utf8') !== 'none') return null;
    const [, o2] = readSshString(raw, off); // kdfname
    off = o2;
    const [, o3] = readSshString(raw, off); // kdfoptions
    off = o3;
    const numKeys = raw.readUInt32BE(off);
    off += 4;
    if (numKeys < 1) return null;

    const [pubBlob, o4] = readSshString(raw, off);
    off = o4;
    const [privBlock, o5] = readSshString(raw, off);
    void o5;

    // privBlock: check1(4) + check2(4) + keytype + pub(32) + priv(64) + comment
    let pOff = 8;
    const [keyType, p1] = readSshString(privBlock, pOff);
    pOff = p1;
    if (keyType.toString('utf8') !== 'ssh-ed25519') return null;
    const [, p2] = readSshString(privBlock, pOff); // pub32
    pOff = p2;
    const [priv64] = readSshString(privBlock, pOff);
    const seed = priv64.subarray(0, 32);

    const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
    const privateKey = crypto.createPrivateKey({
      key: pkcs8,
      format: 'der',
      type: 'pkcs8',
    });

    return { name, pubBlob: Buffer.from(pubBlob), privateKey };
  } catch {
    return null;
  }
}

export function loadSshKeysFromCiphers(ciphers: DecryptedCipher[]): LoadedSshKey[] {
  const keys: LoadedSshKey[] = [];
  for (const c of ciphers) {
    if (c.type !== CipherType.SshKey || !c.sshKey?.privateKey) continue;
    const parsed = parseOpenSshEd25519(c.sshKey.privateKey, c.name);
    if (parsed) keys.push(parsed);
  }
  return keys;
}

export class KeyletSshAgent {
  private server: net.Server | null = null;
  private keys: LoadedSshKey[] = [];

  constructor(private readonly socketPath: string) {}

  updateKeys(ciphers: DecryptedCipher[]): number {
    this.keys = loadSshKeysFromCiphers(ciphers);
    return this.keys.length;
  }

  start(ciphers: DecryptedCipher[]): Promise<number> {
    const count = this.updateKeys(ciphers);
    if (this.server) return Promise.resolve(count);

    fs.mkdirSync(path.dirname(this.socketPath), { recursive: true, mode: 0o700 });
    if (fs.existsSync(this.socketPath)) {
      fs.unlinkSync(this.socketPath);
    }

    return new Promise((resolve, reject) => {
      const server = net.createServer((socket) => {
        let buf = Buffer.alloc(0);
        socket.on('data', (chunk: Buffer) => {
          buf = Buffer.concat([buf, chunk]);
          while (buf.length >= 4) {
            const msgLen = buf.readUInt32BE(0);
            if (buf.length < 4 + msgLen) break;
            const packet = buf.subarray(4, 4 + msgLen);
            buf = buf.subarray(4 + msgLen);
            const reply = this.handlePacket(packet);
            socket.write(reply);
          }
        });
      });

      server.on('error', reject);
      server.listen(this.socketPath, () => {
        fs.chmodSync(this.socketPath, 0o600);
        this.server = server;
        resolve(count);
      });
    });
  }

  stop(): void {
    this.keys = [];
    if (this.server) {
      this.server.close();
      this.server = null;
    }
    if (fs.existsSync(this.socketPath)) {
      fs.unlinkSync(this.socketPath);
    }
  }

  handlePacket(packet: Buffer): Buffer {
    if (packet.length < 1) {
      return wrapAgentPacket(SSH_AGENT_FAILURE, Buffer.alloc(0));
    }
    const msgType = packet.readUInt8(0);
    const body = packet.subarray(1);

    if (msgType === SSH_AGENTC_REQUEST_IDENTITIES) {
      const countBuf = Buffer.alloc(4);
      countBuf.writeUInt32BE(this.keys.length, 0);
      const parts: Buffer[] = [countBuf];
      for (const k of this.keys) {
        parts.push(encodeSshString(k.pubBlob));
        parts.push(encodeSshString(k.name));
      }
      return wrapAgentPacket(SSH_AGENT_IDENTITIES_ANSWER, Buffer.concat(parts));
    }

    if (msgType === SSH_AGENTC_SIGN_REQUEST) {
      try {
        const [reqBlob, o1] = readSshString(body, 0);
        const [data] = readSshString(body, o1);
        const key = this.keys.find((k) => k.pubBlob.equals(reqBlob));
        if (!key) {
          return wrapAgentPacket(SSH_AGENT_FAILURE, Buffer.alloc(0));
        }
        const sig = crypto.sign(null, data, key.privateKey);
        const sigBlob = Buffer.concat([
          encodeSshString('ssh-ed25519'),
          encodeSshString(sig),
        ]);
        return wrapAgentPacket(SSH_AGENT_SIGN_RESPONSE, encodeSshString(sigBlob));
      } catch {
        return wrapAgentPacket(SSH_AGENT_FAILURE, Buffer.alloc(0));
      }
    }

    return wrapAgentPacket(SSH_AGENT_FAILURE, Buffer.alloc(0));
  }
}
