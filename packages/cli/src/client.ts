import fs from 'node:fs';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { getSocketPath } from './config.js';

export function ipcRequest<T>(
  method: 'GET' | 'POST',
  urlPath: string,
  body?: unknown,
  socketPath = getSocketPath(),
): Promise<T> {
  return new Promise((resolve, reject) => {
    const payload = body !== undefined ? JSON.stringify(body) : undefined;
    const req = http.request(
      {
        socketPath,
        path: urlPath,
        method,
        headers: payload
          ? {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(payload),
            }
          : undefined,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          try {
            const parsed = JSON.parse(raw) as T & { ok?: boolean; error?: string };
            if (res.statusCode && res.statusCode >= 400) {
              reject(new Error(parsed.error || `IPC error ${res.statusCode}`));
              return;
            }
            resolve(parsed);
          } catch {
            reject(new Error(`Invalid daemon response: ${raw}`));
          }
        });
      },
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

export async function isDaemonRunning(socketPath = getSocketPath()): Promise<boolean> {
  if (!fs.existsSync(socketPath)) return false;
  try {
    await ipcRequest<{ ok: boolean }>('GET', '/ping', undefined, socketPath);
    return true;
  } catch {
    return false;
  }
}

export async function ensureDaemon(binScriptPath: string): Promise<void> {
  if (await isDaemonRunning()) return;

  const child = spawn(process.execPath, [binScriptPath, '__daemon'], {
    detached: true,
    stdio: 'ignore',
    env: process.env,
  });
  child.unref();

  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 50));
    if (await isDaemonRunning()) return;
  }
  throw new Error('Failed to start Keylet session daemon');
}
