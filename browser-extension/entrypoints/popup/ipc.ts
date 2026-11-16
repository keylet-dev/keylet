import { browser } from 'wxt/browser';
import type { RuntimeRequest, RuntimeResponse } from '@keylet/core';

export class RuntimeError extends Error {
  constructor(
    message: string,
    public readonly twoFactorProviders?: number[],
  ) {
    super(message);
    this.name = 'RuntimeError';
  }
}

export async function sendRuntimeMessage<T>(req: RuntimeRequest): Promise<T> {
  const res = (await browser.runtime.sendMessage(req)) as RuntimeResponse<T>;
  if (!res || !res.ok) {
    throw new RuntimeError(
      res?.error ?? 'Background worker unavailable',
      res?.twoFactorProviders,
    );
  }
  return res.data;
}
