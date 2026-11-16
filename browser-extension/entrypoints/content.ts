import { browser } from 'wxt/browser';
import { defineContentScript } from 'wxt/utils/define-content-script';
import type { MatchedCipher, RuntimeResponse } from '@keylet/core';

function isVisible(el: HTMLElement): boolean {
  const style = window.getComputedStyle(el);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
    return false;
  }
  const rect = el.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}

function setNativeInputValue(input: HTMLInputElement, value: string): void {
  const descriptor = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    'value',
  );
  if (descriptor?.set) {
    descriptor.set.call(input, value);
  } else {
    input.value = value;
  }
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}

function findLoginInputs(anchor?: HTMLInputElement): {
  usernameInput: HTMLInputElement | null;
  passwordInput: HTMLInputElement | null;
} {
  const form = anchor?.form ?? anchor?.closest('form') ?? document;
  const allInputs = Array.from(
    form.querySelectorAll<HTMLInputElement>('input'),
  ).filter((el) => !el.disabled && !el.readOnly && isVisible(el));

  const passwordInput =
    (anchor?.type === 'password' ? anchor : null) ??
    allInputs.find((el) => el.type === 'password') ??
    null;

  const isUsernameCandidate = (el: HTMLInputElement) => {
    const type = el.type.toLowerCase();
    const ac = (el.autocomplete || '').toLowerCase();
    const name = (el.name || el.id || '').toLowerCase();
    if (ac.includes('username') || ac === 'email') return true;
    if (type === 'email') return true;
    if (type === 'text' || type === 'tel') {
      if (
        name.includes('user') ||
        name.includes('email') ||
        name.includes('login') ||
        name.includes('account')
      ) {
        return true;
      }
      // Fallback: text input appearing right before password input
      if (passwordInput) {
        const pwIdx = allInputs.indexOf(passwordInput);
        const myIdx = allInputs.indexOf(el);
        return myIdx !== -1 && myIdx < pwIdx;
      }
    }
    return false;
  };

  let usernameInput: HTMLInputElement | null = null;
  if (anchor && anchor.type !== 'password' && isUsernameCandidate(anchor)) {
    usernameInput = anchor;
  } else {
    const candidates = allInputs.filter(isUsernameCandidate);
    usernameInput = candidates[candidates.length - 1] ?? null;
  }

  return { usernameInput, passwordInput };
}

function findOtpInput(anchor?: HTMLInputElement): HTMLInputElement | null {
  if (anchor && isOtpField(anchor)) return anchor;
  const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('input')).filter(
    (el) => !el.disabled && !el.readOnly && isVisible(el),
  );
  return inputs.find(isOtpField) ?? null;
}

function isOtpField(el: HTMLInputElement): boolean {
  const ac = (el.autocomplete || '').toLowerCase();
  if (ac === 'one-time-code') return true;
  const type = el.type.toLowerCase();
  if (type !== 'text' && type !== 'tel' && type !== 'number') return false;
  const hint = `${el.name} ${el.id} ${el.placeholder}`.toLowerCase();
  return /\b(totp|otp|2fa|mfa|verification|auth.?code)\b/.test(hint);
}

function isLoginField(el: EventTarget | null): el is HTMLInputElement {
  if (!(el instanceof HTMLInputElement)) return false;
  if (el.disabled || el.readOnly) return false;
  if (isOtpField(el)) return true;
  if (el.type === 'password') return true;
  const ac = (el.autocomplete || '').toLowerCase();
  if (ac.includes('username') || ac === 'email') return true;
  if (el.type === 'email') return true;
  if (el.type === 'text') {
    const form = el.form ?? el.closest('form') ?? document;
    return Boolean(form.querySelector('input[type="password"]'));
  }
  return false;
}

export default defineContentScript({
  matches: ['https://*/*', 'http://localhost/*', 'http://127.0.0.1/*'],
  runAt: 'document_idle',

  main() {
    let popoverHost: HTMLDivElement | null = null;
    let savePromptHost: HTMLDivElement | null = null;
    let activeInput: HTMLInputElement | null = null;

    function removePopover() {
      popoverHost?.remove();
      popoverHost = null;
    }

    function fillFields(
      username: string,
      password: string,
      totp?: string,
      anchor?: HTMLInputElement,
    ) {
      const { usernameInput, passwordInput } = findLoginInputs(anchor);
      if (usernameInput && username) {
        setNativeInputValue(usernameInput, username);
      }
      if (passwordInput && password) {
        setNativeInputValue(passwordInput, password);
      }
      if (totp) {
        const otpInput = findOtpInput(anchor);
        if (otpInput) {
          setNativeInputValue(otpInput, totp);
        }
      }
      removePopover();
    }

    function showAutofillPopover(
      target: HTMLInputElement,
      matches: MatchedCipher[],
    ) {
      removePopover();
      if (matches.length === 0) return;

      const rect = target.getBoundingClientRect();
      const host = document.createElement('div');
      host.style.position = 'fixed';
      host.style.top = `${Math.min(window.innerHeight - 160, rect.bottom + 4)}px`;
      host.style.left = `${Math.max(8, rect.left)}px`;
      host.style.width = `${Math.max(240, Math.min(340, rect.width))}px`;
      host.style.zIndex = '2147483647';

      const shadow = host.attachShadow({ mode: 'closed' });
      const style = document.createElement('style');
      style.textContent = `
        .card {
          background: #151820;
          color: #f3f4f6;
          border: 1px solid rgba(255,255,255,0.14);
          border-radius: 8px;
          box-shadow: 0 12px 28px rgba(0,0,0,0.45);
          font-family: -apple-system, BlinkMacSystemFont, 'Inter', sans-serif;
          overflow: hidden;
          font-size: 12.5px;
        }
        .header {
          padding: 5px 10px;
          font-size: 10.5px;
          font-weight: 600;
          color: #9ca3af;
          border-bottom: 1px solid rgba(255,255,255,0.08);
          display: flex;
          justify-content: space-between;
        }
        .item {
          padding: 7px 10px;
          cursor: pointer;
          display: flex;
          flex-direction: column;
          gap: 1px;
        }
        .item:hover { background: #232938; }
        .name { font-weight: 500; color: #f9fafb; }
        .user { font-size: 11px; color: #9ca3af; }
      `;

      const card = document.createElement('div');
      card.className = 'card';

      const header = document.createElement('div');
      header.className = 'header';
      header.innerHTML = '<span>Keylet</span><span>Autofill</span>';
      card.appendChild(header);

      for (const m of matches.slice(0, 4)) {
        const row = document.createElement('div');
        row.className = 'item';
        const nameEl = document.createElement('div');
        nameEl.className = 'name';
        nameEl.textContent = m.name;
        const userEl = document.createElement('div');
        userEl.className = 'user';
        userEl.textContent = m.login?.username || 'No username';
        row.append(nameEl, userEl);

        row.addEventListener('mousedown', (e) => {
          e.preventDefault();
          void browser.runtime.sendMessage({
            type: 'AUTOFILL_CIPHER',
            cipherId: m.id,
          });
          removePopover();
        });
        card.appendChild(row);
      }

      shadow.append(style, card);
      document.documentElement.appendChild(host);
      popoverHost = host;
    }

    function showSavePrompt(username: string, password: string) {
      savePromptHost?.remove();

      const host = document.createElement('div');
      host.style.position = 'fixed';
      host.style.top = '16px';
      host.style.right = '16px';
      host.style.zIndex = '2147483647';

      const shadow = host.attachShadow({ mode: 'closed' });
      const style = document.createElement('style');
      style.textContent = `
        .banner {
          width: 300px;
          background: #151820;
          color: #f3f4f6;
          border: 1px solid rgba(255,255,255,0.16);
          border-radius: 10px;
          padding: 12px;
          box-shadow: 0 12px 32px rgba(0,0,0,0.5);
          font-family: -apple-system, BlinkMacSystemFont, 'Inter', sans-serif;
          font-size: 12.5px;
        }
        .title { font-weight: 600; margin-bottom: 4px; }
        .sub { color: #9ca3af; font-size: 11.5px; margin-bottom: 10px; word-break: break-all; }
        .actions { display: flex; justify-content: flex-end; gap: 8px; }
        button {
          border-radius: 6px;
          border: 1px solid rgba(255,255,255,0.12);
          padding: 5px 10px;
          font-size: 12px;
          cursor: pointer;
          font-weight: 500;
        }
        .dismiss { background: #1c202b; color: #d1d5db; }
        .save { background: #3b82f6; border-color: transparent; color: #fff; }
      `;

      const banner = document.createElement('div');
      banner.className = 'banner';

      const title = document.createElement('div');
      title.className = 'title';
      title.textContent = 'Save login to Keylet?';

      const sub = document.createElement('div');
      sub.className = 'sub';
      sub.textContent = `${window.location.hostname}${username ? ` · ${username}` : ''}`;

      const actions = document.createElement('div');
      actions.className = 'actions';

      const dismissBtn = document.createElement('button');
      dismissBtn.className = 'dismiss';
      dismissBtn.textContent = 'Not now';
      dismissBtn.onclick = () => host.remove();

      const saveBtn = document.createElement('button');
      saveBtn.className = 'save';
      saveBtn.textContent = 'Save';
      saveBtn.onclick = async () => {
        saveBtn.textContent = 'Saving…';
        saveBtn.disabled = true;
        await browser.runtime.sendMessage({
          type: 'SAVE_LOGIN',
          name: window.location.hostname,
          username,
          password,
          uri: window.location.origin,
        });
        host.remove();
      };

      actions.append(dismissBtn, saveBtn);
      banner.append(title, sub, actions);
      shadow.append(style, banner);
      document.documentElement.appendChild(host);
      savePromptHost = host;
    }

    browser.runtime.onMessage.addListener((msg: unknown) => {
      const m = msg as {
        type?: string;
        username?: string;
        password?: string;
        totp?: string;
      };
      if (m?.type === 'KEYLET_FILL') {
        fillFields(
          m.username ?? '',
          m.password ?? '',
          m.totp,
          activeInput ?? undefined,
        );
      }
    });

    document.addEventListener('focusin', async (e) => {
      if (!isLoginField(e.target)) return;
      activeInput = e.target;

      try {
        const res = (await browser.runtime.sendMessage({
          type: 'GET_TAB_MATCHES',
          tabUrl: window.location.href,
        })) as RuntimeResponse<MatchedCipher[]>;

        if (res?.ok && res.data.length > 0 && document.activeElement === activeInput) {
          showAutofillPopover(activeInput, res.data);
        }
      } catch {
        // Extension context invalidated or locked
      }
    });

    document.addEventListener('focusout', () => {
      setTimeout(() => {
        if (!document.activeElement || !isLoginField(document.activeElement)) {
          removePopover();
        }
      }, 150);
    });

    document.addEventListener(
      'submit',
      async (e) => {
        const form = e.target;
        if (!(form instanceof HTMLFormElement)) return;
        const pwInput = form.querySelector<HTMLInputElement>('input[type="password"]');
        if (!pwInput?.value) return;

        const { usernameInput } = findLoginInputs(pwInput);
        const username = usernameInput?.value ?? '';
        const password = pwInput.value;

        try {
          const res = (await browser.runtime.sendMessage({
            type: 'GET_TAB_MATCHES',
            tabUrl: window.location.href,
          })) as RuntimeResponse<MatchedCipher[]>;

          if (!res?.ok) return;
          const alreadySaved = res.data.some(
            (m) =>
              m.login?.password === password &&
              (!username || m.login?.username === username),
          );
          if (!alreadySaved) {
            showSavePrompt(username, password);
          }
        } catch {
          // ignore
        }
      },
      true,
    );
  },
});
