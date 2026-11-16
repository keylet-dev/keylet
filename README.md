# Keylet

A modern, keyboard-first **Bitwarden / Vaultwarden** client suite.

## Repository Structure

```text
keylet/
├── AGENTS.md
├── README.md
└── browser-extension/     # Chrome / Edge / Firefox MV3 extension (WXT + React 19 + @ui-sdk/react)
```

## Browser Extension (`browser-extension/`)

### Features
- **Zero-plaintext secret storage**: Master password and decrypted symmetric keys are never persisted to disk; decrypted session state lives in MV3 memory / `storage.session` with configurable auto-lock (`alarms`).
- **Full Bitwarden / Vaultwarden crypto**:
  - `PBKDF2-SHA256` and `Argon2id` (WASM-accelerated via `hash-wasm` with `@noble/hashes` fallback)
  - `AesCbc256_HmacSha256_B64` (Encrypt-then-MAC)
  - RFC 6238 TOTP generator + live 30s countdown ring
- **Raycast-style Popup**: Global search (`↑`/`↓`, `Enter`, `⌘↵`, `Tab`), current-tab URI matching, Create/Edit/Delete for Logins/Notes/Cards, Password Generator, Quick Unlock PIN, and Clipboard Auto-Clear.
- **Autofill Content Script**: `Ctrl+Shift+L` / `Cmd+Shift+L` autofill (username, password, and `one-time-code` TOTP), Shadow DOM inline popover, and form-submit save prompt.

### Development

```bash
cd browser-extension
npm install
npm run typecheck
npm test
npm run build           # Chrome MV3 -> .output/chrome-mv3
npm run build:firefox   # Firefox MV3 -> .output/firefox-mv3
npm run zip             # Distributable zip archives -> .output/*.zip
```

### Loading in Chrome / Edge
1. Open `chrome://extensions/` and enable **Developer mode**.
2. Click **Load unpacked** and select `browser-extension/.output/chrome-mv3`.
3. Shortcuts: `Ctrl/Cmd + Shift + K` to open popup, `Ctrl/Cmd + Shift + L` to autofill active tab.
