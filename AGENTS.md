# Keylet — AGENTS.md

## Project Overview

**Keylet** is a modern, keyboard-first, lightweight **browser extension** (Chrome / Edge / Firefox MV3) for **Bitwarden / Vaultwarden** servers, designed as a clean, fast, Raycast-inspired alternative to the official Bitwarden browser extension.

- **Target Platforms**: Chromium (Manifest V3) & Firefox (WebExtension)
- **Primary Backend**: Self-hosted **Vaultwarden** & official **Bitwarden** APIs
- **UI Philosophy**: Minimalist, high-contrast, keyboard-navigable (Command Palette / Raycast feel), built with **Vercel UI SDK** (`@ui-sdk/core` + `@ui-sdk/react`) for accessible headless behaviors.

---

## Tech Stack

- **Extension Framework**: [WXT](https://wxt.dev/) (Vite-based, TypeScript, MV3 first-class support, HMR) — *recommended*
- **UI Framework**: React 19 + TypeScript (`strict: true`)
- **UI Behaviors**: `@ui-sdk/core` + `@ui-sdk/react` (headless WAI-ARIA behaviors: `Tabs`, `Select`, `Autocomplete`, `Input`, `PasswordInput`, `SegmentedControl`, `Slider`, `Switch`, `Dialog`, `Toast`, `definePrimitive`, etc.)
- **Styling**: Tailwind CSS or clean CSS variables using `@ui-sdk` `data-*` state attributes (`[data-selected]`, `[data-highlighted]`, `[data-checked]`, `[data-open]`, `[data-pending]`)
- **Crypto / Vault Protocol**:
  - Web Crypto API (`crypto.subtle`) + `@noble/hashes` (Argon2id / PBKDF2-SHA256)
  - Bitwarden / Vaultwarden REST API (`/identity/connect/token`, `/api/sync`, `/api/ciphers`, etc.)
  - TOTP generation (HMAC-SHA1 / RFC 6238 via Web Crypto)
- **Node Runtime**: Node >= 22 (in this environment: `/home/devbox/.nvm/versions/node/v22.23.3/bin`)

---

## Core Product Scope (MVP → V1)

### Phase 1: Project Setup & Vault Auth
1. Initialize WXT + React 19 + TypeScript + `@ui-sdk/core` + `@ui-sdk/react`.
2. **Server & Login View**:
   - Server URL selector/input (presets for `bitwarden.com`, `bitwarden.eu`, and **Custom Self-hosted / Vaultwarden** URL, enforcing `https://` except `localhost`).
   - Pre-login (`/identity/accounts/prelogin`) to fetch KDF type (`PBKDF2` vs `Argon2id`) and iterations/memory/parallelism.
   - Master password key derivation, `/identity/connect/token` authentication, and symmetric key decryption (`encKey` + `macKey`).
   - Lock / Unlock screen (PIN or Master Password; keep decrypted symmetric key in background/session memory only, never `localStorage`).

### Phase 2: Vault Sync & Raycast-Style Popup UI
1. **Sync Engine** (`/api/sync`):
   - Decrypt ciphers (Logins, Secure Notes, Cards, Identities) and folders in background worker.
   - Store encrypted vault snapshot in `chrome.storage.local` + decrypted in-memory cache with auto-lock timeout (`chrome.alarms`).
2. **Popup / Sidepanel UI (built with `@ui-sdk/react`)**:
   - **Global Search Bar** at top, auto-focused on popup open (`↑`/`↓` to navigate, `Enter` to autofill or copy, `Tab` to switch views).
   - **Current Tab Matches** pinned at top (URL domain / host matching).
   - **Segmented / Tabbed Filter**: `All`, `Logins`, `Notes`, `Cards`, `Favorites`.
   - **Item Detail Drawer / View**:
     - One-click copy for Username, Password, and live **TOTP** countdown ring (`30s` period).
     - Masked password reveal toggle (`PasswordInput`).
   - **Password Generator** (`Slider` for length, `Switch` for uppercase/lowercase/numbers/symbols/ambiguous, live entropy indicator).

### Phase 3: Autofill & Content Script
1. **Content Script**:
   - Detect login / signup / TOTP forms (`input[type="password"]`, `autocomplete="username"`, etc.).
   - Keyboard shortcut (`Ctrl+Shift+L` / `Cmd+Shift+L` via `commands` in manifest) to autofill the best-matching credential for the active tab.
   - Optional subtle inline autofill icon/popover inside focused login inputs.
2. **Context Menu / Save Prompt**:
   - Detect form submission with new credentials and offer to save/update in Vaultwarden.

---

## Architecture & Security Rules (Non-Negotiable)

1. **Zero Secret Persistence in Plaintext**:
   - Never persist the Master Password or decrypted `SymmetricKey` to `chrome.storage.local`, `localStorage`, or `indexedDB`.
   - Keep decrypted keys and vault items in the MV3 Service Worker / `chrome.storage.session` (with auto-lock timer) and clear references on lock.
2. **Strict CSP & No Remote Code**:
   - MV3 compliant: no `eval`, no remote scripts, no inline scripts.
3. **UI SDK Usage Guidelines**:
   - Install Vercel's UI SDK skill if available (`npx skills add vercel-labs/ui --skill ui-sdk`) or inspect `node_modules/@ui-sdk/react/dist/*.d.ts` before using any component's props.
   - Always check exact `.d.ts` signatures—`@ui-sdk/*` is currently in `0.1.0-beta.x` and APIs evolve quickly.
   - Do **not** expose `createAgent()` / Agent Bridge in production builds of a password manager; keep sensitive credentials isolated from any page-level or agent inspection.
4. **Protocol Accuracy**:
   - Bitwarden cipher encryption uses `AesCbc256_HmacSha256_B64` (EncType `2`): always verify HMAC-SHA256 MAC **before** AES-CBC decryption (Encrypt-then-MAC).
   - Support both KDF `0` (PBKDF2-SHA256) and KDF `1` (Argon2id) so modern Vaultwarden accounts work out of the box.

---

## Development Commands

```bash
# Ensure Node 22+ is on PATH
export PATH=/home/devbox/.nvm/versions/node/v22.23.3/bin:$PATH

# Install dependencies
npm install

# Start dev server (Chrome MV3)
npm run dev

# Typecheck & build
npm run build
```

---

## Suggested Directory Structure

```text
keylet/
├── AGENTS.md
├── package.json
├── wxt.config.ts
├── entrypoints/
│   ├── background.ts          # Vault sync, crypto state, auto-lock, message router
│   ├── content.ts             # Form detection & autofill injection
│   └── popup/
│       ├── index.html
│       ├── main.tsx
│       └── App.tsx            # UI SDK-powered Raycast-style popup
├── src/
│   ├── crypto/                # KDF (PBKDF2 / Argon2id), AES-CBC + HMAC, TOTP
│   ├── api/                   # Bitwarden / Vaultwarden REST client & types
│   ├── matching/              # URI / domain matching rules
│   ├── components/            # Styled wrappers around @ui-sdk/react primitives
│   └── styles/                # Theme tokens & UI SDK data-* styles
└── tests/                     # Unit tests for crypto, URI matching, TOTP (Vitest)
```

---

## Agent Working Agreements

- **Verify types**: Run `tsc --noEmit` (or `npm run build`) after edits; never guess `@ui-sdk/react` prop names without checking `node_modules/@ui-sdk/react/dist/`.
- **Test crypto thoroughly**: Every crypto helper (key stretching, EncString parsing/decrypting/encrypting, TOTP) MUST have Vitest unit tests using known Bitwarden test vectors before wiring UI.
- **Keep UI snappy**: Popup must open and render cached/unlocked items in `< 100ms`; avoid heavy bundle bloat.
- **Keep Agent Skill in sync**: Whenever CLI commands, flags, output formats, or supported import/secret workflows change, evaluate whether `packages/cli/src/skills.ts` (`KEYLET_SKILL_MD`) should be updated to stay accurate.
