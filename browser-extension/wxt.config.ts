import { defineConfig } from 'wxt';

export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  manifest: {
    name: 'Keylet',
    description: 'Keyboard-first, lightweight Bitwarden & Vaultwarden browser extension',
    icons: {
      16: 'icon/16.png',
      32: 'icon/32.png',
      48: 'icon/48.png',
      128: 'icon/128.png',
    },
    permissions: ['storage', 'alarms', 'activeTab', 'clipboardWrite', 'contextMenus'],
    host_permissions: ['https://*/*', 'http://localhost/*', 'http://127.0.0.1/*'],
    commands: {
      autofill: {
        suggested_key: {
          default: 'Ctrl+Shift+L',
          mac: 'Command+Shift+L',
        },
        description: 'Autofill best-matching credential for the active tab',
      },
      _execute_action: {
        suggested_key: {
          default: 'Ctrl+Shift+K',
          mac: 'Command+Shift+K',
        },
      },
    },
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';",
    },
  },
});
