import { useRef, useState } from 'react';
import { Button } from '@ui-sdk/react/button';
import {
  PasswordInput,
  PasswordInputControl,
  PasswordInputToggle,
} from '@ui-sdk/react/password-input';
import {
  SegmentedControl,
  SegmentedControlIndicator,
  SegmentedControlItem,
} from '@ui-sdk/react/segmented-control';
import { ArrowLeft, Eye, EyeOff, KeyRound, Lock, LogOut, Plus, RefreshCw, Upload } from 'lucide-react';
import { parseImportBytes, type VaultStatus } from '@keylet/core';
import { sendRuntimeMessage } from '../ipc';

interface SettingsViewProps {
  status: VaultStatus;
  onBack: () => void;
  onStatusChange: (status: VaultStatus) => void;
  onAddAccount: () => void;
  onToast: (msg: string) => void;
}

const TIMEOUT_OPTIONS = [
  { value: '1', label: '1m' },
  { value: '5', label: '5m' },
  { value: '15', label: '15m' },
  { value: '30', label: '30m' },
  { value: '60', label: '1h' },
  { value: '0', label: 'Never' },
];

const CLIPBOARD_OPTIONS = [
  { value: '15', label: '15s' },
  { value: '30', label: '30s' },
  { value: '60', label: '60s' },
  { value: '0', label: 'Never' },
];

export function SettingsView({
  status,
  onBack,
  onStatusChange,
  onAddAccount,
  onToast,
}: SettingsViewProps) {
  const [pinInput, setPinInput] = useState('');
  const [pinError, setPinError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  async function handleTimeoutChange(val: string | null) {
    if (!val) return;
    const next = await sendRuntimeMessage<VaultStatus>({
      type: 'UPDATE_SETTINGS',
      autoLockMinutes: Number(val),
    });
    onStatusChange(next);
    onToast('Auto-lock updated');
  }

  async function handleClipboardChange(val: string | null) {
    if (!val) return;
    const next = await sendRuntimeMessage<VaultStatus>({
      type: 'UPDATE_SETTINGS',
      clipboardClearSeconds: Number(val),
    });
    onStatusChange(next);
    onToast('Clipboard auto-clear updated');
  }

  async function handleSetPin() {
    setPinError(null);
    try {
      const next = await sendRuntimeMessage<VaultStatus>({
        type: 'SET_PIN',
        pin: pinInput,
      });
      setPinInput('');
      onStatusChange(next);
      onToast('Quick Unlock PIN enabled');
    } catch (err) {
      setPinError(err instanceof Error ? err.message : 'Failed to set PIN');
    }
  }

  async function handleClearPin() {
    const next = await sendRuntimeMessage<VaultStatus>({ type: 'CLEAR_PIN' });
    onStatusChange(next);
    onToast('Quick Unlock PIN removed');
  }

  async function handleSync() {
    const next = await sendRuntimeMessage<VaultStatus>({ type: 'SYNC_VAULT' });
    onStatusChange(next);
    onToast('Vault synced');
  }

  async function handleLock() {
    const next = await sendRuntimeMessage<VaultStatus>({ type: 'LOCK' });
    onStatusChange(next);
  }

  async function handleLogout() {
    const next = await sendRuntimeMessage<VaultStatus>({ type: 'LOGOUT' });
    onStatusChange(next);
  }

  async function handleImportFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setImportError(null);
    setImporting(true);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const parsed = await parseImportBytes(bytes);
      if (parsed.items.length === 0) {
        throw new Error('No importable items found in file');
      }
      const next = await sendRuntimeMessage<VaultStatus>({
        type: 'IMPORT_CIPHERS',
        items: parsed.items,
      });
      onStatusChange(next);
      onToast(`Imported ${parsed.items.length} items (${parsed.format})`);
    } catch (err) {
      setImportError(err instanceof Error ? err.message : 'Import failed');
    } finally {
      setImporting(false);
    }
  }

  return (
    <div className="app-shell">
      <div className="top-bar">
        <button
          type="button"
          className="icon-btn"
          onClick={onBack}
          aria-label="Back to vault"
        >
          <ArrowLeft size={16} />
        </button>
        <div style={{ flex: 1, fontWeight: 600, fontSize: 14 }}>Settings</div>
      </div>

      <div className="panel">
        <div className="detail-card">
          <div className="detail-row">
            <div>
              <div className="detail-row-label">Account</div>
              <div className="detail-row-val">{status.email}</div>
            </div>
          </div>
          <div className="detail-row">
            <div>
              <div className="detail-row-label">Server</div>
              <div className="detail-row-val" style={{ fontSize: 12 }}>
                {status.serverUrl}
              </div>
            </div>
          </div>
          <div className="detail-row">
            <div>
              <div className="detail-row-label">Last Synced</div>
              <div className="detail-row-val" style={{ fontSize: 12 }}>
                {status.lastSyncAt
                  ? new Date(status.lastSyncAt).toLocaleString()
                  : 'Never'}
              </div>
            </div>
            <span className="kbd">{status.cipherCount} items</span>
          </div>
        </div>

        <div className="field-group">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="field-label">Accounts ({status.accounts.length})</span>
            <button
              type="button"
              className="btn"
              style={{ height: 24, minHeight: 24, padding: '0 8px', fontSize: 11 }}
              onClick={onAddAccount}
            >
              <Plus size={12} />
              Add Account
            </button>
          </div>
          <div className="detail-card">
            {status.accounts.map((acc) => {
              const isActive = acc.id === status.activeAccountId;
              return (
                <div className="detail-row" key={acc.id}>
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div className="detail-row-val" style={{ fontSize: 12.5 }}>
                      {acc.email}
                    </div>
                    <div className="detail-row-label" style={{ marginBottom: 0 }}>
                      {acc.serverUrl}
                    </div>
                  </div>
                  {isActive ? (
                    <span className="match-badge">Active</span>
                  ) : (
                    <button
                      type="button"
                      className="btn"
                      style={{ height: 26, minHeight: 26, padding: '0 8px', fontSize: 11.5 }}
                      onClick={async () => {
                        const next = await sendRuntimeMessage<VaultStatus>({
                          type: 'SWITCH_ACCOUNT',
                          accountId: acc.id,
                        });
                        onStatusChange(next);
                      }}
                    >
                      Switch
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        <div className="field-group">
          <span className="field-label">Auto-Lock Timeout</span>
          <SegmentedControl
            className="segmented"
            value={String(status.autoLockMinutes)}
            onValueChange={(v) => void handleTimeoutChange(v)}
          >
            <SegmentedControlIndicator className="segmented-indicator" />
            {TIMEOUT_OPTIONS.map((opt) => (
              <SegmentedControlItem
                key={opt.value}
                className="segmented-item"
                value={opt.value}
              >
                {opt.label}
              </SegmentedControlItem>
            ))}
          </SegmentedControl>
        </div>

        <div className="field-group">
          <span className="field-label">Clear Clipboard After Copy</span>
          <SegmentedControl
            className="segmented"
            value={String(status.clipboardClearSeconds)}
            onValueChange={(v) => void handleClipboardChange(v)}
          >
            <SegmentedControlIndicator className="segmented-indicator" />
            {CLIPBOARD_OPTIONS.map((opt) => (
              <SegmentedControlItem
                key={opt.value}
                className="segmented-item"
                value={opt.value}
              >
                {opt.label}
              </SegmentedControlItem>
            ))}
          </SegmentedControl>
        </div>

        <div className="field-group">
          <span className="field-label">
            Quick Unlock PIN {status.hasPin ? '(Enabled)' : '(Off)'}
          </span>
          {status.hasPin ? (
            <Button className="btn" onClick={() => handleClearPin()}>
              <KeyRound size={14} />
              Remove Quick Unlock PIN
            </Button>
          ) : (
            <div style={{ display: 'flex', gap: 6 }}>
              <PasswordInput
                className="password-group"
                value={pinInput}
                onValueChange={setPinInput}
              >
                <PasswordInputControl
                  className="password-control"
                  placeholder="4+ char PIN"
                />
                <PasswordInputToggle
                  className="password-toggle"
                  aria-label="Show PIN"
                  render={(props, state) => (
                    <button {...props} type="button">
                      {state.visible ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  )}
                />
              </PasswordInput>
              <Button
                className="btn btn-primary"
                onClick={() => handleSetPin()}
                disabled={pinInput.trim().length < 4}
              >
                Set
              </Button>
            </div>
          )}
          {pinError && <div className="error-banner">{pinError}</div>}
        </div>

        <input
          ref={fileInputRef}
          type="file"
          accept=".json,.csv,.1pux"
          style={{ display: 'none' }}
          onChange={(e) => void handleImportFile(e)}
        />
        <Button
          className="btn"
          disabled={importing}
          onClick={() => fileInputRef.current?.click()}
        >
          <Upload size={14} />
          {importing ? 'Importing…' : 'Import Vault (Bitwarden / 1Password / Chrome)'}
        </Button>
        {importError && <div className="error-banner">{importError}</div>}

        <Button className="btn" onClick={() => handleSync()}>
          <RefreshCw size={14} />
          Sync Vault Now
        </Button>

        <Button className="btn" onClick={() => handleLock()}>
          <Lock size={14} />
          Lock Vault
        </Button>

        <Button className="btn btn-danger" onClick={() => handleLogout()}>
          <LogOut size={14} />
          Log Out &amp; Clear Local Data
        </Button>
      </div>
    </div>
  );
}
