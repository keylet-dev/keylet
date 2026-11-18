import { useState } from 'react';
import { Button } from '@ui-sdk/react/button';
import {
  PasswordInput,
  PasswordInputControl,
  PasswordInputToggle,
} from '@ui-sdk/react/password-input';
import { Eye, EyeOff, KeyRound, LogOut, Unlock } from 'lucide-react';
import type { VaultStatus } from '@keylet/core';
import { sendRuntimeMessage } from '../ipc';
import { KeyletLogo } from './KeyletLogo';

interface LockViewProps {
  status: VaultStatus;
  onUnlock: (status: VaultStatus) => void;
  onSwitchAccount: (accountId: string) => void;
  onAddAccount: () => void;
  onLogout: (status: VaultStatus) => void;
}

export function LockView({
  status,
  onUnlock,
  onSwitchAccount,
  onAddAccount,
  onLogout,
}: LockViewProps) {
  const [usePin, setUsePin] = useState(status.hasPin);
  const [secret, setSecret] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleUnlock() {
    if (loading) return;
    setError(null);
    setLoading(true);
    try {
      const next = await sendRuntimeMessage<VaultStatus>(
        usePin
          ? { type: 'UNLOCK_PIN', pin: secret }
          : { type: 'UNLOCK', masterPassword: secret },
      );
      onUnlock(next);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unlock failed';
      setError(msg);
      if (msg.includes('Master Password')) {
        setUsePin(false);
        setSecret('');
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleLogout() {
    const next = await sendRuntimeMessage<VaultStatus>({ type: 'LOGOUT' });
    onLogout(next);
  }

  return (
    <form
      className="panel panel-auth"
      style={{ justifyContent: 'center' }}
      onSubmit={(e) => {
        e.preventDefault();
        void handleUnlock();
      }}
    >
      <div style={{ textAlign: 'center', marginBottom: 8 }}>
        <div style={{ marginBottom: 10 }}>
          <KeyletLogo size={44} />
        </div>
        <div style={{ fontSize: 18, fontWeight: 600 }}>Vault Locked</div>
        <div style={{ fontSize: 13.5, color: 'var(--text-secondary)', marginTop: 3 }}>
          {status.email}
        </div>
        <div style={{ fontSize: 12.5, color: 'var(--text-muted)', marginTop: 2 }}>
          {status.serverUrl}
        </div>
      </div>

      <div className="field-group">
        <label className="field-label" htmlFor="unlock-password">
          {usePin ? 'Quick Unlock PIN' : 'Master Password'}
        </label>
        <PasswordInput
          className="password-group"
          value={secret}
          onValueChange={setSecret}
          required
        >
          <PasswordInputControl
            id="unlock-password"
            className="password-control"
            placeholder={usePin ? 'Enter PIN' : 'Enter master password'}
            autoFocus
          />
          <PasswordInputToggle
            className="password-toggle"
            aria-label="Show secret"
            render={(props, state) => (
              <button {...props} type="button">
                {state.visible ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            )}
          />
        </PasswordInput>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <Button type="submit" className="btn btn-primary" disabled={loading}>
        <Unlock size={15} />
        {loading ? 'Unlocking…' : usePin ? 'Unlock with PIN' : 'Unlock Vault'}
      </Button>

      {status.hasPin && (
        <Button
          type="button"
          className="btn"
          onClick={() => {
            setUsePin((v) => !v);
            setSecret('');
            setError(null);
          }}
        >
          <KeyRound size={14} />
          {usePin ? 'Use Master Password instead' : 'Use Quick Unlock PIN'}
        </Button>
      )}

      {status.accounts.length > 1 && (
        <div className="field-group">
          <span className="field-label">Switch Account</span>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {status.accounts.map((acc) => (
              <button
                key={acc.id}
                type="button"
                className="btn"
                style={{
                  height: 32,
                  minHeight: 32,
                  padding: '0 12px',
                  fontSize: 12.5,
                  borderColor:
                    acc.id === status.activeAccountId
                      ? 'var(--accent)'
                      : undefined,
                }}
                onClick={() => onSwitchAccount(acc.id)}
              >
                {acc.email}
              </button>
            ))}
          </div>
        </div>
      )}

      <Button type="button" className="btn" onClick={onAddAccount}>
        Add Another Account
      </Button>

      <Button type="button" className="btn" onClick={() => handleLogout()}>
        <LogOut size={14} />
        Log out
      </Button>
    </form>
  );
}
