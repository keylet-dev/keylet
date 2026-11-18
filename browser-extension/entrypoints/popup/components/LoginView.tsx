import { useState } from 'react';
import { Button } from '@ui-sdk/react/button';
import { Input } from '@ui-sdk/react/input';
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
import { ArrowLeft, Eye, EyeOff, ShieldCheck } from 'lucide-react';
import { SERVER_PRESETS, type ServerPreset, type VaultStatus } from '@keylet/core';
import { RuntimeError, sendRuntimeMessage } from '../ipc';
import { KeyletLogo } from './KeyletLogo';

interface LoginViewProps {
  onSuccess: (status: VaultStatus) => void;
  onCancel?: () => void;
}

export function LoginView({ onSuccess, onCancel }: LoginViewProps) {
  const [preset, setPreset] = useState<ServerPreset['id']>('us');
  const [customUrl, setCustomUrl] = useState('https://');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [twoFactorProviders, setTwoFactorProviders] = useState<number[] | null>(
    null,
  );
  const [twoFactorToken, setTwoFactorToken] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const activeServerUrl =
    preset === 'custom'
      ? customUrl
      : (SERVER_PRESETS.find((p) => p.id === preset)?.url ?? '');

  async function handleSubmit() {
    if (loading) return;
    setError(null);
    setLoading(true);
    try {
      const status = await sendRuntimeMessage<VaultStatus>({
        type: 'LOGIN',
        serverUrl: activeServerUrl,
        email,
        masterPassword: password,
        twoFactorProvider: twoFactorProviders?.[0],
        twoFactorToken: twoFactorToken || undefined,
      });
      onSuccess(status);
    } catch (err) {
      if (err instanceof RuntimeError && err.twoFactorProviders?.length) {
        setTwoFactorProviders(err.twoFactorProviders);
        setError('Enter your two-factor authentication code to continue.');
        return;
      }
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <form
      className="panel panel-auth"
      onSubmit={(e) => {
        e.preventDefault();
        void handleSubmit();
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
        {onCancel && (
          <button
            type="button"
            className="icon-btn"
            onClick={onCancel}
            aria-label="Cancel"
          >
            <ArrowLeft size={16} />
          </button>
        )}
        <KeyletLogo size={36} />
        <div>
          <div style={{ fontSize: 18, fontWeight: 600 }}>Keylet</div>
          <div style={{ fontSize: 13.5, color: 'var(--text-secondary)' }}>
            Connect to Bitwarden or Vaultwarden
          </div>
        </div>
      </div>

      <div className="field-group">
        <span className="field-label">Server</span>
        <SegmentedControl
          className="segmented"
          value={preset}
          onValueChange={(val) => {
            if (val) setPreset(val);
          }}
        >
          <SegmentedControlIndicator className="segmented-indicator" />
          <SegmentedControlItem className="segmented-item" value="us">
            bitwarden.com
          </SegmentedControlItem>
          <SegmentedControlItem className="segmented-item" value="eu">
            bitwarden.eu
          </SegmentedControlItem>
          <SegmentedControlItem className="segmented-item" value="custom">
            Self-hosted
          </SegmentedControlItem>
        </SegmentedControl>
      </div>

      {preset === 'custom' && (
        <div className="field-group">
          <label className="field-label" htmlFor="server-url">
            Vaultwarden / Server URL
          </label>
          <Input
            id="server-url"
            className="text-input"
            type="url"
            placeholder="https://vault.example.com"
            value={customUrl}
            onValueChange={setCustomUrl}
            required
          />
        </div>
      )}

      <div className="field-group">
        <label className="field-label" htmlFor="login-email">
          Email Address
        </label>
        <Input
          id="login-email"
          className="text-input"
          type="email"
          placeholder="you@example.com"
          value={email}
          onValueChange={setEmail}
          autoFocus
          required
        />
      </div>

      <div className="field-group">
        <label className="field-label" htmlFor="login-password">
          Master Password
        </label>
        <PasswordInput
          className="password-group"
          value={password}
          onValueChange={setPassword}
          required
        >
          <PasswordInputControl
            id="login-password"
            className="password-control"
            placeholder="Master password"
          />
          <PasswordInputToggle
            className="password-toggle"
            aria-label="Toggle master password visibility"
            render={(props, state) => (
              <button {...props} type="button">
                {state.visible ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            )}
          />
        </PasswordInput>
      </div>

      {twoFactorProviders && (
        <div className="field-group">
          <label className="field-label" htmlFor="login-2fa">
            2FA Verification Code
          </label>
          <Input
            id="login-2fa"
            className="text-input mono"
            placeholder="6-digit code"
            value={twoFactorToken}
            onValueChange={setTwoFactorToken}
            autoFocus
            required
          />
        </div>
      )}

      {error && <div className="error-banner">{error}</div>}

      <Button
        type="submit"
        className="btn btn-primary"
        disabled={loading}
      >
        <ShieldCheck size={15} />
        {loading ? 'Signing in & Syncing…' : 'Sign in & Sync Vault'}
      </Button>
    </form>
  );
}
