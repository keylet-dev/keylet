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
import { Switch, SwitchThumb } from '@ui-sdk/react/switch';
import { ArrowLeft, Eye, EyeOff, Save, Wand2 } from 'lucide-react';
import {
  type CipherInput,
  CipherType,
  type DecryptedCipher,
  type DecryptedFolder,
  DEFAULT_PASSWORD_OPTIONS,
  generateEd25519SshKeyPair,
  generatePassword,
} from '@keylet/core';

interface CipherFormProps {
  initialCipher?: DecryptedCipher | null;
  folders?: DecryptedFolder[];
  defaultUri?: string | null;
  onCancel: () => void;
  onSave: (cipher: CipherInput, cipherId?: string) => Promise<void>;
}

type FormType = 'login' | 'note' | 'card' | 'ssh';

function toFormType(t?: CipherType): FormType {
  if (t === CipherType.SecureNote) return 'note';
  if (t === CipherType.Card) return 'card';
  if (t === CipherType.SshKey) return 'ssh';
  return 'login';
}

export function CipherForm({
  initialCipher,
  folders = [],
  defaultUri,
  onCancel,
  onSave,
}: CipherFormProps) {
  const isEdit = Boolean(initialCipher);
  const [formType, setFormType] = useState<FormType>(
    toFormType(initialCipher?.type),
  );
  const [name, setName] = useState(initialCipher?.name ?? '');
  const [folderId, setFolderId] = useState<string>(initialCipher?.folderId ?? '');
  const [favorite, setFavorite] = useState(initialCipher?.favorite ?? false);
  const [notes, setNotes] = useState(initialCipher?.notes ?? '');

  // Login fields
  const [username, setUsername] = useState(initialCipher?.login?.username ?? '');
  const [password, setPassword] = useState(initialCipher?.login?.password ?? '');
  const [totp, setTotp] = useState(initialCipher?.login?.totp ?? '');
  const [uri, setUri] = useState(
    initialCipher?.login?.uris[0]?.uri ?? defaultUri ?? '',
  );

  // Card fields
  const [cardholderName, setCardholderName] = useState(
    initialCipher?.card?.cardholderName ?? '',
  );
  const [brand, setBrand] = useState(initialCipher?.card?.brand ?? '');
  const [cardNumber, setCardNumber] = useState(initialCipher?.card?.number ?? '');
  const [expMonth, setExpMonth] = useState(initialCipher?.card?.expMonth ?? '');
  const [expYear, setExpYear] = useState(initialCipher?.card?.expYear ?? '');
  const [cvv, setCvv] = useState(initialCipher?.card?.code ?? '');

  // SSH Key fields
  const [sshPrivate, setSshPrivate] = useState(initialCipher?.sshKey?.privateKey ?? '');
  const [sshPublic, setSshPublic] = useState(initialCipher?.sshKey?.publicKey ?? '');
  const [sshFingerprint, setSshFingerprint] = useState(initialCipher?.sshKey?.keyFingerprint ?? '');

  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (saving) return;
    if (!name.trim()) {
      setError('Name is required');
      return;
    }

    setError(null);
    setSaving(true);
    try {
      const type =
        formType === 'note'
          ? CipherType.SecureNote
          : formType === 'card'
            ? CipherType.Card
            : formType === 'ssh'
              ? CipherType.SshKey
              : CipherType.Login;

      const payload: CipherInput = {
        type,
        name: name.trim(),
        notes: notes || null,
        favorite,
        folderId: folderId || null,
      };

      if (type === CipherType.Login) {
        payload.login = {
          username: username || null,
          password: password || null,
          totp: totp || null,
          uris: uri.trim() ? [{ uri: uri.trim(), match: null }] : [],
        };
      } else if (type === CipherType.Card) {
        payload.card = {
          cardholderName: cardholderName || null,
          brand: brand || null,
          number: cardNumber || null,
          expMonth: expMonth || null,
          expYear: expYear || null,
          code: cvv || null,
        };
      } else if (type === CipherType.SshKey) {
        payload.sshKey = {
          privateKey: sshPrivate || null,
          publicKey: sshPublic || null,
          keyFingerprint: sshFingerprint || null,
        };
      }

      await onSave(payload, initialCipher?.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save item');
    } finally {
      setSaving(false);
    }
  }

  return (
    <form className="app-shell" onSubmit={(e) => void handleSubmit(e)}>
      <div className="top-bar">
        <button
          type="button"
          className="icon-btn"
          onClick={onCancel}
          aria-label="Cancel"
        >
          <ArrowLeft size={16} />
        </button>
        <div style={{ flex: 1, fontWeight: 600, fontSize: 14 }}>
          {isEdit ? 'Edit Item' : 'New Item'}
        </div>
        <Button
          type="submit"
          className="btn btn-primary"
          style={{ height: 30, padding: '0 10px', fontSize: 12 }}
          disabled={saving}
        >
          <Save size={13} />
          {saving ? 'Saving…' : 'Save'}
        </Button>
      </div>

      <div className="panel" style={{ gap: 10 }}>
        {!isEdit && (
          <SegmentedControl
            className="segmented"
            value={formType}
            onValueChange={(v) => {
              if (v) setFormType(v);
            }}
          >
            <SegmentedControlIndicator className="segmented-indicator" />
            <SegmentedControlItem className="segmented-item" value="login">
              Login
            </SegmentedControlItem>
            <SegmentedControlItem className="segmented-item" value="note">
              Note
            </SegmentedControlItem>
            <SegmentedControlItem className="segmented-item" value="card">
              Card
            </SegmentedControlItem>
            <SegmentedControlItem className="segmented-item" value="ssh">
              SSH
            </SegmentedControlItem>
          </SegmentedControl>
        )}

        <div className="field-group">
          <label className="field-label" htmlFor="cipher-name">
            Name
          </label>
          <Input
            id="cipher-name"
            className="text-input"
            placeholder="e.g. GitHub"
            value={name}
            onValueChange={setName}
            autoFocus
            required
          />
        </div>

        {formType === 'login' && (
          <>
            <div className="field-group">
              <label className="field-label" htmlFor="cipher-user">
                Username / Email
              </label>
              <Input
                id="cipher-user"
                className="text-input"
                placeholder="you@example.com"
                value={username}
                onValueChange={setUsername}
              />
            </div>

            <div className="field-group">
              <label className="field-label" htmlFor="cipher-pass">
                Password
              </label>
              <PasswordInput
                className="password-group"
                value={password}
                onValueChange={setPassword}
              >
                <PasswordInputControl
                  id="cipher-pass"
                  className="password-control"
                  placeholder="Password"
                />
                <button
                  type="button"
                  className="password-toggle"
                  title="Generate strong password"
                  onClick={() => {
                    const { password: gen } = generatePassword(
                      DEFAULT_PASSWORD_OPTIONS,
                    );
                    setPassword(gen);
                  }}
                >
                  <Wand2 size={14} />
                </button>
                <PasswordInputToggle
                  className="password-toggle"
                  aria-label="Toggle password visibility"
                  render={(props, state) => (
                    <button {...props} type="button">
                      {state.visible ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  )}
                />
              </PasswordInput>
            </div>

            <div className="field-group">
              <label className="field-label" htmlFor="cipher-uri">
                Website URL
              </label>
              <Input
                id="cipher-uri"
                className="text-input"
                placeholder="https://example.com"
                value={uri}
                onValueChange={setUri}
              />
            </div>

            <div className="field-group">
              <label className="field-label" htmlFor="cipher-totp">
                Authenticator Key (TOTP Secret / URI)
              </label>
              <Input
                id="cipher-totp"
                className="text-input mono"
                placeholder="Base32 secret or otpauth://..."
                value={totp}
                onValueChange={setTotp}
              />
            </div>
          </>
        )}

        {formType === 'card' && (
          <>
            <div className="field-group">
              <label className="field-label" htmlFor="card-holder">
                Cardholder Name
              </label>
              <Input
                id="card-holder"
                className="text-input"
                value={cardholderName}
                onValueChange={setCardholderName}
              />
            </div>
            <div className="field-group">
              <label className="field-label" htmlFor="card-number">
                Card Number
              </label>
              <Input
                id="card-number"
                className="text-input mono"
                value={cardNumber}
                onValueChange={setCardNumber}
              />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
              <div className="field-group">
                <label className="field-label" htmlFor="card-mm">
                  Exp MM
                </label>
                <Input
                  id="card-mm"
                  className="text-input mono"
                  placeholder="08"
                  value={expMonth}
                  onValueChange={setExpMonth}
                />
              </div>
              <div className="field-group">
                <label className="field-label" htmlFor="card-yy">
                  Exp YYYY
                </label>
                <Input
                  id="card-yy"
                  className="text-input mono"
                  placeholder="2028"
                  value={expYear}
                  onValueChange={setExpYear}
                />
              </div>
              <div className="field-group">
                <label className="field-label" htmlFor="card-cvv">
                  CVV
                </label>
                <Input
                  id="card-cvv"
                  className="text-input mono"
                  value={cvv}
                  onValueChange={setCvv}
                />
              </div>
            </div>
            <div className="field-group">
              <label className="field-label" htmlFor="card-brand">
                Brand
              </label>
              <Input
                id="card-brand"
                className="text-input"
                placeholder="Visa / Mastercard"
                value={brand}
                onValueChange={setBrand}
              />
            </div>
          </>
        )}

        {formType === 'ssh' && (
          <>
            <Button
              type="button"
              className="btn"
              onClick={async () => {
                const kp = await generateEd25519SshKeyPair(name.trim() || 'keylet');
                setSshPrivate(kp.privateKey);
                setSshPublic(kp.publicKey);
                setSshFingerprint(kp.keyFingerprint);
              }}
            >
              <Wand2 size={14} />
              Generate Ed25519 SSH Keypair
            </Button>
            <div className="field-group">
              <label className="field-label" htmlFor="ssh-pub">
                Public Key
              </label>
              <Input
                id="ssh-pub"
                className="text-input mono"
                placeholder="ssh-ed25519 ..."
                value={sshPublic}
                onValueChange={setSshPublic}
              />
            </div>
            <div className="field-group">
              <label className="field-label" htmlFor="ssh-fp">
                Fingerprint
              </label>
              <Input
                id="ssh-fp"
                className="text-input mono"
                placeholder="SHA256:..."
                value={sshFingerprint}
                onValueChange={setSshFingerprint}
              />
            </div>
            <div className="field-group">
              <label className="field-label" htmlFor="ssh-priv">
                Private Key
              </label>
              <textarea
                id="ssh-priv"
                className="text-input mono"
                style={{ height: 84, padding: '8px 10px', fontSize: 11 }}
                value={sshPrivate}
                onChange={(e) => setSshPrivate(e.target.value)}
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
              />
            </div>
          </>
        )}

        <div className="field-group">
          <label className="field-label" htmlFor="cipher-notes">
            Notes
          </label>
          <textarea
            id="cipher-notes"
            className="text-input"
            style={{ height: 74, padding: '8px 10px', resize: 'vertical' }}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Optional notes…"
          />
        </div>

        {folders.length > 0 && (
          <div className="field-group">
            <label className="field-label" htmlFor="cipher-folder">
              Folder
            </label>
            <select
              id="cipher-folder"
              className="text-input"
              value={folderId}
              onChange={(e) => setFolderId(e.target.value)}
            >
              <option value="">No Folder</option>
              {folders.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.name}
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="switch-row">
          <span style={{ fontSize: 12.5 }}>Favorite</span>
          <Switch
            className="switch-root"
            checked={favorite}
            onCheckedChange={setFavorite}
            aria-label="Favorite"
          >
            <SwitchThumb className="switch-thumb" />
          </Switch>
        </div>

        {error && <div className="error-banner">{error}</div>}
      </div>
    </form>
  );
}
