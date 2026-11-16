import { useState } from 'react';
import { Button } from '@ui-sdk/react/button';
import {
  PasswordInput,
  PasswordInputControl,
  PasswordInputToggle,
} from '@ui-sdk/react/password-input';
import {
  ArrowLeft,
  Copy,
  Eye,
  EyeOff,
  ExternalLink,
  Pencil,
  Sparkles,
  Star,
  Trash2,
} from 'lucide-react';
import { CipherType } from '@keylet/core';
import type { MatchedCipher } from '@keylet/core';
import { TotpBadge } from './TotpBadge';

interface CipherDetailProps {
  cipher: MatchedCipher;
  onBack: () => void;
  onCopy: (label: string, value: string, isSecret?: boolean) => void;
  onAutofill: (cipherId: string) => Promise<void>;
  onEdit: (cipher: MatchedCipher) => void;
  onDelete: (cipherId: string) => Promise<void>;
}

export function CipherDetail({
  cipher,
  onBack,
  onCopy,
  onAutofill,
  onEdit,
  onDelete,
}: CipherDetailProps) {
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  return (
    <div className="app-shell">
      <div className="top-bar">
        <button
          type="button"
          className="icon-btn"
          onClick={onBack}
          aria-label="Back to list"
        >
          <ArrowLeft size={16} />
        </button>
        <div
          style={{
            flex: 1,
            fontWeight: 600,
            fontSize: 14,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          {cipher.name}
          {cipher.favorite && (
            <Star size={13} fill="var(--warning)" color="var(--warning)" />
          )}
        </div>
        {cipher.type === CipherType.Login && (
          <Button
            className="btn btn-primary"
            style={{ height: 30, padding: '0 10px', fontSize: 12 }}
            onClick={() => onAutofill(cipher.id)}
          >
            <Sparkles size={13} />
            Autofill
          </Button>
        )}
        <button
          type="button"
          className="icon-btn"
          title="Edit item"
          onClick={() => onEdit(cipher)}
        >
          <Pencil size={14} />
        </button>
        <button
          type="button"
          className="icon-btn"
          title="Delete item"
          onClick={() => setConfirmDelete((v) => !v)}
        >
          <Trash2 size={14} color={confirmDelete ? 'var(--danger)' : undefined} />
        </button>
      </div>

      {confirmDelete && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '8px 12px',
            background: 'var(--danger-soft)',
            borderBottom: '1px solid rgba(239, 68, 68, 0.25)',
            fontSize: 12,
          }}
        >
          <span>Delete &ldquo;{cipher.name}&rdquo;?</span>
          <div style={{ display: 'flex', gap: 6 }}>
            <button
              type="button"
              className="btn"
              style={{ height: 26, padding: '0 8px', fontSize: 11.5 }}
              onClick={() => setConfirmDelete(false)}
            >
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-danger"
              style={{ height: 26, padding: '0 8px', fontSize: 11.5 }}
              disabled={deleting}
              onClick={async () => {
                setDeleting(true);
                try {
                  await onDelete(cipher.id);
                } finally {
                  setDeleting(false);
                }
              }}
            >
              {deleting ? 'Deleting…' : 'Confirm'}
            </button>
          </div>
        </div>
      )}

      <div className="panel" style={{ gap: 10 }}>
        {cipher.type === CipherType.Login && cipher.login && (
          <>
            <div className="detail-card">
              {cipher.login.username && (
                <div className="detail-row">
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div className="detail-row-label">Username</div>
                    <div className="detail-row-val">{cipher.login.username}</div>
                  </div>
                  <button
                    type="button"
                    className="icon-btn"
                    onClick={() => onCopy('Username', cipher.login!.username!)}
                    aria-label="Copy username"
                  >
                    <Copy size={14} />
                  </button>
                </div>
              )}

              {cipher.login.password && (
                <div className="detail-row">
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div className="detail-row-label">Password</div>
                    <PasswordInput
                      value={cipher.login.password}
                      readOnly
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                      }}
                    >
                      <PasswordInputControl
                        className="password-control"
                        style={{ padding: 0, fontSize: 13 }}
                      />
                      <PasswordInputToggle
                        className="icon-btn"
                        aria-label="Reveal password"
                        render={(props, state) => (
                          <button {...props} type="button">
                            {state.visible ? (
                              <EyeOff size={14} />
                            ) : (
                              <Eye size={14} />
                            )}
                          </button>
                        )}
                      />
                    </PasswordInput>
                  </div>
                  <button
                    type="button"
                    className="icon-btn"
                    onClick={() => onCopy('Password', cipher.login!.password!, true)}
                    aria-label="Copy password"
                  >
                    <Copy size={14} />
                  </button>
                </div>
              )}
            </div>

            {cipher.login.totp && (
              <TotpBadge
                secret={cipher.login.totp}
                onCopy={(code) => onCopy('TOTP code', code, true)}
              />
            )}

            {cipher.login.uris.length > 0 && (
              <div className="detail-card">
                {cipher.login.uris.map((u, idx) => (
                  <div className="detail-row" key={`${u.uri}-${idx}`}>
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div className="detail-row-label">Website {idx + 1}</div>
                      <div className="detail-row-val" style={{ fontSize: 12 }}>
                        {u.uri}
                      </div>
                    </div>
                    <a
                      href={u.uri.startsWith('http') ? u.uri : `https://${u.uri}`}
                      target="_blank"
                      rel="noreferrer"
                      className="icon-btn"
                      aria-label="Open URL"
                    >
                      <ExternalLink size={14} />
                    </a>
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {cipher.type === CipherType.Card && cipher.card && (
          <div className="detail-card">
            {cipher.card.cardholderName && (
              <div className="detail-row">
                <div>
                  <div className="detail-row-label">Cardholder</div>
                  <div className="detail-row-val">{cipher.card.cardholderName}</div>
                </div>
                <button
                  type="button"
                  className="icon-btn"
                  onClick={() => onCopy('Cardholder', cipher.card!.cardholderName!)}
                >
                  <Copy size={14} />
                </button>
              </div>
            )}
            {cipher.card.number && (
              <div className="detail-row">
                <div>
                  <div className="detail-row-label">Card Number</div>
                  <div className="detail-row-val mono">{cipher.card.number}</div>
                </div>
                <button
                  type="button"
                  className="icon-btn"
                  onClick={() => onCopy('Card Number', cipher.card!.number!)}
                >
                  <Copy size={14} />
                </button>
              </div>
            )}
            {(cipher.card.expMonth || cipher.card.expYear) && (
              <div className="detail-row">
                <div>
                  <div className="detail-row-label">Expiration</div>
                  <div className="detail-row-val mono">
                    {cipher.card.expMonth ?? '--'}/{cipher.card.expYear ?? '----'}
                  </div>
                </div>
                {cipher.card.code && (
                  <button
                    type="button"
                    className="btn"
                    style={{ height: 28, fontSize: 11.5, padding: '0 8px' }}
                    onClick={() => onCopy('CVV', cipher.card!.code!)}
                  >
                    Copy CVV
                  </button>
                )}
              </div>
            )}
          </div>
        )}

        {cipher.type === CipherType.Identity && cipher.identity && (
          <div className="detail-card">
            {(cipher.identity.firstName || cipher.identity.lastName) && (
              <div className="detail-row">
                <div>
                  <div className="detail-row-label">Name</div>
                  <div className="detail-row-val">
                    {[cipher.identity.firstName, cipher.identity.lastName]
                      .filter(Boolean)
                      .join(' ')}
                  </div>
                </div>
              </div>
            )}
            {cipher.identity.email && (
              <div className="detail-row">
                <div>
                  <div className="detail-row-label">Email</div>
                  <div className="detail-row-val">{cipher.identity.email}</div>
                </div>
                <button
                  type="button"
                  className="icon-btn"
                  onClick={() => onCopy('Email', cipher.identity!.email!)}
                >
                  <Copy size={14} />
                </button>
              </div>
            )}
            {cipher.identity.phone && (
              <div className="detail-row">
                <div>
                  <div className="detail-row-label">Phone</div>
                  <div className="detail-row-val">{cipher.identity.phone}</div>
                </div>
                <button
                  type="button"
                  className="icon-btn"
                  onClick={() => onCopy('Phone', cipher.identity!.phone!)}
                >
                  <Copy size={14} />
                </button>
              </div>
            )}
          </div>
        )}

        {cipher.type === CipherType.SshKey && cipher.sshKey && (
          <div className="detail-card">
            {cipher.sshKey.keyFingerprint && (
              <div className="detail-row">
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div className="detail-row-label">Fingerprint</div>
                  <div className="detail-row-val mono" style={{ fontSize: 11.5 }}>
                    {cipher.sshKey.keyFingerprint}
                  </div>
                </div>
                <button
                  type="button"
                  className="icon-btn"
                  onClick={() => onCopy('Fingerprint', cipher.sshKey!.keyFingerprint!)}
                >
                  <Copy size={14} />
                </button>
              </div>
            )}
            {cipher.sshKey.publicKey && (
              <div className="detail-row">
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div className="detail-row-label">Public Key</div>
                  <div className="detail-row-val mono" style={{ fontSize: 11 }}>
                    {cipher.sshKey.publicKey}
                  </div>
                </div>
                <button
                  type="button"
                  className="icon-btn"
                  onClick={() => onCopy('Public Key', cipher.sshKey!.publicKey!)}
                >
                  <Copy size={14} />
                </button>
              </div>
            )}
            {cipher.sshKey.privateKey && (
              <div className="detail-row">
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div className="detail-row-label">Private Key</div>
                  <div className="detail-row-val mono" style={{ fontSize: 11 }}>
                    ••••••••••••••••••••
                  </div>
                </div>
                <button
                  type="button"
                  className="icon-btn"
                  onClick={() => onCopy('Private Key', cipher.sshKey!.privateKey!, true)}
                >
                  <Copy size={14} />
                </button>
              </div>
            )}
          </div>
        )}

        {cipher.fields.length > 0 && (
          <div className="detail-card">
            {cipher.fields.map((f, idx) => (
              <div className="detail-row" key={`${f.name}-${idx}`}>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div className="detail-row-label">{f.name || 'Field'}</div>
                  <div className="detail-row-val">{f.value}</div>
                </div>
                <button
                  type="button"
                  className="icon-btn"
                  onClick={() => onCopy(f.name || 'Field', f.value)}
                >
                  <Copy size={14} />
                </button>
              </div>
            ))}
          </div>
        )}

        {cipher.notes && (
          <div className="detail-card">
            <div className="detail-row" style={{ alignItems: 'flex-start' }}>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div className="detail-row-label">Notes</div>
                <div
                  className="detail-row-val"
                  style={{ whiteSpace: 'pre-wrap', fontSize: 12.5 }}
                >
                  {cipher.notes}
                </div>
              </div>
              <button
                type="button"
                className="icon-btn"
                onClick={() => onCopy('Notes', cipher.notes!)}
              >
                <Copy size={14} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
