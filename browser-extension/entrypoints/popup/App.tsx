import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Input, InputClear, InputGroup } from '@ui-sdk/react/input';
import {
  SegmentedControl,
  SegmentedControlIndicator,
  SegmentedControlItem,
} from '@ui-sdk/react/segmented-control';
import {
  Copy,
  CreditCard,
  FileText,
  KeyRound,
  Lock,
  Plus,
  Search,
  Settings,
  Sparkles,
  Star,
  User,
  Wand2,
  X,
} from 'lucide-react';
import { CipherType, type DecryptedFolder } from '@keylet/core';
import type { CipherInput } from '@keylet/core';
import type {
  MatchedCipher,
  VaultDataPayload,
  VaultStatus,
} from '@keylet/core';
import { CipherDetail } from './components/CipherDetail';
import { CipherForm } from './components/CipherForm';
import { GeneratorView } from './components/GeneratorView';
import { KeyletLogo } from './components/KeyletLogo';
import { LockView } from './components/LockView';
import { LoginView } from './components/LoginView';
import { SettingsView } from './components/SettingsView';
import { sendRuntimeMessage } from './ipc';

type FilterTab = 'all' | 'logins' | 'notes' | 'cards' | 'favorites';
type SubView = 'list' | 'generator' | 'settings' | 'create' | 'edit' | 'add_account';

const FILTER_TABS: FilterTab[] = ['all', 'logins', 'notes', 'cards', 'favorites'];

function cipherSubtitle(c: MatchedCipher): string {
  if (c.type === CipherType.Login) return c.login?.username || 'No username';
  if (c.type === CipherType.Card) {
    const last4 = c.card?.number ? c.card.number.slice(-4) : '••••';
    return `${c.card?.brand ?? 'Card'} •••• ${last4}`;
  }
  if (c.type === CipherType.Identity) {
    return c.identity?.email || c.identity?.username || 'Identity';
  }
  if (c.type === CipherType.SshKey) {
    return c.sshKey?.keyFingerprint || 'SSH Key';
  }
  return 'Secure Note';
}

function CipherAvatar({ cipher }: { cipher: MatchedCipher }) {
  switch (cipher.type) {
    case CipherType.Login:
      return <>{(cipher.name.trim()[0] ?? 'K').toUpperCase()}</>;
    case CipherType.Card:
      return <CreditCard size={14} />;
    case CipherType.Identity:
      return <User size={14} />;
    case CipherType.SshKey:
      return <KeyRound size={14} />;
    default:
      return <FileText size={14} />;
  }
}

export function App() {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [ciphers, setCiphers] = useState<MatchedCipher[]>([]);
  const [folders, setFolders] = useState<DecryptedFolder[]>([]);
  const [tabUrl, setTabUrl] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<FilterTab>('all');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [activeCipher, setActiveCipher] = useState<MatchedCipher | null>(null);
  const [subView, setSubView] = useState<SubView>('list');
  const [toast, setToast] = useState<string | null>(null);

  const searchRef = useRef<HTMLInputElement>(null);
  const rowRefs = useRef<(HTMLDivElement | null)[]>([]);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const clipTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 1800);
  }, []);

  const loadVault = useCallback(async () => {
    const data = await sendRuntimeMessage<VaultDataPayload>({
      type: 'GET_VAULT_DATA',
    });
    setCiphers(data.ciphers);
    setFolders(data.folders);
    setTabUrl(data.tabUrl);
  }, []);

  const refreshStatus = useCallback(async () => {
    const s = await sendRuntimeMessage<VaultStatus>({ type: 'GET_STATUS' });
    setStatus(s);
    if (s.state === 'unlocked') {
      await loadVault();
    } else {
      setCiphers([]);
      setActiveCipher(null);
      setSubView('list');
    }
  }, [loadVault]);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  const copySecret = useCallback(
    async (label: string, value: string, isSecret = false) => {
      await navigator.clipboard.writeText(value);
      const clearSecs = status?.clipboardClearSeconds ?? 30;
      if (clipTimer.current) clearTimeout(clipTimer.current);
      if (isSecret && clearSecs > 0) {
        showToast(`Copied ${label} (clears in ${clearSecs}s)`);
        clipTimer.current = setTimeout(() => {
          void navigator.clipboard.writeText('').catch(() => {});
        }, clearSecs * 1000);
      } else {
        showToast(`Copied ${label}`);
      }
    },
    [showToast, status?.clipboardClearSeconds],
  );

  const handleSaveCipher = useCallback(
    async (cipherInput: CipherInput, cipherId?: string) => {
      const nextStatus = await sendRuntimeMessage<VaultStatus>(
        cipherId
          ? { type: 'UPDATE_CIPHER', cipherId, cipher: cipherInput }
          : { type: 'CREATE_CIPHER', cipher: cipherInput },
      );
      setStatus(nextStatus);
      await loadVault();
      setActiveCipher(null);
      setSubView('list');
      showToast(cipherId ? 'Item updated' : 'Item saved');
    },
    [loadVault, showToast],
  );

  const handleDeleteCipher = useCallback(
    async (cipherId: string) => {
      const nextStatus = await sendRuntimeMessage<VaultStatus>({
        type: 'DELETE_CIPHER',
        cipherId,
      });
      setStatus(nextStatus);
      await loadVault();
      setActiveCipher(null);
      setSubView('list');
      showToast('Item deleted');
    },
    [loadVault, showToast],
  );

  const handleAutofill = useCallback(
    async (cipherId: string) => {
      try {
        await sendRuntimeMessage({ type: 'AUTOFILL_CIPHER', cipherId });
        showToast('Autofilled');
        window.close();
      } catch (err) {
        showToast(err instanceof Error ? err.message : 'Autofill failed');
      }
    },
    [showToast],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return ciphers.filter((c) => {
      if (filter === 'logins' && c.type !== CipherType.Login) return false;
      if (filter === 'notes' && c.type !== CipherType.SecureNote) return false;
      if (filter === 'cards' && c.type !== CipherType.Card) return false;
      if (filter === 'favorites' && !c.favorite) return false;

      if (!q) return true;
      const hay = [
        c.name,
        c.login?.username ?? '',
        ...(c.login?.uris.map((u) => u.uri) ?? []),
        c.notes ?? '',
      ]
        .join(' ')
        .toLowerCase();
      return hay.includes(q);
    });
  }, [ciphers, filter, query]);

  const tabMatches = useMemo(
    () => filtered.filter((c) => c.matchScore > 0),
    [filtered],
  );
  const otherItems = useMemo(
    () => filtered.filter((c) => c.matchScore === 0),
    [filtered],
  );

  // Flat ordered list matching visual order for keyboard navigation
  const orderedList = useMemo(
    () => [...tabMatches, ...otherItems],
    [tabMatches, otherItems],
  );

  useEffect(() => {
    setSelectedIndex(0);
  }, [query, filter]);

  useEffect(() => {
    rowRefs.current[selectedIndex]?.scrollIntoView({ block: 'nearest' });
  }, [selectedIndex]);

  useEffect(() => {
    if (status?.state === 'unlocked' && subView === 'list' && !activeCipher) {
      searchRef.current?.focus();
    }
  }, [status?.state, subView, activeCipher]);

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((i) =>
        orderedList.length ? (i + 1) % orderedList.length : 0,
      );
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((i) =>
        orderedList.length
          ? (i - 1 + orderedList.length) % orderedList.length
          : 0,
      );
    } else if (e.key === 'Tab') {
      e.preventDefault();
      const idx = FILTER_TABS.indexOf(filter);
      const next =
        FILTER_TABS[
          (idx + (e.shiftKey ? -1 : 1) + FILTER_TABS.length) % FILTER_TABS.length
        ]!;
      setFilter(next);
    } else if (e.key === 'Enter') {
      const target = orderedList[selectedIndex];
      if (!target) return;
      e.preventDefault();
      if (e.metaKey || e.ctrlKey) {
        setActiveCipher(target);
      } else if (target.matchScore > 0 && target.type === CipherType.Login) {
        void handleAutofill(target.id);
      } else if (target.type === CipherType.Login && target.login?.password) {
        void copySecret('Password', target.login.password, true);
      } else {
        setActiveCipher(target);
      }
    } else if (e.key === 'ArrowRight' && document.activeElement !== searchRef.current) {
      const target = orderedList[selectedIndex];
      if (target) setActiveCipher(target);
    } else if (e.key === 'Escape' && query) {
      e.preventDefault();
      setQuery('');
    }
  }

  if (!status) {
    return (
      <div className="empty-state">
        <KeyletLogo size={36} />
        <span>Loading Keylet…</span>
      </div>
    );
  }

  if (status.state === 'logged_out' || subView === 'add_account') {
    return (
      <LoginView
        onCancel={
          status.accounts.length > 0
            ? () => setSubView('list')
            : undefined
        }
        onSuccess={async (next) => {
          setStatus(next);
          setSubView('list');
          if (next.state === 'unlocked') await loadVault();
        }}
      />
    );
  }

  if (status.state === 'locked') {
    return (
      <LockView
        status={status}
        onUnlock={async (next) => {
          setStatus(next);
          if (next.state === 'unlocked') await loadVault();
        }}
        onSwitchAccount={async (accountId) => {
          const next = await sendRuntimeMessage<VaultStatus>({
            type: 'SWITCH_ACCOUNT',
            accountId,
          });
          setStatus(next);
        }}
        onAddAccount={() => setSubView('add_account')}
        onLogout={(next) => setStatus(next)}
      />
    );
  }

  if (subView === 'generator') {
    return (
      <div className="app-shell">
        <GeneratorView
          onBack={() => setSubView('list')}
          onCopy={(label, val) => void copySecret(label, val)}
        />
        {toast && <div className="toast-pill">{toast}</div>}
      </div>
    );
  }

  if (subView === 'settings') {
    return (
      <div className="app-shell">
        <SettingsView
          status={status}
          onBack={() => setSubView('list')}
          onStatusChange={(next) => {
            setStatus(next);
            if (next.state === 'unlocked') void loadVault();
          }}
          onAddAccount={() => setSubView('add_account')}
          onToast={showToast}
        />
        {toast && <div className="toast-pill">{toast}</div>}
      </div>
    );
  }

  if (subView === 'create' || (subView === 'edit' && activeCipher)) {
    let defaultOrigin: string | null = null;
    if (tabUrl && (tabUrl.startsWith('http://') || tabUrl.startsWith('https://'))) {
      try {
        defaultOrigin = new URL(tabUrl).origin;
      } catch {
        defaultOrigin = null;
      }
    }
    return (
      <div className="app-shell">
        <CipherForm
          initialCipher={subView === 'edit' ? activeCipher : null}
          folders={folders}
          defaultUri={subView === 'create' ? defaultOrigin : null}
          onCancel={() => setSubView('list')}
          onSave={handleSaveCipher}
        />
        {toast && <div className="toast-pill">{toast}</div>}
      </div>
    );
  }

  if (activeCipher) {
    return (
      <div className="app-shell">
        <CipherDetail
          cipher={activeCipher}
          onBack={() => setActiveCipher(null)}
          onCopy={(label, val, isSecret) =>
            void copySecret(label, val, isSecret)
          }
          onAutofill={handleAutofill}
          onEdit={() => setSubView('edit')}
          onDelete={handleDeleteCipher}
        />
        {toast && <div className="toast-pill">{toast}</div>}
      </div>
    );
  }

  const renderRow = (c: MatchedCipher, flatIdx: number) => {
    const isSelected = flatIdx === selectedIndex;
    return (
      <div
        key={c.id}
        ref={(el) => {
          rowRefs.current[flatIdx] = el;
        }}
        className="cipher-row"
        data-selected={isSelected}
        onMouseEnter={() => setSelectedIndex(flatIdx)}
        onClick={() => setActiveCipher(c)}
      >
        <div className="cipher-avatar">
          <CipherAvatar cipher={c} />
        </div>
        <div className="cipher-meta">
          <div className="cipher-title">
            <span
              style={{
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              {c.name}
            </span>
            {c.favorite && (
              <Star size={11} fill="var(--warning)" color="var(--warning)" />
            )}
            {c.matchScore > 0 && <span className="match-badge">Match</span>}
          </div>
          <div className="cipher-subtitle">{cipherSubtitle(c)}</div>
        </div>

        <div className="row-actions" onClick={(e) => e.stopPropagation()}>
          {c.type === CipherType.Login && c.matchScore > 0 && (
            <button
              type="button"
              className="icon-btn"
              title="Autofill"
              onClick={() => void handleAutofill(c.id)}
            >
              <Sparkles size={14} color="var(--accent)" />
            </button>
          )}
          {c.type === CipherType.Login && c.login?.username && (
            <button
              type="button"
              className="icon-btn"
              title="Copy username"
              onClick={() => void copySecret('Username', c.login!.username!)}
            >
              <User size={14} />
            </button>
          )}
          {c.type === CipherType.Login && c.login?.password && (
            <button
              type="button"
              className="icon-btn"
              title="Copy password"
              onClick={() =>
                void copySecret('Password', c.login!.password!, true)
              }
            >
              <Copy size={14} />
            </button>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="app-shell" onKeyDown={handleKeyDown}>
      <div className="top-bar">
        <InputGroup className="search-group">
          <Search size={15} color="var(--text-muted)" />
          <Input
            ref={searchRef}
            className="search-input"
            placeholder="Search vault…"
            value={query}
            onValueChange={setQuery}
            autoFocus
          />
          <InputClear
            className="clear-btn"
            aria-label="Clear search"
            render={(props) => (
              <button {...props} type="button">
                <X size={12} />
              </button>
            )}
          />
        </InputGroup>

        <button
          type="button"
          className="icon-btn"
          title="New Item"
          onClick={() => {
            setActiveCipher(null);
            setSubView('create');
          }}
        >
          <Plus size={16} />
        </button>
        <button
          type="button"
          className="icon-btn"
          title="Password Generator"
          onClick={() => setSubView('generator')}
        >
          <Wand2 size={15} />
        </button>
        <button
          type="button"
          className="icon-btn"
          title="Settings"
          onClick={() => setSubView('settings')}
        >
          <Settings size={15} />
        </button>
        <button
          type="button"
          className="icon-btn"
          title="Lock Vault"
          onClick={async () => {
            const next = await sendRuntimeMessage<VaultStatus>({ type: 'LOCK' });
            setStatus(next);
          }}
        >
          <Lock size={15} />
        </button>
      </div>

      <div className="filter-bar">
        <SegmentedControl
          className="segmented"
          value={filter}
          onValueChange={(v) => {
            if (v) setFilter(v);
          }}
        >
          <SegmentedControlIndicator className="segmented-indicator" />
          <SegmentedControlItem className="segmented-item" value="all">
            All
          </SegmentedControlItem>
          <SegmentedControlItem className="segmented-item" value="logins">
            Logins
          </SegmentedControlItem>
          <SegmentedControlItem className="segmented-item" value="notes">
            Notes
          </SegmentedControlItem>
          <SegmentedControlItem className="segmented-item" value="cards">
            Cards
          </SegmentedControlItem>
          <SegmentedControlItem className="segmented-item" value="favorites">
            Favs
          </SegmentedControlItem>
        </SegmentedControl>
      </div>

      <div className="scroll-body">
        {orderedList.length === 0 ? (
          <div className="empty-state">
            <Search size={22} />
            <span>
              {query ? `No items matching "${query}"` : 'No items in this view'}
            </span>
          </div>
        ) : (
          <>
            {tabMatches.length > 0 && (
              <>
                <div className="section-label">Current Tab</div>
                {tabMatches.map((c, idx) => renderRow(c, idx))}
              </>
            )}
            {otherItems.length > 0 && (
              <>
                <div className="section-label">
                  {tabMatches.length > 0 ? 'All Items' : 'Vault'}
                </div>
                {otherItems.map((c, idx) =>
                  renderRow(c, tabMatches.length + idx),
                )}
              </>
            )}
          </>
        )}
      </div>

      <div className="footer-bar">
        <span>
          <span className="kbd">↑↓</span> navigate ·{' '}
          <span className="kbd">↵</span>{' '}
          {orderedList[selectedIndex]?.matchScore ? 'autofill' : 'copy'} ·{' '}
          <span className="kbd">⌘↵</span> details
        </span>
        <span>
          <span className="kbd">Tab</span> filter
        </span>
      </div>

      {toast && <div className="toast-pill">{toast}</div>}
    </div>
  );
}
