import { useMemo, useState } from 'react';
import {
  Slider,
  SliderControl,
  SliderIndicator,
  SliderThumb,
  SliderTrack,
} from '@ui-sdk/react/slider';
import { Switch, SwitchThumb } from '@ui-sdk/react/switch';
import { ArrowLeft, Copy, RefreshCw } from 'lucide-react';
import {
  DEFAULT_PASSWORD_OPTIONS,
  generatePassword,
  type PasswordOptions,
} from '@keylet/core';

interface GeneratorViewProps {
  onBack: () => void;
  onCopy: (label: string, value: string) => void;
}

export function GeneratorView({ onBack, onCopy }: GeneratorViewProps) {
  const [opts, setOpts] = useState<PasswordOptions>(DEFAULT_PASSWORD_OPTIONS);
  const [seed, setSeed] = useState(0);

  const { password, entropyBits } = useMemo(() => {
    void seed;
    return generatePassword(opts);
  }, [opts, seed]);

  const strengthLabel =
    entropyBits >= 100
      ? 'Very Strong'
      : entropyBits >= 70
        ? 'Strong'
        : entropyBits >= 50
          ? 'Fair'
          : 'Weak';

  const strengthColor =
    entropyBits >= 100
      ? 'var(--success)'
      : entropyBits >= 70
        ? 'var(--accent)'
        : entropyBits >= 50
          ? 'var(--warning)'
          : 'var(--danger)';

  const toggle = (key: keyof Omit<PasswordOptions, 'length'>) => {
    setOpts((prev) => ({ ...prev, [key]: !prev[key] }));
  };

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
        <div style={{ flex: 1, fontWeight: 600, fontSize: 14 }}>
          Password Generator
        </div>
      </div>

      <div className="panel">
        <div
          className="detail-card"
          style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 10 }}
        >
          <div
            className="mono"
            style={{
              fontSize: 15,
              wordBreak: 'break-all',
              lineHeight: 1.5,
              minHeight: 46,
              color: 'var(--text-primary)',
            }}
          >
            {password}
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: 11.5,
            }}
          >
            <span style={{ color: strengthColor, fontWeight: 600 }}>
              {strengthLabel} ({entropyBits} bits)
            </span>
            <div style={{ display: 'flex', gap: 6 }}>
              <button
                type="button"
                className="btn"
                style={{ height: 28, padding: '0 10px', fontSize: 12 }}
                onClick={() => setSeed((s) => s + 1)}
              >
                <RefreshCw size={13} />
                New
              </button>
              <button
                type="button"
                className="btn btn-primary"
                style={{ height: 28, padding: '0 10px', fontSize: 12 }}
                onClick={() => onCopy('Generated password', password)}
              >
                <Copy size={13} />
                Copy
              </button>
            </div>
          </div>
        </div>

        <div className="detail-card" style={{ padding: 12 }}>
          <Slider
            className="slider-root"
            min={8}
            max={64}
            step={1}
            value={opts.length}
            onValueChange={(val) => {
              const next = Array.isArray(val) ? val[0] : val;
              setOpts((prev) => ({ ...prev, length: next }));
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                fontSize: 12,
              }}
            >
              <span className="field-label">Length</span>
              <span className="mono" style={{ fontWeight: 600 }}>
                {opts.length}
              </span>
            </div>
            <SliderControl className="slider-control">
              <SliderTrack className="slider-track">
                <SliderIndicator className="slider-indicator" />
                <SliderThumb
                  index={0}
                  className="slider-thumb"
                  aria-label="Password length"
                />
              </SliderTrack>
            </SliderControl>
          </Slider>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {(
            [
              ['uppercase', 'Uppercase (A-Z)'],
              ['lowercase', 'Lowercase (a-z)'],
              ['numbers', 'Numbers (0-9)'],
              ['symbols', 'Symbols (!@#$...)'],
              ['excludeAmbiguous', 'Avoid Ambiguous (I, l, 1, O, 0)'],
            ] as const
          ).map(([key, label]) => (
            <div className="switch-row" key={key}>
              <span style={{ fontSize: 12.5 }}>{label}</span>
              <Switch
                className="switch-root"
                checked={opts[key]}
                onCheckedChange={() => toggle(key)}
                aria-label={label}
              >
                <SwitchThumb className="switch-thumb" />
              </Switch>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
