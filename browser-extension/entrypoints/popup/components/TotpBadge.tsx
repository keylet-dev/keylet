import { useEffect, useState } from 'react';
import { Copy } from 'lucide-react';
import { generateTotp, type TotpResult } from '@keylet/core';

interface TotpBadgeProps {
  secret: string;
  onCopy: (code: string) => void;
}

export function TotpBadge({ secret, onCopy }: TotpBadgeProps) {
  const [totp, setTotp] = useState<TotpResult | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function tick() {
      try {
        const res = await generateTotp(secret);
        if (!cancelled) {
          setTotp(res);
          setError(false);
        }
      } catch {
        if (!cancelled) setError(true);
      }
    }

    void tick();
    const timer = setInterval(() => {
      void tick();
    }, 1000);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [secret]);

  if (error || !totp) return null;

  const radius = 10;
  const circumference = 2 * Math.PI * radius;
  const progress = totp.remainingSeconds / totp.period;
  const strokeDashoffset = circumference * (1 - progress);
  const formattedCode =
    totp.code.length === 6
      ? `${totp.code.slice(0, 3)} ${totp.code.slice(3)}`
      : totp.code;

  return (
    <div
      className="totp-box"
      onClick={() => onCopy(totp.code)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onCopy(totp.code);
        }
      }}
      title="Click to copy TOTP code"
    >
      <div>
        <div className="detail-row-label">Verification Code (TOTP)</div>
        <div className="totp-code">{formattedCode}</div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <svg width="26" height="26" viewBox="0 0 26 26">
          <circle
            cx="13"
            cy="13"
            r={radius}
            fill="none"
            stroke="rgba(255,255,255,0.1)"
            strokeWidth="2.5"
          />
          <circle
            cx="13"
            cy="13"
            r={radius}
            fill="none"
            stroke={totp.remainingSeconds <= 5 ? 'var(--warning)' : 'var(--accent)'}
            strokeWidth="2.5"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            transform="rotate(-90 13 13)"
          />
          <text
            x="13"
            y="16"
            textAnchor="middle"
            fontSize="8.5"
            fill="var(--text-secondary)"
            fontFamily="var(--font-mono)"
          >
            {totp.remainingSeconds}
          </text>
        </svg>
        <Copy size={14} color="var(--text-secondary)" />
      </div>
    </div>
  );
}
