interface KeyletLogoProps {
  size?: number;
}

export function KeyletLogo({ size = 34 }: KeyletLogoProps) {
  const iconSize = Math.round(size * 0.56);
  const radius = Math.round(size * 0.24);
  return (
    <span
      style={{
        width: size,
        height: size,
        borderRadius: radius,
        background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: '#ffffff',
        flexShrink: 0,
        boxShadow: '0 2px 8px rgba(37, 99, 235, 0.35)',
      }}
    >
      <svg
        width={iconSize}
        height={iconSize}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <circle cx="7.5" cy="15.5" r="4.5" />
        <path d="m21 2-9.6 9.6" />
        <path d="m15.5 7.5 3 3L22 7l-3-3" />
      </svg>
    </span>
  );
}
