import type { CSSProperties } from "react";

type LogoProps = {
  /** Show wordmark next to the mark */
  withWordmark?: boolean;
  /** Wordmark color for light/dark surfaces */
  wordmarkTone?: "light" | "dark";
  /** Mark edge length in px */
  size?: number;
  className?: string;
  style?: CSSProperties;
};

/** SentinelAI brand mark: Honeywell-red square with white lowercase s + optional wordmark. */
export function Logo({
  withWordmark = true,
  wordmarkTone = "light",
  size = 32,
  className,
  style,
}: LogoProps) {
  const wordmarkColor = wordmarkTone === "dark" ? "#111111" : "#FFFFFF";
  const wordmarkSize = Math.max(15, Math.round(size * 0.66));

  return (
    <span
      className={className}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: Math.max(10, Math.round(size * 0.34)),
        lineHeight: 1,
        ...style,
      }}
    >
      <svg
        width={size}
        height={size}
        viewBox="0 0 36 36"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden={withWordmark}
        role={withWordmark ? "presentation" : "img"}
        aria-label={withWordmark ? undefined : "SentinelAI"}
        style={{ flexShrink: 0 }}
        shapeRendering="geometricPrecision"
      >
        <rect width="36" height="36" fill="#E4002B" />
        <path
          fill="#FFFFFF"
          d="M25.2 13.1c0-2.85-2.25-4.7-5.85-4.7-3.55 0-6.05 1.85-6.55 4.75h3.55c.35-1.2 1.5-2.05 3-2.05 1.55 0 2.55.8 2.55 2 0 1.15-.75 1.75-3.15 2.4l-1.55.4c-3.45.9-5.25 2.45-5.25 5.35 0 3.15 2.5 5.2 6.25 5.2 3.7 0 6.3-1.95 6.85-4.9h-3.6c-.35 1.35-1.6 2.2-3.3 2.2-1.7 0-2.85-.85-2.85-2.15 0-1.15.8-1.8 3.2-2.45l1.6-.4c3.55-.95 5.25-2.55 5.25-5.65z"
        />
      </svg>

      {withWordmark ? (
        <span
          style={{
            fontFamily:
              '"Plus Jakarta Sans", "IBM Plex Sans", system-ui, -apple-system, sans-serif',
            fontSize: wordmarkSize,
            fontWeight: 700,
            letterSpacing: "-0.02em",
            color: wordmarkColor,
            whiteSpace: "nowrap",
          }}
        >
          SentinelAI
        </span>
      ) : null}
    </span>
  );
}

export default Logo;
