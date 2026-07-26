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

type BrandNameProps = {
  className?: string;
  style?: CSSProperties;
  /** Base color for "Sentinel"; "AI" is always theme red. */
  tone?: "light" | "dark" | "inherit";
};

const THEME_RED = "var(--hw-red, #E4002B)";

/** "Sentinel" + red "AI" — use for all product wordmarks. */
export function BrandName({
  className,
  style,
  tone = "inherit",
}: BrandNameProps) {
  const baseColor =
    tone === "light" ? "#FFFFFF" : tone === "dark" ? "#111111" : undefined;

  return (
    <span
      className={className}
      style={{
        color: baseColor,
        ...style,
      }}
    >
      Sentinel
      <span style={{ color: THEME_RED }}>AI</span>
    </span>
  );
}

/** SentinelAI brand mark from ``/logo.png`` + optional wordmark. */
export function Logo({
  withWordmark = true,
  wordmarkTone = "light",
  size = 32,
  className,
  style,
}: LogoProps) {
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
      <img
        src="/logo.png"
        width={size}
        height={size}
        alt={withWordmark ? "" : "SentinelAI"}
        aria-hidden={withWordmark}
        style={{
          flexShrink: 0,
          width: size,
          height: size,
          objectFit: "contain",
          display: "block",
          borderRadius: Math.max(4, Math.round(size * 0.12)),
        }}
      />

      {withWordmark ? (
        <BrandName
          tone={wordmarkTone}
          style={{
            fontFamily:
              '"Plus Jakarta Sans", "IBM Plex Sans", system-ui, -apple-system, sans-serif',
            fontSize: wordmarkSize,
            fontWeight: 700,
            letterSpacing: "-0.02em",
            whiteSpace: "nowrap",
          }}
        />
      ) : null}
    </span>
  );
}

export default Logo;
