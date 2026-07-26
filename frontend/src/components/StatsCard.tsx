import { useEffect, useRef, useState } from "react";

import styles from "./StatsCard.module.css";

interface StatsCardProps {
  label: string;
  value: number | string;
  tone?: "default" | "anomaly" | "high" | "critical";
  hint?: string;
  /** Count-up duration in ms when value is numeric. */
  durationMs?: number;
}

function easeOutCubic(t: number): number {
  return 1 - (1 - t) ** 3;
}

function useCountUp(target: number, durationMs: number): number {
  const [display, setDisplay] = useState(0);
  const displayRef = useRef(0);
  const frameRef = useRef(0);

  useEffect(() => {
    const from = displayRef.current;
    const start = performance.now();

    if (frameRef.current) {
      cancelAnimationFrame(frameRef.current);
    }

    if (target === from) {
      setDisplay(target);
      displayRef.current = target;
      return;
    }

    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / durationMs);
      const next = Math.round(from + (target - from) * easeOutCubic(progress));
      displayRef.current = next;
      setDisplay(next);
      if (progress < 1) {
        frameRef.current = requestAnimationFrame(tick);
      }
    };

    frameRef.current = requestAnimationFrame(tick);
    return () => {
      if (frameRef.current) cancelAnimationFrame(frameRef.current);
    };
  }, [target, durationMs]);

  return display;
}

export default function StatsCard({
  label,
  value,
  tone = "default",
  hint,
  durationMs = 900,
}: StatsCardProps) {
  const numeric = typeof value === "number" && Number.isFinite(value);
  const counted = useCountUp(numeric ? value : 0, durationMs);

  return (
    <article className={`${styles.card} ${styles[tone]}`}>
      <p className={styles.label}>{label}</p>
      <p className={styles.value} aria-label={numeric ? String(value) : undefined}>
        {numeric ? counted : value}
      </p>
      {hint ? <p className={styles.hint}>{hint}</p> : null}
    </article>
  );
}
