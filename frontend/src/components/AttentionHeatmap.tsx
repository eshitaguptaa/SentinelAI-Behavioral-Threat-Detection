import { memo, useMemo } from "react";

import styles from "./AttentionHeatmap.module.css";
import type { BehaviourInsight } from "../types/models";

interface AttentionHeatmapProps {
  insight: BehaviourInsight | null | undefined;
}

/** Event types that typically carry investigative weight — used only to
 *  emphasize legend labels when those rows/cols already have high attention.
 *  Display weights are always derived from real last-layer attention. */
const HIGHLIGHT_EVENTS = new Set([
  "FAILED_LOGIN",
  "ADMIN_LOGIN",
  "USB_INSERT",
  "FILE_DOWNLOAD",
  "VPN_CONNECT",
  "POLICY_CHANGE",
  "SSH_LOGIN",
  "REMOTE_DESKTOP",
  "PASSWORD_CHANGE",
]);

/**
 * Contrast-enhance a raw attention matrix for display only.
 * Uses robust percentile normalisation + gamma so peaks stand out without
 * inventing weights.
 */
function enhanceAttentionMatrix(
  matrix: number[][],
  size: number,
): number[][] {
  const values: number[] = [];
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c < size; c += 1) {
      const v = Number(matrix[r]?.[c] ?? 0);
      if (Number.isFinite(v)) values.push(v);
    }
  }
  if (values.length === 0) return [];

  const sorted = [...values].sort((a, b) => a - b);
  const at = (p: number) =>
    sorted[Math.min(sorted.length - 1, Math.max(0, Math.floor(p * (sorted.length - 1))))];
  const lo = at(0.05);
  const hi = Math.max(at(0.95), lo + 1e-9);
  const gamma = 0.55;

  const out: number[][] = [];
  for (let r = 0; r < size; r += 1) {
    const row: number[] = [];
    for (let c = 0; c < size; c += 1) {
      const raw = Number(matrix[r]?.[c] ?? 0);
      const clipped = Math.min(hi, Math.max(lo, raw));
      const norm = (clipped - lo) / (hi - lo);
      row.push(Math.pow(norm, gamma));
    }
    out.push(row);
  }
  return out;
}

function AttentionHeatmap({ insight }: AttentionHeatmapProps) {
  const available = insight?.attention_available !== false;
  const matrix = available ? (insight?.attention_weights ?? []) : [];
  const labels = insight?.event_types ?? [];
  const size = Math.min(matrix.length, labels.length, 16);

  const { cells, peakLabels } = useMemo(() => {
    const enhanced = enhanceAttentionMatrix(matrix, size);
    const rows: { key: string; value: number; highlight: boolean }[][] = [];
    const peaks = new Set<string>();

    for (let r = 0; r < size; r += 1) {
      const row: { key: string; value: number; highlight: boolean }[] = [];
      for (let c = 0; c < size; c += 1) {
        const value = enhanced[r]?.[c] ?? 0;
        const rowLabel = labels[r] ?? "";
        const colLabel = labels[c] ?? "";
        const highlight =
          value >= 0.72 &&
          (HIGHLIGHT_EVENTS.has(rowLabel) || HIGHLIGHT_EVENTS.has(colLabel));
        if (highlight) {
          peaks.add(rowLabel);
          peaks.add(colLabel);
        }
        row.push({
          key: `${r}-${c}`,
          value,
          highlight,
        });
      }
      rows.push(row);
    }
    return { cells: rows, peakLabels: peaks };
  }, [matrix, size, labels]);

  if (!insight) {
    return (
      <section className={styles.panel} aria-label="Attention heatmap">
        <h2 className={styles.title}>Attention Heatmap</h2>
        <p className={styles.empty}>
          Attention weights appear after Transformer inference on a session.
        </p>
      </section>
    );
  }

  if (!available || size === 0) {
    return (
      <section className={styles.panel} aria-label="Attention heatmap">
        <h2 className={styles.title}>Attention Heatmap</h2>
        <p className={styles.empty}>Attention unavailable</p>
      </section>
    );
  }

  return (
    <section className={styles.panel} aria-label="Attention heatmap">
      <h2 className={styles.title}>Attention Heatmap</h2>
      <p className={styles.caption}>
        Real last-layer self-attention (first {size} events). Display-normalised
        for contrast — brighter cells = stronger attention.
      </p>
      <div
        className={styles.grid}
        style={{ gridTemplateColumns: `repeat(${size}, minmax(0, 1fr))` }}
      >
        {cells.flatMap((row, r) =>
          row.map((cell) => {
            const alpha = 0.06 + cell.value * 0.94;
            const glow = cell.highlight ? 0.35 + cell.value * 0.45 : 0;
            return (
              <div
                key={cell.key}
                className={cell.highlight ? styles.cellHot : styles.cell}
                title={`${labels[r]} → weight ${cell.value.toFixed(3)}`}
                style={{
                  background: `rgba(226, 75, 75, ${alpha})`,
                  boxShadow: glow
                    ? `0 0 6px rgba(226, 75, 75, ${glow})`
                    : undefined,
                }}
              />
            );
          }),
        )}
      </div>
      <div className={styles.legend}>
        {labels.slice(0, size).map((label) => (
          <span
            key={label}
            className={
              peakLabels.has(label) ? styles.legendItemHot : styles.legendItem
            }
          >
            {label}
          </span>
        ))}
      </div>
    </section>
  );
}

export default memo(AttentionHeatmap);
