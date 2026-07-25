import { memo, useMemo } from "react";

import styles from "./AttentionHeatmap.module.css";
import type { BehaviourInsight } from "../types/models";

interface AttentionHeatmapProps {
  insight: BehaviourInsight | null | undefined;
}

function AttentionHeatmap({ insight }: AttentionHeatmapProps) {
  const available = insight?.attention_available !== false;
  const matrix = available ? (insight?.attention_weights ?? []) : [];
  const labels = insight?.event_types ?? [];
  const size = Math.min(matrix.length, labels.length, 16);

  const cells = useMemo(() => {
    const rows: { key: string; value: number }[][] = [];
    for (let r = 0; r < size; r += 1) {
      const row: { key: string; value: number }[] = [];
      for (let c = 0; c < size; c += 1) {
        row.push({
          key: `${r}-${c}`,
          value: Number(matrix[r]?.[c] ?? 0),
        });
      }
      rows.push(row);
    }
    return rows;
  }, [matrix, size]);

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
        Real last-layer self-attention (first {size} events; brighter = stronger).
      </p>
      <div
        className={styles.grid}
        style={{ gridTemplateColumns: `repeat(${size}, minmax(0, 1fr))` }}
      >
        {cells.flatMap((row, r) =>
          row.map((cell) => (
            <div
              key={cell.key}
              className={styles.cell}
              title={`${labels[r]} → weight ${cell.value.toFixed(3)}`}
              style={{
                background: `rgba(226, 75, 75, ${0.08 + Math.min(1, cell.value) * 0.85})`,
              }}
            />
          )),
        )}
      </div>
      <div className={styles.legend}>
        {labels.slice(0, size).map((label) => (
          <span key={label} className={styles.legendItem}>
            {label}
          </span>
        ))}
      </div>
    </section>
  );
}

export default memo(AttentionHeatmap);
