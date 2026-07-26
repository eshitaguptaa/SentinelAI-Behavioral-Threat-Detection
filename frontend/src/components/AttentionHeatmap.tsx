import { memo, useMemo, useState, type CSSProperties } from "react";

import styles from "./AttentionHeatmap.module.css";
import type { BehaviourInsight } from "../types/models";

interface AttentionHeatmapProps {
  insight: BehaviourInsight | null | undefined;
}

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
    sorted[
      Math.min(
        sorted.length - 1,
        Math.max(0, Math.floor(p * (sorted.length - 1))),
      )
    ];
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

function friendlyLabel(label: string): string {
  return label.replace(/_/g, " ");
}

function AttentionHeatmap({ insight }: AttentionHeatmapProps) {
  const available = insight?.attention_available !== false;
  const matrix = available ? (insight?.attention_weights ?? []) : [];
  const labels = insight?.event_types ?? [];
  const size = Math.min(matrix.length, labels.length, 16);
  const [active, setActive] = useState<{ row: number; col: number } | null>(
    null,
  );
  const [focusIndex, setFocusIndex] = useState<number | null>(null);

  const { cells, peakIndexes, peakCount, topLinks } = useMemo(() => {
    const enhanced = enhanceAttentionMatrix(matrix, size);
    const rows: { key: string; value: number; highlight: boolean }[][] = [];
    const peaks = new Set<number>();
    const links: { row: number; col: number; value: number }[] = [];

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
          peaks.add(r);
          peaks.add(c);
        }
        if (value >= 0.72 && r !== c) {
          links.push({ row: r, col: c, value });
        }
        row.push({ key: `${r}-${c}`, value, highlight });
      }
      rows.push(row);
    }

    links.sort((a, b) => b.value - a.value);

    return {
      cells: rows,
      peakIndexes: peaks,
      peakCount: peaks.size,
      topLinks: links.slice(0, 3),
    };
  }, [matrix, size, labels]);

  if (!insight) {
    return (
      <section className={styles.panel} aria-label="Attention heatmap">
        <div className={styles.header}>
          <div>
            <p className={styles.kicker}>Evidence</p>
            <h2 className={styles.title}>Attention map</h2>
          </div>
        </div>
        <p className={styles.empty}>
          Attention weights appear after Transformer inference on a session.
        </p>
      </section>
    );
  }

  if (!available || size === 0) {
    return (
      <section className={styles.panel} aria-label="Attention heatmap">
        <div className={styles.header}>
          <div>
            <p className={styles.kicker}>Evidence</p>
            <h2 className={styles.title}>Attention map</h2>
          </div>
        </div>
        <p className={styles.empty}>Attention unavailable for this session.</p>
      </section>
    );
  }

  const hoverRow = active?.row ?? focusIndex;
  const hoverCol = active?.col ?? focusIndex;
  const activeCell = active != null ? cells[active.row]?.[active.col] : null;
  const fromLabel =
    active != null ? friendlyLabel(labels[active.row] ?? "") : null;
  const toLabel =
    active != null ? friendlyLabel(labels[active.col] ?? "") : null;

  const matrixStyle = {
    "--matrix-size": size,
  } as CSSProperties;

  return (
    <section className={styles.panel} aria-label="Attention heatmap">
      <div className={styles.header}>
        <div>
          <p className={styles.kicker}>Evidence</p>
          <h2 className={styles.title}>Attention map</h2>
          <p className={styles.caption}>
            Deeper red means stronger focus between events. Hover a cell to read
            the link.
          </p>
        </div>
        <span className={styles.badge}>
          {peakCount > 0 ? `${peakCount} hot` : `${size}×${size}`}
        </span>
      </div>

      <div className={styles.workspace}>
        <div className={styles.matrixBlock}>
          <div
            className={styles.matrix}
            style={matrixStyle}
            onMouseLeave={() => {
              setActive(null);
              setFocusIndex(null);
            }}
          >
            <div className={styles.corner} aria-hidden>
              <span>From</span>
              <span>↘ To</span>
            </div>

            {labels.slice(0, size).map((label, index) => (
              <button
                key={`col-${index}`}
                type="button"
                className={`${styles.colLabel} ${
                  hoverCol === index ? styles.axisActive : ""
                } ${peakIndexes.has(index) ? styles.axisHot : ""}`}
                style={{ gridColumn: index + 2, gridRow: 1 }}
                title={friendlyLabel(label)}
                onMouseEnter={() => setFocusIndex(index)}
                onFocus={() => setFocusIndex(index)}
              >
                {String(index + 1).padStart(2, "0")}
              </button>
            ))}

            {labels.slice(0, size).map((label, index) => (
              <button
                key={`row-${index}`}
                type="button"
                className={`${styles.rowLabel} ${
                  hoverRow === index ? styles.axisActive : ""
                } ${peakIndexes.has(index) ? styles.axisHot : ""}`}
                style={{ gridColumn: 1, gridRow: index + 2 }}
                title={friendlyLabel(label)}
                onMouseEnter={() => setFocusIndex(index)}
                onFocus={() => setFocusIndex(index)}
              >
                {String(index + 1).padStart(2, "0")}
              </button>
            ))}

            {cells.flatMap((row, r) =>
              row.map((cell, c) => {
                const alpha = 0.08 + cell.value * 0.92;
                const lit =
                  hoverRow === r ||
                  hoverCol === c ||
                  (active?.row === r && active?.col === c);
                const dimmed =
                  (hoverRow != null || hoverCol != null) && !lit;
                return (
                  <button
                    key={cell.key}
                    type="button"
                    className={`${styles.cell} ${
                      cell.highlight ? styles.cellHot : ""
                    } ${lit ? styles.cellLit : ""} ${
                      dimmed ? styles.cellDim : ""
                    }`}
                    style={{
                      gridColumn: c + 2,
                      gridRow: r + 2,
                      background: `rgba(228, 0, 43, ${alpha})`,
                    }}
                    aria-label={`From ${friendlyLabel(labels[r] ?? "")} to ${friendlyLabel(labels[c] ?? "")}: ${cell.value.toFixed(2)}`}
                    onMouseEnter={() => setActive({ row: r, col: c })}
                    onFocus={() => setActive({ row: r, col: c })}
                  />
                );
              }),
            )}
          </div>

          <div className={styles.readout} aria-live="polite">
            {active && activeCell && fromLabel && toLabel ? (
              <>
                <span className={styles.readoutPair}>
                  <strong>{fromLabel}</strong>
                  <em>→</em>
                  <strong>{toLabel}</strong>
                </span>
                <span className={styles.readoutScore}>
                  {(activeCell.value * 100).toFixed(0)}
                  <small> focus</small>
                </span>
              </>
            ) : (
              <span className={styles.readoutHint}>
                Hover a cell to see which event focuses on which.
              </span>
            )}
          </div>

          <div className={styles.scale} aria-hidden>
            <span>Weaker</span>
            <div className={styles.scaleBar} />
            <span>Stronger</span>
          </div>
        </div>

        <aside className={styles.roster} aria-label="Event order">
          <div className={styles.rosterHead}>
            <p className={styles.rosterKicker}>Session order</p>
            <p className={styles.rosterTitle}>Events</p>
          </div>
          <ol className={styles.rosterList}>
            {labels.slice(0, size).map((label, index) => {
              const hot = peakIndexes.has(index);
              const activeRow = hoverRow === index || hoverCol === index;
              return (
                <li key={`${label}-${index}`}>
                  <button
                    type="button"
                    className={`${styles.rosterItem} ${
                      hot ? styles.rosterItemHot : ""
                    } ${activeRow ? styles.rosterItemActive : ""}`}
                    onMouseEnter={() => setFocusIndex(index)}
                    onMouseLeave={() => setFocusIndex(null)}
                    onFocus={() => setFocusIndex(index)}
                    onBlur={() => setFocusIndex(null)}
                  >
                    <span className={styles.rosterIndex}>
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <span className={styles.rosterLabel}>
                      {friendlyLabel(label)}
                    </span>
                    {hot ? (
                      <span className={styles.rosterPeak}>Hot</span>
                    ) : null}
                  </button>
                </li>
              );
            })}
          </ol>

          {topLinks.length > 0 ? (
            <div className={styles.topLinks}>
              <p className={styles.rosterKicker}>Strongest links</p>
              <ul>
                {topLinks.map((link) => (
                  <li key={`${link.row}-${link.col}`}>
                    <button
                      type="button"
                      className={styles.linkItem}
                      onMouseEnter={() =>
                        setActive({ row: link.row, col: link.col })
                      }
                      onMouseLeave={() => setActive(null)}
                      onFocus={() =>
                        setActive({ row: link.row, col: link.col })
                      }
                      onBlur={() => setActive(null)}
                    >
                      <span>
                        {friendlyLabel(labels[link.row] ?? "")}
                        <em> → </em>
                        {friendlyLabel(labels[link.col] ?? "")}
                      </span>
                      <strong>{(link.value * 100).toFixed(0)}</strong>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </aside>
      </div>
    </section>
  );
}

export default memo(AttentionHeatmap);
