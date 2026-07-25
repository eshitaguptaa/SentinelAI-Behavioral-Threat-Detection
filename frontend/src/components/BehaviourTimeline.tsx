import { memo, useMemo } from "react";

import styles from "./BehaviourTimeline.module.css";
import type { BehaviourInsight } from "../types/models";

interface BehaviourTimelineProps {
  insight: BehaviourInsight | null | undefined;
}

function BehaviourTimeline({ insight }: BehaviourTimelineProps) {
  const events = insight?.event_types ?? [];
  const errors = insight?.per_event_errors ?? [];

  const { median, maxError } = useMemo(() => {
    if (errors.length === 0) {
      return { median: 0, maxError: 1e-6 };
    }
    const sorted = [...errors].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    const med =
      sorted.length % 2 === 0
        ? (sorted[mid - 1] + sorted[mid]) / 2
        : sorted[mid];
    return {
      median: med,
      maxError: Math.max(1e-6, ...errors),
    };
  }, [errors]);

  if (!insight || events.length === 0) {
    return (
      <section className={styles.panel} aria-label="Behaviour timeline">
        <h2 className={styles.title}>Behaviour Timeline</h2>
        <p className={styles.empty}>
          Run analysis with the Transformer model to inspect session event
          order and reconstruction pressure.
        </p>
      </section>
    );
  }

  return (
    <section className={styles.panel} aria-label="Behaviour timeline">
      <div className={styles.header}>
        <h2 className={styles.title}>Behaviour Timeline</h2>
        <p className={styles.meta}>
          Session {insight.session_id || "—"} · {events.length} events
        </p>
      </div>
      <ol className={styles.list}>
        {events.map((eventType, index) => {
          const error = errors[index] ?? 0;
          const anomalous = error > median * 1.05;
          const intensity = anomalous
            ? Math.min(1, (error - median) / Math.max(maxError - median, 1e-6))
            : 0;
          return (
            <li
              key={`${eventType}-${index}`}
              className={`${styles.item} ${anomalous ? styles.anomalous : styles.normal}`}
            >
              <span className={styles.index}>{index + 1}</span>
              <span className={styles.event}>{eventType}</span>
              <span
                className={styles.bar}
                style={
                  anomalous
                    ? {
                        width: `${18 + intensity * 82}%`,
                        opacity: 0.4 + intensity * 0.6,
                      }
                    : { width: "10%", opacity: 0.18 }
                }
                title={`Reconstruction error ${error.toFixed(3)}`}
              />
            </li>
          );
        })}
      </ol>
    </section>
  );
}

export default memo(BehaviourTimeline);
