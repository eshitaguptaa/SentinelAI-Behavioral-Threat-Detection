import { memo, useMemo } from "react";

import styles from "./BehaviourTimeline.module.css";
import type { BehaviourInsight } from "../types/models";

interface BehaviourTimelineProps {
  insight: BehaviourInsight | null | undefined;
}

function friendlyLabel(label: string): string {
  return label.replace(/_/g, " ");
}

function BehaviourTimeline({ insight }: BehaviourTimelineProps) {
  const events = insight?.event_types ?? [];
  const errors = insight?.per_event_errors ?? [];

  const { median, maxError, anomalousCount, peakIndex, peakError } = useMemo(() => {
    if (errors.length === 0) {
      return {
        median: 0,
        maxError: 1e-6,
        anomalousCount: 0,
        peakIndex: -1,
        peakError: 0,
      };
    }
    const sorted = [...errors].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    const med =
      sorted.length % 2 === 0
        ? (sorted[mid - 1] + sorted[mid]) / 2
        : sorted[mid];
    const max = Math.max(1e-6, ...errors);
    const count = errors.filter((error) => error > med * 1.05).length;
    let peak = 0;
    for (let i = 1; i < errors.length; i += 1) {
      if (errors[i] > errors[peak]) peak = i;
    }
    return {
      median: med,
      maxError: max,
      anomalousCount: count,
      peakIndex: peak,
      peakError: errors[peak] ?? 0,
    };
  }, [errors]);

  if (!insight || events.length === 0) {
    return (
      <section className={styles.panel} aria-label="Behaviour timeline">
        <div className={styles.header}>
          <div>
            <p className={styles.kicker}>Evidence</p>
            <h2 className={styles.title}>Behaviour timeline</h2>
          </div>
        </div>
        <p className={styles.empty}>
          Run analysis with the Transformer model to inspect session event
          order and reconstruction pressure.
        </p>
      </section>
    );
  }

  const elevatedShare =
    events.length > 0 ? Math.round((anomalousCount / events.length) * 100) : 0;

  return (
    <section className={styles.panel} aria-label="Behaviour timeline">
      <div className={styles.header}>
        <div>
          <p className={styles.kicker}>Evidence</p>
          <h2 className={styles.title}>Behaviour timeline</h2>
          <p className={styles.meta}>
            Session {insight.session_id || "—"} · {events.length} events in order
          </p>
        </div>
      </div>

      <div className={styles.summary} aria-label="Pressure summary">
        <div className={styles.summaryCard}>
          <span>Elevated</span>
          <strong>
            {anomalousCount}
            <small>/{events.length}</small>
          </strong>
        </div>
        <div className={styles.summaryCard}>
          <span>Share</span>
          <strong>
            {elevatedShare}
            <small>%</small>
          </strong>
        </div>
        <div className={`${styles.summaryCard} ${styles.summaryPeak}`}>
          <span>Peak step</span>
          <strong>
            {peakIndex >= 0 ? String(peakIndex + 1).padStart(2, "0") : "—"}
          </strong>
          <em>
            {peakIndex >= 0
              ? `${friendlyLabel(events[peakIndex] ?? "")} · ${peakError.toFixed(3)}`
              : "No peak"}
          </em>
        </div>
      </div>

      <div className={styles.legend} aria-hidden>
        <span className={styles.legendNormal}>Baseline</span>
        <span className={styles.legendHot}>Above median pressure</span>
      </div>

      <ol className={styles.list}>
        {events.map((eventType, index) => {
          const error = errors[index] ?? 0;
          const anomalous = error > median * 1.05;
          const intensity = anomalous
            ? Math.min(1, (error - median) / Math.max(maxError - median, 1e-6))
            : 0;
          const isPeak = index === peakIndex;
          return (
            <li
              key={`${eventType}-${index}`}
              className={`${styles.item} ${anomalous ? styles.anomalous : styles.normal} ${
                isPeak ? styles.peak : ""
              }`}
            >
              <span className={styles.index}>
                {String(index + 1).padStart(2, "0")}
              </span>
              <span className={styles.rail} aria-hidden>
                <span className={styles.dot} />
              </span>
              <div className={styles.eventBlock}>
                <span className={styles.event}>{friendlyLabel(eventType)}</span>
                <span className={styles.errorValue}>{error.toFixed(3)}</span>
              </div>
              <span
                className={styles.barTrack}
                title={`Reconstruction error ${error.toFixed(3)}`}
              >
                <span
                  className={styles.bar}
                  style={
                    anomalous
                      ? {
                          width: `${18 + intensity * 82}%`,
                          opacity: 0.5 + intensity * 0.5,
                        }
                      : { width: "10%", opacity: 0.22 }
                  }
                />
              </span>
              {isPeak ? <span className={styles.peakTag}>Peak</span> : null}
            </li>
          );
        })}
      </ol>
    </section>
  );
}

export default memo(BehaviourTimeline);
