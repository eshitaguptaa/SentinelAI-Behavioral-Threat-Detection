import { memo } from "react";

import styles from "./ExplanationPanel.module.css";
import type { PredictResult } from "../types/models";
import { ATTACK_COLORS, RISK_COLORS, STATUS_COLORS } from "../types/models";

interface ExplanationPanelProps {
  result: PredictResult | null;
}

function ExplanationPanel({ result }: ExplanationPanelProps) {
  if (!result) {
    return (
      <section className={styles.panel} aria-label="Explanation panel">
        <h2 className={styles.title}>Explanation</h2>
        <p className={styles.empty}>
          Select an employee from the table to inspect summary, factors,
          observations, attack classification, and recommendation.
        </p>
      </section>
    );
  }

  const {
    explanation,
    risk_assessment,
    prediction,
    attack_classification,
    behaviour_insight: insight,
    mitre,
  } = result;
  const levelColor =
    RISK_COLORS[explanation.risk_level] || "var(--text-muted)";
  const attackColor =
    ATTACK_COLORS[attack_classification.attack_type] || "#8a98a8";
  const statusColor = STATUS_COLORS[result.status] || "var(--text-muted)";

  return (
    <section className={styles.panel} aria-label="Explanation panel">
      <div className={styles.header}>
        <div>
          <h2 className={styles.title}>Explanation</h2>
          <p className={styles.identity}>
            {explanation.employee_id} · {explanation.simulation_day}
          </p>
        </div>
        <div className={styles.badges}>
          <span
            className={styles.level}
            style={{
              color: statusColor,
              borderColor: `${statusColor}66`,
              background: `${statusColor}1a`,
            }}
          >
            {result.status}
          </span>
          <span
            className={styles.level}
            style={{
              color: levelColor,
              borderColor: `${levelColor}66`,
              background: `${levelColor}1a`,
            }}
          >
            {explanation.risk_level}
          </span>
          <span
            className={styles.level}
            style={{
              color: attackColor,
              borderColor: `${attackColor}66`,
              background: `${attackColor}1a`,
            }}
          >
            {attack_classification.attack_type}
          </span>
        </div>
      </div>

      <div className={styles.scores}>
        <div>
          <span className={styles.scoreLabel}>Anomaly</span>
          <strong>{prediction.normalized_score.toFixed(1)}</strong>
        </div>
        <div>
          <span className={styles.scoreLabel}>Behaviour</span>
          <strong>
            {(insight?.behaviour_score ?? 100 - prediction.normalized_score).toFixed(
              1,
            )}
          </strong>
        </div>
        <div>
          <span className={styles.scoreLabel}>Confidence</span>
          <strong>
            {Math.round((insight?.confidence_score ?? attack_classification.attack_confidence) * 100)}
            %
          </strong>
        </div>
        <div>
          <span className={styles.scoreLabel}>Risk</span>
          <strong>{risk_assessment.risk_score.toFixed(1)}</strong>
        </div>
      </div>

      {mitre ? (
        <div className={styles.block}>
          <h3>MITRE ATT&CK</h3>
          <p>
            <strong>
              {mitre.technique_id} · {mitre.technique_name}
            </strong>
            {" — "}
            {mitre.tactic_name} ({mitre.tactic_id})
          </p>
          <p className={styles.muted}>{mitre.description}</p>
        </div>
      ) : null}

      {insight?.top_suspicious_events?.length ? (
        <div className={styles.block}>
          <h3>Top Suspicious Events</h3>
          <ul>
            {insight.top_suspicious_events.map((event) => (
              <li key={`${event.index}-${event.event_type}`}>
                <strong>
                  #{event.index + 1} {event.event_type}
                </strong>
                {" — "}
                {event.explanation ||
                  `reconstruction error ${event.reconstruction_error.toFixed(3)}`}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className={styles.block}>
        <h3>Attack Classification</h3>
        <p>
          <strong>{attack_classification.attack_type}</strong>
          {" — "}
          signature rules when matched; otherwise None / Unknown Behaviour /
          Behavioural Anomaly from the Transformer score.
        </p>
        {attack_classification.matched_signals.length === 0 ? (
          <p className={styles.muted}>No matched signals.</p>
        ) : (
          <ul>
            {attack_classification.matched_signals.map((signal) => (
              <li key={signal}>{signal}</li>
            ))}
          </ul>
        )}
      </div>

      <div className={styles.block}>
        <h3>Summary</h3>
        <p>{explanation.summary}</p>
      </div>

      <div className={styles.block}>
        <h3>Transformer Findings</h3>
        {explanation.contributing_factors.length === 0 ? (
          <p className={styles.muted}>No Transformer findings recorded.</p>
        ) : (
          <ul>
            {explanation.contributing_factors.map((factor) => (
              <li key={factor}>{factor}</li>
            ))}
          </ul>
        )}
      </div>

      <div className={styles.block}>
        <h3>Rule Findings</h3>
        {explanation.observations.length === 0 ? (
          <p className={styles.muted}>No rule findings triggered.</p>
        ) : (
          <ul>
            {explanation.observations.map((observation) => (
              <li key={observation}>{observation}</li>
            ))}
          </ul>
        )}
      </div>

      <div className={`${styles.block} ${styles.recommendation}`}>
        <h3>Recommendation</h3>
        <p>{explanation.recommendation}</p>
      </div>
    </section>
  );
}

export default memo(ExplanationPanel);
