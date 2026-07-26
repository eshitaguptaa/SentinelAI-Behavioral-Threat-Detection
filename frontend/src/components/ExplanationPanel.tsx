import { memo } from "react";
import { Crosshair, ShieldAlert, Sparkles, Target } from "lucide-react";

import styles from "./ExplanationPanel.module.css";
import type { PredictResult } from "../types/models";
import { ATTACK_COLORS } from "../types/models";

interface ExplanationPanelProps {
  result: PredictResult | null;
  /** When true, omit identity header (page hero already shows it). */
  embedded?: boolean;
}

function ExplanationPanel({ result, embedded = false }: ExplanationPanelProps) {
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
    attack_classification,
    behaviour_insight: insight,
    mitre,
  } = result;
  const attackColor =
    ATTACK_COLORS[attack_classification.attack_type] || "#8a98a8";

  return (
    <section
      className={embedded ? styles.dossier : styles.panel}
      aria-label="Case briefing"
    >
      {!embedded ? (
        <div className={styles.header}>
          <div>
            <h2 className={styles.title}>Explanation</h2>
            <p className={styles.identity}>
              {explanation.employee_id} · {explanation.simulation_day}
            </p>
          </div>
        </div>
      ) : null}

      <div className={styles.grid}>
        <article className={`${styles.card} ${styles.cardWide}`}>
          <div className={styles.cardHead}>
            <div className={styles.cardLead}>
              <span className={styles.cardIcon} aria-hidden>
                <Sparkles size={15} strokeWidth={2.25} />
              </span>
              <div>
                <p className={styles.cardKicker}>Narrative</p>
                <h3 className={styles.cardTitle}>Analyst summary</h3>
              </div>
            </div>
          </div>
          <p className={styles.cardBody}>{explanation.summary}</p>
        </article>

        <article className={`${styles.card} ${styles.recommend}`}>
          <div className={styles.cardHead}>
            <div className={styles.cardLead}>
              <span className={styles.cardIconHot} aria-hidden>
                <ShieldAlert size={15} strokeWidth={2.25} />
              </span>
              <div>
                <p className={styles.cardKicker}>Action</p>
                <h3 className={styles.cardTitle}>Recommendation</h3>
              </div>
            </div>
          </div>
          <p className={styles.recommendBody}>{explanation.recommendation}</p>
        </article>

        {mitre ? (
          <article className={styles.card}>
            <div className={styles.cardHead}>
              <div className={styles.cardLead}>
                <span className={styles.cardIcon} aria-hidden>
                  <Crosshair size={15} strokeWidth={2.25} />
                </span>
                <div>
                  <p className={styles.cardKicker}>MITRE ATT&CK</p>
                  <h3 className={styles.cardTitle}>
                    {mitre.technique_id}
                    <span className={styles.techniqueName}>
                      {mitre.technique_name}
                    </span>
                  </h3>
                </div>
              </div>
            </div>
            <div className={styles.mitreMeta}>
              <span>{mitre.tactic_name}</span>
              <span className={styles.mitreId}>{mitre.tactic_id}</span>
            </div>
            <p className={styles.cardMuted}>{mitre.description}</p>
          </article>
        ) : null}

        <article className={styles.card}>
          <div className={styles.cardHead}>
            <div className={styles.cardLead}>
              <span className={styles.cardIcon} aria-hidden>
                <Target size={15} strokeWidth={2.25} />
              </span>
              <div>
                <p className={styles.cardKicker}>Classification</p>
                <h3 className={styles.cardTitle}>Attack type</h3>
              </div>
            </div>
          </div>
          <p
            className={styles.attackType}
            style={{ color: attackColor }}
          >
            {attack_classification.attack_type}
          </p>
          <p className={styles.cardMuted}>
            Signature rules when matched; otherwise inferred from Transformer
            score.
          </p>
          {attack_classification.matched_signals.length === 0 ? (
            <p className={styles.cardMuted}>No matched signals.</p>
          ) : (
            <ul className={styles.signalList}>
              {attack_classification.matched_signals.map((signal) => (
                <li key={signal}>{signal}</li>
              ))}
            </ul>
          )}
        </article>

        {insight?.top_suspicious_events?.length ? (
          <article className={`${styles.card} ${styles.cardWide}`}>
            <div className={styles.cardHead}>
              <div>
                <p className={styles.cardKicker}>Priority signals</p>
                <h3 className={styles.cardTitle}>Top suspicious events</h3>
              </div>
              <span className={styles.countBadge}>
                {insight.top_suspicious_events.length}
              </span>
            </div>
            <ol className={styles.eventList}>
              {insight.top_suspicious_events.map((event, index) => (
                <li key={`${event.index}-${event.event_type}`}>
                  <span className={styles.eventRank}>
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <div className={styles.eventBody}>
                    <strong>
                      #{event.index + 1} {event.event_type}
                    </strong>
                    <span>
                      {event.explanation ||
                        `Reconstruction error ${event.reconstruction_error.toFixed(3)}`}
                    </span>
                  </div>
                  <span className={styles.eventError}>
                    {event.reconstruction_error.toFixed(3)}
                  </span>
                </li>
              ))}
            </ol>
          </article>
        ) : null}

        <article className={styles.card}>
          <div className={styles.cardHead}>
            <div>
              <p className={styles.cardKicker}>Model</p>
              <h3 className={styles.cardTitle}>Transformer findings</h3>
            </div>
            <span className={styles.countBadge}>
              {explanation.contributing_factors.length}
            </span>
          </div>
          {explanation.contributing_factors.length === 0 ? (
            <p className={styles.cardMuted}>No Transformer findings recorded.</p>
          ) : (
            <ul className={styles.findings}>
              {explanation.contributing_factors.map((factor) => (
                <li key={factor}>{factor}</li>
              ))}
            </ul>
          )}
        </article>

        <article className={styles.card}>
          <div className={styles.cardHead}>
            <div>
              <p className={styles.cardKicker}>Rules</p>
              <h3 className={styles.cardTitle}>Rule findings</h3>
            </div>
            <span className={styles.countBadge}>
              {explanation.observations.length}
            </span>
          </div>
          {explanation.observations.length === 0 ? (
            <p className={styles.cardMuted}>No rule findings triggered.</p>
          ) : (
            <ul className={styles.findings}>
              {explanation.observations.map((observation) => (
                <li key={observation}>{observation}</li>
              ))}
            </ul>
          )}
        </article>
      </div>
    </section>
  );
}

export default memo(ExplanationPanel);
