import {
  useEffect,
  useId,
  useMemo,
  useState,
  type CSSProperties,
} from "react";
import { Link } from "react-router-dom";
import {
  AnimatePresence,
  motion,
  useReducedMotion,
} from "framer-motion";
import {
  ArrowLeft,
  ArrowRight,
  Crosshair,
  Radar,
  ShieldAlert,
} from "lucide-react";

import AttentionHeatmap from "../components/AttentionHeatmap";
import BehaviourTimeline from "../components/BehaviourTimeline";
import { useAnalysis } from "../contexts/AnalysisContext";
import {
  ATTACK_COLORS,
  RISK_COLORS,
  STATUS_COLORS,
  type PredictResult,
} from "../types/models";
import styles from "./InvestigatePage.module.css";

type Stage = "brief" | "signals" | "evidence";

const STAGES: { id: Stage; index: string; label: string }[] = [
  { id: "brief", index: "01", label: "Brief" },
  { id: "signals", index: "02", label: "Signals" },
  { id: "evidence", index: "03", label: "Evidence" },
];

function extractBriefFacts(summary: string): { label: string; value: string }[] {
  const facts: { label: string; value: string }[] = [];
  const decision = summary.match(/Decision:\s*(.+?)(?=\s+Reason:|\.|$)/i)?.[1]?.trim();
  const reason = summary.match(/Reason:\s*(.+?)(?=\.\s|Transformer|Rule findings|$)/i)?.[1]?.trim();
  if (decision) facts.push({ label: "Decision", value: decision.replace(/\.$/, "") });
  if (reason) facts.push({ label: "Reason", value: reason.replace(/\.$/, "") });
  if (facts.length === 0) {
    const first = (summary.split(/(?<=\.)\s+/)[0] ?? summary).trim();
    facts.push({
      label: "Why",
      value: first.length > 140 ? `${first.slice(0, 137)}…` : first,
    });
  }
  return facts.slice(0, 2);
}

/** Split dense recommendation prose into readable action steps. */
function parseActionSteps(recommendation: string): string[] {
  const raw = recommendation.trim();
  if (!raw) return [];

  const parts = raw
    .split(/;|\n|(?<=[.!?])\s+(?=[A-Z])/)
    .map((part) => part.trim().replace(/^[-–•]+\s*/, "").replace(/[.]+$/, ""))
    .filter((part) => part.length > 0);

  const steps = (parts.length > 1 ? parts : [raw.replace(/[.]+$/, "")]).map((step) => {
    const cleaned = step.replace(/^(and|then|also)\s+/i, "").trim();
    return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
  });

  return steps.slice(0, 6);
}

function useCountUp(target: number, durationMs = 1100, enabled = true): number {
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    if (!enabled) {
      setDisplay(target);
      return;
    }
    let frame = 0;
    const start = performance.now();

    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs);
      const eased = 1 - (1 - t) ** 3;
      setDisplay(target * eased);
      if (t < 1) frame = requestAnimationFrame(tick);
    };

    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target, durationMs, enabled]);

  return display;
}

function RiskGauge({
  score,
  color,
  label,
}: {
  score: number;
  color: string;
  label: string;
}) {
  const reduceMotion = useReducedMotion();
  const uid = useId();
  const gradientId = `risk-gauge-${uid.replace(/:/g, "")}`;
  const size = 180;
  const stroke = 9;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  const animated = useCountUp(clamped, 1200, !reduceMotion);
  const offset = circumference * (1 - animated / 100);

  return (
    <div className={styles.gaugeWrap}>
      <svg
        className={styles.gaugeSvg}
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        aria-hidden
      >
        <defs>
          <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={color} />
            <stop offset="100%" stopColor="#e4002b" />
          </linearGradient>
        </defs>
        <circle
          className={styles.gaugeTrack}
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={stroke}
        />
        <motion.circle
          className={styles.gaugeArc}
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={stroke}
          stroke={`url(#${gradientId})`}
          strokeDasharray={circumference}
          initial={
            reduceMotion
              ? { strokeDashoffset: offset }
              : { strokeDashoffset: circumference }
          }
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.25, ease: [0.22, 1, 0.36, 1] }}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
        <circle
          className={styles.gaugeInner}
          cx={size / 2}
          cy={size / 2}
          r={radius - 22}
        />
      </svg>
      <div className={styles.gaugeReadout}>
        <p className={styles.gaugeLabel}>{label}</p>
        <p className={styles.gaugeValue} aria-label={`Risk score ${clamped.toFixed(1)}`}>
          {animated.toFixed(1)}
        </p>
        <p className={styles.gaugeUnit}>/ 100</p>
      </div>
    </div>
  );
}

function RingMeter({
  label,
  value,
  display,
  color,
  suffix = "",
  delay = 0,
  tone = "light",
}: {
  label: string;
  value: number;
  display: string;
  color: string;
  suffix?: string;
  delay?: number;
  tone?: "light" | "dark";
}) {
  const reduceMotion = useReducedMotion();
  const size = 56;
  const stroke = 4;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, value));
  const offset = circumference * (1 - pct / 100);
  const track = tone === "dark" ? "rgba(255,255,255,0.12)" : "rgba(17,17,17,0.08)";

  return (
    <div className={`${styles.ringCard} ${tone === "dark" ? styles.ringCardDark : ""}`}>
      <div className={styles.ringVisual} aria-hidden>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={track}
            strokeWidth={stroke}
          />
          <motion.circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="butt"
            strokeDasharray={circumference}
            initial={
              reduceMotion
                ? { strokeDashoffset: offset }
                : { strokeDashoffset: circumference }
            }
            animate={{ strokeDashoffset: offset }}
            transition={{
              duration: 1,
              delay: reduceMotion ? 0 : delay,
              ease: [0.22, 1, 0.36, 1],
            }}
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
          />
        </svg>
        <span className={styles.ringValue}>
          {display}
          {suffix}
        </span>
      </div>
      <p className={styles.ringLabel}>{label}</p>
    </div>
  );
}

function formatSignalLabel(signal: string): string {
  return signal
    .replace(/_/g, " ")
    .replace(/=/g, " · ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function BriefStage({ result }: { result: PredictResult }) {
  const { explanation, attack_classification, mitre } = result;
  const attackColor =
    ATTACK_COLORS[attack_classification.attack_type] || "#8a98a8";
  const facts = extractBriefFacts(explanation.summary);
  const signals = attack_classification.matched_signals.slice(0, 4);
  const steps = parseActionSteps(explanation.recommendation);

  return (
    <div className={styles.briefLayout}>
      {steps.length > 0 ? (
        <article className={styles.actionBanner} aria-label="Suggested response">
          <div className={styles.actionHead}>
            <span className={styles.actionKicker}>
              <ShieldAlert size={14} strokeWidth={2.25} aria-hidden />
              Suggested response
            </span>
            <span className={styles.actionCount}>{steps.length} steps</span>
          </div>
          <ol className={styles.actionSteps}>
            {steps.map((step, index) => (
              <li key={`${index}-${step}`}>
                <span className={styles.actionStepNum}>
                  {String(index + 1).padStart(2, "0")}
                </span>
                <span className={styles.actionStepText}>{step}</span>
              </li>
            ))}
          </ol>
        </article>
      ) : null}

      <section className={styles.intelBoard} aria-label="Case intelligence">
        <div className={styles.intelHead}>
          <p className={styles.tileKicker}>Case intelligence</p>
          <h3 className={styles.intelTitle}>Why this case fired</h3>
        </div>

        {facts.length > 0 ? (
          <div className={styles.verdictRow} aria-label="Case facts">
            {facts.map((fact, index) => (
              <div key={fact.label} className={styles.verdictItem}>
                <span className={styles.verdictIndex}>
                  {String(index + 1).padStart(2, "0")}
                </span>
                <div className={styles.verdictCopy}>
                  <span>{fact.label}</span>
                  <strong>{fact.value}</strong>
                </div>
              </div>
            ))}
          </div>
        ) : null}

        <div className={styles.classifyRow}>
          {mitre ? (
            <article className={styles.mitrePanel}>
              <div className={styles.mitreTop}>
                <span className={styles.mitreBadge}>
                  <Crosshair size={13} strokeWidth={2.25} aria-hidden />
                  MITRE ATT&CK
                </span>
                <span className={styles.techniqueCode}>{mitre.technique_id}</span>
              </div>
              <p className={styles.mitreName}>{mitre.technique_name}</p>
              <div className={styles.mitreTactic}>
                <span className={styles.tacticName}>{mitre.tactic_name}</span>
                <span className={styles.tacticCode}>{mitre.tactic_id}</span>
              </div>
            </article>
          ) : null}

          <article
            className={`${styles.attackPanel} ${mitre ? "" : styles.attackPanelSolo}`}
            style={{ "--attack-accent": attackColor } as CSSProperties}
          >
            <div className={styles.attackTop}>
              <span className={styles.tileKicker}>Attack class</span>
            </div>
            <p className={styles.attackType}>{attack_classification.attack_type}</p>
            {signals.length > 0 ? (
              <ul className={styles.signalRow}>
                {signals.map((signal) => (
                  <li key={signal}>{formatSignalLabel(signal)}</li>
                ))}
              </ul>
            ) : (
              <p className={styles.tileMuted}>No matched signals</p>
            )}
          </article>
        </div>
      </section>
    </div>
  );
}

function SignalsStage({ result }: { result: PredictResult }) {
  const { explanation, behaviour_insight: insight } = result;
  const events = insight?.top_suspicious_events ?? [];

  return (
    <div className={styles.signalsLayout}>
      <article className={`${styles.tile} ${styles.tilePriority}`}>
        <div className={styles.tileHead}>
          <div>
            <p className={styles.tileKicker}>Priority signals</p>
            <h3 className={styles.tileTitle}>Top suspicious events</h3>
          </div>
          <span className={styles.countBadge}>{events.length}</span>
        </div>
        {events.length === 0 ? (
          <p className={styles.tileMuted}>No elevated events recorded for this session.</p>
        ) : (
          <ol className={styles.eventList}>
            {events.map((event, index) => {
              const maxErr = Math.max(
                ...events.map((e) => e.reconstruction_error),
                1e-6,
              );
              const width = Math.max(
                8,
                (event.reconstruction_error / maxErr) * 100,
              );
              return (
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
                    <span className={styles.eventMeter} aria-hidden>
                      <span style={{ width: `${width}%` }} />
                    </span>
                  </div>
                  <span className={styles.eventError}>
                    {event.reconstruction_error.toFixed(3)}
                  </span>
                </li>
              );
            })}
          </ol>
        )}
      </article>

      <div className={styles.findingsPair}>
        <article className={styles.tile}>
          <div className={styles.tileHead}>
            <div>
              <p className={styles.tileKicker}>Model</p>
              <h3 className={styles.tileTitle}>Transformer findings</h3>
            </div>
            <span className={styles.countBadge}>
              {explanation.contributing_factors.length}
            </span>
          </div>
          {explanation.contributing_factors.length === 0 ? (
            <p className={styles.tileMuted}>No Transformer findings recorded.</p>
          ) : (
            <ul className={styles.findings}>
              {explanation.contributing_factors.map((factor, i) => (
                <li key={factor}>
                  <span>{String(i + 1).padStart(2, "0")}</span>
                  {factor}
                </li>
              ))}
            </ul>
          )}
        </article>

        <article className={styles.tile}>
          <div className={styles.tileHead}>
            <div>
              <p className={styles.tileKicker}>Rules</p>
              <h3 className={styles.tileTitle}>Rule findings</h3>
            </div>
            <span className={styles.countBadge}>
              {explanation.observations.length}
            </span>
          </div>
          {explanation.observations.length === 0 ? (
            <p className={styles.tileMuted}>No rule findings triggered.</p>
          ) : (
            <ul className={styles.findings}>
              {explanation.observations.map((observation, i) => (
                <li key={observation}>
                  <span>{String(i + 1).padStart(2, "0")}</span>
                  {observation}
                </li>
              ))}
            </ul>
          )}
        </article>
      </div>
    </div>
  );
}

export default function InvestigatePage() {
  const { selectedResult, rows, selectedId } = useAnalysis();
  const reduceMotion = useReducedMotion();
  const [stage, setStage] = useState<Stage>("brief");

  const riskScore = selectedResult?.risk_assessment.risk_score ?? 0;
  const anomalyScore = selectedResult?.prediction.normalized_score ?? 0;
  const behaviourScore =
    selectedResult?.behaviour_insight?.behaviour_score ?? 100 - anomalyScore;
  const confidence =
    (selectedResult?.behaviour_insight?.confidence_score ??
      selectedResult?.attack_classification.attack_confidence ??
      0) * 100;

  const anomalyAnimated = useCountUp(anomalyScore, 1000, !reduceMotion);
  const behaviourAnimated = useCountUp(behaviourScore, 1000, !reduceMotion);
  const confidenceAnimated = useCountUp(confidence, 1000, !reduceMotion);

  const caseKey = selectedId ?? "none";

  useEffect(() => {
    setStage("brief");
  }, [caseKey]);

  const stageMotion = useMemo(
    () =>
      reduceMotion
        ? {
            initial: { opacity: 1 },
            animate: { opacity: 1 },
            exit: { opacity: 1 },
          }
        : {
            initial: { opacity: 0, y: 14, filter: "blur(4px)" },
            animate: { opacity: 1, y: 0, filter: "blur(0px)" },
            exit: { opacity: 0, y: -10, filter: "blur(4px)" },
          },
    [reduceMotion],
  );

  if (rows.length === 0) {
    return (
      <div className={styles.page}>
        <div className={styles.toolbar}>
          <div>
            <p className={styles.eyebrow}>Case work</p>
            <h1 className={styles.pageTitle}>Investigate</h1>
          </div>
        </div>
        <div className={styles.emptyState}>
          <h3>No batch loaded</h3>
          <p>Upload a workbook or try sample data before opening a case.</p>
          <Link to="/app" className={styles.primaryBtn}>
            Go to Upload
          </Link>
        </div>
      </div>
    );
  }

  if (!selectedId || !selectedResult) {
    return (
      <div className={styles.page}>
        <div className={styles.toolbar}>
          <div>
            <p className={styles.eyebrow}>Case work</p>
            <h1 className={styles.pageTitle}>Investigate</h1>
            <p className={styles.pageCaption}>
              Open a prediction to enter the case vault — brief, signals, and evidence.
            </p>
          </div>
          <Link to="/app/predictions" className={styles.primaryBtn}>
            Open Predictions
            <ArrowRight size={14} aria-hidden />
          </Link>
        </div>
        <div className={styles.emptyVault}>
          <div className={styles.emptyVaultMark} aria-hidden>
            <Radar size={36} strokeWidth={1.5} />
          </div>
          <h3>Select a prediction</h3>
          <p>
            Pick a row from the triage queue. This page becomes a full case vault for
            that session.
          </p>
          <Link to="/app/predictions" className={styles.primaryBtn}>
            Open Predictions
          </Link>
        </div>
      </div>
    );
  }

  const {
    risk_assessment,
    attack_classification,
    status,
    prediction,
  } = selectedResult;

  const levelColor =
    RISK_COLORS[risk_assessment.risk_level] || "var(--text-muted)";
  const statusColor = STATUS_COLORS[status] || "var(--text-muted)";
  const attackColor =
    ATTACK_COLORS[attack_classification.attack_type] || "#8a98a8";

  const threatHot =
    status === "Confirmed Threat" ||
    status === "Under Investigation" ||
    risk_assessment.risk_level === "CRITICAL" ||
    risk_assessment.risk_level === "HIGH";

  return (
    <div className={styles.page}>
      <div className={styles.toolbar}>
        <div className={styles.toolbarTitle}>
          <p className={styles.eyebrow}>Case vault</p>
          <h1 className={styles.pageTitle}>Investigate</h1>
        </div>
        <Link to="/app/predictions" className={styles.secondaryBtn}>
          <ArrowLeft size={14} aria-hidden />
          Change case
        </Link>
      </div>

      <motion.div
        key={caseKey}
        className={styles.layout}
        initial={reduceMotion ? false : { opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      >
        <section
          className={`${styles.vault} ${threatHot ? styles.vaultHot : ""}`}
          aria-label="Case command"
        >
          <div className={styles.vaultScan} aria-hidden />
          <div className={styles.vaultGrid} aria-hidden />
          <p className={styles.vaultWatermark} aria-hidden>
            {prediction.employee_id}
          </p>

          <div className={styles.vaultBody}>
            <div className={styles.vaultMain}>
              <p className={styles.vaultKicker}>
                <span className={styles.liveDot} aria-hidden />
                Active case
              </p>
              <h2 className={styles.vaultIdentity}>{prediction.employee_id}</h2>
              <p className={styles.vaultDay}>{prediction.simulation_day}</p>
              <div className={styles.vaultBadges}>
                <span
                  className={styles.badge}
                  style={{ "--badge-color": statusColor } as CSSProperties}
                >
                  {status}
                </span>
                <span
                  className={styles.badge}
                  style={{ "--badge-color": levelColor } as CSSProperties}
                >
                  {risk_assessment.risk_level}
                </span>
                <span
                  className={styles.badge}
                  style={{ "--badge-color": attackColor } as CSSProperties}
                >
                  {attack_classification.attack_type}
                </span>
              </div>
            </div>

            <div className={styles.vaultSide}>
              <RiskGauge
                score={riskScore}
                color={levelColor}
                label="Risk"
              />
            </div>
          </div>

          <div className={styles.vaultMeters} aria-label="Score breakdown">
            <RingMeter
              label="Anomaly"
              value={anomalyScore}
              display={anomalyAnimated.toFixed(0)}
              color="#ff5a75"
              delay={0.05}
              tone="dark"
            />
            <RingMeter
              label="Behaviour"
              value={behaviourScore}
              display={behaviourAnimated.toFixed(0)}
              color="#e0b15a"
              delay={0.1}
              tone="dark"
            />
            <RingMeter
              label="Confidence"
              value={confidence}
              display={`${Math.round(confidenceAnimated)}`}
              suffix="%"
              color="#e08a3c"
              delay={0.15}
              tone="dark"
            />
          </div>
        </section>

        <nav className={styles.stageNav} aria-label="Investigation stages">
          {STAGES.map((item) => {
            const active = stage === item.id;
            return (
              <button
                key={item.id}
                type="button"
                className={`${styles.stageTab} ${active ? styles.stageTabActive : ""}`}
                onClick={() => setStage(item.id)}
                aria-pressed={active}
              >
                <span className={styles.stageIndex}>{item.index}</span>
                <strong>{item.label}</strong>
                {active ? (
                  <motion.span
                    className={styles.stageIndicator}
                    layoutId={reduceMotion ? undefined : "stage-indicator"}
                  />
                ) : null}
              </button>
            );
          })}
        </nav>

        <div className={styles.stageFrame}>
          <AnimatePresence mode="wait">
            <motion.div
              key={stage}
              className={styles.stagePane}
              initial={stageMotion.initial}
              animate={stageMotion.animate}
              exit={stageMotion.exit}
              transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
            >
              {stage === "brief" ? (
                <BriefStage result={selectedResult} />
              ) : null}
              {stage === "signals" ? (
                <SignalsStage result={selectedResult} />
              ) : null}
              {stage === "evidence" ? (
                <div className={styles.evidence}>
                  <BehaviourTimeline insight={selectedResult.behaviour_insight} />
                  <AttentionHeatmap insight={selectedResult.behaviour_insight} />
                </div>
              ) : null}
            </motion.div>
          </AnimatePresence>
        </div>
      </motion.div>
    </div>
  );
}
