import { useEffect, useState, type CSSProperties } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import {
  ArrowRight,
  ChevronDown,
  Crosshair,
  GitBranch,
  Link2,
} from "lucide-react";

import {
  ATTACK_COLORS,
  RISK_COLORS,
  STATUS_COLORS,
  type CampaignCase,
  type CampaignStage,
} from "../types/models";
import styles from "./CampaignKillChain.module.css";

function formatSignal(signal: string): string {
  return signal
    .replace(/_/g, " ")
    .replace(/=/g, " · ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function phaseForAttack(attackType: string): string {
  const map: Record<string, string> = {
    "Impossible Travel": "Initial access",
    "Brute Force": "Initial access",
    "Credential Stuffing": "Initial access",
    "Device Spoofing": "Initial access",
    "Lateral Movement": "Expansion",
    "Suspicious VPN Usage": "Expansion",
    "Insider Activity": "Expansion",
    "Insider Drift": "Expansion",
    "Mass Download": "Objective",
    "Low-and-Slow Exfiltration": "Objective",
  };
  return map[attackType] ?? "Stage";
}

function StageCard({
  stage,
  total,
  expanded,
  onToggle,
  onOpen,
  reduceMotion,
}: {
  stage: CampaignStage;
  total: number;
  expanded: boolean;
  onToggle: () => void;
  onOpen?: (stage: CampaignStage) => void;
  reduceMotion: boolean | null;
}) {
  const attackColor = ATTACK_COLORS[stage.attack_type] || "#8a98a8";
  const riskColor = RISK_COLORS[stage.risk_level] || "#8a98a8";
  const statusColor = STATUS_COLORS[stage.status] || "#8a98a8";
  const phase = phaseForAttack(stage.attack_type);
  const factors = [
    ...stage.contributing_factors.slice(0, 2),
    ...stage.matched_signals.slice(0, 2),
  ].slice(0, 3);

  return (
    <article
      className={[
        styles.stageCard,
        stage.is_focus ? styles.stageFocus : "",
        expanded ? styles.stageExpanded : "",
      ]
        .filter(Boolean)
        .join(" ")}
      style={{ "--attack-accent": attackColor } as CSSProperties}
    >
      <button
        type="button"
        className={styles.stageHead}
        onClick={onToggle}
        aria-expanded={expanded}
      >
        <div className={styles.stageTop}>
          <span className={styles.stageIndex}>
            {String(stage.stage_index + 1).padStart(2, "0")}
            <span className={styles.stageOf}>/{String(total).padStart(2, "0")}</span>
          </span>
          <span className={styles.phasePill}>{phase}</span>
          <motion.span
            className={styles.chevron}
            animate={{ rotate: expanded ? 180 : 0 }}
            transition={{ duration: reduceMotion ? 0 : 0.2 }}
            aria-hidden
          >
            <ChevronDown size={14} strokeWidth={2.25} />
          </motion.span>
        </div>

        <strong className={styles.attackName}>{stage.attack_type}</strong>
        <span className={styles.stageMetaLine}>
          {stage.employee_id}
          <span aria-hidden>·</span>
          {stage.simulation_day}
        </span>

        <div className={styles.stageScoreRow}>
          <span
            className={styles.stageRisk}
            style={{ "--badge-color": riskColor } as CSSProperties}
          >
            {stage.risk_score.toFixed(0)}
            <small>risk</small>
          </span>
          {stage.mitre ? (
            <span className={styles.mitrePeek}>
              <Crosshair size={11} strokeWidth={2.25} aria-hidden />
              {stage.mitre.technique_id}
            </span>
          ) : (
            <span
              className={styles.statusPeek}
              style={{ "--badge-color": statusColor } as CSSProperties}
            >
              {stage.status}
            </span>
          )}
        </div>
      </button>

      <AnimatePresence initial={false}>
        {expanded ? (
          <motion.div
            className={styles.stageBody}
            initial={
              reduceMotion ? { opacity: 1 } : { height: 0, opacity: 0 }
            }
            animate={
              reduceMotion
                ? { opacity: 1 }
                : { height: "auto", opacity: 1 }
            }
            exit={
              reduceMotion ? { opacity: 0 } : { height: 0, opacity: 0 }
            }
            transition={{ duration: 0.22 }}
          >
            <div className={styles.stageMeta}>
              <span style={{ "--badge-color": statusColor } as CSSProperties}>
                {stage.status}
              </span>
              <span style={{ "--badge-color": riskColor } as CSSProperties}>
                {stage.risk_level}
              </span>
              {stage.mitre ? (
                <span className={styles.mitreChip}>
                  {stage.mitre.technique_id} · {stage.mitre.technique_name}
                </span>
              ) : null}
            </div>

            {stage.mitre ? (
              <p className={styles.mitreLine}>
                <strong>{stage.mitre.tactic_name}</strong>
                {" — "}
                {stage.mitre.description}
              </p>
            ) : null}

            {factors.length > 0 ? (
              <ul className={styles.factorList}>
                {factors.map((factor) => (
                  <li key={factor}>{formatSignal(factor)}</li>
                ))}
              </ul>
            ) : (
              <p className={styles.muted}>No contributing factors recorded.</p>
            )}

            {onOpen ? (
              <button
                type="button"
                className={styles.openStageBtn}
                onClick={(event) => {
                  event.stopPropagation();
                  onOpen(stage);
                }}
              >
                Open this stage as case
                <ArrowRight size={13} strokeWidth={2.25} aria-hidden />
              </button>
            ) : null}
          </motion.div>
        ) : null}
      </AnimatePresence>
    </article>
  );
}

export default function CampaignKillChain({
  campaign,
  onOpenStage,
}: {
  campaign: CampaignCase | null;
  onOpenStage?: (stage: CampaignStage) => void;
}) {
  const reduceMotion = useReducedMotion();
  const [expandedIndex, setExpandedIndex] = useState(-1);

  useEffect(() => {
    // Always start collapsed when the focused campaign changes.
    setExpandedIndex(-1);
  }, [campaign?.case_id]);

  if (!campaign || campaign.stage_count < 2) {
    return null;
  }

  const peakColor =
    RISK_COLORS[campaign.peak_risk_level] || "var(--hw-red)";
  const statusColor = STATUS_COLORS[campaign.status] || "var(--text-muted)";

  return (
    <section className={styles.panel} aria-label="Kill-chain campaign">
      <div className={styles.head}>
        <div className={styles.headCopy}>
          <p className={styles.kicker}>
            <GitBranch size={13} strokeWidth={2.25} aria-hidden />
            Kill chain
          </p>
          <h3 className={styles.title}>{campaign.campaign_name}</h3>
          <p className={styles.summary}>
            Correlated for {campaign.entity_ids.join(", ")} via{" "}
            <strong>{campaign.correlation_basis}</strong>
            {" · "}
            peak risk {campaign.peak_risk_score.toFixed(0)} (
            {campaign.peak_risk_level})
          </p>
        </div>

        <div className={styles.headStats}>
          <div className={styles.statCard}>
            <span className={styles.statLabel}>Stages</span>
            <strong>{campaign.stage_count}</strong>
          </div>
          <div
            className={styles.statCard}
            style={{ "--stat-accent": peakColor } as CSSProperties}
          >
            <span className={styles.statLabel}>Peak risk</span>
            <strong className={styles.statAccent}>
              {campaign.peak_risk_score.toFixed(0)}
            </strong>
          </div>
          <div
            className={styles.statCard}
            style={{ "--stat-accent": statusColor } as CSSProperties}
          >
            <span className={styles.statLabel}>Case status</span>
            <strong className={styles.statAccentSmall}>{campaign.status}</strong>
          </div>
        </div>
      </div>

      <ol className={styles.progress} aria-label="Campaign stage progress">
        {campaign.stages.map((stage, index) => {
          const active = expandedIndex === stage.stage_index;
          const color = ATTACK_COLORS[stage.attack_type] || "#8a98a8";
          return (
            <li key={`progress-${stage.stage_index}`} className={styles.progressItem}>
              <button
                type="button"
                className={[
                  styles.progressNode,
                  active ? styles.progressNodeActive : "",
                  stage.is_focus ? styles.progressNodeFocus : "",
                ]
                  .filter(Boolean)
                  .join(" ")}
                style={{ "--attack-accent": color } as CSSProperties}
                onClick={() => setExpandedIndex(stage.stage_index)}
                aria-label={`Stage ${stage.stage_index + 1}: ${stage.attack_type}`}
              >
                <span className={styles.progressDot} />
                <span className={styles.progressLabel}>
                  {String(stage.stage_index + 1).padStart(2, "0")}
                </span>
              </button>
              {index < campaign.stages.length - 1 ? (
                <span className={styles.progressConnector} aria-hidden>
                  <ArrowRight size={12} strokeWidth={2.5} />
                </span>
              ) : null}
            </li>
          );
        })}
      </ol>

      <div className={styles.basisRow}>
        <span className={styles.basisBadge}>
          <Link2 size={12} aria-hidden />
          {campaign.correlation_basis}
        </span>
        <span className={styles.hint}>
          Select a stage for MITRE mapping and contributing factors
        </span>
      </div>

      <motion.div
        className={styles.stages}
        initial={reduceMotion ? false : { opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
      >
        {campaign.stages.map((stage, index) => (
          <div key={`${stage.employee_id}-${stage.simulation_day}-${stage.stage_index}`} className={styles.stageSlot}>
            <StageCard
              stage={stage}
              total={campaign.stage_count}
              expanded={expandedIndex === stage.stage_index}
              onToggle={() =>
                setExpandedIndex((prev) =>
                  prev === stage.stage_index ? -1 : stage.stage_index,
                )
              }
              onOpen={onOpenStage}
              reduceMotion={reduceMotion}
            />
            {index < campaign.stages.length - 1 ? (
              <div className={styles.stageArrow} aria-hidden>
                <ArrowRight size={16} strokeWidth={2.25} />
              </div>
            ) : null}
          </div>
        ))}
      </motion.div>
    </section>
  );
}
