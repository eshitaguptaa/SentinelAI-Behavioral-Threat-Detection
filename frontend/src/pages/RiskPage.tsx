import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight } from "lucide-react";

import RiskChart from "../components/RiskChart";
import RiskTrend from "../components/RiskTrend";
import StatsCard from "../components/StatsCard";
import { useAnalysis } from "../contexts/AnalysisContext";
import { RISK_COLORS } from "../types/models";
import styles from "./RiskPage.module.css";

function useCountUp(target: number, durationMs = 1100): number {
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    let frame = 0;
    const start = performance.now();
    const from = 0;

    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs);
      const eased = 1 - (1 - t) ** 3;
      setDisplay(Math.round(from + (target - from) * eased));
      if (t < 1) frame = requestAnimationFrame(tick);
    };

    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target, durationMs]);

  return display;
}

export default function RiskPage() {
  const { distribution, rows, stats, hydrating, sourceFileName, selectRow } =
    useAnalysis();
  const navigate = useNavigate();

  const total = useMemo(
    () => distribution.reduce((sum, point) => sum + point.count, 0),
    [distribution],
  );

  const elevated = stats.high + stats.critical;
  const exposurePct = total > 0 ? Math.round((elevated / total) * 100) : 0;
  const exposureAnimated = useCountUp(exposurePct);

  const curveSummary = useMemo(() => {
    if (!rows.length) return null;
    const sorted = [...rows].sort((a, b) => b.risk_score - a.risk_score);
    return {
      sessions: rows.length,
      peakRisk: sorted[0]?.risk_score ?? 0,
      peakAnomaly: Math.max(...rows.map((row) => row.anomaly_score)),
      avgRisk:
        rows.reduce((sum, row) => sum + row.risk_score, 0) / Math.max(rows.length, 1),
    };
  }, [rows]);

  const watchlist = useMemo(
    () => [...rows].sort((a, b) => b.risk_score - a.risk_score).slice(0, 6),
    [rows],
  );

  const spectrumSegments = useMemo(
    () =>
      distribution
        .filter((entry) => entry.count > 0)
        .map((entry, index) => ({
          ...entry,
          pct: total > 0 ? (entry.count / total) * 100 : 0,
          delay: `${0.12 + index * 0.08}s`,
          color: entry.fill || RISK_COLORS[entry.level] || "#6b6b6b",
        })),
    [distribution, total],
  );

  const openWatchItem = (id: string) => {
    const row = rows.find((r) => r.id === id);
    if (!row) return;
    selectRow(row);
    navigate("/app/investigate");
  };

  return (
    <div className={styles.page}>
      <div className={styles.toolbar}>
        <div>
          <p className={styles.eyebrow}>Analytics</p>
          <h1 className={styles.pageTitle}>Risk Analysis</h1>
          {rows.length > 0 ? (
            <p className={styles.pageCaption}>
              Where this batch concentrates threat — by level, curve, and watchlist.
            </p>
          ) : null}
        </div>
        {rows.length > 0 ? (
          <Link to="/app/predictions" className={styles.primaryBtn}>
            Open Predictions
            <ArrowRight size={14} aria-hidden />
          </Link>
        ) : null}
      </div>

      {hydrating ? (
        <div className={styles.emptyState}>
          <h3>Restoring last session…</h3>
        </div>
      ) : rows.length === 0 ? (
        <div className={styles.emptyState}>
          <h3>No batch loaded</h3>
          <p>Upload a workbook or try sample data first.</p>
          <Link to="/app" className={styles.primaryBtn}>
            Go to Upload
          </Link>
        </div>
      ) : (
        <div className={styles.layout}>
          <section className={styles.hero} aria-label="Batch exposure">
            <div className={styles.heroGrid} aria-hidden />
            <div className={styles.heroMain}>
              <div>
                <p className={styles.heroKicker}>Exposure brief</p>
                <h2 className={styles.heroTitle}>
                  {sourceFileName ?? "Loaded batch"} under watch
                </h2>
                <p className={styles.heroLead}>
                  {elevated > 0
                    ? `${elevated} of ${rows.length} rows land in high or critical — review the curve and watchlist before triage.`
                    : `All ${rows.length} rows sit below high risk. Confirm the distribution, then move to predictions.`}
                </p>
              </div>
              <div className={styles.heroMeta}>
                <span className={styles.chip}>{rows.length} rows</span>
                <span className={styles.chip}>{stats.employees} employees</span>
                <span className={styles.chip}>{stats.confirmed} confirmed</span>
                <span className={styles.chip}>{stats.critical} critical</span>
              </div>
            </div>
            <div className={styles.heroSide}>
              <p className={styles.exposureLabel}>Elevated share</p>
              <p className={styles.exposureValue} aria-label={`${exposurePct} percent`}>
                {exposureAnimated}
                <span>%</span>
              </p>
              <div className={styles.meter} aria-hidden>
                <div
                  className={styles.meterFill}
                  style={{ width: `${Math.max(exposurePct, 2)}%` }}
                />
              </div>
              <p className={styles.exposureHint}>
                High + critical as a share of this batch.
              </p>
            </div>
          </section>

          <section className={styles.spectrum} aria-label="Risk spectrum">
            <div className={styles.spectrumHead}>
              <div>
                <p className={styles.spectrumKicker}>Composition</p>
                <h2 className={styles.spectrumTitle}>Risk spectrum</h2>
              </div>
              <span className={styles.panelBadge}>{total} scored</span>
            </div>

            <div className={styles.spectrumTrack} role="img" aria-label="Risk level mix">
              {spectrumSegments.map((seg) => (
                <div
                  key={seg.level}
                  className={styles.spectrumSeg}
                  style={{
                    width: `${seg.pct}%`,
                    background: seg.color,
                    animationDelay: seg.delay,
                  }}
                  title={`${seg.level}: ${seg.count} (${Math.round(seg.pct)}%)`}
                >
                  {seg.pct >= 10 ? (
                    <span className={styles.spectrumSegLabel}>{seg.level}</span>
                  ) : null}
                </div>
              ))}
            </div>

            <ul className={styles.spectrumLegend}>
              {distribution.map((entry, index) => {
                const pct = total > 0 ? Math.round((entry.count / total) * 100) : 0;
                const color = entry.fill || RISK_COLORS[entry.level] || "#6b6b6b";
                return (
                  <li
                    key={entry.level}
                    style={
                      {
                        "--seg-color": color,
                        animationDelay: `${0.14 + index * 0.05}s`,
                      } as CSSProperties
                    }
                  >
                    <span>{entry.level}</span>
                    <strong>{entry.count}</strong>
                    <em>{pct}% of batch</em>
                  </li>
                );
              })}
            </ul>
          </section>

          <div className={styles.metrics}>
            <StatsCard label="Batch rows" value={rows.length} />
            <StatsCard
              label="High + critical"
              value={elevated}
              tone="high"
              hint={`${exposurePct}% of batch`}
            />
            <StatsCard
              label="Confirmed threats"
              value={stats.confirmed}
              tone="critical"
            />
            <StatsCard
              label="Peak risk"
              value={curveSummary ? curveSummary.peakRisk.toFixed(1) : "—"}
              hint="Highest score in batch"
            />
          </div>

          <div className={styles.chartsRow}>
            <RiskChart data={distribution} />
            <RiskTrend rows={rows} />
          </div>

          <div className={styles.lowerGrid}>
            <section className={styles.panel} aria-label="Priority watchlist">
              <div className={styles.panelHead}>
                <div>
                  <p className={styles.panelKicker}>Priority</p>
                  <h2 className={styles.panelTitle}>Watchlist</h2>
                  <p className={styles.panelCaption}>
                    Highest risk scores in this batch
                  </p>
                </div>
                <span className={styles.panelBadge}>Top {watchlist.length}</span>
              </div>
              <ul className={styles.watchList}>
                {watchlist.map((row, index) => {
                  const levelColor =
                    RISK_COLORS[row.risk_level] || "var(--text-muted)";
                  return (
                    <li key={row.id}>
                      <button
                        type="button"
                        className={styles.watchItem}
                        onClick={() => openWatchItem(row.id)}
                      >
                        <span className={styles.watchRank}>
                          {String(index + 1).padStart(2, "0")}
                        </span>
                        <span className={styles.watchBody}>
                          <strong>{row.employee_id}</strong>
                          <span>
                            {row.risk_level} · {row.attack_type || "Unclassified"}
                          </span>
                        </span>
                        <span className={styles.watchScore}>
                          <strong style={{ color: levelColor }}>
                            {row.risk_score.toFixed(1)}
                          </strong>
                          <span style={{ color: levelColor }}>Risk</span>
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </section>

            {curveSummary ? (
              <section className={styles.panel} aria-label="Curve summary">
                <div className={styles.panelHead}>
                  <div>
                    <p className={styles.panelKicker}>Signals</p>
                    <h2 className={styles.panelTitle}>Curve summary</h2>
                    <p className={styles.panelCaption}>
                      Peak and average scores across the ranked curve
                    </p>
                  </div>
                </div>
                <ul className={styles.curveGrid}>
                  <li>
                    <span>Sessions ranked</span>
                    <strong>{curveSummary.sessions}</strong>
                  </li>
                  <li>
                    <span>Peak risk</span>
                    <strong>{curveSummary.peakRisk.toFixed(1)}</strong>
                  </li>
                  <li>
                    <span>Peak anomaly</span>
                    <strong>{curveSummary.peakAnomaly.toFixed(1)}</strong>
                  </li>
                  <li>
                    <span>Avg risk</span>
                    <strong>{curveSummary.avgRisk.toFixed(1)}</strong>
                  </li>
                </ul>
              </section>
            ) : null}
          </div>

          <div className={styles.ctaStrip}>
            <div>
              <strong>Ready to triage?</strong>
              <p>
                Open the ranked predictions queue and drill into any watchlist case.
              </p>
            </div>
            <Link to="/app/predictions" className={styles.primaryBtn}>
              Continue to Predictions
              <ArrowRight size={14} aria-hidden />
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
