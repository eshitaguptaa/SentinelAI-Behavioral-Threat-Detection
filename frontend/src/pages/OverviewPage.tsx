import { Link, Navigate, useNavigate } from "react-router-dom";
import { ArrowRight, Download, RefreshCw, Upload } from "lucide-react";

import StatsCard from "../components/StatsCard";
import StatusRefreshButton from "../components/StatusRefreshButton";
import { useAnalysis } from "../contexts/AnalysisContext";
import { BUILT_IN_SAMPLE_LABEL } from "../services/excelImport";
import styles from "./Dashboard.module.css";

export default function OverviewPage() {
  const {
    stats,
    rows,
    loading,
    hydrating,
    backendStatus,
    sourceFileName,
    rerunAnalysis,
    downloadActiveWorkbook,
    canDownloadWorkbook,
  } = useAnalysis();
  const navigate = useNavigate();

  const offline = backendStatus === "offline";
  const isSample = sourceFileName === BUILT_IN_SAMPLE_LABEL;

  if (hydrating) {
    return (
      <div className={styles.pageFill}>
        <div className={styles.toolbar}>
          <div>
            <p className={styles.eyebrow}>Security operations</p>
            <h1 className={styles.pageTitle}>Overview</h1>
          </div>
        </div>
        <div className={styles.emptyState}>
          <h3>Restoring last session…</h3>
        </div>
      </div>
    );
  }

  if (rows.length === 0) {
    return <Navigate to="/app" replace />;
  }

  return (
    <div className={styles.pageFill}>
      <div className={styles.toolbar}>
        <div>
          <p className={styles.eyebrow}>Security operations</p>
          <h1 className={styles.pageTitle}>Overview</h1>
        </div>
        <div className={styles.actions}>
          <StatusRefreshButton />
          {canDownloadWorkbook ? (
            <button
              type="button"
              className={styles.secondaryBtn}
              onClick={() => downloadActiveWorkbook()}
              disabled={loading}
              title="Download the Excel workbook this report was scored from"
            >
              <Download size={14} aria-hidden />
              {isSample ? "Download sample" : "Download workbook"}
            </button>
          ) : null}
          <button
            type="button"
            className={styles.secondaryBtn}
            onClick={() => navigate("/app")}
            disabled={loading}
          >
            <Upload size={14} aria-hidden />
            New file
          </button>
          <button
            type="button"
            className={styles.primaryBtn}
            onClick={() => void rerunAnalysis()}
            disabled={loading || offline}
          >
            <RefreshCw size={14} aria-hidden />
            {loading ? "Running…" : "Re-run"}
          </button>
        </div>
      </div>

      <div className={styles.overviewLoaded}>
        <div className={styles.heroBand}>
          <h2 className={styles.heroBandTitle}>{sourceFileName ?? "Batch ready"}</h2>
          <div className={styles.heroStats} aria-label="Batch summary">
            <div className={styles.heroStat}>
              <strong>{rows.length}</strong>
              <span>Rows analysed</span>
            </div>
            <div className={styles.heroStatRule} aria-hidden />
            <div className={styles.heroStat}>
              <strong>{stats.critical + stats.high}</strong>
              <span>High or critical</span>
            </div>
          </div>
          <div className={styles.heroMeta}>
            <span className={styles.chip}>{stats.confirmed} confirmed</span>
            <span className={styles.chip}>{stats.critical} critical</span>
            <span className={styles.chip}>{stats.high} high</span>
            {isSample ? (
              <button
                type="button"
                className={styles.chipAction}
                onClick={() => downloadActiveWorkbook()}
                disabled={!canDownloadWorkbook || loading}
              >
                <Download size={12} aria-hidden />
                Download sample workbook
              </button>
            ) : null}
          </div>
        </div>

        <div className={styles.cards}>
          <StatsCard label="Employees" value={stats.employees} />
          <StatsCard label="Confirmed Threats" value={stats.confirmed} tone="critical" />
          <StatsCard label="High Risk" value={stats.high} tone="high" />
          <StatsCard label="Critical Risk" value={stats.critical} tone="critical" />
        </div>

        <div className={styles.workflow} aria-label="Continue analysis">
          <Link to="/app/risk" className={styles.workflowStep}>
            <span className={styles.workflowIndex}>01</span>
            <strong>See where risk spikes</strong>
            <span className={styles.workflowCopy}>
              Spot which employees jumped to high or critical — before you dig into anyone.
            </span>
            <span className={styles.workflowCta}>
              Open Risk
              <ArrowRight size={16} aria-hidden />
            </span>
          </Link>
          <Link to="/app/predictions" className={styles.workflowStep}>
            <span className={styles.workflowIndex}>02</span>
            <strong>Triage the full queue</strong>
            <span className={styles.workflowCopy}>
              Ranked results ready to scan. Pick a row and jump straight into the case.
            </span>
            <span className={styles.workflowCta}>
              Open Predictions
              <ArrowRight size={16} aria-hidden />
            </span>
          </Link>
          <Link to="/app/investigate" className={styles.workflowStep}>
            <span className={styles.workflowIndex}>03</span>
            <strong>Prove what happened</strong>
            <span className={styles.workflowCopy}>
              Event timeline, model attention, and plain-language why this looks anomalous.
            </span>
            <span className={styles.workflowCta}>
              Open Investigate
              <ArrowRight size={16} aria-hidden />
            </span>
          </Link>
        </div>
      </div>
    </div>
  );
}
