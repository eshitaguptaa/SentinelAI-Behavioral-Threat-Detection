import { Activity, Database, Link2, Server } from "lucide-react";

import StatusRefreshButton from "../components/StatusRefreshButton";
import { useAnalysis } from "../contexts/AnalysisContext";
import { getApiBaseUrl } from "../services/api";
import styles from "./SystemPage.module.css";

export default function SystemPage() {
  const { backendStatus, appVersion, rows, sourceFileName, stats } =
    useAnalysis();

  const online = backendStatus === "online";
  const checking = backendStatus === "checking";
  const statusLabel = online
    ? "Healthy"
    : checking
      ? "Checking"
      : "Unreachable";
  const statusTone = online ? "ok" : checking ? "wait" : "down";

  return (
    <div className={styles.page}>
      <div className={styles.toolbar}>
        <div>
          <p className={styles.eyebrow}>Platform</p>
          <h1 className={styles.pageTitle}>System</h1>
          <p className={styles.pageCaption}>
            Live API health and what this browser session currently holds.
          </p>
        </div>
        <StatusRefreshButton label="Refresh status" />
      </div>

      <section
        className={`${styles.hero} ${styles[`hero_${statusTone}`]}`}
        aria-label="Backend health"
      >
        <div className={styles.heroGrid} aria-hidden />
        <div className={styles.heroMain}>
          <p className={styles.heroKicker}>
            <span className={`${styles.liveDot} ${styles[`dot_${statusTone}`]}`} />
            Inference service
          </p>
          <h2 className={styles.heroTitle}>{statusLabel}</h2>
          <p className={styles.heroLead}>
            {online
              ? "FastAPI is reachable and ready for batch prediction."
              : checking
                ? "Probing the backend health endpoint…"
                : "Cannot reach the API. Start the backend or check the base URL."}
          </p>
        </div>
        <div className={styles.heroSide}>
          <p className={styles.sideLabel}>API base</p>
          <code className={styles.sideCode}>{getApiBaseUrl()}</code>
          <p className={styles.sideHint}>Used by the SOC workspace for all calls.</p>
        </div>
      </section>

      <div className={styles.metrics} aria-label="Session metrics">
        <article className={styles.metric}>
          <div className={styles.metricIcon} aria-hidden>
            <Server size={16} strokeWidth={2.25} />
          </div>
          <div className={styles.metricCopy}>
            <p className={styles.metricKicker}>Backend</p>
            <h3 className={styles.metricTitle}>Service state</h3>
            <p className={styles.metricHint}>
              Health of the FastAPI inference service.
            </p>
          </div>
          <p className={`${styles.metricValue} ${styles[`value_${statusTone}`]}`}>
            {statusLabel}
          </p>
        </article>

        <article className={styles.metric}>
          <div className={styles.metricIcon} aria-hidden>
            <Link2 size={16} strokeWidth={2.25} />
          </div>
          <div className={styles.metricCopy}>
            <p className={styles.metricKicker}>Endpoint</p>
            <h3 className={styles.metricTitle}>API base</h3>
            <p className={styles.metricHint}>
              Base URL configured for this frontend build.
            </p>
          </div>
          <code className={styles.metricCode}>{getApiBaseUrl()}</code>
        </article>

        <article className={styles.metric}>
          <div className={styles.metricIcon} aria-hidden>
            <Database size={16} strokeWidth={2.25} />
          </div>
          <div className={styles.metricCopy}>
            <p className={styles.metricKicker}>Session</p>
            <h3 className={styles.metricTitle}>Loaded rows</h3>
            <p className={styles.metricHint}>
              Employee-day results held in this browser session.
            </p>
          </div>
          <p className={styles.metricValue}>{rows.length}</p>
        </article>

        <article className={styles.metric}>
          <div className={styles.metricIcon} aria-hidden>
            <Activity size={16} strokeWidth={2.25} />
          </div>
          <div className={styles.metricCopy}>
            <p className={styles.metricKicker}>Build</p>
            <h3 className={styles.metricTitle}>App version</h3>
            <p className={styles.metricHint}>
              Reported by the backend info endpoint.
            </p>
          </div>
          <p className={styles.metricValue}>{appVersion ?? "—"}</p>
        </article>
      </div>

      <section className={styles.batch} aria-label="Current batch">
        <div className={styles.batchHead}>
          <div>
            <p className={styles.metricKicker}>Workspace load</p>
            <h2 className={styles.batchTitle}>Current batch</h2>
          </div>
          <span className={styles.batchBadge}>
            {rows.length > 0 ? "In memory" : "Empty"}
          </span>
        </div>
        <div className={styles.batchBody}>
          <div className={styles.batchFile}>
            <span>Source</span>
            <strong>{sourceFileName ?? "No workbook loaded"}</strong>
          </div>
          <div className={styles.batchStats}>
            <div>
              <span>Employees</span>
              <strong>{stats.employees}</strong>
            </div>
            <div>
              <span>Confirmed</span>
              <strong>{stats.confirmed}</strong>
            </div>
            <div>
              <span>Critical</span>
              <strong>{stats.critical}</strong>
            </div>
            <div>
              <span>High</span>
              <strong>{stats.high}</strong>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
