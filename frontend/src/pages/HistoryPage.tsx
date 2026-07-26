import { useNavigate } from "react-router-dom";
import { History, Trash2 } from "lucide-react";

import { useAnalysis } from "../contexts/AnalysisContext";
import styles from "./Dashboard.module.css";

function formatWhen(iso: string): string {
  try {
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}

export default function HistoryPage() {
  const {
    history,
    activeReportId,
    hydrating,
    loading,
    loadReport,
    removeReport,
    refreshHistory,
  } = useAnalysis();
  const navigate = useNavigate();

  const onOpen = async (id: string) => {
    const ok = await loadReport(id);
    if (ok) navigate("/app/overview");
  };

  return (
    <div className={styles.page}>
      <div className={styles.toolbar}>
        <div>
          <p className={styles.eyebrow}>Saved sessions</p>
          <h1 className={styles.pageTitle}>History</h1>
          <p className={styles.pageCaption}>
            Past analysis reports stay on this device after refresh.
          </p>
        </div>
        <button
          type="button"
          className={styles.secondaryBtn}
          onClick={() => void refreshHistory()}
          disabled={loading || hydrating}
        >
          Refresh list
        </button>
      </div>

      {hydrating ? (
        <div className={styles.emptyState}>
          <h3>Loading history…</h3>
        </div>
      ) : history.length === 0 ? (
        <div className={styles.emptyState}>
          <History size={22} aria-hidden />
          <h3>No reports yet</h3>
          <p>Upload a workbook or run sample data — finished analyses show up here.</p>
          <button
            type="button"
            className={styles.primaryBtn}
            onClick={() => navigate("/app")}
          >
            Go to Upload
          </button>
        </div>
      ) : (
        <ul className={styles.historyList}>
          {history.map((item) => {
            const active = item.id === activeReportId;
            return (
              <li key={item.id}>
                <article
                  className={`${styles.historyCard} ${active ? styles.historyCardActive : ""}`}
                >
                  <div className={styles.historyMain}>
                    <p className={styles.sectionLabel}>
                      {active ? "Active report" : "Saved report"}
                    </p>
                    <h2 className={styles.historyTitle}>{item.sourceFileName}</h2>
                    <p className={styles.historyWhen}>{formatWhen(item.createdAt)}</p>
                    <div className={styles.historyMeta}>
                      <span>{item.stats.rows} rows</span>
                      <span>{item.stats.employees} employees</span>
                      <span>{item.stats.confirmed} confirmed</span>
                      <span>{item.stats.high + item.stats.critical} high+</span>
                    </div>
                  </div>
                  <div className={styles.historyActions}>
                    <button
                      type="button"
                      className={styles.primaryBtn}
                      disabled={loading}
                      onClick={() => void onOpen(item.id)}
                    >
                      Open
                    </button>
                    <button
                      type="button"
                      className={styles.secondaryBtn}
                      disabled={loading}
                      aria-label={`Delete ${item.sourceFileName}`}
                      onClick={() => void removeReport(item.id)}
                    >
                      <Trash2 size={14} aria-hidden />
                      Delete
                    </button>
                  </div>
                </article>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
