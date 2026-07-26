import { useEffect } from "react";
import { Outlet, useLocation } from "react-router-dom";

import Sidebar from "../components/Sidebar";
import { AnalysisProvider, useAnalysis } from "../contexts/AnalysisContext";
import styles from "../pages/Dashboard.module.css";

const TITLES: Record<string, string> = {
  "/app": "Upload",
  "/app/overview": "Overview",
  "/app/history": "History",
  "/app/risk": "Risk Analysis",
  "/app/predictions": "Predictions",
  "/app/investigate": "Investigate",
  "/app/system": "System",
};

function SocShell() {
  const { error, errorTitle, loading, hydrating, clearError } = useAnalysis();
  const location = useLocation();
  const contextLabel = TITLES[location.pathname] ?? "Workspace";

  useEffect(() => {
    document.title = `SentinelAI · ${contextLabel}`;
    document.body.style.background = "";
  }, [contextLabel]);

  return (
    <div className={styles.shell}>
      <Sidebar />
      <div className={styles.mainColumn}>
        <main className={styles.main} data-scroll-root>
          {error ? (
            <div className={styles.error} role="alert">
              <div>
                <strong>{errorTitle ?? "Unable to complete analysis"}</strong>
                <p>{error}</p>
              </div>
              <button type="button" className={styles.secondaryBtn} onClick={clearError}>
                Dismiss
              </button>
            </div>
          ) : null}

          {loading || hydrating ? (
            <div className={styles.loading} role="status" aria-live="polite">
              <span className={styles.spinner} aria-hidden />
              {hydrating
                ? "Restoring saved session…"
                : "Running SentinelAI pipeline across feature vectors…"}
            </div>
          ) : null}

          <Outlet />
        </main>
      </div>
    </div>
  );
}

export default function SocLayout() {
  return (
    <AnalysisProvider>
      <SocShell />
    </AnalysisProvider>
  );
}
