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

          <Outlet />
        </main>

        {loading || hydrating ? (
          <div
            className={styles.loadingOverlay}
            role="status"
            aria-live="polite"
            aria-busy="true"
          >
            <div className={styles.loadingPanel}>
              <div className={styles.loadingOrb} aria-hidden>
                <span className={styles.loadingRing} />
                <span className={styles.loadingRing} />
                <span className={styles.loadingCore} />
              </div>
              <p className={styles.loadingEyebrow}>SentinelAI</p>
              <h2 className={styles.loadingTitle}>
                {hydrating ? "Restoring your workspace" : "Scoring behavioural risk"}
              </h2>
              <p className={styles.loadingCopy}>
                {hydrating
                  ? "Bringing back the last analysis session…"
                  : "Running detection, risk fusion, and case prep. This may take a moment."}
              </p>
              {!hydrating ? (
                <ul className={styles.loadingStages} aria-hidden>
                  <li>Detect</li>
                  <li>Fuse risk</li>
                  <li>Explain</li>
                </ul>
              ) : null}
            </div>
          </div>
        ) : null}
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
