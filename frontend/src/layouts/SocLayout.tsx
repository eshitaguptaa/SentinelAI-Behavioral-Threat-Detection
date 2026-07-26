import { useEffect, useId, useState } from "react";
import { Menu, X } from "lucide-react";
import { Outlet, useLocation } from "react-router-dom";

import Sidebar from "../components/Sidebar";
import { BrandName, Logo } from "../components/Logo";
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
  const { error, errorTitle, loading, clearError } = useAnalysis();
  const location = useLocation();
  const contextLabel = TITLES[location.pathname] ?? "Workspace";
  const [navOpen, setNavOpen] = useState(false);
  const drawerId = useId();

  useEffect(() => {
    document.title = `SentinelAI · ${contextLabel}`;
    document.body.style.background = "";
  }, [contextLabel]);

  useEffect(() => {
    setNavOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!navOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setNavOpen(false);
    };
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [navOpen]);

  return (
    <div className={styles.shell}>
      <Sidebar variant="rail" />

      <div className={styles.mainColumn}>
        <header className={styles.mobileTopbar}>
          <button
            type="button"
            className={styles.menuBtn}
            aria-label={navOpen ? "Close navigation" : "Open navigation"}
            aria-expanded={navOpen}
            aria-controls={drawerId}
            onClick={() => setNavOpen((open) => !open)}
          >
            {navOpen ? <X size={18} aria-hidden /> : <Menu size={18} aria-hidden />}
          </button>
          <div className={styles.mobileBrand}>
            <Logo withWordmark={false} size={26} />
            <div className={styles.mobileBrandText}>
              <span className={styles.mobileBrandName}>
                <BrandName />
              </span>
              <span className={styles.mobileContext}>{contextLabel}</span>
            </div>
          </div>
        </header>

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

        {loading ? (
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
              <h2 className={styles.loadingTitle}>Scoring behavioural risk</h2>
              <p className={styles.loadingCopy}>
                Running detection, risk fusion, and case prep. This may take a moment.
              </p>
              <ul className={styles.loadingStages} aria-hidden>
                <li>Detect</li>
                <li>Fuse risk</li>
                <li>Explain</li>
              </ul>
            </div>
          </div>
        ) : null}
      </div>

      <button
        type="button"
        className={`${styles.navScrim} ${navOpen ? styles.navScrimOpen : ""}`}
        aria-label="Close navigation"
        tabIndex={navOpen ? 0 : -1}
        onClick={() => setNavOpen(false)}
      />
      <Sidebar
        id={drawerId}
        variant="drawer"
        open={navOpen}
        onNavigate={() => setNavOpen(false)}
      />
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
