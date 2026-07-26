import { RefreshCw } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { useAnalysis } from "../contexts/AnalysisContext";
import styles from "../pages/Dashboard.module.css";

type Phase = "idle" | "busy" | "done";

interface StatusRefreshButtonProps {
  label?: string;
}

export default function StatusRefreshButton({
  label = "Refresh",
}: StatusRefreshButtonProps) {
  const { refreshBackendStatus, backendStatus, loading } = useAnalysis();
  const [phase, setPhase] = useState<Phase>("idle");
  const resetTimer = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (resetTimer.current != null) {
        window.clearTimeout(resetTimer.current);
      }
    };
  }, []);

  const onRefresh = async () => {
    if (phase === "busy" || loading) return;
    if (resetTimer.current != null) {
      window.clearTimeout(resetTimer.current);
      resetTimer.current = null;
    }

    setPhase("busy");
    const started = Date.now();
    await refreshBackendStatus();
    // Keep the busy state visible long enough to feel intentional.
    const remaining = Math.max(0, 500 - (Date.now() - started));
    if (remaining) {
      await new Promise((resolve) => window.setTimeout(resolve, remaining));
    }

    setPhase("done");
    resetTimer.current = window.setTimeout(() => {
      setPhase("idle");
      resetTimer.current = null;
    }, 1800);
  };

  const doneOk = phase === "done" && backendStatus === "online";
  const doneFail = phase === "done" && backendStatus !== "online";

  const text =
    phase === "busy"
      ? "Refreshing…"
      : doneOk
        ? "API online"
        : doneFail
          ? "API offline"
          : label;

  return (
    <button
      type="button"
      className={`${styles.secondaryBtn} ${doneOk ? styles.refreshDone : ""} ${doneFail ? styles.refreshFail : ""}`}
      onClick={() => void onRefresh()}
      disabled={loading || phase === "busy"}
      aria-live="polite"
    >
      <RefreshCw
        size={14}
        aria-hidden
        className={phase === "busy" ? styles.refreshSpin : undefined}
      />
      {text}
    </button>
  );
}
