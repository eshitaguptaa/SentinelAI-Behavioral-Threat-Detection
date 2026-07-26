import { Navigate } from "react-router-dom";
import type { ReactNode } from "react";

import { useAnalysis } from "../contexts/AnalysisContext";

/** Blocks analysis pages until the first report exists (current session or history). */
export default function RequireAnalysis({ children }: { children: ReactNode }) {
  const { rows, history, hydrating } = useAnalysis();

  if (hydrating) return null;

  const unlocked = rows.length > 0 || history.length > 0;
  if (!unlocked) {
    return <Navigate to="/app" replace />;
  }

  return children;
}
