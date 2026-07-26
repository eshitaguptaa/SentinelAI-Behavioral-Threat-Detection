import { Navigate, Route, Routes } from "react-router-dom";

import RequireAnalysis from "./components/RequireAnalysis";
import ScrollToTop from "./components/ScrollToTop";
import SocLayout from "./layouts/SocLayout";
import HistoryPage from "./pages/HistoryPage";
import InvestigatePage from "./pages/InvestigatePage";
import LandingPage from "./pages/LandingPage";
import OverviewPage from "./pages/OverviewPage";
import PredictionsPage from "./pages/PredictionsPage";
import RiskPage from "./pages/RiskPage";
import SystemPage from "./pages/SystemPage";
import UploadPage from "./pages/UploadPage";
import styles from "./App.module.css";

export default function App() {
  return (
    <div className={styles.app}>
      <ScrollToTop />
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/app" element={<SocLayout />}>
          <Route index element={<UploadPage />} />
          <Route path="system" element={<SystemPage />} />
          <Route
            path="overview"
            element={
              <RequireAnalysis>
                <OverviewPage />
              </RequireAnalysis>
            }
          />
          <Route
            path="history"
            element={
              <RequireAnalysis>
                <HistoryPage />
              </RequireAnalysis>
            }
          />
          <Route
            path="risk"
            element={
              <RequireAnalysis>
                <RiskPage />
              </RequireAnalysis>
            }
          />
          <Route
            path="predictions"
            element={
              <RequireAnalysis>
                <PredictionsPage />
              </RequireAnalysis>
            }
          />
          <Route
            path="investigate"
            element={
              <RequireAnalysis>
                <InvestigatePage />
              </RequireAnalysis>
            }
          />
        </Route>
        <Route path="/dashboard" element={<Navigate to="/app" replace />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  );
}
