import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import EmployeeTable from "../components/EmployeeTable";
import ExplanationPanel from "../components/ExplanationPanel";
import Header from "../components/Header";
import RiskChart from "../components/RiskChart";
import Sidebar, { type SidebarSection } from "../components/Sidebar";
import StatsCard from "../components/StatsCard";
import {
  buildDemoFeatureVectors,
  fetchAppInfo,
  fetchHealth,
  getApiBaseUrl,
  predictBatch,
  toUserFriendlyError,
} from "../services/api";
import type {
  BackendStatus,
  EmployeeRiskRow,
  PredictResult,
  RiskDistributionPoint,
} from "../types/models";
import { RISK_COLORS } from "../types/models";
import styles from "./Dashboard.module.css";

function toRows(results: PredictResult[]): EmployeeRiskRow[] {
  return results.map((result) => ({
    id: `${result.prediction.employee_id}::${result.prediction.simulation_day}`,
    employee_id: result.prediction.employee_id,
    simulation_day: result.prediction.simulation_day,
    anomaly_score: result.prediction.normalized_score,
    risk_score: result.risk_assessment.risk_score,
    risk_level: result.risk_assessment.risk_level,
    attack_type: result.attack_classification.attack_type,
    attack_confidence: result.attack_classification.attack_confidence,
    status: result.status,
    result,
  }));
}

function buildDistribution(rows: EmployeeRiskRow[]): RiskDistributionPoint[] {
  const levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
  const counts: Record<string, number> = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
  };
  for (const row of rows) {
    const key = row.risk_level in counts ? row.risk_level : "LOW";
    counts[key] += 1;
  }
  return levels.map((level) => ({
    level,
    count: counts[level],
    fill: RISK_COLORS[level],
  }));
}

function Section({
  id,
  children,
}: {
  id: string;
  children: ReactNode;
}) {
  return (
    <div id={id} className={styles.section}>
      {children}
    </div>
  );
}

export default function Dashboard() {
  const [section, setSection] = useState<SidebarSection>("dashboard");
  const [backendStatus, setBackendStatus] = useState<BackendStatus>("checking");
  const [appVersion, setAppVersion] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rows, setRows] = useState<EmployeeRiskRow[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selectedResult = useMemo(() => {
    const match = rows.find((row) => row.id === selectedId);
    return match?.result ?? null;
  }, [rows, selectedId]);

  const distribution = useMemo(() => buildDistribution(rows), [rows]);

  const stats = useMemo(() => {
    const employees = new Set(rows.map((row) => row.employee_id)).size;
    const confirmed = rows.filter(
      (row) => row.status === "Confirmed Threat",
    ).length;
    const high = rows.filter((row) => row.risk_level === "HIGH").length;
    const critical = rows.filter((row) => row.risk_level === "CRITICAL").length;
    return { employees, confirmed, high, critical };
  }, [rows]);

  const refreshBackendStatus = useCallback(async () => {
    setBackendStatus("checking");
    try {
      const [health, info] = await Promise.all([fetchHealth(), fetchAppInfo()]);
      if (health.status.toLowerCase() === "healthy" || info.status) {
        setBackendStatus("online");
      } else {
        setBackendStatus("offline");
      }
      setAppVersion(info.version);
    } catch {
      setBackendStatus("offline");
      setAppVersion(undefined);
    }
  }, []);

  const runAnalysis = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const vectors = buildDemoFeatureVectors(24);
      const results = await predictBatch(vectors);
      const nextRows = toRows(results).sort(
        (a, b) => b.risk_score - a.risk_score,
      );
      setRows(nextRows);
      setSelectedId(nextRows[0]?.id ?? null);
      setBackendStatus("online");
    } catch (err) {
      setError(toUserFriendlyError(err));
      setBackendStatus("offline");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshBackendStatus();
  }, [refreshBackendStatus]);

  useEffect(() => {
    const target = document.getElementById(section);
    if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [section]);

  const onSelectRow = useCallback((row: EmployeeRiskRow) => {
    setSelectedId(row.id);
    setSection("explainability");
  }, []);

  return (
    <div className={styles.shell}>
      <Header backendStatus={backendStatus} appVersion={appVersion} />

      <div className={styles.body}>
        <Sidebar active={section} onNavigate={setSection} />

        <main className={styles.main}>
          <div className={styles.toolbar}>
            <div>
              <h2 className={styles.pageTitle}>Security Operations Overview</h2>
              <p className={styles.pageCaption}>
                Live inference via {getApiBaseUrl()} · Isolation Forest → Risk →
                Explainability
              </p>
            </div>
            <div className={styles.actions}>
              <button
                type="button"
                className={styles.secondaryBtn}
                onClick={() => void refreshBackendStatus()}
                disabled={loading}
              >
                Refresh status
              </button>
              <button
                type="button"
                className={styles.primaryBtn}
                onClick={() => void runAnalysis()}
                disabled={loading}
              >
                {loading ? "Running…" : "Run batch analysis"}
              </button>
            </div>
          </div>

          {error ? (
            <div className={styles.error} role="alert">
              <strong>Unable to complete analysis</strong>
              <p>{error}</p>
            </div>
          ) : null}

          {loading ? (
            <div className={styles.loading} role="status" aria-live="polite">
              <span className={styles.spinner} aria-hidden />
              Running SentinelAI pipeline…
            </div>
          ) : null}

          <Section id="dashboard">
            <div className={styles.cards}>
              <StatsCard
                label="Total Employees"
                value={stats.employees}
                hint="Unique IDs in current batch"
              />
              <StatsCard
                label="Confirmed Threats"
                value={stats.confirmed}
                tone="critical"
                hint="Final status Confirmed Threat"
              />
              <StatsCard
                label="High Risk"
                value={stats.high}
                tone="high"
                hint="Risk level HIGH"
              />
              <StatsCard
                label="Critical Risk"
                value={stats.critical}
                tone="critical"
                hint="Risk level CRITICAL"
              />
            </div>
          </Section>

          <Section id="risk">
            <RiskChart data={distribution} />
          </Section>

          <Section id="predictions">
            <EmployeeTable
              rows={rows}
              selectedId={selectedId}
              onSelect={onSelectRow}
            />
          </Section>

          <Section id="explainability">
            <ExplanationPanel result={selectedResult} />
          </Section>

          <Section id="system">
            <div className={styles.systemPanel}>
              <h2>System Status</h2>
              <ul>
                <li>
                  Backend:{" "}
                  <strong>
                    {backendStatus === "online"
                      ? "Healthy"
                      : backendStatus === "checking"
                        ? "Checking"
                        : "Unreachable"}
                  </strong>
                </li>
                <li>
                  API base: <code>{getApiBaseUrl()}</code>
                </li>
                <li>
                  Loaded rows: <strong>{rows.length}</strong>
                </li>
                <li>
                  App version: <strong>{appVersion ?? "—"}</strong>
                </li>
              </ul>
            </div>
          </Section>
        </main>
      </div>
    </div>
  );
}
