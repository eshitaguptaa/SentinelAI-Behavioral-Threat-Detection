import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import {
  buildDemoFeatureVectors,
  fetchAppInfo,
  fetchHealth,
  predictBatch,
  toUserFriendlyError,
} from "../services/api";
import {
  buildReportStats,
  createReportId,
  deleteReport as deleteStoredReport,
  getActiveReport,
  getReport,
  listReportSummaries,
  saveReport,
  setActiveReportId,
  type AnalysisReport,
  type AnalysisReportSummary,
} from "../services/analysisHistory";
import {
  ExcelImportError,
  parseFeatureVectorsFromExcel,
} from "../services/excelImport";
import type {
  BackendStatus,
  EmployeeRiskRow,
  FeatureVectorPayload,
  PredictResult,
  RiskDistributionPoint,
} from "../types/models";
import { RISK_COLORS } from "../types/models";

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

function applyReport(
  report: AnalysisReport,
  setters: {
    setRows: (rows: EmployeeRiskRow[]) => void;
    setSelectedId: (id: string | null) => void;
    setSourceFileName: (name: string | null) => void;
    setLoadedVectors: (vectors: FeatureVectorPayload[] | null) => void;
    setActiveReportIdState: (id: string | null) => void;
  },
) {
  const nextRows = toRows(report.results).sort((a, b) => b.risk_score - a.risk_score);
  setters.setLoadedVectors(report.vectors);
  setters.setSourceFileName(report.sourceFileName);
  setters.setRows(nextRows);
  setters.setSelectedId(
    report.selectedId && nextRows.some((row) => row.id === report.selectedId)
      ? report.selectedId
      : (nextRows[0]?.id ?? null),
  );
  setters.setActiveReportIdState(report.id);
}

interface AnalysisContextValue {
  backendStatus: BackendStatus;
  appVersion?: string;
  loading: boolean;
  hydrating: boolean;
  error: string | null;
  errorTitle: string | null;
  rows: EmployeeRiskRow[];
  selectedId: string | null;
  selectedResult: PredictResult | null;
  distribution: RiskDistributionPoint[];
  sourceFileName: string | null;
  activeReportId: string | null;
  history: AnalysisReportSummary[];
  stats: {
    employees: number;
    confirmed: number;
    high: number;
    critical: number;
  };
  refreshBackendStatus: () => Promise<void>;
  refreshHistory: () => Promise<void>;
  analyzeExcelFile: (file: File) => Promise<boolean>;
  runSampleAnalysis: () => Promise<boolean>;
  rerunAnalysis: () => Promise<boolean>;
  loadReport: (id: string) => Promise<boolean>;
  removeReport: (id: string) => Promise<void>;
  selectRow: (row: EmployeeRiskRow) => void;
  clearError: () => void;
  clearResults: () => void;
}

const AnalysisContext = createContext<AnalysisContextValue | null>(null);

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [backendStatus, setBackendStatus] = useState<BackendStatus>("checking");
  const [appVersion, setAppVersion] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);
  const [hydrating, setHydrating] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [errorTitle, setErrorTitle] = useState<string | null>(null);
  const [rows, setRows] = useState<EmployeeRiskRow[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [sourceFileName, setSourceFileName] = useState<string | null>(null);
  const [loadedVectors, setLoadedVectors] = useState<FeatureVectorPayload[] | null>(
    null,
  );
  const [activeReportId, setActiveReportIdState] = useState<string | null>(null);
  const [history, setHistory] = useState<AnalysisReportSummary[]>([]);

  const selectedResult = useMemo(() => {
    const match = rows.find((row) => row.id === selectedId);
    return match?.result ?? null;
  }, [rows, selectedId]);

  const distribution = useMemo(() => buildDistribution(rows), [rows]);

  const stats = useMemo(() => {
    const employees = new Set(rows.map((row) => row.employee_id)).size;
    const confirmed = rows.filter((row) => row.status === "Confirmed Threat").length;
    const high = rows.filter((row) => row.risk_level === "HIGH").length;
    const critical = rows.filter((row) => row.risk_level === "CRITICAL").length;
    return { employees, confirmed, high, critical };
  }, [rows]);

  const refreshHistory = useCallback(async () => {
    try {
      setHistory(await listReportSummaries());
    } catch {
      setHistory([]);
    }
  }, []);

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

  const showError = useCallback((title: string, detail: string) => {
    setErrorTitle(title);
    setError(detail);
  }, []);

  const persistSession = useCallback(
    async (
      vectors: FeatureVectorPayload[],
      label: string,
      nextRows: EmployeeRiskRow[],
      nextSelectedId: string | null,
    ) => {
      const results = nextRows.map((row) => row.result);
      const report: AnalysisReport = {
        id: createReportId(),
        createdAt: new Date().toISOString(),
        sourceFileName: label,
        vectors,
        results,
        selectedId: nextSelectedId,
        stats: buildReportStats(results),
      };
      try {
        await saveReport(report);
        setActiveReportIdState(report.id);
        await refreshHistory();
      } catch (err) {
        console.warn("[analysisHistory] Failed to persist report", err);
      }
    },
    [refreshHistory],
  );

  const analyzeVectors = useCallback(
    async (vectors: FeatureVectorPayload[], label: string) => {
      setLoading(true);
      setError(null);
      setErrorTitle(null);
      try {
        const results = await predictBatch(vectors);
        const nextRows = toRows(results).sort((a, b) => b.risk_score - a.risk_score);
        // Prefer EMP-K01 kill-chain stage for the demo path when present.
        const killChainRow = nextRows.find(
          (row) =>
            row.employee_id === "EMP-K01" &&
            row.simulation_day === "2026-03-09",
        );
        const nextSelectedId = killChainRow?.id ?? nextRows[0]?.id ?? null;
        setLoadedVectors(vectors);
        setSourceFileName(label);
        setRows(nextRows);
        setSelectedId(nextSelectedId);
        setBackendStatus("online");
        await persistSession(vectors, label, nextRows, nextSelectedId);
        return true;
      } catch (err) {
        showError("Unable to complete analysis", toUserFriendlyError(err));
        setBackendStatus("offline");
        return false;
      } finally {
        setLoading(false);
      }
    },
    [persistSession, showError],
  );

  const analyzeExcelFile = useCallback(
    async (file: File) => {
      setLoading(true);
      setError(null);
      setErrorTitle(null);
      try {
        const vectors = await parseFeatureVectorsFromExcel(file);
        setLoading(false);
        return await analyzeVectors(vectors, file.name);
      } catch (err) {
        if (err instanceof ExcelImportError) {
          showError("File format doesn’t match", err.message);
        } else {
          showError(
            "Couldn’t import this file",
            err instanceof Error ? err.message : toUserFriendlyError(err),
          );
        }
        setLoading(false);
        return false;
      }
    },
    [analyzeVectors, showError],
  );

  const runSampleAnalysis = useCallback(async () => {
    const vectors = buildDemoFeatureVectors(24);
    return analyzeVectors(vectors, "Built-in sample data");
  }, [analyzeVectors]);

  const rerunAnalysis = useCallback(async () => {
    if (!loadedVectors?.length) {
      showError(
        "No data loaded",
        "Upload an Excel file first, or load the built-in sample.",
      );
      return false;
    }
    return analyzeVectors(loadedVectors, sourceFileName ?? "Current batch");
  }, [analyzeVectors, loadedVectors, showError, sourceFileName]);

  const loadReport = useCallback(
    async (id: string) => {
      setLoading(true);
      setError(null);
      setErrorTitle(null);
      try {
        const report = await getReport(id);
        if (!report) {
          showError("Report not found", "That history item is no longer available.");
          return false;
        }
        applyReport(report, {
          setRows,
          setSelectedId,
          setSourceFileName,
          setLoadedVectors,
          setActiveReportIdState,
        });
        await setActiveReportId(report.id);
        return true;
      } catch (err) {
        showError(
          "Couldn’t open report",
          err instanceof Error ? err.message : "Failed to load saved report.",
        );
        return false;
      } finally {
        setLoading(false);
      }
    },
    [showError],
  );

  const removeReport = useCallback(
    async (id: string) => {
      await deleteStoredReport(id);
      if (activeReportId === id) {
        setRows([]);
        setSelectedId(null);
        setLoadedVectors(null);
        setSourceFileName(null);
        setActiveReportIdState(null);
      }
      await refreshHistory();
    },
    [activeReportId, refreshHistory],
  );

  const selectRow = useCallback((row: EmployeeRiskRow) => {
    setSelectedId(row.id);
  }, []);

  const clearError = useCallback(() => {
    setError(null);
    setErrorTitle(null);
  }, []);

  const clearResults = useCallback(() => {
    setRows([]);
    setSelectedId(null);
    setLoadedVectors(null);
    setSourceFileName(null);
    setActiveReportIdState(null);
    setError(null);
    setErrorTitle(null);
    void setActiveReportId(null);
  }, []);

  useEffect(() => {
    void refreshBackendStatus();
  }, [refreshBackendStatus]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [report, summaries] = await Promise.all([
          getActiveReport(),
          listReportSummaries(),
        ]);
        if (cancelled) return;
        setHistory(summaries);
        if (report) {
          applyReport(report, {
            setRows,
            setSelectedId,
            setSourceFileName,
            setLoadedVectors,
            setActiveReportIdState,
          });
        }
      } catch (err) {
        console.warn("[analysisHistory] Failed to hydrate session", err);
      } finally {
        if (!cancelled) setHydrating(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const value = useMemo(
    () => ({
      backendStatus,
      appVersion,
      loading,
      hydrating,
      error,
      errorTitle,
      rows,
      selectedId,
      selectedResult,
      distribution,
      sourceFileName,
      activeReportId,
      history,
      stats,
      refreshBackendStatus,
      refreshHistory,
      analyzeExcelFile,
      runSampleAnalysis,
      rerunAnalysis,
      loadReport,
      removeReport,
      selectRow,
      clearError,
      clearResults,
    }),
    [
      backendStatus,
      appVersion,
      loading,
      hydrating,
      error,
      errorTitle,
      rows,
      selectedId,
      selectedResult,
      distribution,
      sourceFileName,
      activeReportId,
      history,
      stats,
      refreshBackendStatus,
      refreshHistory,
      analyzeExcelFile,
      runSampleAnalysis,
      rerunAnalysis,
      loadReport,
      removeReport,
      selectRow,
      clearError,
      clearResults,
    ],
  );

  return (
    <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>
  );
}

export function useAnalysis() {
  const ctx = useContext(AnalysisContext);
  if (!ctx) {
    throw new Error("useAnalysis must be used within AnalysisProvider");
  }
  return ctx;
}
