/** Shared TypeScript models aligned with the SentinelAI FastAPI contract. */

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type BackendStatus = "online" | "offline" | "checking";

export interface AppInfo {
  application: string;
  version: string;
  status: string;
}

export interface HealthStatus {
  status: string;
}

/** Phase 8 feature vector payload accepted by POST /predict*. */
export interface FeatureVectorPayload {
  employee_id: string;
  simulation_day: string;
  [key: string]: string | number | null | undefined;
}

export interface AnomalyPrediction {
  employee_id: string;
  simulation_day: string;
  raw_score: number;
  normalized_score: number;
  prediction: number;
  is_anomaly: boolean;
}

export interface RiskAssessment {
  employee_id: string;
  simulation_day: string;
  anomaly_score: number;
  risk_score: number;
  risk_level: RiskLevel | string;
  contributing_factors: string[];
  recommendation: string;
}

export interface RiskExplanation {
  employee_id: string;
  simulation_day: string;
  risk_score: number;
  risk_level: RiskLevel | string;
  summary: string;
  contributing_factors: string[];
  observations: string[];
  recommendation: string;
}

export interface PredictResult {
  prediction: AnomalyPrediction;
  risk_assessment: RiskAssessment;
  explanation: RiskExplanation;
}

export interface PredictBatchResponse {
  results: PredictResult[];
}

/** Flattened row for the employee table. */
export interface EmployeeRiskRow {
  id: string;
  employee_id: string;
  simulation_day: string;
  anomaly_score: number;
  risk_score: number;
  risk_level: string;
  is_anomaly: boolean;
  result: PredictResult;
}

export interface RiskDistributionPoint {
  level: string;
  count: number;
  fill: string;
}

export const RISK_COLORS: Record<string, string> = {
  LOW: "#3dba7a",
  MEDIUM: "#e4c35a",
  HIGH: "#e08a3c",
  CRITICAL: "#e24b4b",
};
