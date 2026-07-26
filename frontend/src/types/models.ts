/** Shared TypeScript models aligned with the SentinelAI FastAPI contract. */

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type BackendStatus = "online" | "offline" | "checking";

/** Final SOC status — derived on the backend from risk_level + attack_type. */
export type FinalStatus =
  | "Normal"
  | "Suspicious"
  | "Under Investigation"
  | "Confirmed Threat";

export type AttackType =
  | "Impossible Travel"
  | "Brute Force"
  | "Credential Stuffing"
  | "Device Spoofing"
  | "Lateral Movement"
  | "Low-and-Slow Exfiltration"
  | "Insider Drift"
  | "Insider Activity"
  | "Mass Download"
  | "Suspicious VPN Usage"
  | "None"
  | "Behavioural Anomaly"
  | "Unknown Behaviour"
  | "Normal Activity"
  | string;

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
  event_sequence?: string[];
  [key: string]: string | number | string[] | null | undefined;
}

export interface AnomalyPrediction {
  employee_id: string;
  simulation_day: string;
  raw_score: number;
  normalized_score: number;
  prediction: number;
  is_anomaly: boolean;
}

export interface SuspiciousEvent {
  index: number;
  event_type: string;
  reconstruction_error: number;
  attention_mass: number;
  explanation?: string;
}

export interface BehaviourInsight {
  session_id: string;
  reconstruction_error: number;
  anomaly_score: number;
  behaviour_score: number;
  confidence_score: number;
  behaviour_embedding: number[];
  event_types: string[];
  per_event_errors: number[];
  attention_weights: number[][];
  attention_available?: boolean;
  top_suspicious_events: SuspiciousEvent[];
  model: string;
}

export interface MitreMapping {
  attack_type: string;
  tactic_id: string;
  tactic_name: string;
  technique_id: string;
  technique_name: string;
  description: string;
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

export interface AttackClassification {
  employee_id: string;
  simulation_day: string;
  attack_type: AttackType;
  attack_confidence: number;
  matched_signals: string[];
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
  attack_classification: AttackClassification;
  explanation: RiskExplanation;
  /** Backend-derived final status — never compute this in the UI. */
  status: FinalStatus | string;
  behaviour_insight?: BehaviourInsight | null;
  mitre?: MitreMapping | null;
  cold_start?: {
    is_cold_start: boolean;
    event_count: number;
    trust: number;
    reason: string;
    adjusted_normalized_score: number;
  } | null;
  concept_drift?: {
    entity_id: string;
    ewma: number;
    delta: number;
    is_gradual_drift: boolean;
    is_abrupt_shift: boolean;
    reason: string;
    adjusted_normalized_score: number;
  } | null;
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
  attack_type: string;
  attack_confidence: number;
  status: FinalStatus | string;
  result: PredictResult;
}

export interface RiskDistributionPoint {
  level: string;
  count: number;
  fill: string;
}

export const RISK_COLORS: Record<string, string> = {
  LOW: "#1f8a5b",
  MEDIUM: "#c48a1a",
  HIGH: "#d2641f",
  CRITICAL: "#e4002b",
};

export const STATUS_COLORS: Record<string, string> = {
  Normal: "#1f8a5b",
  Suspicious: "#c48a1a",
  "Under Investigation": "#d2641f",
  "Confirmed Threat": "#e4002b",
};

/** Unique badge colours per attack classification label. */
export const ATTACK_COLORS: Record<string, string> = {
  "Impossible Travel": "#5b8def",
  "Brute Force": "#e24b4b",
  "Credential Stuffing": "#c45cdd",
  "Device Spoofing": "#27a8a0",
  "Lateral Movement": "#e08a3c",
  "Low-and-Slow Exfiltration": "#7a6bb5",
  "Insider Drift": "#9aa0a6",
  "Insider Activity": "#d4a017",
  "Mass Download": "#e06b9f",
  "Suspicious VPN Usage": "#6b8cae",
  None: "#8a98a8",
  "Behavioural Anomaly": "#e08a3c",
  "Unknown Behaviour": "#c4a35a",
  "Normal Activity": "#3dba7a",
};
