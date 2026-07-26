import demoFeatureVectors from "../data/demoFeatureVectors.json";

import axios, { AxiosError } from "axios";

import type {
  AppInfo,
  FeatureVectorPayload,
  HealthStatus,
  PredictBatchResponse,
  PredictResult,
} from "../types/models";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.toString() || "http://127.0.0.1:8000";

const client = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60_000,
  headers: { "Content-Type": "application/json" },
});

export function getApiBaseUrl(): string {
  return API_BASE_URL;
}

export function toUserFriendlyError(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const ax = error as AxiosError<{ detail?: string | unknown }>;
    if (ax.code === "ECONNABORTED") {
      return "Request timed out. Check that the SentinelAI API is running.";
    }
    if (!ax.response) {
      return "Unable to reach the SentinelAI backend. Verify the API is online.";
    }
    const detail = ax.response.data?.detail;
    if (typeof detail === "string" && detail.trim()) {
      return detail;
    }
    if (ax.response.status === 503) {
      return "Inference model is unavailable. Set SENTINELAI_MODEL_PATH on the API.";
    }
    if (ax.response.status === 400) {
      return "Invalid request. Check feature vector fields and try again.";
    }
    if (ax.response.status === 422) {
      return "Request validation failed. Some required fields are missing or invalid — check your columns against the template.";
    }
    return `Backend error (${ax.response.status}). Please try again.`;
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return "An unexpected error occurred.";
}

export async function fetchAppInfo(): Promise<AppInfo> {
  const { data } = await client.get<AppInfo>("/");
  return data;
}

export async function fetchHealth(): Promise<HealthStatus> {
  const { data } = await client.get<HealthStatus>("/health");
  return data;
}

export async function predictOne(
  featureVector: FeatureVectorPayload,
): Promise<PredictResult> {
  const { data } = await client.post<PredictResult>("/predict", {
    feature_vector: featureVector,
  });
  return data;
}

export async function predictBatch(
  featureVectors: FeatureVectorPayload[],
): Promise<PredictResult[]> {
  const { data } = await client.post<PredictBatchResponse>("/predict/batch", {
    feature_vectors: featureVectors,
  });
  return data.results;
}

type DemoKind = "normal" | "mild_anomaly" | "confirmed_attack";

type DemoVectorRecord = FeatureVectorPayload & {
  demo_kind?: DemoKind;
  attack_scenario?: string;
};

/**
 * Enterprise-realistic demo vectors for the SOC dashboard.
 *
 * Mix (~24 users): ~75% normal, ~10% mild behavioural anomalies (no attack
 * rule), ~15% confirmed attacks. Normal sessions are sampled from the same
 * ``events.csv`` distribution used to train the Transformer — no attack
 * features are injected into normal rows.
 *
 * Source of truth: ``synthetic_data/demo/session_generator.py``
 * (regenerate JSON via ``scripts/export_and_audit_demo.py``).
 */
export function buildDemoFeatureVectors(
  count = 24,
  simulationDay = "2026-03-10",
): FeatureVectorPayload[] {
  const source = demoFeatureVectors as DemoVectorRecord[];
  if (!Array.isArray(source) || source.length === 0) {
    throw new Error(
      "demoFeatureVectors.json is empty. Run scripts/export_and_audit_demo.py",
    );
  }

  const normals = source.filter((row) => row.demo_kind === "normal");
  const mild = source.filter((row) => row.demo_kind === "mild_anomaly");
  const attacks = source.filter((row) => row.demo_kind === "confirmed_attack");

  const nAttack = Math.max(1, Math.round(count * 0.15));
  const nMild = Math.max(1, Math.round(count * 0.1));
  const nNormal = Math.max(1, count - nAttack - nMild);

  const pick = (pool: DemoVectorRecord[], n: number, offset: number) => {
    const out: DemoVectorRecord[] = [];
    for (let i = 0; i < n; i += 1) {
      out.push(pool[(offset + i) % pool.length] ?? pool[0]);
    }
    return out;
  };

  const selected = [
    ...pick(normals.length ? normals : source, nNormal, 0),
    ...pick(mild.length ? mild : source, nMild, 3),
    ...pick(attacks.length ? attacks : source, nAttack, 7),
  ].slice(0, count);

  return selected.map((row, index) => {
    const { demo_kind: _kind, attack_scenario: _scenario, ...rest } = row;
    return {
      ...rest,
      employee_id: `EMP-${String(index + 1).padStart(3, "0")}`,
      simulation_day: simulationDay,
      event_sequence: [...(row.event_sequence ?? [])],
    };
  });
}
