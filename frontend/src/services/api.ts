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
      return "Request validation failed. Some required fields are missing or invalid.";
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

/**
 * Deterministic demo feature vectors for SOC walkthroughs when no live
 * simulation export is wired yet. Values vary by employee index.
 */
export function buildDemoFeatureVectors(
  count = 24,
  simulationDay = "2026-03-10",
): FeatureVectorPayload[] {
  const vectors: FeatureVectorPayload[] = [];
  for (let i = 0; i < count; i += 1) {
    const tier = i % 5;
    vectors.push({
      employee_id: `EMP-${String(i + 1).padStart(3, "0")}`,
      simulation_day: simulationDay,
      total_events: 18 + (i % 12) * 3,
      login_count: tier === 3 ? 14 : 1 + (i % 3),
      logout_count: 1 + (i % 2),
      auth_failure_rate: tier === 4 ? 0.55 : tier === 3 ? 0.28 : 0.02 * (i % 4),
      max_failed_login_streak: tier === 4 ? 8 : tier === 3 ? 4 : i % 2,
      country_change_count: tier === 2 ? 2 + (i % 2) : tier >= 3 ? 1 : 0,
      location_change_count: tier === 1 ? 5 : 1 + (i % 5),
      unique_device_count: tier === 0 && i > 10 ? 4 : 1 + (i % 3),
      unique_location_count: tier === 1 ? 4 : 1 + (i % 3),
      resource_entropy: tier >= 3 ? 2.4 : 0.4 + (i % 5) * 0.2,
      device_entropy: tier === 0 && i > 10 ? 1.3 : 0.2 + (i % 4) * 0.15,
      after_hours_event_count: tier === 4 ? 14 : i % 4,
      download_size_mb_sum: tier === 4 ? 180 : tier === 3 ? 70 : 5 + i,
      mass_download_event_count: tier === 4 ? 2 : 0,
      vpn_usage_ratio: i % 7 === 0 ? 0.72 : 0.1 + (i % 5) * 0.05,
      burst_max_5min: tier >= 3 ? 22 + (i % 10) : 4 + (i % 6),
      active_duration_hours: tier === 4 ? 13 : 7 + (i % 5),
      file_access_ratio: tier === 4 ? 0.55 : 0.15 + (i % 5) * 0.05,
      night_event_count: tier >= 3 ? 6 : i % 3,
    });
  }
  return vectors;
}
