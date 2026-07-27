import demoCampaignChain from "../data/demoCampaignChain.json";
import demoFeatureVectors from "../data/demoFeatureVectors.json";

import axios, { AxiosError } from "axios";

import type {
  AppInfo,
  CorrelateCampaignsResponse,
  FeatureVectorPayload,
  HealthStatus,
  PredictBatchResponse,
  PredictResult,
} from "../types/models";
import {
  downloadFeatureVectorsWorkbook,
  SAMPLE_WORKBOOK_NAME,
} from "./excelImport";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.toString() || "http://127.0.0.1:8000";

const client = axios.create({
  baseURL: API_BASE_URL,
  // Railway CPU inference can exceed 60s under load / cold start.
  timeout: 180_000,
  headers: { "Content-Type": "application/json" },
});

export function getApiBaseUrl(): string {
  return API_BASE_URL;
}

export function toUserFriendlyError(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const ax = error as AxiosError<{ detail?: string | unknown }>;
    if (ax.code === "ECONNABORTED") {
      return "Request timed out while scoring. Try again — the API may be busy or waking up.";
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

export async function correlateCampaigns(
  results: PredictResult[],
  focusEmployeeId?: string | null,
  focusSimulationDay?: string | null,
): Promise<CorrelateCampaignsResponse> {
  const { data } = await client.post<CorrelateCampaignsResponse>(
    "/correlate/campaigns",
    {
      results,
      focus_employee_id: focusEmployeeId ?? null,
      focus_simulation_day: focusSimulationDay ?? null,
    },
  );
  return data;
}

type DemoKind = "normal" | "mild_anomaly" | "confirmed_attack";

type DemoVectorRecord = FeatureVectorPayload & {
  demo_kind?: DemoKind;
  attack_scenario?: string;
  campaign_id?: string;
};

/** Default enterprise sample size (matches exported demoFeatureVectors.json). */
export const DEMO_SAMPLE_SIZE = 500;

export const BATCH_CHUNK_SIZE = 25;

/**
 * Enterprise-realistic demo vectors for the SOC dashboard.
 *
 * Source of truth: ``synthetic_data/demo/session_generator.py``
 * Regenerate with ``python scripts/export_enterprise_demo.py`` (500 employees,
 * ~94% normal / 3% mild / 3% attacks; quiet normals filtered to low recon error).
 * Appends the EMP-K01 kill-chain campaign stages for Investigate.
 */
export function buildDemoFeatureVectors(
  count = DEMO_SAMPLE_SIZE,
): FeatureVectorPayload[] {
  const source = demoFeatureVectors as DemoVectorRecord[];
  if (!Array.isArray(source) || source.length === 0) {
    throw new Error(
      "demoFeatureVectors.json is empty. Run scripts/export_enterprise_demo.py",
    );
  }

  const stripMeta = (row: DemoVectorRecord): FeatureVectorPayload => {
    const { demo_kind: _kind, attack_scenario: _scenario, ...rest } = row;
    return {
      ...rest,
      employee_id: row.employee_id,
      simulation_day: row.simulation_day,
      event_sequence: [...(row.event_sequence ?? [])],
      ...(row.campaign_id ? { campaign_id: row.campaign_id } : {}),
    };
  };

  // Prefer the pre-exported enterprise corpus as-is (unique EMP ids + mix).
  let selected: DemoVectorRecord[];
  if (count >= source.length) {
    selected = source;
  } else {
    const normals = source.filter((row) => row.demo_kind === "normal");
    const mild = source.filter((row) => row.demo_kind === "mild_anomaly");
    const attacks = source.filter((row) => row.demo_kind === "confirmed_attack");
    const nAttack = Math.max(1, Math.round(count * 0.1));
    const nMild = Math.max(1, Math.round(count * 0.08));
    const nNormal = Math.max(1, count - nAttack - nMild);
    const pick = (pool: DemoVectorRecord[], n: number) =>
      pool.slice(0, Math.min(n, pool.length));
    selected = [
      ...pick(normals.length ? normals : source, nNormal),
      ...pick(mild.length ? mild : source, nMild),
      ...pick(attacks.length ? attacks : source, nAttack),
    ].slice(0, count);
  }

  const remapped = selected.map(stripMeta);

  const chain = (demoCampaignChain as DemoVectorRecord[]).map(stripMeta);

  return [...remapped, ...chain];
}

/** Score a large demo batch in chunks to avoid gateway / UI timeouts. */
export async function predictBatchChunked(
  featureVectors: FeatureVectorPayload[],
  chunkSize = BATCH_CHUNK_SIZE,
): Promise<PredictResult[]> {
  if (featureVectors.length <= chunkSize) {
    return predictBatch(featureVectors);
  }
  const results: PredictResult[] = [];
  for (let i = 0; i < featureVectors.length; i += chunkSize) {
    const chunk = featureVectors.slice(i, i + chunkSize);
    const partial = await predictBatch(chunk);
    results.push(...partial);
  }
  return results;
}

/** Download the exact workbook used by ``Run sample`` (including EMP-K01). */
export function downloadDemoSampleWorkbook(): void {
  downloadFeatureVectorsWorkbook(
    buildDemoFeatureVectors(DEMO_SAMPLE_SIZE),
    SAMPLE_WORKBOOK_NAME,
  );
}

