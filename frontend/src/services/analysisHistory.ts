import type { FeatureVectorPayload, PredictResult } from "../types/models";

export interface AnalysisReportStats {
  employees: number;
  confirmed: number;
  high: number;
  critical: number;
  rows: number;
}

export interface AnalysisReport {
  id: string;
  createdAt: string;
  sourceFileName: string;
  vectors: FeatureVectorPayload[];
  results: PredictResult[];
  selectedId: string | null;
  stats: AnalysisReportStats;
}

export interface AnalysisReportSummary {
  id: string;
  createdAt: string;
  sourceFileName: string;
  stats: AnalysisReportStats;
}

const DB_NAME = "sentinelai-soc";
const DB_VERSION = 1;
const REPORTS_STORE = "reports";
const META_STORE = "meta";
const ACTIVE_KEY = "activeReportId";
const MAX_REPORTS = 25;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(REPORTS_STORE)) {
        db.createObjectStore(REPORTS_STORE, { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains(META_STORE)) {
        db.createObjectStore(META_STORE);
      }
    };
  });
}

function idbReq<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

function txDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("IndexedDB transaction failed"));
    tx.onabort = () => reject(tx.error ?? new Error("IndexedDB transaction aborted"));
  });
}

export function createReportId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `report-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

export function summarizeReport(report: AnalysisReport): AnalysisReportSummary {
  return {
    id: report.id,
    createdAt: report.createdAt,
    sourceFileName: report.sourceFileName,
    stats: report.stats,
  };
}

export async function saveReport(report: AnalysisReport): Promise<void> {
  const db = await openDb();

  const readTx = db.transaction(REPORTS_STORE, "readonly");
  const existing = (await idbReq(
    readTx.objectStore(REPORTS_STORE).getAll(),
  )) as AnalysisReport[];

  const writeTx = db.transaction([REPORTS_STORE, META_STORE], "readwrite");
  const reports = writeTx.objectStore(REPORTS_STORE);
  const meta = writeTx.objectStore(META_STORE);

  reports.put(report);
  meta.put(report.id, ACTIVE_KEY);

  const merged = [
    report,
    ...existing.filter((item) => item.id !== report.id),
  ]
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .slice(MAX_REPORTS);

  const keep = new Set(merged.map((item) => item.id));
  existing.forEach((item) => {
    if (!keep.has(item.id)) reports.delete(item.id);
  });

  await txDone(writeTx);
  db.close();
}

export async function deleteReport(id: string): Promise<void> {
  const db = await openDb();
  const active = await getActiveReportId();
  const tx = db.transaction([REPORTS_STORE, META_STORE], "readwrite");
  tx.objectStore(REPORTS_STORE).delete(id);
  if (active === id) {
    tx.objectStore(META_STORE).delete(ACTIVE_KEY);
  }
  await txDone(tx);
  db.close();
}

export async function setActiveReportId(id: string | null): Promise<void> {
  const db = await openDb();
  const tx = db.transaction(META_STORE, "readwrite");
  const meta = tx.objectStore(META_STORE);
  if (id) meta.put(id, ACTIVE_KEY);
  else meta.delete(ACTIVE_KEY);
  await txDone(tx);
  db.close();
}

export async function getActiveReportId(): Promise<string | null> {
  const db = await openDb();
  const tx = db.transaction(META_STORE, "readonly");
  const value = await idbReq(tx.objectStore(META_STORE).get(ACTIVE_KEY));
  db.close();
  return (value as string | undefined) ?? null;
}

export async function getReport(id: string): Promise<AnalysisReport | null> {
  const db = await openDb();
  const tx = db.transaction(REPORTS_STORE, "readonly");
  const value = await idbReq(tx.objectStore(REPORTS_STORE).get(id));
  db.close();
  return (value as AnalysisReport | undefined) ?? null;
}

export async function getActiveReport(): Promise<AnalysisReport | null> {
  const id = await getActiveReportId();
  if (!id) return null;
  return getReport(id);
}

export async function listReportSummaries(): Promise<AnalysisReportSummary[]> {
  const db = await openDb();
  const tx = db.transaction(REPORTS_STORE, "readonly");
  const all = (await idbReq(tx.objectStore(REPORTS_STORE).getAll())) as AnalysisReport[];
  db.close();
  return all
    .map(summarizeReport)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export function buildReportStats(
  results: PredictResult[],
): AnalysisReportStats {
  const employees = new Set(results.map((r) => r.prediction.employee_id)).size;
  const confirmed = results.filter((r) => r.status === "Confirmed Threat").length;
  const high = results.filter((r) => r.risk_assessment.risk_level === "HIGH").length;
  const critical = results.filter(
    (r) => r.risk_assessment.risk_level === "CRITICAL",
  ).length;
  return {
    employees,
    confirmed,
    high,
    critical,
    rows: results.length,
  };
}
