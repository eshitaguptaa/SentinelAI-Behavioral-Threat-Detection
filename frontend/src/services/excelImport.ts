import * as XLSX from "xlsx";

import type { FeatureVectorPayload } from "../types/models";

/** Columns expected in an uploaded workbook (identity + common behavioural fields). */
export const EXCEL_TEMPLATE_COLUMNS = [
  "employee_id",
  "simulation_day",
  "event_sequence",
  "total_events",
  "login_count",
  "logout_count",
  "auth_failure_rate",
  "max_failed_login_streak",
  "country_change_count",
  "location_change_count",
  "unique_device_count",
  "unique_location_count",
  "resource_entropy",
  "device_entropy",
  "after_hours_event_count",
  "download_size_mb_sum",
  "mass_download_event_count",
  "vpn_usage_ratio",
  "burst_max_5min",
  "active_duration_hours",
  "file_access_ratio",
  "night_event_count",
  "application_access_count",
  "file_access_count",
] as const;

const REQUIRED_COLUMNS = ["employee_id", "simulation_day"] as const;

const META_SKIP = new Set(["demo_kind", "attack_scenario", "label"]);

export class ExcelImportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExcelImportError";
  }
}

function normalizeHeader(value: unknown): string {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[\s\-]+/g, "_")
    .replace(/__+/g, "_");
}

function parseEventSequence(value: unknown): string[] | undefined {
  if (value == null || value === "") return undefined;
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }
  const raw = String(value).trim();
  if (!raw) return undefined;
  if (raw.startsWith("[")) {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (Array.isArray(parsed)) {
        return parsed.map((item) => String(item).trim()).filter(Boolean);
      }
    } catch {
      // fall through to delimiter split
    }
  }
  return raw
    .split(/[|,;]/)
    .map((part) => part.trim())
    .filter(Boolean);
}

function coerceCell(key: string, value: unknown): string | number | string[] | null | undefined {
  if (value == null || value === "") return undefined;
  if (key === "event_sequence") return parseEventSequence(value);
  if (key === "employee_id" || key === "simulation_day") {
    if (value instanceof Date) {
      return value.toISOString().slice(0, 10);
    }
    return String(value).trim();
  }
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const asString = String(value).trim();
  if (!asString) return undefined;
  const asNumber = Number(asString);
  if (asString !== "" && Number.isFinite(asNumber) && /^-?\d+(\.\d+)?$/.test(asString)) {
    return asNumber;
  }
  return asString;
}

function isEmptyRow(row: Record<string, unknown>): boolean {
  return Object.values(row).every((value) => value == null || String(value).trim() === "");
}

function collectHeaders(rows: Record<string, unknown>[]): string[] {
  const headers = new Set<string>();
  for (const row of rows.slice(0, 5)) {
    for (const key of Object.keys(row)) {
      const normalized = normalizeHeader(key);
      if (normalized) headers.add(normalized);
    }
  }
  return [...headers];
}

function assertExpectedStructure(headers: string[]): void {
  const headerSet = new Set(headers);
  const missing = REQUIRED_COLUMNS.filter((column) => !headerSet.has(column));
  if (!missing.length) return;

  const recognizable = headers
    .filter((header) => !META_SKIP.has(header))
    .slice(0, 10);
  const foundNote = recognizable.length
    ? ` Found: ${recognizable.join(", ")}${headers.length > recognizable.length ? "…" : ""}.`
    : " No recognizable column headers were found.";

  throw new ExcelImportError(
    `This file doesn’t match the expected structure. Missing required column${
      missing.length > 1 ? "s" : ""
    }: ${missing.join(", ")}.${foundNote} Download the template, keep the header row, and try again.`,
  );
}

function rowToPayload(
  row: Record<string, unknown>,
  index: number,
): FeatureVectorPayload {
  const payload: FeatureVectorPayload = {
    employee_id: "",
    simulation_day: "",
  };

  for (const [rawKey, rawValue] of Object.entries(row)) {
    const key = normalizeHeader(rawKey);
    if (!key || META_SKIP.has(key)) continue;
    const coerced = coerceCell(key, rawValue);
    if (coerced === undefined) continue;
    payload[key] = coerced;
  }

  if (!payload.employee_id) {
    throw new ExcelImportError(`Row ${index + 2}: missing employee_id.`);
  }
  if (!payload.simulation_day) {
    throw new ExcelImportError(`Row ${index + 2}: missing simulation_day (YYYY-MM-DD).`);
  }

  if (typeof payload.simulation_day === "string") {
    payload.simulation_day = payload.simulation_day.trim().slice(0, 10);
  }

  return payload;
}

export async function parseFeatureVectorsFromExcel(
  file: File,
): Promise<FeatureVectorPayload[]> {
  const name = file.name.toLowerCase();
  if (!/\.(xlsx|xls|csv)$/.test(name)) {
    throw new ExcelImportError(
      "Please upload an Excel (.xlsx, .xls) or CSV (.csv) file.",
    );
  }

  let workbook: XLSX.WorkBook;
  try {
    const buffer = await file.arrayBuffer();
    workbook = XLSX.read(buffer, { type: "array", cellDates: true });
  } catch {
    throw new ExcelImportError(
      "We couldn’t read this file. Make sure it’s a valid .xlsx, .xls, or .csv and isn’t corrupted, then try again.",
    );
  }

  const sheetName = workbook.SheetNames[0];
  if (!sheetName) {
    throw new ExcelImportError("The workbook has no sheets.");
  }

  const sheet = workbook.Sheets[sheetName];
  let rows: Record<string, unknown>[];
  try {
    rows = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, {
      defval: null,
      raw: false,
    });
  } catch {
    throw new ExcelImportError(
      "We couldn’t parse the spreadsheet rows. Check that the first row contains column headers, then try again.",
    );
  }

  if (!rows.length) {
    throw new ExcelImportError(
      "The spreadsheet is empty. Add at least one data row under the header, or download the template.",
    );
  }

  assertExpectedStructure(collectHeaders(rows));

  const vectors: FeatureVectorPayload[] = [];
  const rowProblems: string[] = [];

  rows.forEach((row, index) => {
    if (isEmptyRow(row)) return;
    try {
      vectors.push(rowToPayload(row, index));
    } catch (err) {
      rowProblems.push(
        err instanceof Error ? err.message : `Row ${index + 2}: could not be read.`,
      );
    }
  });

  if (!vectors.length) {
    const preview = rowProblems.slice(0, 3).join(" ");
    throw new ExcelImportError(
      preview
        ? `No valid rows could be imported. ${preview}${
            rowProblems.length > 3 ? ` (+${rowProblems.length - 3} more)` : ""
          } Download the template and match the required columns.`
        : "No valid feature rows were found in the file. Download the template and try again.",
    );
  }

  if (rowProblems.length) {
    console.warn(
      `[excelImport] Skipped ${rowProblems.length} invalid row(s):`,
      rowProblems.slice(0, 5),
    );
  }

  return vectors;
}

/** Build a starter workbook users can fill and re-upload. */
export function downloadFeatureVectorTemplate(): void {
  const sample = [
    {
      employee_id: "EMP-001",
      simulation_day: "2026-03-10",
      event_sequence: "LOGIN|APPLICATION_ACCESS|EMAIL_ACCESS|LOGOUT",
      total_events: 21,
      login_count: 1,
      logout_count: 1,
      auth_failure_rate: 0.01,
      max_failed_login_streak: 0,
      country_change_count: 0,
      location_change_count: 1,
      unique_device_count: 1,
      unique_location_count: 1,
      resource_entropy: 0.45,
      device_entropy: 0.15,
      after_hours_event_count: 0,
      download_size_mb_sum: 4,
      mass_download_event_count: 0,
      vpn_usage_ratio: 0.05,
      burst_max_5min: 3,
      active_duration_hours: 7.5,
      file_access_ratio: 0,
      night_event_count: 0,
      application_access_count: 14,
      file_access_count: 2,
    },
    {
      employee_id: "EMP-002",
      simulation_day: "2026-03-10",
      event_sequence: "LOGIN|FAILED_LOGIN|FAILED_LOGIN|VPN_CONNECT|FILE_DOWNLOAD|LOGOUT",
      total_events: 18,
      login_count: 2,
      logout_count: 1,
      auth_failure_rate: 0.35,
      max_failed_login_streak: 4,
      country_change_count: 1,
      location_change_count: 2,
      unique_device_count: 2,
      unique_location_count: 2,
      resource_entropy: 0.8,
      device_entropy: 0.55,
      after_hours_event_count: 5,
      download_size_mb_sum: 420,
      mass_download_event_count: 2,
      vpn_usage_ratio: 0.6,
      burst_max_5min: 9,
      active_duration_hours: 3.2,
      file_access_ratio: 0.4,
      night_event_count: 4,
      application_access_count: 6,
      file_access_count: 8,
    },
  ];

  const worksheet = XLSX.utils.json_to_sheet(sample, {
    header: [...EXCEL_TEMPLATE_COLUMNS],
  });
  const workbook = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(workbook, worksheet, "feature_vectors");
  XLSX.writeFile(workbook, "sentinelai_feature_vectors_template.xlsx");
}
