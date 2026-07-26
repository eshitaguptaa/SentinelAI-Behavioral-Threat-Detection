import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, RefreshCw, Search } from "lucide-react";

import EmployeeTable from "../components/EmployeeTable";
import { useAnalysis } from "../contexts/AnalysisContext";
import type { EmployeeRiskRow } from "../types/models";
import styles from "./PredictionsPage.module.css";

type LevelFilter = "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type StatusFilter = "ALL" | "Confirmed Threat" | "Under Investigation" | "Suspicious" | "Normal";
type SortKey = "risk" | "anomaly" | "employee";

const LEVEL_FILTERS: LevelFilter[] = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
const STATUS_FILTERS: StatusFilter[] = [
  "ALL",
  "Confirmed Threat",
  "Under Investigation",
  "Suspicious",
  "Normal",
];

export default function PredictionsPage() {
  const {
    rows,
    selectedId,
    selectRow,
    loading,
    hydrating,
    backendStatus,
    rerunAnalysis,
    sourceFileName,
    stats,
  } = useAnalysis();
  const navigate = useNavigate();

  const [query, setQuery] = useState("");
  const [levelFilter, setLevelFilter] = useState<LevelFilter>("ALL");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("ALL");
  const [sortKey, setSortKey] = useState<SortKey>("risk");

  const levelCounts = useMemo(() => {
    const counts: Record<LevelFilter, number> = {
      ALL: rows.length,
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };
    for (const row of rows) {
      const level = row.risk_level as Exclude<LevelFilter, "ALL">;
      if (level in counts) counts[level] += 1;
    }
    return counts;
  }, [rows]);

  const filteredRows = useMemo(() => {
    const q = query.trim().toLowerCase();
    let next = rows.filter((row) => {
      if (levelFilter !== "ALL" && row.risk_level !== levelFilter) return false;
      if (statusFilter !== "ALL" && row.status !== statusFilter) return false;
      if (!q) return true;
      return (
        row.employee_id.toLowerCase().includes(q) ||
        row.attack_type.toLowerCase().includes(q) ||
        String(row.status).toLowerCase().includes(q) ||
        row.simulation_day.toLowerCase().includes(q) ||
        row.risk_level.toLowerCase().includes(q)
      );
    });

    next = [...next].sort((a, b) => {
      if (sortKey === "employee") {
        return a.employee_id.localeCompare(b.employee_id);
      }
      if (sortKey === "anomaly") {
        return b.anomaly_score - a.anomaly_score;
      }
      return b.risk_score - a.risk_score;
    });

    return next;
  }, [rows, query, levelFilter, statusFilter, sortKey]);

  const filtersActive =
    levelFilter !== "ALL" || statusFilter !== "ALL" || query.trim().length > 0;

  const onSelect = (row: EmployeeRiskRow) => {
    selectRow(row);
    navigate("/app/investigate");
  };

  const clearFilters = () => {
    setQuery("");
    setLevelFilter("ALL");
    setStatusFilter("ALL");
  };

  return (
    <div className={styles.page}>
      <div className={styles.toolbar}>
        <div>
          <p className={styles.eyebrow}>Triage queue</p>
          <h1 className={styles.pageTitle}>Predictions</h1>
          {rows.length > 0 ? (
            <p className={styles.pageCaption}>
              Ranked batch results — filter, sort, and open a case to investigate.
            </p>
          ) : null}
        </div>
        {rows.length > 0 ? (
          <div className={styles.actions}>
            <Link to="/app/risk" className={styles.secondaryBtn}>
              Risk analysis
            </Link>
            <button
              type="button"
              className={styles.secondaryBtn}
              onClick={() => void rerunAnalysis()}
              disabled={loading || backendStatus === "offline"}
            >
              <RefreshCw size={14} aria-hidden />
              {loading ? "Running…" : "Re-run"}
            </button>
          </div>
        ) : null}
      </div>

      {hydrating ? (
        <div className={styles.emptyState}>
          <h3>Restoring last session…</h3>
        </div>
      ) : rows.length === 0 ? (
        <div className={styles.emptyState}>
          <h3>No batch loaded</h3>
          <p>Upload a workbook or try sample data first.</p>
          <Link to="/app" className={styles.primaryBtn}>
            Go to Upload
          </Link>
        </div>
      ) : (
        <div className={styles.layout}>
          <section className={styles.hero} aria-label="Queue summary">
            <div className={styles.heroGrid} aria-hidden />
            <div className={styles.heroMain}>
              <div>
                <p className={styles.heroKicker}>Active queue</p>
                <h2 className={styles.heroTitle}>
                  {sourceFileName ?? "Loaded batch"} ready for triage
                </h2>
                <p className={styles.heroLead}>
                  {stats.confirmed > 0
                    ? `${stats.confirmed} confirmed threat${stats.confirmed === 1 ? "" : "s"} and ${stats.high + stats.critical} elevated rows — start at the top of the ranked list.`
                    : `${rows.length} scored rows. Sort by risk or anomaly, then open a case.`}
                </p>
              </div>
              <div className={styles.heroMeta}>
                <span className={styles.chip}>{rows.length} predictions</span>
                <span className={styles.chip}>{stats.employees} employees</span>
                <span className={styles.chip}>{stats.critical} critical</span>
              </div>
            </div>
            <div className={styles.heroStats}>
              <div className={`${styles.heroStat} ${styles.heroStatHot}`}>
                <strong>{stats.confirmed}</strong>
                <span>Confirmed</span>
              </div>
              <div className={`${styles.heroStat} ${styles.heroStatHot}`}>
                <strong>{stats.critical}</strong>
                <span>Critical</span>
              </div>
              <div className={`${styles.heroStat} ${styles.heroStatWarn}`}>
                <strong>{stats.high}</strong>
                <span>High</span>
              </div>
            </div>
          </section>

          <div className={styles.controls}>
            <div className={styles.controlsTop}>
              <label className={styles.searchWrap}>
                <Search size={15} aria-hidden />
                <span className={styles.visuallyHidden}>Search predictions</span>
                <input
                  className={styles.search}
                  type="search"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search employee, attack, status…"
                  autoComplete="off"
                />
              </label>
              <div className={styles.sortGroup} role="group" aria-label="Sort queue">
                <button
                  type="button"
                  className={`${styles.sortBtn} ${sortKey === "risk" ? styles.sortBtnActive : ""}`}
                  onClick={() => setSortKey("risk")}
                >
                  Risk ↓
                </button>
                <button
                  type="button"
                  className={`${styles.sortBtn} ${sortKey === "anomaly" ? styles.sortBtnActive : ""}`}
                  onClick={() => setSortKey("anomaly")}
                >
                  Anomaly ↓
                </button>
                <button
                  type="button"
                  className={`${styles.sortBtn} ${sortKey === "employee" ? styles.sortBtnActive : ""}`}
                  onClick={() => setSortKey("employee")}
                >
                  Employee
                </button>
              </div>
            </div>

            <div className={styles.filterRow} role="group" aria-label="Filter by risk level">
              <span className={styles.filterLabel}>Level</span>
              {LEVEL_FILTERS.map((level) => (
                <button
                  key={level}
                  type="button"
                  className={`${styles.filterBtn} ${levelFilter === level ? styles.filterBtnActive : ""}`}
                  onClick={() => setLevelFilter(level)}
                >
                  {level === "ALL" ? "All" : level}
                  <span className={styles.filterCount}>{levelCounts[level]}</span>
                </button>
              ))}
            </div>

            <div className={styles.filterRow} role="group" aria-label="Filter by status">
              <span className={styles.filterLabel}>Status</span>
              {STATUS_FILTERS.map((status) => (
                <button
                  key={status}
                  type="button"
                  className={`${styles.filterBtn} ${statusFilter === status ? styles.filterBtnActive : ""}`}
                  onClick={() => setStatusFilter(status)}
                >
                  {status === "ALL" ? "All" : status}
                </button>
              ))}
            </div>

            <div className={styles.resultMeta}>
              <p>
                Showing <strong>{filteredRows.length}</strong> of {rows.length}
              </p>
              {filtersActive ? (
                <button type="button" className={styles.clearFilters} onClick={clearFilters}>
                  Clear filters
                </button>
              ) : null}
            </div>
          </div>

          <EmployeeTable
            rows={filteredRows}
            selectedId={selectedId}
            onSelect={onSelect}
            sortKey={sortKey}
          />

          <div className={styles.ctaStrip}>
            <div>
              <strong>Select a row to investigate</strong>
              <p>Opens the full employee report on Investigation.</p>
            </div>
            <Link to="/app/investigate" className={styles.primaryBtn}>
              Open Investigation
              <ArrowRight size={14} aria-hidden />
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
