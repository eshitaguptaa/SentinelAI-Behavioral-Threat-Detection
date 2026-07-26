import { memo } from "react";
import { ArrowUpRight } from "lucide-react";

import styles from "./EmployeeTable.module.css";
import type { EmployeeRiskRow } from "../types/models";
import { ATTACK_COLORS, RISK_COLORS, STATUS_COLORS } from "../types/models";

interface EmployeeTableProps {
  rows: EmployeeRiskRow[];
  selectedId: string | null;
  onSelect: (row: EmployeeRiskRow) => void;
  sortKey?: "risk" | "anomaly" | "employee";
}

function formatScore(value: number): string {
  return value.toFixed(1);
}

function formatConfidence(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function EmployeeTable({
  rows,
  selectedId,
  onSelect,
  sortKey = "risk",
}: EmployeeTableProps) {
  return (
    <section className={styles.panel} aria-label="Employee risk table">
      <div className={styles.header}>
        <div>
          <p className={styles.kicker}>Queue</p>
          <h2 className={styles.title}>Employee predictions</h2>
          <p className={styles.caption}>
            {rows.length === 0
              ? "No rows match the current filters"
              : `${rows.length} ranked row${rows.length === 1 ? "" : "s"} · click to investigate`}
          </p>
        </div>
        <span className={styles.headerBadge}>
          Sorted by {sortKey === "employee" ? "ID" : sortKey}
        </span>
      </div>

      <div className={styles.tableWrap}>
        {rows.length === 0 ? (
          <p className={styles.empty}>
            No employees match. Clear filters or adjust search.
          </p>
        ) : (
          <>
          <table className={styles.table}>
            <thead>
              <tr>
                <th className={styles.colRank}>#</th>
                <th>Employee</th>
                <th>Risk</th>
                <th className={styles.colDesktop}>Anomaly</th>
                <th>Level</th>
                <th>Attack</th>
                <th className={styles.colDesktop}>Status</th>
                <th className={styles.colAction}>
                  <span className={styles.visuallyHidden}>Open</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => {
                const selected = row.id === selectedId;
                const levelColor =
                  RISK_COLORS[row.risk_level] || "var(--text-muted)";
                const attackColor =
                  ATTACK_COLORS[row.attack_type] || "#8a98a8";
                const statusColor =
                  STATUS_COLORS[row.status] || "var(--text-muted)";
                const riskPct = Math.max(4, Math.min(100, row.risk_score));
                const anomalyPct = Math.max(4, Math.min(100, row.anomaly_score));

                return (
                  <tr
                    key={row.id}
                    className={selected ? styles.selected : undefined}
                    onClick={() => onSelect(row)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        onSelect(row);
                      }
                    }}
                    tabIndex={0}
                    role="button"
                    aria-pressed={selected}
                    style={{ animationDelay: `${Math.min(index, 12) * 0.03}s` }}
                  >
                    <td className={styles.colRank}>
                      <span
                        className={`${styles.rank} ${index < 3 ? styles.rankHot : ""}`}
                      >
                        {String(index + 1).padStart(2, "0")}
                      </span>
                    </td>
                    <td>
                      <div className={styles.employeeCell}>
                        <strong className={styles.mono}>{row.employee_id}</strong>
                        <span>{row.simulation_day}</span>
                      </div>
                    </td>
                    <td>
                      <div className={styles.scoreCell}>
                        <strong
                          className={styles.mono}
                          style={{ color: levelColor }}
                        >
                          {formatScore(row.risk_score)}
                        </strong>
                        <span
                          className={styles.meter}
                          aria-hidden
                        >
                          <i
                            style={{
                              width: `${riskPct}%`,
                              background: levelColor,
                            }}
                          />
                        </span>
                      </div>
                    </td>
                    <td className={styles.colDesktop}>
                      <div className={styles.scoreCell}>
                        <strong className={styles.mono}>
                          {formatScore(row.anomaly_score)}
                        </strong>
                        <span className={styles.meter} aria-hidden>
                          <i
                            style={{
                              width: `${anomalyPct}%`,
                              background: "#d2641f",
                            }}
                          />
                        </span>
                      </div>
                    </td>
                    <td>
                      <span
                        className={styles.badge}
                        style={{
                          color: levelColor,
                          borderColor: `${levelColor}55`,
                          background: `${levelColor}14`,
                        }}
                      >
                        {row.risk_level}
                      </span>
                    </td>
                    <td>
                      <div className={styles.attackCell}>
                        <span
                          className={styles.badge}
                          title={`Confidence ${formatConfidence(row.attack_confidence)}`}
                          style={{
                            color: attackColor,
                            borderColor: `${attackColor}55`,
                            background: `${attackColor}14`,
                          }}
                        >
                          {row.attack_type}
                        </span>
                        <span className={styles.conf}>
                          {formatConfidence(row.attack_confidence)}
                        </span>
                      </div>
                    </td>
                    <td className={styles.colDesktop}>
                      <span
                        className={styles.badge}
                        style={{
                          color: statusColor,
                          borderColor: `${statusColor}55`,
                          background: `${statusColor}14`,
                        }}
                      >
                        {row.status}
                      </span>
                    </td>
                    <td className={styles.colAction}>
                      <span className={styles.openCue} aria-hidden>
                        <ArrowUpRight size={15} />
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          <ul className={styles.cardList}>
            {rows.map((row, index) => {
              const selected = row.id === selectedId;
              const levelColor =
                RISK_COLORS[row.risk_level] || "var(--text-muted)";
              const attackColor =
                ATTACK_COLORS[row.attack_type] || "#8a98a8";
              return (
                <li key={`card-${row.id}`}>
                  <button
                    type="button"
                    className={`${styles.card} ${selected ? styles.cardSelected : ""}`}
                    onClick={() => onSelect(row)}
                    aria-pressed={selected}
                  >
                    <div className={styles.cardTop}>
                      <span
                        className={`${styles.rank} ${index < 3 ? styles.rankHot : ""}`}
                      >
                        {String(index + 1).padStart(2, "0")}
                      </span>
                      <div className={styles.employeeCell}>
                        <strong className={styles.mono}>{row.employee_id}</strong>
                        <span>{row.simulation_day}</span>
                      </div>
                      <span
                        className={styles.badge}
                        style={{
                          color: levelColor,
                          borderColor: `${levelColor}55`,
                          background: `${levelColor}14`,
                        }}
                      >
                        {row.risk_level}
                      </span>
                    </div>
                    <div className={styles.cardMeta}>
                      <span>
                        Risk <strong className={styles.mono}>{formatScore(row.risk_score)}</strong>
                      </span>
                      <span>
                        Anomaly{" "}
                        <strong className={styles.mono}>
                          {formatScore(row.anomaly_score)}
                        </strong>
                      </span>
                    </div>
                    <div className={styles.cardFoot}>
                      <span
                        className={styles.badge}
                        style={{
                          color: attackColor,
                          borderColor: `${attackColor}55`,
                          background: `${attackColor}14`,
                        }}
                      >
                        {row.attack_type}
                      </span>
                      <span className={styles.cardStatus}>{row.status}</span>
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
          </>
        )}
      </div>
    </section>
  );
}

export default memo(EmployeeTable);
