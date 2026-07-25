import { memo } from "react";

import styles from "./EmployeeTable.module.css";
import type { EmployeeRiskRow } from "../types/models";
import { ATTACK_COLORS, RISK_COLORS, STATUS_COLORS } from "../types/models";

interface EmployeeTableProps {
  rows: EmployeeRiskRow[];
  selectedId: string | null;
  onSelect: (row: EmployeeRiskRow) => void;
}

function formatScore(value: number): string {
  return value.toFixed(1);
}

function formatConfidence(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function EmployeeTable({ rows, selectedId, onSelect }: EmployeeTableProps) {
  return (
    <section className={styles.panel} aria-label="Employee risk table">
      <div className={styles.header}>
        <h2 className={styles.title}>Employee Predictions</h2>
        <p className={styles.caption}>{rows.length} employee-day rows</p>
      </div>

      <div className={styles.tableWrap}>
        {rows.length === 0 ? (
          <p className={styles.empty}>
            No employees loaded. Run analysis to populate this table.
          </p>
        ) : (
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Employee ID</th>
                <th>Simulation Day</th>
                <th>Anomaly Score</th>
                <th>Risk Score</th>
                <th>Risk Level</th>
                <th>Attack Type</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const selected = row.id === selectedId;
                const levelColor =
                  RISK_COLORS[row.risk_level] || "var(--text-muted)";
                const attackColor =
                  ATTACK_COLORS[row.attack_type] || "#8a98a8";
                const statusColor =
                  STATUS_COLORS[row.status] || "var(--text-muted)";
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
                  >
                    <td className={styles.mono}>{row.employee_id}</td>
                    <td>{row.simulation_day}</td>
                    <td className={styles.mono}>
                      {formatScore(row.anomaly_score)}
                    </td>
                    <td className={styles.mono}>
                      {formatScore(row.risk_score)}
                    </td>
                    <td>
                      <span
                        className={styles.badge}
                        style={{
                          color: levelColor,
                          borderColor: `${levelColor}66`,
                          background: `${levelColor}1a`,
                        }}
                      >
                        {row.risk_level}
                      </span>
                    </td>
                    <td>
                      <span
                        className={styles.badge}
                        title={`Confidence ${formatConfidence(row.attack_confidence)}`}
                        style={{
                          color: attackColor,
                          borderColor: `${attackColor}66`,
                          background: `${attackColor}1a`,
                        }}
                      >
                        {row.attack_type}
                      </span>
                    </td>
                    <td>
                      <span
                        className={styles.badge}
                        style={{
                          color: statusColor,
                          borderColor: `${statusColor}66`,
                          background: `${statusColor}1a`,
                        }}
                      >
                        {row.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}

export default memo(EmployeeTable);
