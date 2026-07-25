import { memo, useMemo } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import styles from "./RiskTrend.module.css";
import type { EmployeeRiskRow } from "../types/models";

interface RiskTrendProps {
  rows: EmployeeRiskRow[];
}

function RiskTrend({ rows }: RiskTrendProps) {
  const data = useMemo(() => {
    // Preserve analysed-session order by descending risk (actual scores, no smoothing).
    const sorted = [...rows].sort((a, b) => b.risk_score - a.risk_score);
    return sorted.map((row, index) => ({
      label: String(index + 1),
      employee: row.employee_id,
      anomaly: Number(row.anomaly_score.toFixed(1)),
      risk: Number(row.risk_score.toFixed(1)),
    }));
  }, [rows]);

  if (data.length === 0) {
    return (
      <section className={styles.panel} aria-label="Risk trend">
        <h2 className={styles.title}>Risk Trend</h2>
        <p className={styles.empty}>Run batch analysis to plot anomaly vs risk.</p>
      </section>
    );
  }

  return (
    <section className={styles.panel} aria-label="Risk trend">
      <h2 className={styles.title}>Risk Trend</h2>
      <p className={styles.caption}>
        Sessions ordered by risk score (highest first) — raw analysed values.
      </p>
      <div className={styles.chart}>
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={data}>
            <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
            <XAxis dataKey="label" tick={{ fill: "#8a98a8", fontSize: 11 }} />
            <YAxis domain={[0, 100]} tick={{ fill: "#8a98a8", fontSize: 11 }} />
            <Tooltip
              contentStyle={{
                background: "#121820",
                border: "1px solid #243041",
                borderRadius: 8,
              }}
              formatter={(value, name) => [
                value,
                name === "anomaly" ? "Anomaly" : "Risk",
              ]}
              labelFormatter={(_label, payload) => {
                const employee = payload?.[0]?.payload?.employee;
                return employee ? String(employee) : "";
              }}
            />
            <Line
              type="linear"
              dataKey="anomaly"
              stroke="#e08a3c"
              strokeWidth={2}
              dot={{ r: 3 }}
              name="Anomaly"
            />
            <Line
              type="linear"
              dataKey="risk"
              stroke="#e24b4b"
              strokeWidth={2}
              dot={{ r: 3 }}
              name="Risk"
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}

export default memo(RiskTrend);
