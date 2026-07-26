import { memo, useMemo } from "react";
import {
  Area,
  CartesianGrid,
  ComposedChart,
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
  const { data, tickInterval } = useMemo(() => {
    const sorted = [...rows].sort((a, b) => b.risk_score - a.risk_score);
    const points = sorted.map((row, index) => ({
      label: String(index + 1),
      employee: row.employee_id,
      anomaly: Number(row.anomaly_score.toFixed(1)),
      risk: Number(row.risk_score.toFixed(1)),
      level: row.risk_level,
    }));
    const interval = points.length <= 8 ? 0 : points.length <= 16 ? 1 : 3;
    return { data: points, tickInterval: interval };
  }, [rows]);

  if (data.length === 0) {
    return (
      <section className={styles.panel} aria-label="Risk trend">
        <p className={styles.kicker}>Trend</p>
        <h2 className={styles.title}>Score curve</h2>
        <p className={styles.empty}>Run batch analysis to plot anomaly vs risk.</p>
      </section>
    );
  }

  return (
    <section className={styles.panel} aria-label="Risk trend">
      <div className={styles.header}>
        <div>
          <p className={styles.kicker}>Trend</p>
          <h2 className={styles.title}>Score curve</h2>
          <p className={styles.caption}>
            Ranked highest → lowest risk for this batch
          </p>
        </div>
        <div className={styles.seriesKey} aria-hidden>
          <span>
            <i className={styles.anomalyKey} />
            Anomaly
          </span>
          <span>
            <i className={styles.riskKey} />
            Risk
          </span>
        </div>
      </div>

      <div className={styles.chart}>
        <ResponsiveContainer width="100%" height={280}>
          <ComposedChart data={data} margin={{ top: 16, right: 12, left: 0, bottom: 4 }}>
            <defs>
              <linearGradient id="riskAreaFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#e4002b" stopOpacity={0.22} />
                <stop offset="100%" stopColor="#e4002b" stopOpacity={0.02} />
              </linearGradient>
              <linearGradient id="anomalyAreaFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#d2641f" stopOpacity={0.16} />
                <stop offset="100%" stopColor="#d2641f" stopOpacity={0.01} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="rgba(17,17,17,0.05)" vertical={false} />
            <XAxis
              dataKey="label"
              interval={tickInterval}
              tick={{ fill: "#98a2b3", fontSize: 11 }}
              axisLine={{ stroke: "rgba(17,17,17,0.1)" }}
              tickLine={false}
              minTickGap={20}
            />
            <YAxis
              domain={[0, 100]}
              tick={{ fill: "#98a2b3", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              width={28}
            />
            <Tooltip
              contentStyle={{
                background: "#111",
                border: "none",
                borderRadius: 0,
                color: "#fff",
                fontSize: 12,
                padding: "10px 12px",
                boxShadow: "0 12px 28px rgba(0,0,0,0.28)",
              }}
              labelStyle={{ color: "rgba(255,255,255,0.55)", marginBottom: 4 }}
              formatter={(value, name) => [
                value,
                name === "anomaly" ? "Anomaly" : "Risk",
              ]}
              labelFormatter={(_label, payload) => {
                const point = payload?.[0]?.payload;
                if (!point) return "";
                return `${point.employee} · ${point.level}`;
              }}
            />
            <Area
              type="monotone"
              dataKey="anomaly"
              stroke="#d2641f"
              strokeWidth={2.2}
              fill="url(#anomalyAreaFill)"
              dot={false}
              activeDot={{ r: 4.5, strokeWidth: 0, fill: "#d2641f" }}
              name="anomaly"
              animationDuration={1000}
            />
            <Area
              type="monotone"
              dataKey="risk"
              stroke="#e4002b"
              strokeWidth={2.5}
              fill="url(#riskAreaFill)"
              dot={false}
              activeDot={{ r: 4.5, strokeWidth: 0, fill: "#e4002b" }}
              name="risk"
              animationDuration={1100}
            />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}

export default memo(RiskTrend);
