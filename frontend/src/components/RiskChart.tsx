import { memo, useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import styles from "./RiskChart.module.css";
import { RISK_COLORS, type RiskDistributionPoint } from "../types/models";

interface RiskChartProps {
  data: RiskDistributionPoint[];
}

function RiskChart({ data }: RiskChartProps) {
  const hasData = useMemo(() => data.some((d) => d.count > 0), [data]);

  return (
    <section className={styles.panel} aria-label="Risk score distribution">
      <div className={styles.header}>
        <h2 className={styles.title}>Risk Score Distribution</h2>
        <p className={styles.caption}>Employee-days by risk level</p>
      </div>

      <div className={styles.chartWrap}>
        {!hasData ? (
          <p className={styles.empty}>No prediction data yet. Run a batch analysis to populate the chart.</p>
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
              <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
              <XAxis
                dataKey="level"
                tick={{ fill: "#9aa7b5", fontSize: 12 }}
                axisLine={{ stroke: "rgba(255,255,255,0.08)" }}
                tickLine={false}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: "#9aa7b5", fontSize: 12 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                cursor={{ fill: "rgba(255,255,255,0.04)" }}
                contentStyle={{
                  background: "#121820",
                  border: "1px solid rgba(255,255,255,0.1)",
                  borderRadius: 8,
                  color: "#e8eef4",
                }}
              />
              <Bar dataKey="count" radius={[6, 6, 0, 0]} maxBarSize={56}>
                {data.map((entry) => (
                  <Cell
                    key={entry.level}
                    fill={entry.fill || RISK_COLORS[entry.level] || "#6b7c8f"}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </section>
  );
}

export default memo(RiskChart);
