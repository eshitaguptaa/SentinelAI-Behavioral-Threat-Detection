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
  const total = useMemo(() => data.reduce((sum, d) => sum + d.count, 0), [data]);
  const peak = useMemo(
    () => data.reduce((max, d) => Math.max(max, d.count), 0),
    [data],
  );

  return (
    <section className={styles.panel} aria-label="Risk score distribution">
      <div className={styles.header}>
        <div>
          <p className={styles.kicker}>Distribution</p>
          <h2 className={styles.title}>Risk levels</h2>
          <p className={styles.caption}>Employee-days grouped by score band</p>
        </div>
        {hasData ? (
          <div className={styles.meta}>
            <span className={styles.total}>{total} total</span>
            <span className={styles.peak}>Peak {peak}</span>
          </div>
        ) : null}
      </div>

      <div className={styles.chartWrap}>
        {!hasData ? (
          <p className={styles.empty}>No prediction data yet.</p>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <BarChart
              data={data}
              margin={{ top: 16, right: 8, left: 0, bottom: 4 }}
              barCategoryGap="32%"
            >
              <defs>
                {data.map((entry) => {
                  const fill = entry.fill || RISK_COLORS[entry.level] || "#6b6b6b";
                  const id = `riskBar-${entry.level}`;
                  return (
                    <linearGradient key={id} id={id} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={fill} stopOpacity={1} />
                      <stop offset="100%" stopColor={fill} stopOpacity={0.72} />
                    </linearGradient>
                  );
                })}
              </defs>
              <CartesianGrid stroke="rgba(17,17,17,0.05)" vertical={false} />
              <XAxis
                dataKey="level"
                tick={{ fill: "#667085", fontSize: 11, fontWeight: 600 }}
                axisLine={{ stroke: "rgba(17,17,17,0.1)" }}
                tickLine={false}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: "#98a2b3", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
                width={28}
              />
              <Tooltip
                cursor={{ fill: "rgba(228,0,43,0.04)" }}
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
                formatter={(value) => {
                  const count = Number(value) || 0;
                  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                  return [`${count} rows · ${pct}%`, "Count"];
                }}
              />
              <Bar dataKey="count" maxBarSize={52} radius={[2, 2, 0, 0]} animationDuration={900}>
                {data.map((entry) => (
                  <Cell
                    key={entry.level}
                    fill={`url(#riskBar-${entry.level})`}
                    stroke={entry.fill || RISK_COLORS[entry.level] || "#6b6b6b"}
                    strokeWidth={0}
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
