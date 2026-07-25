import styles from "./StatsCard.module.css";

interface StatsCardProps {
  label: string;
  value: number | string;
  tone?: "default" | "anomaly" | "high" | "critical";
  hint?: string;
}

export default function StatsCard({
  label,
  value,
  tone = "default",
  hint,
}: StatsCardProps) {
  return (
    <article className={`${styles.card} ${styles[tone]}`}>
      <p className={styles.label}>{label}</p>
      <p className={styles.value}>{value}</p>
      {hint ? <p className={styles.hint}>{hint}</p> : null}
    </article>
  );
}
