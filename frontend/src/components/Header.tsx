import styles from "./Header.module.css";

import type { BackendStatus } from "../types/models";

interface HeaderProps {
  backendStatus: BackendStatus;
  appVersion?: string;
}

function statusLabel(status: BackendStatus): string {
  if (status === "online") return "Backend online";
  if (status === "offline") return "Backend offline";
  return "Checking backend…";
}

export default function Header({ backendStatus, appVersion }: HeaderProps) {
  return (
    <header className={styles.header}>
      <div className={styles.brandBlock}>
        <div className={styles.mark} aria-hidden />
        <div>
          <h1 className={styles.title}>SentinelAI</h1>
          <p className={styles.subtitle}>SOC Dashboard</p>
        </div>
      </div>

      <div className={styles.meta}>
        {appVersion ? (
          <span className={styles.version}>v{appVersion}</span>
        ) : null}
        <div
          className={`${styles.status} ${styles[backendStatus]}`}
          role="status"
          aria-live="polite"
        >
          <span className={styles.dot} aria-hidden />
          {statusLabel(backendStatus)}
        </div>
      </div>
    </header>
  );
}
