import { Link } from "react-router-dom";

import { Logo } from "./Logo";
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
        <Link to="/" className={styles.brandLink} aria-label="Back to SentinelAI home">
          <Logo withWordmark={false} size={32} />
          <div>
            <span className={styles.title}>SentinelAI</span>
            <p className={styles.subtitle}>SOC Dashboard</p>
          </div>
        </Link>
      </div>

      <div className={styles.meta}>
        <Link to="/" className={styles.homeLink}>
          ← Landing
        </Link>
        {appVersion ? <span className={styles.version}>v{appVersion}</span> : null}
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
