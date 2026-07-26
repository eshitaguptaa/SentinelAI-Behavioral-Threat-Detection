import { Link, NavLink } from "react-router-dom";
import {
  Activity,
  ArrowLeft,
  History,
  LayoutDashboard,
  ListChecks,
  ShieldAlert,
  Server,
  Upload,
} from "lucide-react";

import { useAnalysis } from "../contexts/AnalysisContext";
import { BrandName, Logo } from "./Logo";
import styles from "./Sidebar.module.css";

type SidebarProps = {
  variant?: "rail" | "drawer";
  open?: boolean;
  onNavigate?: () => void;
  id?: string;
};

export default function Sidebar({
  variant = "rail",
  open = false,
  onNavigate,
  id,
}: SidebarProps) {
  const { rows, history, hydrating } = useAnalysis();
  const unlocked = !hydrating && (rows.length > 0 || history.length > 0);

  const navItems = unlocked
    ? [
        { to: "/app", end: true, label: "Upload", icon: Upload },
        { to: "/app/overview", end: false, label: "Overview", icon: LayoutDashboard },
        { to: "/app/risk", end: false, label: "Risk Analysis", icon: Activity },
        { to: "/app/predictions", end: false, label: "Predictions", icon: ListChecks },
        { to: "/app/investigate", end: false, label: "Investigate", icon: ShieldAlert },
        { to: "/app/system", end: false, label: "System", icon: Server },
        { to: "/app/history", end: false, label: "History", icon: History },
      ]
    : [
        { to: "/app", end: true, label: "Upload", icon: Upload },
        { to: "/app/system", end: false, label: "System", icon: Server },
      ];

  const rootClass = [
    styles.sidebar,
    variant === "rail" ? styles.rail : styles.drawerPanel,
    variant === "drawer" && open ? styles.drawerPanelOpen : "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <aside id={id} className={rootClass} aria-label="SOC navigation">
      <Link
        to="/app"
        className={styles.brand}
        aria-label="SentinelAI workspace home"
        onClick={onNavigate}
      >
        <Logo withWordmark={false} size={32} />
        <span className={styles.brandText}>
          <span className={styles.brandName}>
            <BrandName tone="light" />
          </span>
          <span className={styles.brandSub}>SOC Workspace</span>
        </span>
      </Link>

      <div>
        <p className={styles.sectionLabel}>Navigate</p>
        <nav className={styles.nav}>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={onNavigate}
                className={({ isActive }) =>
                  `${styles.link} ${isActive ? styles.active : ""}`
                }
              >
                <Icon className={styles.icon} aria-hidden />
                {item.label}
              </NavLink>
            );
          })}
        </nav>
      </div>

      <div className={styles.footer}>
        <Link
          to="/"
          className={styles.landingLink}
          aria-label="Back to landing page"
          onClick={onNavigate}
        >
          <ArrowLeft className={styles.landingIcon} aria-hidden />
        </Link>
      </div>
    </aside>
  );
}
