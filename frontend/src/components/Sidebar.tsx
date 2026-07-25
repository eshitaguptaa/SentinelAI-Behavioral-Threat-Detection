import styles from "./Sidebar.module.css";

export type SidebarSection =
  | "dashboard"
  | "predictions"
  | "risk"
  | "explainability"
  | "system";

interface SidebarProps {
  active: SidebarSection;
  onNavigate: (section: SidebarSection) => void;
}

const ITEMS: { id: SidebarSection; label: string }[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "predictions", label: "Predictions" },
  { id: "risk", label: "Risk Analysis" },
  { id: "explainability", label: "Explainability" },
  { id: "system", label: "System Status" },
];

export default function Sidebar({ active, onNavigate }: SidebarProps) {
  return (
    <aside className={styles.sidebar} aria-label="SOC navigation">
      <p className={styles.sectionLabel}>Operations</p>
      <nav className={styles.nav}>
        {ITEMS.map((item) => (
          <button
            key={item.id}
            type="button"
            className={`${styles.link} ${active === item.id ? styles.active : ""}`}
            onClick={() => onNavigate(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>
    </aside>
  );
}
