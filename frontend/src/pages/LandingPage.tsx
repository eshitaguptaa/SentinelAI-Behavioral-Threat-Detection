import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  motion,
  useMotionTemplate,
  useMotionValue,
  useReducedMotion,
  useScroll,
  useSpring,
  useTransform,
} from "framer-motion";

import { BrandName, Logo } from "../components/Logo";
import styles from "./LandingPage.module.css";

const NAV_LINKS = [
  { href: "#intelligence", label: "Intelligence" },
  { href: "#pipeline", label: "Pipeline" },
  { href: "#outcomes", label: "Outcomes" },
];

const STAGES = [
  {
    step: "01",
    title: "Feature engineering",
    body: "Timeline events become numerical behavioural vectors — session rhythm, access entropy, location velocity, and more.",
  },
  {
    step: "02",
    title: "Anomaly detection",
    body: "Isolation Forest scores unsupervised deviation from each employee’s normal operating baseline.",
  },
  {
    step: "03",
    title: "Risk fusion",
    body: "Deterministic rules fuse anomaly signal with enterprise context into severity analysts can act on.",
  },
  {
    step: "04",
    title: "Explainability",
    body: "Every finding ships with plain-language drivers — so investigations start with answers, not hunches.",
  },
];

const OUTCOMES = [
  {
    title: "Anomaly clarity",
    body: "See which sessions break the behavioural baseline — without drowning in raw event noise.",
    image:
      "https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=1200&q=80",
    alt: "Security analyst reviewing monitoring systems",
  },
  {
    title: "Risk that ranks",
    body: "Severity fused from model score and enterprise rules so the queue always starts with what matters.",
    image:
      "https://images.unsplash.com/photo-1451187580459-43490279c0fa?auto=format&fit=crop&w=1200&q=80",
    alt: "Global digital network representing enterprise risk posture",
  },
  {
    title: "Investigations that move",
    body: "Explainability surfaces the drivers behind each alert so analysts spend less time guessing.",
    image:
      "https://images.unsplash.com/photo-1516321318423-f06f85e504b3?auto=format&fit=crop&w=1200&q=80",
    alt: "Team collaborating on investigation workflows",
  },
];

const FOOTER_COLUMNS = [
  {
    title: "Product",
    links: [
      { label: "Intelligence", href: "#intelligence" },
      { label: "Pipeline", href: "#pipeline" },
      { label: "Outcomes", href: "#outcomes" },
    ],
  },
  {
    title: "Platform",
    links: [
      { label: "Anomaly Detection", href: "#pipeline" },
      { label: "Risk Engine", href: "#pipeline" },
      { label: "Explainability", href: "#pipeline" },
    ],
  },
  {
    title: "Product access",
    links: [
      { label: "Open SOC", href: "/app" },
      { label: "Request Demo", href: "/app" },
    ],
  },
];

const PULSE_ITEMS = [
  "Behavioural baseline online",
  "Isolation Forest scoring",
  "Risk fusion active",
  "Explainability ready",
  "SOC investigation queue",
];

function Reveal({
  children,
  className = "",
  delay = 0,
}: {
  children: ReactNode;
  className?: string;
  delay?: number;
}) {
  const reduce = useReducedMotion();

  if (reduce) {
    return <div className={className}>{children}</div>;
  }

  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 36 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.2, margin: "0px 0px -8% 0px" }}
      transition={{ duration: 0.85, delay, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  );
}

function ScrollProgress() {
  const { scrollYProgress } = useScroll();
  const scaleX = useSpring(scrollYProgress, { stiffness: 120, damping: 28, restDelta: 0.001 });

  return (
    <motion.div
      className={styles.scrollProgress}
      style={{ scaleX, transformOrigin: "0% 50%" }}
      aria-hidden
    />
  );
}

function SiteHeader() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header className={`${styles.header} ${scrolled ? styles.headerScrolled : ""}`}>
      <div className={`${styles.wrap} ${styles.headerInner}`}>
        <a href="#top" className={styles.brand} aria-label="SentinelAI home">
          <Logo size={32} wordmarkTone={scrolled ? "dark" : "light"} />
        </a>

        <nav className={`${styles.nav} ${scrolled ? styles.navDark : styles.navLight}`}>
          {NAV_LINKS.map((link) => (
            <a key={link.href} href={link.href}>
              {link.label}
            </a>
          ))}
        </nav>

        <div className={styles.headerActions}>
          <Link
            to="/app"
            className={`${styles.headerTextLink} ${
              scrolled ? styles.headerTextLinkDark : styles.headerTextLinkLight
            }`}
          >
            Open SOC
          </Link>
          <motion.div whileHover={{ y: -1 }} whileTap={{ scale: 0.98 }}>
            <Link to="/app" className={`${styles.btnPrimary} ${styles.btnCompact}`}>
              Enter Platform
            </Link>
          </motion.div>
          <button
            type="button"
            className={styles.menuBtn}
            aria-label="Toggle menu"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            <span className={styles.menuLines} aria-hidden>
              <span style={{ background: scrolled ? "var(--hw-ink)" : "#fff" }} />
              <span style={{ background: scrolled ? "var(--hw-ink)" : "#fff" }} />
              <span style={{ background: scrolled ? "var(--hw-ink)" : "#fff" }} />
            </span>
          </button>
        </div>
      </div>

      {open && (
        <div className={styles.mobileNav}>
          {NAV_LINKS.map((link) => (
            <a key={link.href} href={link.href} onClick={() => setOpen(false)}>
              {link.label}
            </a>
          ))}
          <Link to="/app" onClick={() => setOpen(false)}>
            Enter Platform
          </Link>
        </div>
      )}
    </header>
  );
}

function Hero() {
  const reduce = useReducedMotion();
  const sectionRef = useRef<HTMLElement>(null);
  const { scrollYProgress } = useScroll({
    target: sectionRef,
    offset: ["start start", "end start"],
  });

  const imageY = useTransform(scrollYProgress, [0, 1], ["0%", "18%"]);
  const contentY = useTransform(scrollYProgress, [0, 1], ["0%", "10%"]);
  const contentOpacity = useTransform(scrollYProgress, [0, 0.7], [1, 0.15]);

  const mouseX = useMotionValue(50);
  const mouseY = useMotionValue(50);
  const spotlight = useMotionTemplate`radial-gradient(650px circle at ${mouseX}% ${mouseY}%, rgba(228, 0, 43, 0.16), transparent 55%)`;

  const onMove = (e: React.MouseEvent<HTMLElement>) => {
    if (reduce) return;
    const rect = e.currentTarget.getBoundingClientRect();
    mouseX.set(((e.clientX - rect.left) / rect.width) * 100);
    mouseY.set(((e.clientY - rect.top) / rect.height) * 100);
  };

  return (
    <section ref={sectionRef} className={styles.hero} onMouseMove={onMove}>
      <motion.div className={styles.heroMedia} style={reduce ? undefined : { y: imageY }}>
        <div className={styles.heroKenBurns}>
          <img
            src="https://images.unsplash.com/photo-1581091226825-a6a2a5aee158?auto=format&fit=crop&w=2400&q=80"
            alt="Industrial operations facility with critical infrastructure systems"
          />
        </div>
        <div className={styles.heroShade} />
        <div className={styles.hwGrid} style={{ position: "absolute", inset: 0, opacity: 0.35 }} />
        {!reduce && <motion.div className={styles.heroSpotlight} style={{ background: spotlight }} />}
        {!reduce && (
          <>
            <span className={`${styles.orb} ${styles.orbA}`} aria-hidden />
            <span className={`${styles.orb} ${styles.orbB}`} aria-hidden />
            <span className={`${styles.orb} ${styles.orbC}`} aria-hidden />
          </>
        )}
      </motion.div>

      <motion.div
        className={styles.heroContent}
        style={reduce ? undefined : { y: contentY, opacity: contentOpacity }}
      >
        <div>
          <motion.p
            className={styles.heroBrand}
            initial={reduce ? false : { opacity: 0, y: 28 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, ease: [0.22, 1, 0.36, 1] }}
          >
            <BrandName />
          </motion.p>
          <motion.div
            className={styles.heroRule}
            initial={reduce ? false : { scaleX: 0 }}
            animate={{ scaleX: 1 }}
            transition={{ duration: 0.9, delay: 0.25, ease: [0.22, 1, 0.36, 1] }}
          />
          <motion.h1
            className={styles.heroTitle}
            initial={reduce ? false : { opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, delay: 0.18, ease: [0.22, 1, 0.36, 1] }}
          >
            Behavioural threat detection for operations where failure is never an option.
          </motion.h1>
          <motion.p
            className={styles.heroLead}
            initial={reduce ? false : { opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, delay: 0.32, ease: [0.22, 1, 0.36, 1] }}
          >
            Unsupervised anomaly detection, deterministic risk scoring, and analyst-ready
            explanations — built for enterprise security operations.
          </motion.p>
          <motion.div
            className={styles.heroCtas}
            initial={reduce ? false : { opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, delay: 0.45, ease: [0.22, 1, 0.36, 1] }}
          >
            <motion.div whileHover={{ y: -2 }} whileTap={{ scale: 0.98 }}>
              <Link to="/app" className={styles.btnPrimary}>
                Enter Platform
              </Link>
            </motion.div>
            <motion.div whileHover={{ y: -2 }} whileTap={{ scale: 0.98 }}>
              <a href="#pipeline" className={styles.btnGhost}>
                See the Pipeline
              </a>
            </motion.div>
          </motion.div>
        </div>
      </motion.div>

      <a href="#why" className={styles.scrollCue} aria-label="Scroll to explore">
        <span className={styles.scrollCueLine} />
        <span>Scroll</span>
      </a>
    </section>
  );
}

function PulseStrip() {
  const items = [...PULSE_ITEMS, ...PULSE_ITEMS];
  return (
    <div className={styles.pulseStrip} aria-hidden>
      <div className={styles.pulseTrack}>
        {items.map((item, i) => (
          <span key={`${item}-${i}`} className={styles.pulseItem}>
            <span className={styles.pulseDot} />
            {item}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function LandingPage() {
  useEffect(() => {
    document.title = "SentinelAI — Behavioural Threat Detection";
    const prev = document.body.style.background;
    document.body.style.background = "#ffffff";
    return () => {
      document.body.style.background = prev;
      document.title = "SentinelAI · SOC Dashboard";
    };
  }, []);

  return (
    <div className={styles.landingRoot} id="top">
      <ScrollProgress />
      <SiteHeader />

      <main>
        <Hero />
        <PulseStrip />

        <section id="why" className={styles.sectionTight}>
          <div className={styles.wrap}>
            <Reveal>
              <div className={styles.expertiseGrid}>
                <div>
                  <p className={styles.monoLabel}>Why SentinelAI</p>
                  <h2 className={styles.sectionTitle}>
                    Expertise where behaviour meets consequence.
                  </h2>
                </div>
                <p className={styles.expertiseLead}>
                  Enterprise security fails quietly — one unusual login, one impossible travel hop,
                  one privilege spike after hours. SentinelAI turns those moments into ranked,
                  explained risk your SOC can trust.
                </p>
              </div>
            </Reveal>

            <div className={styles.pillars}>
              {[
                {
                  label: "Unsupervised",
                  detail: "Isolation Forest detects deviation without attack label leakage.",
                },
                {
                  label: "Deterministic risk",
                  detail:
                    "Rules fuse model score with enterprise context into actionable severity.",
                },
                {
                  label: "SOC-ready",
                  detail: "Explanations, timelines, and investigation views built for operators.",
                },
              ].map((item, i) => (
                <Reveal key={item.label} delay={i * 0.12}>
                  <motion.div className={styles.pillar} whileHover={{ y: -4 }}>
                    <div className={styles.redRule} />
                    <h3>{item.label}</h3>
                    <p>{item.detail}</p>
                  </motion.div>
                </Reveal>
              ))}
            </div>
          </div>
        </section>

        <section id="intelligence">
          <div className={styles.intel}>
            <motion.div
              className={styles.intelMedia}
              initial={{ opacity: 0, scale: 1.04 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true, amount: 0.3 }}
              transition={{ duration: 1.1, ease: [0.22, 1, 0.36, 1] }}
            >
              <img
                src="https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=1600&q=80"
                alt="Data center infrastructure representing continuous behavioural monitoring"
              />
              <div className={styles.intelShade} />
            </motion.div>
            <div className={styles.intelCopy}>
              <Reveal>
                <p className={styles.monoLabel}>Who we protect</p>
                <h2 className={styles.sectionTitle}>
                  Intelligence set in motion across every session.
                </h2>
                <motion.div
                  className={styles.redRule}
                  style={{ marginTop: "1.25rem", originX: 0 }}
                  initial={{ scaleX: 0 }}
                  whileInView={{ scaleX: 1 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.8, delay: 0.2, ease: [0.22, 1, 0.36, 1] }}
                />
                <p className={styles.intelBody}>
                  SentinelAI watches how people actually work — logins, access patterns, location
                  shifts, and resource use — then surfaces behaviour that breaks the pattern before
                  it becomes an incident.
                </p>
                <p className={styles.intelBody}>
                  Built for SOCs that need clarity under pressure: what changed, how severe it is,
                  and why the model flagged it.
                </p>
              </Reveal>
            </div>
          </div>
        </section>

        <section id="pipeline" className={`${styles.pipeline} ${styles.hwMesh} ${styles.section}`}>
          <div className={styles.radar} aria-hidden />
          <div className={styles.radarSweep} aria-hidden />
          <div className={styles.pipelineBloom} aria-hidden />
          <div className={styles.wrap} style={{ position: "relative" }}>
            <Reveal>
              <p className={styles.monoLabel}>How it works</p>
              <h2 className={`${styles.sectionTitle} ${styles.pipelineTitle}`}>
                From raw activity to explained risk — in one continuous pipeline.
              </h2>
              <p className={`${styles.sectionLead} ${styles.pipelineLead}`}>
                Detection stays unsupervised. Risk and explanations stay deterministic. No attack
                labels leak into production scoring.
              </p>
            </Reveal>

            <div className={styles.stages}>
              {STAGES.map((stage, i) => (
                <Reveal key={stage.step} delay={i * 0.1}>
                  <motion.article className={styles.stage} whileHover={{ y: -3 }}>
                    <span className={styles.stageStep}>{stage.step}</span>
                    <h3>{stage.title}</h3>
                    <p>{stage.body}</p>
                  </motion.article>
                </Reveal>
              ))}
            </div>
          </div>
        </section>

        <section id="outcomes" className={`${styles.outcomes} ${styles.section}`}>
          <div className={styles.wrap}>
            <Reveal>
              <p className={styles.monoLabel}>Outcomes</p>
              <h2 className={styles.sectionTitle}>
                Tangible results for security teams under real operational load.
              </h2>
              <p className={styles.sectionLead}>
                Built for environments where missed signals carry real consequence — refineries of
                identity data, hospitals of privilege, and plants of continuous access.
              </p>
            </Reveal>

            <div className={styles.outcomesList}>
              {OUTCOMES.map((item, index) => (
                <Reveal key={item.title} delay={index * 0.08}>
                  <article
                    className={`${styles.outcomeRow} ${index % 2 === 1 ? styles.outcomeFlip : ""}`}
                  >
                    <div className={styles.outcomeMedia}>
                      <img src={item.image} alt={item.alt} />
                    </div>
                    <div className={styles.outcomeCopy}>
                      <span className={styles.monoLabel}>
                        {String(index + 1).padStart(2, "0")}
                      </span>
                      <h3>{item.title}</h3>
                      <p>{item.body}</p>
                    </div>
                  </article>
                </Reveal>
              ))}
            </div>
          </div>
        </section>

        <section id="contact" className={`${styles.contact} ${styles.hwGradient} ${styles.section}`}>
          <div
            className={`${styles.hwGrid} ${styles.contactGrid}`}
            style={{ position: "absolute", inset: 0, opacity: 0.3, pointerEvents: "none" }}
          />
          <div className={`${styles.wrap} ${styles.contactInner}`}>
            <Reveal>
              <p className={styles.monoLabel} style={{ color: "rgba(255,255,255,0.8)" }}>
                Ready to connect?
              </p>
              <h2 className={styles.contactTitle}>
                Join the journey to autonomous threat awareness.
              </h2>
              <p className={styles.contactLead}>
                Bring behavioural intelligence into your SOC — open the platform and investigate
                anomalous sessions with ranked risk and clear explanations.
              </p>
            </Reveal>
            <Reveal delay={0.15} className={styles.contactCtas}>
              <motion.div whileHover={{ y: -2 }} whileTap={{ scale: 0.98 }}>
                <Link to="/app" className={styles.btnLight}>
                  Enter Platform
                </Link>
              </motion.div>
              <motion.div whileHover={{ y: -2 }} whileTap={{ scale: 0.98 }}>
                <a href="#pipeline" className={styles.btnOutlineLight}>
                  Explore Pipeline
                </a>
              </motion.div>
            </Reveal>
          </div>
        </section>
      </main>

      <footer className={styles.footer}>
        <div className={styles.wrap}>
          <div className={styles.footerGrid}>
            <div>
              <a href="#top" className={styles.brand} aria-label="SentinelAI home">
                <Logo size={32} wordmarkTone="light" />
              </a>
              <p className={styles.footerBrandText}>
                Behavioural anomaly detection and risk intelligence for enterprise security
                operations — inspired by the clarity of industrial-grade platforms.
              </p>
            </div>

            {FOOTER_COLUMNS.map((col) => (
              <div key={col.title}>
                <p className={styles.footerColTitle}>{col.title}</p>
                <ul>
                  {col.links.map((link) => (
                    <li key={link.label}>
                      {link.href.startsWith("/") ? (
                        <Link to={link.href}>{link.label}</Link>
                      ) : (
                        <a href={link.href}>{link.label}</a>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          <div className={styles.footerBottom}>
            <p>
              © {new Date().getFullYear()} <BrandName />. Behavioural Threat
              Detection.
            </p>
            <p>
              Visual language inspired by{" "}
              <a
                href="https://www.honeywell.com/us/en"
                target="_blank"
                rel="noopener noreferrer"
              >
                Honeywell Technologies
              </a>
              .
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
