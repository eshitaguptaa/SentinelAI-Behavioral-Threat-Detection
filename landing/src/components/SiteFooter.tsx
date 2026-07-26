const columns = [
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
    title: "Company",
    links: [
      { label: "Request Demo", href: "#contact" },
      { label: "Contact Sales", href: "#contact" },
    ],
  },
];

export function SiteFooter() {
  return (
    <footer className="bg-hw-ink text-white">
      <div className="mx-auto max-w-[1440px] px-5 py-14 sm:px-8 lg:px-12">
        <div className="grid gap-12 lg:grid-cols-[1.4fr_1fr_1fr_1fr]">
          <div>
            <a href="#top" className="inline-flex items-center gap-3">
              <span className="flex h-8 w-8 items-center justify-center hw-gradient-red text-[0.7rem] font-bold text-white">
                S
              </span>
              <span className="font-display text-lg font-bold tracking-[-0.02em]">
                SentinelAI
              </span>
            </a>
            <p className="mt-5 max-w-sm text-sm leading-relaxed text-white/55">
              Behavioural anomaly detection and risk intelligence for enterprise security
              operations — inspired by the clarity of industrial-grade platforms.
            </p>
          </div>

          {columns.map((col) => (
            <div key={col.title}>
              <p className="font-mono text-[0.65rem] uppercase tracking-[0.2em] text-white/40">
                {col.title}
              </p>
              <ul className="mt-4 space-y-3">
                {col.links.map((link) => (
                  <li key={link.label}>
                    <a
                      href={link.href}
                      className="text-sm text-white/70 transition-colors hover:text-hw-red"
                    >
                      {link.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div className="mt-14 flex flex-col gap-3 border-t border-white/10 pt-6 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-xs text-white/40">
            © {new Date().getFullYear()} SentinelAI. Behavioural Threat Detection.
          </p>
          <p className="text-xs text-white/40">
            Visual language inspired by{" "}
            <a
              href="https://www.honeywell.com/us/en"
              target="_blank"
              rel="noopener noreferrer"
              className="underline decoration-white/20 underline-offset-2 transition-colors hover:text-white/70"
            >
              Honeywell Technologies
            </a>
            .
          </p>
        </div>
      </div>
    </footer>
  );
}
