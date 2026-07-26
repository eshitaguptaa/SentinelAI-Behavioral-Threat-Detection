import { Reveal } from "./Reveal";

const stages = [
  {
    step: "01",
    title: "Feature engineering",
    body: "Timeline events become numerical behavioural vectors — session rhythm, access entropy, location velocity, and more.",
  },
  {
    step: "02",
    title: "Anomaly detection",
    body: "A Behavioural Transformer scores unsupervised deviation from each employee’s normal operating baseline.",
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

export function PipelineSection() {
  return (
    <section id="pipeline" className="hw-mesh relative overflow-hidden text-white">
      <div className="pointer-events-none absolute -right-24 top-1/4 h-[420px] w-[420px] rounded-full border border-hw-red/20" />
      <div className="pointer-events-none absolute -right-10 top-[28%] h-[300px] w-[300px] animate-radar-sweep rounded-full border border-dashed border-hw-red/30" />

      <div className="relative mx-auto max-w-[1440px] px-5 py-20 sm:px-8 lg:px-12 lg:py-28">
        <Reveal>
          <p className="font-mono text-[0.7rem] uppercase tracking-[0.22em] text-hw-red">
            How it works
          </p>
          <h2 className="mt-4 max-w-3xl font-display text-[clamp(2rem,4vw,3.4rem)] font-bold leading-[1.05] tracking-[-0.03em]">
            From raw activity to explained risk — in one continuous pipeline.
          </h2>
          <p className="mt-5 max-w-2xl text-[1.05rem] leading-relaxed text-white/65">
            Detection stays unsupervised. Risk and explanations stay deterministic. No attack
            labels leak into production scoring.
          </p>
        </Reveal>

        <div className="mt-16 grid gap-0 border-t border-white/10 md:grid-cols-2 xl:grid-cols-4">
          {stages.map((stage, i) => (
            <Reveal
              key={stage.step}
              delayClass={i === 0 ? "" : i === 1 ? "delay-1" : i === 2 ? "delay-2" : "delay-3"}
            >
              <article className="group border-b border-white/10 py-10 md:border-b-0 md:border-r md:px-6 md:py-12 xl:px-8 last:md:border-r-0">
                <span className="font-mono text-[0.75rem] tracking-[0.18em] text-hw-red">
                  {stage.step}
                </span>
                <h3 className="mt-4 font-display text-[1.35rem] font-semibold tracking-[-0.02em] transition-colors group-hover:text-hw-red">
                  {stage.title}
                </h3>
                <p className="mt-3 text-[0.95rem] leading-relaxed text-white/60">{stage.body}</p>
              </article>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
