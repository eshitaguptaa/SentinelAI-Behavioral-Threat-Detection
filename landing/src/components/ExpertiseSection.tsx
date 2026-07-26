import { Reveal } from "./Reveal";

export function ExpertiseSection() {
  return (
    <section className="bg-white">
      <div className="mx-auto max-w-[1440px] px-5 py-20 sm:px-8 lg:px-12 lg:py-24">
        <Reveal>
          <div className="grid gap-10 lg:grid-cols-[0.9fr_1.1fr] lg:items-end">
            <div>
              <p className="font-mono text-[0.7rem] uppercase tracking-[0.22em] text-hw-red">
                Why SentinelAI
              </p>
              <h2 className="mt-4 font-display text-[clamp(2rem,4vw,3.25rem)] font-bold leading-[1.05] tracking-[-0.03em] text-hw-ink">
                Expertise where behaviour meets consequence.
              </h2>
            </div>
            <p className="max-w-xl text-[1.1rem] leading-relaxed text-hw-steel lg:pb-1">
              Enterprise security fails quietly — one unusual login, one impossible travel hop,
              one privilege spike after hours. SentinelAI turns those moments into ranked,
              explained risk your SOC can trust.
            </p>
          </div>
        </Reveal>

        <div className="mt-14 grid gap-px bg-black/10 sm:grid-cols-3">
          {[
            {
              label: "Unsupervised",
              detail: "Isolation Forest detects deviation without attack label leakage.",
            },
            {
              label: "Deterministic risk",
              detail: "Rules fuse model score with enterprise context into actionable severity.",
            },
            {
              label: "SOC-ready",
              detail: "Explanations, timelines, and investigation views built for operators.",
            },
          ].map((item, i) => (
            <Reveal key={item.label} delayClass={i === 0 ? "" : i === 1 ? "delay-1" : "delay-2"}>
              <div className="bg-white px-6 py-10 sm:px-8">
                <div className="h-[3px] w-10 bg-hw-red" />
                <h3 className="mt-6 font-display text-xl font-bold tracking-[-0.02em] text-hw-ink">
                  {item.label}
                </h3>
                <p className="mt-3 text-[0.95rem] leading-relaxed text-hw-steel">{item.detail}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
