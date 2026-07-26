import { Reveal } from "./Reveal";

export function ContactSection() {
  return (
    <section id="contact" className="relative overflow-hidden hw-gradient-red text-white">
      <div className="pointer-events-none absolute inset-0 hw-grid opacity-30" />
      <div className="pointer-events-none absolute -left-20 bottom-0 h-64 w-64 rounded-full bg-black/10 blur-3xl" />
      <div className="pointer-events-none absolute right-0 top-0 h-80 w-80 rounded-full bg-white/10 blur-3xl" />

      <div className="relative mx-auto flex max-w-[1440px] flex-col items-start justify-between gap-10 px-5 py-20 sm:px-8 lg:flex-row lg:items-end lg:px-12 lg:py-28">
        <Reveal className="max-w-2xl">
          <p className="font-mono text-[0.7rem] uppercase tracking-[0.22em] text-white/80">
            Ready to connect?
          </p>
          <h2 className="mt-4 font-display text-[clamp(2.2rem,5vw,4rem)] font-extrabold leading-[1.02] tracking-[-0.035em]">
            Join the journey to autonomous threat awareness.
          </h2>
          <p className="mt-5 max-w-xl text-[1.05rem] leading-relaxed text-white/85">
            Like operators worldwide who run critical systems on trusted platforms — bring
            behavioural intelligence into your SOC with SentinelAI.
          </p>
        </Reveal>

        <Reveal delayClass="delay-2" className="flex w-full flex-col gap-3 sm:w-auto sm:flex-row">
          <a
            href="mailto:demo@sentinelai.local"
            className="inline-flex h-12 items-center justify-center bg-white px-8 text-[0.8rem] font-semibold uppercase tracking-[0.1em] text-hw-red transition-opacity hover:opacity-90"
          >
            Contact Sales
          </a>
          <a
            href="#pipeline"
            className="inline-flex h-12 items-center justify-center border border-white/50 px-8 text-[0.8rem] font-semibold uppercase tracking-[0.1em] text-white transition-colors hover:bg-white/10"
          >
            Explore Pipeline
          </a>
        </Reveal>
      </div>
    </section>
  );
}
