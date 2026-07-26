import Image from "next/image";

export function Hero() {
  return (
    <section
      id="top"
      className="relative flex min-h-[100svh] items-end overflow-hidden"
    >
      <div className="absolute inset-0 animate-scale-in">
        <Image
          src="https://images.unsplash.com/photo-1581091226825-a6a2a5aee158?auto=format&fit=crop&w=2400&q=80"
          alt="Industrial operations facility with critical infrastructure systems"
          fill
          priority
          className="object-cover object-center"
          sizes="100vw"
        />
        <div className="absolute inset-0 bg-gradient-to-t from-black via-black/55 to-black/35" />
        <div className="absolute inset-0 bg-gradient-to-r from-black/70 via-black/30 to-transparent" />
        <div className="absolute inset-0 hw-grid opacity-40" />
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-px animate-pulse-scan bg-gradient-to-r from-transparent via-hw-red to-transparent opacity-60"
          aria-hidden
        />
      </div>

      <div className="relative z-10 mx-auto w-full max-w-[1440px] px-5 pb-16 pt-32 sm:px-8 sm:pb-20 lg:px-12 lg:pb-24">
        <div className="max-w-3xl">
          <p
            className="animate-fade-up font-display text-[clamp(2.75rem,8vw,6.5rem)] font-extrabold leading-[0.92] tracking-[-0.04em] text-white"
            style={{ animationDelay: "0.05s" }}
          >
            SentinelAI
          </p>

          <div
            className="mt-5 h-[3px] w-16 origin-left animate-line-grow bg-hw-red"
            style={{ animationDelay: "0.35s" }}
          />

          <h1
            className="mt-7 max-w-2xl animate-fade-up font-display text-[clamp(1.35rem,3.4vw,2.35rem)] font-semibold leading-[1.15] tracking-[-0.02em] text-white"
            style={{ animationDelay: "0.2s" }}
          >
            Behavioural threat detection for operations where failure is never an option.
          </h1>

          <p
            className="mt-5 max-w-xl animate-fade-up text-[1.05rem] leading-relaxed text-white/75"
            style={{ animationDelay: "0.35s" }}
          >
            Unsupervised anomaly detection, deterministic risk scoring, and analyst-ready
            explanations — built for enterprise security operations.
          </p>

          <div
            className="mt-9 flex animate-fade-up flex-col gap-3 sm:flex-row sm:items-center"
            style={{ animationDelay: "0.5s" }}
          >
            <a
              href="#contact"
              className="inline-flex h-12 items-center justify-center bg-hw-red px-7 text-[0.8rem] font-semibold uppercase tracking-[0.1em] text-white transition-colors hover:bg-hw-red-deep"
            >
              Request a Demo
            </a>
            <a
              href="#pipeline"
              className="inline-flex h-12 items-center justify-center border border-white/35 bg-white/5 px-7 text-[0.8rem] font-semibold uppercase tracking-[0.1em] text-white backdrop-blur-sm transition-colors hover:border-white hover:bg-white/10"
            >
              See the Pipeline
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
