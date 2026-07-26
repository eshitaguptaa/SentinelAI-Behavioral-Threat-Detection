import Image from "next/image";
import { Reveal } from "./Reveal";

export function IntelligenceSection() {
  return (
    <section id="intelligence" className="bg-white">
      <div className="mx-auto grid max-w-[1440px] lg:grid-cols-2">
        <div className="relative min-h-[52vh] lg:min-h-[720px]">
          <Image
            src="https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=1600&q=80"
            alt="Data center infrastructure representing continuous behavioural monitoring"
            fill
            className="object-cover"
            sizes="(max-width: 1024px) 100vw, 50vw"
          />
          <div className="absolute inset-0 bg-gradient-to-t from-black/50 to-transparent lg:bg-gradient-to-r lg:from-transparent lg:to-black/20" />
        </div>

        <div className="flex flex-col justify-center px-5 py-16 sm:px-10 lg:px-16 lg:py-24">
          <Reveal>
            <p className="font-mono text-[0.7rem] uppercase tracking-[0.22em] text-hw-red">
              Who we protect
            </p>
            <h2 className="mt-4 font-display text-[clamp(2rem,4vw,3.4rem)] font-bold leading-[1.05] tracking-[-0.03em] text-hw-ink">
              Intelligence set in motion across every session.
            </h2>
            <div className="mt-5 h-[3px] w-14 bg-hw-red" />
            <p className="mt-6 max-w-lg text-[1.05rem] leading-relaxed text-hw-steel">
              SentinelAI watches how people actually work — logins, access patterns, location
              shifts, and resource use — then surfaces behaviour that breaks the pattern before
              it becomes an incident.
            </p>
            <p className="mt-4 max-w-lg text-[1.05rem] leading-relaxed text-hw-steel">
              Built for SOCs that need clarity under pressure: what changed, how severe it is,
              and why the model flagged it.
            </p>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
