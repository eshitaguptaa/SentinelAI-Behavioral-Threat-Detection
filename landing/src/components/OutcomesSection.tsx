import Image from "next/image";
import { Reveal } from "./Reveal";

const outcomes = [
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

export function OutcomesSection() {
  return (
    <section id="outcomes" className="bg-hw-mist">
      <div className="mx-auto max-w-[1440px] px-5 py-20 sm:px-8 lg:px-12 lg:py-28">
        <Reveal>
          <p className="font-mono text-[0.7rem] uppercase tracking-[0.22em] text-hw-red">
            Outcomes
          </p>
          <h2 className="mt-4 max-w-3xl font-display text-[clamp(2rem,4vw,3.4rem)] font-bold leading-[1.05] tracking-[-0.03em] text-hw-ink">
            Tangible results for security teams under real operational load.
          </h2>
          <p className="mt-5 max-w-2xl text-[1.05rem] leading-relaxed text-hw-steel">
            Built for environments where missed signals carry real consequence — refineries of
            identity data, hospitals of privilege, and plants of continuous access.
          </p>
        </Reveal>

        <div className="mt-14 space-y-0">
          {outcomes.map((item, index) => (
            <Reveal key={item.title} delayClass={index === 0 ? "" : "delay-1"}>
              <article
                className={`grid items-stretch gap-0 border-t border-black/10 lg:grid-cols-2 ${
                  index === outcomes.length - 1 ? "border-b" : ""
                }`}
              >
                <div
                  className={`relative min-h-[280px] sm:min-h-[360px] ${
                    index % 2 === 1 ? "lg:order-2" : ""
                  }`}
                >
                  <Image
                    src={item.image}
                    alt={item.alt}
                    fill
                    className="object-cover"
                    sizes="(max-width: 1024px) 100vw, 50vw"
                  />
                </div>
                <div
                  className={`flex flex-col justify-center bg-white px-6 py-12 sm:px-10 lg:px-14 ${
                    index % 2 === 1 ? "lg:order-1" : ""
                  }`}
                >
                  <span className="font-mono text-[0.7rem] tracking-[0.2em] text-hw-red">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <h3 className="mt-4 font-display text-[clamp(1.6rem,2.5vw,2.2rem)] font-bold tracking-[-0.02em] text-hw-ink">
                    {item.title}
                  </h3>
                  <p className="mt-4 max-w-md text-[1.05rem] leading-relaxed text-hw-steel">
                    {item.body}
                  </p>
                </div>
              </article>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
