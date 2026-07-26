"use client";

import { useEffect, useState } from "react";

const links = [
  { href: "#intelligence", label: "Intelligence" },
  { href: "#pipeline", label: "Pipeline" },
  { href: "#outcomes", label: "Outcomes" },
];

export function SiteHeader() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-50 transition-[background,box-shadow,backdrop-filter] duration-300 ${
        scrolled
          ? "bg-white/92 shadow-[0_1px_0_rgba(0,0,0,0.06)] backdrop-blur-md"
          : "bg-transparent"
      }`}
    >
      <div className="mx-auto flex h-[4.25rem] max-w-[1440px] items-center justify-between px-5 sm:px-8 lg:px-12">
        <a href="#top" className="group flex items-center gap-3">
          <span
            className={`flex h-8 w-8 items-center justify-center hw-gradient-red text-[0.7rem] font-bold tracking-brand text-white transition-transform duration-300 group-hover:scale-105 ${
              scrolled ? "" : "ring-1 ring-white/20"
            }`}
            aria-hidden
          >
            S
          </span>
          <span
            className={`font-display text-[1.05rem] font-bold tracking-[-0.02em] transition-colors ${
              scrolled ? "text-hw-ink" : "text-white"
            }`}
          >
            SentinelAI
          </span>
        </a>

        <nav className="hidden items-center gap-9 md:flex">
          {links.map((link) => (
            <a
              key={link.href}
              href={link.href}
              className={`text-[0.8125rem] font-medium tracking-wide transition-colors ${
                scrolled
                  ? "text-hw-ash hover:text-hw-red"
                  : "text-white/80 hover:text-white"
              }`}
            >
              {link.label}
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-3">
          <a
            href="#contact"
            className={`hidden text-[0.8125rem] font-semibold tracking-wide transition-colors sm:inline-flex ${
              scrolled ? "text-hw-ink hover:text-hw-red" : "text-white hover:text-white/80"
            }`}
          >
            Contact Sales
          </a>
          <a
            href="#contact"
            className="inline-flex h-10 items-center bg-hw-red px-4 text-[0.75rem] font-semibold uppercase tracking-[0.08em] text-white transition-colors hover:bg-hw-red-deep"
          >
            Request Demo
          </a>
          <button
            type="button"
            className={`inline-flex h-10 w-10 items-center justify-center md:hidden ${
              scrolled ? "text-hw-ink" : "text-white"
            }`}
            aria-label="Toggle menu"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            <span className="sr-only">Menu</span>
            <span className="flex w-5 flex-col gap-1.5">
              <span className={`h-px w-full ${scrolled ? "bg-hw-ink" : "bg-white"}`} />
              <span className={`h-px w-full ${scrolled ? "bg-hw-ink" : "bg-white"}`} />
              <span className={`h-px w-3 ${scrolled ? "bg-hw-ink" : "bg-white"}`} />
            </span>
          </button>
        </div>
      </div>

      {open && (
        <div className="border-t border-black/5 bg-white px-5 py-4 md:hidden">
          <div className="flex flex-col gap-3">
            {links.map((link) => (
              <a
                key={link.href}
                href={link.href}
                className="py-2 text-sm font-medium text-hw-ink"
                onClick={() => setOpen(false)}
              >
                {link.label}
              </a>
            ))}
          </div>
        </div>
      )}
    </header>
  );
}
