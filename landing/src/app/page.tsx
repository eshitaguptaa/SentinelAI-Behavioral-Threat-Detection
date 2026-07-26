import { ContactSection } from "@/components/ContactSection";
import { ExpertiseSection } from "@/components/ExpertiseSection";
import { Hero } from "@/components/Hero";
import { IntelligenceSection } from "@/components/IntelligenceSection";
import { OutcomesSection } from "@/components/OutcomesSection";
import { PipelineSection } from "@/components/PipelineSection";
import { SiteFooter } from "@/components/SiteFooter";
import { SiteHeader } from "@/components/SiteHeader";

export default function Home() {
  return (
    <>
      <SiteHeader />
      <main>
        <Hero />
        <ExpertiseSection />
        <IntelligenceSection />
        <PipelineSection />
        <OutcomesSection />
        <ContactSection />
      </main>
      <SiteFooter />
    </>
  );
}
