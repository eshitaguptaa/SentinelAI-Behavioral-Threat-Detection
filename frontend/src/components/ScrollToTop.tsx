import { useEffect } from "react";
import { useLocation } from "react-router-dom";

/**
 * Reset scroll position on route changes.
 * The SOC shell scrolls inside ``[data-scroll-root]``; the landing page uses the window.
 */
export default function ScrollToTop() {
  const { pathname, search, hash } = useLocation();

  useEffect(() => {
    if (hash) return;

    window.scrollTo({ top: 0, left: 0, behavior: "auto" });

    const roots = document.querySelectorAll<HTMLElement>("[data-scroll-root]");
    roots.forEach((root) => {
      root.scrollTo({ top: 0, left: 0, behavior: "auto" });
    });
  }, [pathname, search, hash]);

  return null;
}
