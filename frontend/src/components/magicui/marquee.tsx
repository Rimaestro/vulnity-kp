import { cn } from "@/lib/utils";
import { useEffect, useState } from "react";

interface MarqueeProps {
  className?: string;
  reverse?: boolean;
  pauseOnHover?: boolean;
  children?: React.ReactNode;
  vertical?: boolean;
  repeat?: number;
  forceAnimation?: boolean; // Force animation even with reduced motion
  [key: string]: any;
}

export default function Marquee({
  className,
  reverse,
  pauseOnHover = false,
  children,
  vertical = false,
  repeat = 4,
  forceAnimation = false,
  ...props
}: MarqueeProps) {
  const [supportsCustomProperties, setSupportsCustomProperties] = useState(true);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  useEffect(() => {
    // Check for CSS custom properties support
    const testElement = document.createElement('div');
    testElement.style.setProperty('--test', 'test');
    const supportsCSS = testElement.style.getPropertyValue('--test') === 'test';
    setSupportsCustomProperties(supportsCSS);

    // Check for reduced motion preference
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mediaQuery.matches);

    const handleChange = (e: MediaQueryListEvent) => {
      setPrefersReducedMotion(e.matches);
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  // If reduced motion is preferred and not forced, don't animate
  if (prefersReducedMotion && !forceAnimation) {
    return (
      <div
        {...props}
        className={cn(
          "flex overflow-hidden p-2",
          {
            "flex-row": !vertical,
            "flex-col": vertical,
          },
          className,
        )}
      >
        <div className={cn("flex shrink-0 justify-around gap-4", {
          "flex-row": !vertical,
          "flex-col": vertical,
        })}>
          {children}
        </div>
      </div>
    );
  }

  return (
    <div
      {...props}
      className={cn(
        "group flex overflow-hidden p-2",
        supportsCustomProperties
          ? "[--duration:40s] [--gap:1rem] [gap:var(--gap)]"
          : "gap-4",
        {
          "flex-row": !vertical,
          "flex-col": vertical,
          "force-animate": forceAnimation,
        },
        className,
      )}
      style={supportsCustomProperties ? {} : { gap: '1rem' }}
    >
      {Array(repeat)
        .fill(0)
        .map((_, i) => (
          <div
            key={i}
            className={cn(
              "flex shrink-0 justify-around",
              supportsCustomProperties ? "[gap:var(--gap)]" : "gap-4",
              {
                "animate-marquee flex-row": !vertical,
                "animate-marquee-vertical flex-col": vertical,
                "group-hover:[animation-play-state:paused]": pauseOnHover,
                "[animation-direction:reverse]": reverse,
              }
            )}
            style={supportsCustomProperties ? {} : { gap: '1rem' }}
          >
            {children}
          </div>
        ))}
    </div>
  );
}
