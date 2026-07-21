"use client";

import { useEffect, useState } from "react";

export function FreshnessBanner({ generatedAt }: { generatedAt: string }) {
  const [isStale, setIsStale] = useState(false);

  useEffect(() => {
    const generatedTime = new Date(generatedAt).getTime();
    const currentTime = new Date().getTime();
    // 26 hours threshold to allow for slight workflow delay
    const threshold = 26 * 60 * 60 * 1000;
    if (currentTime - generatedTime > threshold) {
      const handle = requestAnimationFrame(() => {
        setIsStale(true);
      });
      return () => cancelAnimationFrame(handle);
    }
  }, [generatedAt]);

  if (!isStale) {
    return null;
  }

  return (
    <div className="freshness-banner" role="alert">
      <div className="freshness-banner__content">
        <span className="freshness-banner__icon" aria-hidden="true">⚠️</span>
        <span>
          <strong>Stale snapshot: </strong>
          Normally refreshed daily. The displayed snapshot may be up to 72 hours old if an upstream source or validation step fails.
        </span>
      </div>
    </div>
  );
}
