import { useEffect, useState } from 'react';
import { getPodMetrics, type MetricsSnapshot } from '../services/api';

/** Latest pod usage of a namespace, refreshed every 30 s while the tab is visible. */
export function usePodMetrics(namespace: string | null, enabled: boolean): MetricsSnapshot | null {
  const [snap, setSnap] = useState<MetricsSnapshot | null>(null);
  useEffect(() => {
    setSnap(null);
    if (!namespace || !enabled) return;
    let live = true;
    const load = () => {
      if (document.hidden) return;
      getPodMetrics(namespace)
        .then((s) => live && setSnap(s))
        .catch(() => live && setSnap({ available: false, reason: 'error', items: [] }));
    };
    load();
    const timer = window.setInterval(load, 30_000);
    document.addEventListener('visibilitychange', load);
    return () => {
      live = false;
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', load);
    };
  }, [namespace, enabled]);
  return snap;
}
