import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  listConfigMaps,
  listCronJobs,
  listDaemonSets,
  listDeployments,
  listHPAs,
  listIngresses,
  listJobs,
  listPods,
  listSecrets,
  listServices,
  listStatefulSets,
} from '../../services/api';
import { podOwner, podStatus } from '../../utils/podStatus';
import type { ObjectMeta } from '../../utils/kubeTypes';

type Item = Record<string, unknown>;

// Only Pods and Deployments take `auto` (the server doesn't audit those reads).
const LIST: Record<string, (namespace: string, auto: boolean) => Promise<{ items: Item[] }>> = {
  pods: (ns, auto) => listPods(ns, auto),
  deployments: (ns, auto) => listDeployments(ns, auto),
  daemonsets: (ns) => listDaemonSets(ns),
  statefulsets: (ns) => listStatefulSets(ns),
  hpas: (ns) => listHPAs(ns),
  services: (ns) => listServices(ns),
  configmaps: (ns) => listConfigMaps(ns),
  secrets: (ns) => listSecrets(ns),
  ingresses: (ns) => listIngresses(ns),
  cronjobs: (ns) => listCronJobs(ns),
  jobs: (ns) => listJobs(ns),
};

const WORKLOAD_TABS = ['deployments', 'statefulsets', 'daemonsets'];

/**
 * The objects of one resource tab in one namespace, polled every 10 s on the
 * Pods and Deployments tabs. `loading` and `error` are shared with the page's
 * own namespace and permission loads, hence the setters.
 */
export function useNamespaceResources(namespace: string | null, tab: string) {
  const { t } = useTranslation();
  const [items, setItems] = useState<Item[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Workload tabs also read the namespace's pods (auto-refresh, not audited) to flag workloads with failing pods.
  const [workloadPods, setWorkloadPods] = useState<Item[]>([]);
  const failingByOwner = useMemo(() => {
    const m = new Map<string, number>();
    for (const p of workloadPods) {
      const owner = podOwner(p);
      if (owner && podStatus(p).tone === 'error') m.set(owner, (m.get(owner) ?? 0) + 1);
    }
    return m;
  }, [workloadPods]);

  // auto: the periodic refresh, which the server doesn't audit. Only the
  // latest load may write: a slow answer for the previous namespace or tab
  // never replaces the current one. A failed auto refresh keeps the list
  // (and shows the error); the next good answer clears the error.
  const loadSeq = useRef(0);
  const reload = useCallback(async (auto = false) => {
    // Numbered first: even a load that has nothing to fetch retires the one in flight.
    const seq = ++loadSeq.current;
    if (!namespace || !tab) return;
    const current = () => seq === loadSeq.current;
    setLoading(true);
    try {
      const list = LIST[tab];
      const result = list ? await list(namespace, auto) : null;
      if (!current()) return;

      let next = result?.items ?? [];
      if (WORKLOAD_TABS.includes(tab)) {
        listPods(namespace, true)
          .then((r) => current() && setWorkloadPods(r.items ?? []))
          .catch(() => current() && setWorkloadPods([]));
      }
      // Pods tab: hide pods owned by a Job. Job-created pods clutter the Pods
      // list (CronJob runs, migration helpers, one-shots); the Jobs tab shows them.
      if (tab === 'pods') {
        next = next.filter((p) => {
          const owners = (p.metadata as ObjectMeta | undefined)?.ownerReferences ?? [];
          return !owners.some((o) => o.kind === 'Job');
        });
      }
      setItems(next);
      setError(null);
    } catch (err) {
      if (!current()) return;
      if (!auto) setItems([]);
      setError((err as Error).message || t('dashboard.loadFailed'));
    } finally {
      if (current()) setLoading(false);
    }
  }, [tab, namespace, t]);

  useEffect(() => {
    void reload();
  }, [reload]);

  useEffect(() => {
    if (!namespace || (tab !== 'pods' && tab !== 'deployments')) return;
    // Not while the tab is in the background; at once when it comes back.
    const tick = () => {
      if (document.visibilityState === 'visible') void reload(true);
    };
    const interval = setInterval(tick, 10000);
    document.addEventListener('visibilitychange', tick);
    return () => {
      clearInterval(interval);
      document.removeEventListener('visibilitychange', tick);
    };
  }, [tab, reload, namespace]);

  return { items, loading, setLoading, error, setError, reload, failingByOwner };
}
