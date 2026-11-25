/** An open Dashboard applies a staged view at once (⌘K while the Dashboard is open). */
export const DASHBOARD_STAGE_EVENT = 'openconsole:dashboard-stage';

/**
 * Stage a Dashboard view (as saved views do) and go there. `dashboardPendingDetail` = the name whose
 * drawer opens (pods and workloads; its kind is `dashboardResourceTab`).
 */
export const openDashboard = (navigate: (p: string) => void, stage: Record<string, string>) => {
  try {
    Object.entries(stage).forEach(([k, v]) => localStorage.setItem(k, v));
  } catch {
    /* ignore */
  }
  window.dispatchEvent(new Event(DASHBOARD_STAGE_EVENT));
  navigate('/');
};

/** Open a pod's drawer on the Dashboard. */
export const openPod = (navigate: (p: string) => void, namespace: string, name: string) =>
  openDashboard(navigate, { dashboardNamespace: namespace, dashboardResourceTab: 'pods', dashboardPendingSearch: name, dashboardPendingDetail: name });
