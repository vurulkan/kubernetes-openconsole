/** Stage a Dashboard view (as saved views do) and go there. */
export const openDashboard = (navigate: (p: string) => void, stage: Record<string, string>) => {
  try {
    Object.entries(stage).forEach(([k, v]) => localStorage.setItem(k, v));
  } catch {
    /* ignore */
  }
  navigate('/');
};

/** Open a pod's drawer on the Dashboard. */
export const openPod = (navigate: (p: string) => void, namespace: string, name: string) =>
  openDashboard(navigate, { dashboardNamespace: namespace, dashboardResourceTab: 'pods', dashboardPendingSearch: name, dashboardPendingPod: name });
