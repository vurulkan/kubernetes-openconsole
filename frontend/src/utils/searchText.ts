// What a plain search term is matched against on each Dashboard tab: the name plus the text the
// tab's columns show, hidden columns included, so list and card view find the same rows. Ages,
// restarts and CPU / memory are left out (numbers that change), and so is anything that isn't a column.
import i18n from '../i18n';
import { containerStates, podController, podStatus } from './podStatus';

type Item = Record<string, any>;

function workloadStatus(desired: number, ready: number, kind: 'deployments' | 'statefulsets' | 'daemonsets'): string {
  const t = i18n.t.bind(i18n);
  if (desired === 0) return t(kind === 'daemonsets' ? 'dashboard.status.noNodes' : 'dashboard.status.scaledToZero');
  if (kind === 'daemonsets') return t('dashboard.status.ready', { ready, desired });
  if (kind === 'statefulsets')
    return t(ready >= desired ? 'dashboard.status.availableCount' : 'dashboard.status.progressingCount', { ready, desired });
  return t(ready >= desired ? 'dashboard.status.available' : 'dashboard.status.progressing');
}

function columnTexts(tab: string, it: Item): unknown[] {
  const t = i18n.t.bind(i18n);
  const spec = it.spec ?? {};
  const st = it.status ?? {};
  switch (tab) {
    case 'pods': {
      const s = podStatus(it);
      const owner = podController(it);
      return [
        s.label,
        s.label === 'Running' && s.tone !== 'ok' && t('dashboard.status.notReady', { ready: s.ready, total: s.total }),
        ...containerStates(it).map((c) => c.name),
        owner?.kind,
        owner?.name,
      ];
    }
    case 'deployments':
    case 'statefulsets': {
      const desired = spec.replicas ?? 0;
      const ready = st.readyReplicas ?? 0;
      return [workloadStatus(desired, ready, tab), `${ready}/${desired}`];
    }
    case 'daemonsets': {
      const desired = st.desiredNumberScheduled ?? 0;
      return [workloadStatus(desired, st.numberReady ?? 0, tab), `${st.currentNumberScheduled ?? 0}/${desired}`];
    }
    case 'services':
      return [
        spec.type,
        spec.clusterIP,
        ...(spec.externalIPs ?? []),
        ...(st.loadBalancer?.ingress ?? []).flatMap((i: Item) => [i.ip, i.hostname]),
        ...(spec.ports ?? []).flatMap((p: Item) => [p.name, p.port, `${p.port}/${p.protocol ?? 'TCP'}`, p.targetPort, p.nodePort]),
      ];
    case 'configmaps':
      return [...Object.keys(it.data ?? {}), ...Object.keys(it.binaryData ?? {})];
    case 'secrets':
      return [it.type, ...(it.keys ?? []).map((k: Item) => k.name)];
    case 'ingresses':
      return (spec.rules ?? []).flatMap((r: Item) => [r.host, ...(r.http?.paths ?? []).map((p: Item) => p.path)]);
    case 'cronjobs':
      return [spec.schedule, t(spec.suspend ? 'dashboard.status.suspended' : 'dashboard.status.active')];
    case 'jobs': {
      const failed = st.failed ?? 0;
      const active = st.active ?? 0;
      if (failed > 0) return [t('dashboard.status.failedN', { count: failed })];
      if (active > 0) return [t('dashboard.status.runningN', { count: active })];
      return [t((st.succeeded ?? 0) > 0 ? 'dashboard.status.succeeded' : 'dashboard.status.pending')];
    }
    case 'hpas': {
      const ref = spec.scaleTargetRef ?? {};
      const min = spec.minReplicas ?? 1;
      const max = spec.maxReplicas ?? 0;
      return [`${ref.kind}/${ref.name}`, `${min}–${max}`, `${min}-${max}`];
    }
    default:
      return [];
  }
}

/** Lower-cased, one value per line so a term can't match across two values. */
export function searchText(tab: string, it: Item): string {
  return [it.metadata?.name, ...columnTexts(tab, it)]
    .filter((v) => v !== undefined && v !== null && v !== false && v !== '')
    .join('\n')
    .toLowerCase();
}
