import React, { useEffect, useRef, useState } from 'react';
import { FileCode2, RotateCcw, Scaling, Terminal } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Drawer } from '../../components/Drawer';
import { Badge, Button, Spinner } from '../../components/ui';
import { PodRestarts, PodStatusBadge } from '../../components/PodStatusBadge';
import {
  getDeploymentReplicaSets,
  getWorkloadEvents,
  getWorkloadRestarts,
  getWorkloadUsageHistory,
  listPods,
  type MetricsSnapshot,
  type ReplicaSetRevision,
  type WorkloadKind,
} from '../../services/api';
import { UsageBar, UsageHistoryPanel } from '../../components/Usage';
import { ownerUsage, podResources, scaleResources } from '../../utils/resources';
import { ageShort } from '../../utils/age';
import { podOwner, podStatus } from '../../utils/podStatus';
import { Conditions, Empty, Events, Fields, Section, type Item } from './DetailParts';
import { RestartHistory } from './RestartHistory';

/** Owner kind of each drawer kind, as podOwner() writes it. */
export const KIND: Record<WorkloadKind, string> = {
  deployments: 'Deployment',
  statefulsets: 'StatefulSet',
  daemonsets: 'DaemonSet',
};

type Props = {
  kind: WorkloadKind;
  workload: Item | null;
  namespace: string;
  canRestart: boolean;
  canScale: boolean;
  onClose: () => void;
  onOpenPod: (pod: Item) => void;
  onLogs: (name: string) => void;
  onYaml: (name: string) => void;
  onRestart: (name: string) => void;
  onScale: (name: string, current: number) => void;
  metrics: MetricsSnapshot | null;
};

/** Desired / updated / ready / available, which the three kinds name differently. */
function rollout(kind: WorkloadKind, w: Item) {
  const spec = w.spec ?? {};
  const st = w.status ?? {};
  if (kind === 'daemonsets') {
    return {
      desired: st.desiredNumberScheduled ?? 0,
      updated: st.updatedNumberScheduled ?? 0,
      ready: st.numberReady ?? 0,
      available: st.numberAvailable ?? 0,
      strategy: spec.updateStrategy?.type === 'RollingUpdate'
        ? `RollingUpdate (maxUnavailable ${spec.updateStrategy.rollingUpdate?.maxUnavailable ?? 1})`
        : spec.updateStrategy?.type,
      revision: undefined as string | undefined,
    };
  }
  const base = {
    desired: spec.replicas ?? 0,
    updated: st.updatedReplicas ?? 0,
    ready: st.readyReplicas ?? 0,
    available: st.availableReplicas ?? 0,
  };
  if (kind === 'statefulsets') {
    const partition = spec.updateStrategy?.rollingUpdate?.partition;
    return {
      ...base,
      strategy: `${spec.updateStrategy?.type ?? 'RollingUpdate'}${partition ? ` (partition ${partition})` : ''}`,
      revision: st.updateRevision as string | undefined,
    };
  }
  return {
    ...base,
    strategy: spec.strategy?.type === 'RollingUpdate'
      ? `RollingUpdate (maxSurge ${spec.strategy.rollingUpdate?.maxSurge ?? '25%'}, maxUnavailable ${spec.strategy.rollingUpdate?.maxUnavailable ?? '25%'})`
      : spec.strategy?.type,
    revision: w.metadata?.annotations?.['deployment.kubernetes.io/revision'] as string | undefined,
  };
}

/** Detail drawer for a Deployment, StatefulSet or DaemonSet. */
export const WorkloadDrawer: React.FC<Props> = ({
  kind,
  workload,
  namespace,
  canRestart,
  canScale,
  onClose,
  onOpenPod,
  onLogs,
  onYaml,
  onRestart,
  onScale,
  metrics,
}) => {
  const { t } = useTranslation();
  const name: string = workload?.metadata?.name ?? '';
  const owner = `${KIND[kind]}/${name}`;
  const version = workload?.metadata?.resourceVersion;
  const [pods, setPods] = useState<Item[] | null>(null);
  const [revisions, setRevisions] = useState<ReplicaSetRevision[] | null>(null);
  const [revisionsError, setRevisionsError] = useState<string | null>(null);

  // Refetch whenever the dashboard's 10 s refresh hands us a new object.
  // Only the first fetch is a user action; the rest are auto-refreshes (not audited).
  const opened = useRef<string | null>(null);
  useEffect(() => {
    if (!name) return;
    let live = true;
    const auto = opened.current === owner;
    opened.current = owner;
    listPods(namespace, auto)
      .then((r) => live && setPods(r.items.filter((p) => podOwner(p) === owner)))
      .catch(() => live && setPods([]));
    if (kind === 'deployments') {
      getDeploymentReplicaSets(namespace, name)
        .then((r) => live && (setRevisions(r.items), setRevisionsError(null)))
        .catch((err: Error) => live && setRevisionsError(err.message));
    }
    return () => {
      live = false;
    };
  }, [namespace, name, kind, workload]);

  if (!workload) return null;
  const spec = workload.spec ?? {};
  const st = workload.status ?? {};
  const r = rollout(kind, workload);
  const stalled = (st.conditions ?? []).some((c: Item) => c.type === 'Progressing' && c.reason === 'ProgressDeadlineExceeded');
  const failing = (pods ?? []).filter((p) => podStatus(p).tone === 'error').length;
  const used = metrics?.available ? ownerUsage(metrics.items, owner) : undefined;
  const budget = scaleResources(podResources(spec.template?.spec?.containers), used?.pods ?? 0);
  const podsByHash = (hash: string) => (pods ?? []).filter((p) => p.metadata?.labels?.['pod-template-hash'] === hash);
  const scalable = kind !== 'daemonsets';

  return (
    <Drawer
      open
      onClose={onClose}
      width="lg"
      title={name}
      description={`${KIND[kind]} · ${namespace} · ${ageShort(workload.metadata?.creationTimestamp)}`}
      footer={
        <>
          <Button variant="outline" size="sm" onClick={() => onYaml(name)}>
            <FileCode2 size={13} />
            {t('dashboard.actions.yaml')}
          </Button>
          {canScale && scalable && (
            <Button variant="outline" size="sm" onClick={() => onScale(name, r.desired)}>
              <Scaling size={13} />
              {t('dashboard.actions.scale')}
            </Button>
          )}
          {canRestart && kind === 'deployments' && (
            <Button variant="outline" size="sm" onClick={() => onRestart(name)}>
              <RotateCcw size={13} />
              {t('dashboard.actions.restart')}
            </Button>
          )}
          {kind === 'deployments' && (
            <Button variant="primary" size="sm" onClick={() => onLogs(name)}>
              <Terminal size={13} />
              {t('dashboard.actions.logs')}
            </Button>
          )}
        </>
      }
    >
      <div className="flex flex-col gap-6">
        <Section title={t('dashboard.detail.rollout')}>
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center gap-2">
              {r.desired === 0 && scalable ? (
                <Badge variant="default">{t('dashboard.status.scaledToZero')}</Badge>
              ) : stalled ? (
                <Badge variant="error">ProgressDeadlineExceeded</Badge>
              ) : r.ready >= r.desired && r.updated >= r.desired ? (
                <Badge variant="success">{t('dashboard.status.available')}</Badge>
              ) : (
                <Badge variant="warning">{t('dashboard.status.progressing')}</Badge>
              )}
              {failing > 0 && <Badge variant="error">{t('dashboard.detail.podsFailing', { count: failing })}</Badge>}
              <span className="font-mono text-xs text-slate-600 dark:text-slate-300">
                {t('dashboard.detail.replicaCounts', r)}
              </span>
            </div>
            <div
              className="h-1.5 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800"
              role="meter"
              aria-label={t('dashboard.detail.ready')}
              aria-valuemin={0}
              aria-valuemax={r.desired}
              aria-valuenow={r.ready}
            >
              <div
                className={`h-full rounded-full ${stalled ? 'bg-rose-500' : r.ready >= r.desired ? 'bg-emerald-500' : 'bg-amber-500'}`}
                style={{ width: `${r.desired ? Math.min(100, (r.ready / r.desired) * 100) : 0}%` }}
              />
            </div>
            <Fields
              rows={[
                [t('dashboard.detail.strategy'), r.strategy],
                ...(r.revision ? ([[t('dashboard.detail.revision'), r.revision]] as Array<[string, React.ReactNode]>) : []),
                [t('dashboard.detail.image'), (spec.template?.spec?.containers ?? []).map((c: Item) => c.image).join(', ')],
              ]}
            />
          </div>
        </Section>

        <Section title={t('dashboard.usage.title')}>
          {used && used.pods > 0 && (
            <div className="grid grid-cols-2 gap-4">
              <UsageBar kind="cpu" used={used.cpu} limit={budget.cpu.limit} request={budget.cpu.request} />
              <UsageBar kind="mem" used={used.memory} limit={budget.mem.limit} request={budget.mem.request} />
            </div>
          )}
          {metrics && !metrics.available && metrics.reason && metrics.reason !== 'warming_up' && (
            <Empty>{t(`dashboard.usage.unavailable.${metrics.reason}`, { defaultValue: t('dashboard.usage.unavailable.error') })}</Empty>
          )}
          <UsageHistoryPanel
            load={(range) => getWorkloadUsageHistory(kind, namespace, name, range)}
            cpuLimit={budget.cpu.limit}
            memLimit={budget.mem.limit}
            reloadKey={`${owner}:${metrics?.updatedAt}`}
          />
        </Section>

        <Section title={t('dashboard.detail.pods')} aside={pods && <span className="text-xs text-slate-500">{pods.length}</span>}>
          {!pods ? (
            <Spinner size="sm" />
          ) : !pods.length ? (
            <Empty>{t('dashboard.detail.none')}</Empty>
          ) : (
            <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
              {pods.map((p) => {
                const s = podStatus(p);
                return (
                  <li key={p.metadata?.name}>
                    <button
                      type="button"
                      onClick={() => onOpenPod(p)}
                      className="grid w-full grid-cols-[1fr_auto_auto] items-center gap-3 px-3 py-2 text-left hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand-500/60 dark:hover:bg-slate-800/50"
                    >
                      <span className="truncate font-mono text-xs text-slate-900 dark:text-slate-100">
                        {p.metadata?.name}
                        <span className="ml-2 text-slate-500 dark:text-slate-400">{p.spec?.nodeName}</span>
                      </span>
                      <PodRestarts status={s} />
                      <PodStatusBadge namespace={namespace} podName={p.metadata?.name} status={s} />
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </Section>

        <Section title={t('dashboard.restarts.title')}>
          <RestartHistory
            load={() => getWorkloadRestarts(kind, namespace, name)}
            reloadKey={`${owner}:${(pods ?? []).reduce((n, p) => n + podStatus(p).restarts, 0)}`}
            showPod
          />
        </Section>

        {kind === 'deployments' && (
          <Section title={t('dashboard.detail.revisions')}>
            {revisionsError ? (
              <Empty>{revisionsError}</Empty>
            ) : !revisions ? (
              <Spinner size="sm" />
            ) : !revisions.length ? (
              <Empty>{t('dashboard.detail.none')}</Empty>
            ) : (
              <ul className="flex flex-col gap-1.5">
                {revisions.map((rs) => {
                  const restarts = podsByHash(rs.podTemplateHash).reduce((sum, p) => sum + podStatus(p).restarts, 0);
                  return (
                    <li
                      key={rs.name}
                      className={`rounded-md border px-2.5 py-1.5 text-xs ${
                        rs.revision === r.revision
                          ? 'border-brand-200 bg-brand-50/60 dark:border-brand-500/30 dark:bg-brand-500/10'
                          : 'border-slate-200 dark:border-slate-800'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                          #{rs.revision}
                          {rs.revision === r.revision && (
                            <span className="ml-2 font-sans font-medium text-brand-700 dark:text-brand-300">
                              {t('dashboard.detail.current')}
                            </span>
                          )}
                        </span>
                        <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                          {t('dashboard.detail.revisionPods', { ready: rs.readyReplicas, total: rs.replicas })}
                          {restarts > 0 && (
                            <span className="ml-1.5 text-amber-700 dark:text-amber-300">
                              · {t('dashboard.podStatus.restartsN', { count: restarts })}
                            </span>
                          )}
                          {' · '}
                          {ageShort(rs.createdAt)}
                        </span>
                      </div>
                      <p className="mt-0.5 break-all font-mono text-slate-600 dark:text-slate-300">{rs.images.join(', ')}</p>
                    </li>
                  );
                })}
              </ul>
            )}
          </Section>
        )}

        <Section title={t('dashboard.detail.conditions')}>
          <Conditions items={st.conditions} />
        </Section>

        <Section title={t('dashboard.detail.events')}>
          <Events load={() => getWorkloadEvents(kind, namespace, name)} version={`${owner}:${version}`} />
        </Section>
      </div>
    </Drawer>
  );
};
