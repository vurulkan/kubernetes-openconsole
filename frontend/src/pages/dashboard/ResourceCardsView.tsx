import React from 'react';
import {
  Activity,
  Calendar,
  FileCode2,
  FileText,
  KeyRound,
  Link2,
  RefreshCw,
  RotateCcw,
  Scaling,
  Search as SearchIcon,
  Terminal,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge, Button } from '../../components/ui';
import { ContainerSquares, PodRestarts, PodStatusBadge, STATUS_DOT } from '../../components/PodStatusBadge';
import { UsageBar } from '../../components/Usage';
import { containerStates, podController, podStatus } from '../../utils/podStatus';
import { formatAge } from '../../utils/age';
import { ownerUsage, podResources, scaleResources } from '../../utils/resources';
import { KIND } from './WorkloadDrawer';
import type { ResourceViewProps } from './ResourceListView';
import type { WorkloadKind } from '../../services/api';

/**
 * The Dashboard's card view. Rendered only in card mode; the browser skips
 * laying out and painting cards outside the viewport (content-visibility), so
 * a namespace with thousands of pods stays smooth while find-in-page and
 * screen readers still reach every card.
 */
export const ResourceCardsView: React.FC<ResourceViewProps & { actionBusy: string | null }> = ({
  activeTab,
  items,
  selectedNamespace,
  searchQuery,
  loading,
  canExecPods,
  canRestartDeployments,
  canScaleDeployments,
  canScaleStatefulSets,
  openYamlModal,
  openEventsModal,
  openLogModal,
  onOpen,
  metrics,
  failingByOwner,
  openConfigMapDataModal,
  openSecretModal,
  canEditSecrets,
  openDeploymentLogs,
  openJobLogs,
  onExec,
  onRestart,
  onScale,
  onScaleStatefulSet,
  actionBusy,
}) => {
  const { t } = useTranslation();
  const isWorkloadTab = activeTab === 'deployments' || activeTab === 'statefulsets' || activeTab === 'daemonsets';
  const usageOf = (name: string) => (metrics?.available ? metrics.items.find((p) => p.name === name) : undefined);
  return (
    <div
      className="grid grid-cols-1 gap-3 p-5 sm:grid-cols-2 xl:grid-cols-3"
    >
      {items.length === 0 && !loading && (
        <div className="col-span-full">
          <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 px-6 py-10 text-center">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400">
              <SearchIcon size={16} />
            </div>
            <p className="text-sm font-medium text-slate-600 dark:text-slate-300">
              {searchQuery ? t('dashboard.emptyFiltered') : t('dashboard.empty')}
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {searchQuery ? t('dashboard.emptyHintSearch') : t('dashboard.emptyHint')}
            </p>
          </div>
        </div>
      )}

      {items.map((item) => {
        const name = (item.metadata as { name?: string })?.name ?? 'Unnamed';
        const uid = (item.metadata as { uid?: string })?.uid ?? name;
        const pod = activeTab === 'pods' ? podStatus(item) : null;

        const desiredReplicas = (item.spec as { replicas?: number })?.replicas ?? 0;
        const readyReplicas = (item.status as { readyReplicas?: number })?.readyReplicas ?? 0;
        const allReplicasReady = desiredReplicas > 0 && readyReplicas >= desiredReplicas;

        const cronSchedule = (item.spec as { schedule?: string })?.schedule ?? '—';
        const lastSchedule =
          (item.status as { lastScheduleTime?: string })?.lastScheduleTime ?? t('dashboard.columns.never');
        const isSuspended = (item.spec as { suspend?: boolean })?.suspend ?? false;

        const ingressRules = (
          item.spec as {
            rules?: Array<{
              host?: string;
              http?: { paths?: Array<{ path?: string }> };
            }>;
          }
        )?.rules ?? [];
        const ingressHosts = ingressRules
          .map((r) => r.host)
          .filter(Boolean) as string[];
        const ingressPaths = ingressRules
          .flatMap((r) => r.http?.paths ?? [])
          .map((p) => p.path)
          .filter(Boolean) as string[];

        // Compute status indicator
        let dotClass = '';
        let statusLabel: React.ReactNode = null;
        if (pod) {
          // A healthy pod that has restarted keeps its green dot with an amber ring.
          dotClass =
            pod.tone === 'ok' && pod.restarts > 0
              ? 'status-dot bg-emerald-500 ring-1 ring-amber-400/50 ring-offset-2 ring-offset-white dark:ring-offset-slate-900'
              : STATUS_DOT[pod.tone];
          const containers = containerStates(item);
          statusLabel = (
            <span className="inline-flex items-center gap-2">
              {containers.length > 1 && <ContainerSquares containers={containers} />}
              <PodStatusBadge namespace={selectedNamespace} podName={name} status={pod} />
            </span>
          );
        } else if (activeTab === 'deployments') {
          if (desiredReplicas === 0) {
            dotClass = 'status-dot status-dot-idle';
            statusLabel = <Badge variant="default">{t('dashboard.status.scaledToZero')}</Badge>;
          } else if (allReplicasReady) {
            dotClass = 'status-dot status-dot-success';
            statusLabel = <Badge variant="success">{t('dashboard.status.available')}</Badge>;
          } else {
            dotClass = 'status-dot status-dot-warning';
            statusLabel = <Badge variant="warning">{t('dashboard.status.progressing')}</Badge>;
          }
        } else if (activeTab === 'daemonsets') {
          const dsStatus = (item.status as {
            desiredNumberScheduled?: number;
            numberReady?: number;
          }) ?? {};
          const desired = dsStatus.desiredNumberScheduled ?? 0;
          const ready = dsStatus.numberReady ?? 0;
          if (desired === 0) {
            dotClass = 'status-dot status-dot-idle';
            statusLabel = <Badge variant="default">{t('dashboard.status.noNodes')}</Badge>;
          } else if (ready >= desired) {
            dotClass = 'status-dot status-dot-success';
            statusLabel = <Badge variant="success">{t('dashboard.status.ready', { ready, desired })}</Badge>;
          } else {
            dotClass = 'status-dot status-dot-warning';
            statusLabel = <Badge variant="warning">{t('dashboard.status.ready', { ready, desired })}</Badge>;
          }
        } else if (activeTab === 'statefulsets') {
          const ssStatus = (item.status as { replicas?: number; readyReplicas?: number }) ?? {};
          const ssDesired = (item.spec as { replicas?: number })?.replicas ?? ssStatus.replicas ?? 0;
          const ssReady = ssStatus.readyReplicas ?? 0;
          if (ssDesired === 0) {
            dotClass = 'status-dot status-dot-idle';
            statusLabel = <Badge variant="default">{t('dashboard.status.scaledToZero')}</Badge>;
          } else if (ssReady >= ssDesired) {
            dotClass = 'status-dot status-dot-success';
            statusLabel = <Badge variant="success">{t('dashboard.status.availableCount', { ready: ssReady, desired: ssDesired })}</Badge>;
          } else {
            dotClass = 'status-dot status-dot-warning';
            statusLabel = <Badge variant="warning">{t('dashboard.status.progressingCount', { ready: ssReady, desired: ssDesired })}</Badge>;
          }
        } else if (activeTab === 'hpas') {
          const hpaStatus = (item.status as {
            currentReplicas?: number;
            desiredReplicas?: number;
          }) ?? {};
          const hpaMin = (item.spec as { minReplicas?: number })?.minReplicas;
          const hpaMax = (item.spec as { maxReplicas?: number })?.maxReplicas ?? 0;
          dotClass = 'status-dot status-dot-success';
          statusLabel = (
            <Badge variant="info">
              {hpaStatus.currentReplicas ?? 0}/{hpaStatus.desiredReplicas ?? 0}
              {' · '}
              {hpaMin ?? 1}–{hpaMax}
            </Badge>
          );
        } else if (activeTab === 'cronjobs') {
          dotClass = isSuspended ? 'status-dot status-dot-warning' : 'status-dot status-dot-success';
          statusLabel = isSuspended ? (
            <Badge variant="warning">{t('dashboard.status.suspended')}</Badge>
          ) : (
            <Badge variant="success">{t('dashboard.status.active')}</Badge>
          );
        } else if (activeTab === 'jobs') {
          const jobStatus = (item.status as {
            succeeded?: number;
            failed?: number;
            active?: number;
            completionTime?: string;
          }) ?? {};
          const succeeded = jobStatus.succeeded ?? 0;
          const failed = jobStatus.failed ?? 0;
          const activeCount = jobStatus.active ?? 0;
          if (failed > 0) {
            dotClass = 'status-dot status-dot-error';
            statusLabel = <Badge variant="error">{t('dashboard.status.failedN', { count: failed })}</Badge>;
          } else if (activeCount > 0) {
            dotClass = 'status-dot status-dot-warning';
            statusLabel = <Badge variant="warning">{t('dashboard.status.runningN', { count: activeCount })}</Badge>;
          } else if (succeeded > 0) {
            dotClass = 'status-dot status-dot-success';
            statusLabel = <Badge variant="success">{t('dashboard.status.succeeded')}</Badge>;
          } else {
            dotClass = 'status-dot status-dot-idle';
            statusLabel = <Badge variant="default">{t('dashboard.status.pending')}</Badge>;
          }
        }

        // A workload whose pods are failing says so, whatever its rollout status.
        const failingPods = isWorkloadTab ? failingByOwner.get(`${KIND[activeTab as WorkloadKind]}/${name}`) ?? 0 : 0;
        if (failingPods > 0) {
          dotClass = STATUS_DOT.error;
          statusLabel = (
            <span className="inline-flex items-center gap-1 whitespace-nowrap">
              {statusLabel}
              <Badge variant="error">{t('dashboard.detail.podsFailing', { count: failingPods })}</Badge>
            </span>
          );
        }
        const showDot = ['pods', 'deployments', 'daemonsets', 'statefulsets', 'hpas', 'cronjobs', 'jobs'].includes(activeTab);
        const createdAt = (item.metadata as { creationTimestamp?: string })?.creationTimestamp;

        return (
          <div
            key={uid}
            className="group relative flex [contain-intrinsic-size:auto_180px] [content-visibility:auto] flex-col gap-3 rounded-xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-slate-900 p-4 shadow-card transition-all duration-150 hover:-translate-y-[1px] hover:border-brand-200 dark:border-brand-500/30 hover:shadow-elevated"
          >
            <div className="flex items-center justify-between gap-2">
              <div className="flex min-w-0 flex-1 items-center gap-2">
                {showDot && <span className={`shrink-0 ${dotClass}`} />}
                {activeTab === 'pods' || isWorkloadTab ? (
                  <button
                    type="button"
                    onClick={() => onOpen(item)}
                    className="truncate rounded font-mono text-[13px] font-semibold text-slate-900 underline-offset-2 hover:text-brand-700 hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 dark:text-slate-100 dark:hover:text-brand-300"
                    title={name}
                  >
                    {name}
                  </button>
                ) : (
                  <span
                    className="truncate font-mono text-[13px] font-semibold text-slate-900 dark:text-slate-100"
                    title={name}
                  >
                    {name}
                  </span>
                )}
              </div>
              <div className="shrink-0 whitespace-nowrap">{statusLabel}</div>
            </div>

            <div className="flex flex-col gap-1 text-[11px] text-slate-500 dark:text-slate-400">
              <div className="flex items-center gap-1.5">
                <Calendar size={11} className="text-slate-500 dark:text-slate-400" />
                <span>{formatAge(createdAt)}</span>
              </div>

              {pod && (
                <div className="flex items-center gap-1.5">
                  <RefreshCw size={11} className="text-slate-500 dark:text-slate-400" />
                  <span>{t('dashboard.columns.restarts')}:</span>
                  <PodRestarts status={pod} />
                </div>
              )}
              {pod && podController(item) && (() => {
                const c = podController(item)!;
                return (
                  <div className="flex items-center gap-1.5">
                    <Link2 size={11} className="text-slate-500 dark:text-slate-400" />
                    <span>{t('dashboard.columns.controlledBy')}:</span>
                    <span className="font-mono text-slate-700 dark:text-slate-200" title={`${c.kind} ${c.name}`}>
                      {c.kind}
                    </span>
                  </div>
                );
              })()}
              {metrics?.available && (activeTab === 'pods' || isWorkloadTab) && (() => {
                const owner = isWorkloadTab ? `${KIND[activeTab as WorkloadKind]}/${name}` : '';
                const used = activeTab === 'pods' ? usageOf(name) : ownerUsage(metrics.items, owner);
                const budget =
                  activeTab === 'pods'
                    ? podResources((item.spec as any)?.containers)
                    : scaleResources(
                        podResources((item.spec as any)?.template?.spec?.containers),
                        ownerUsage(metrics.items, owner).pods,
                      );
                if (!used || (isWorkloadTab && !(used as { pods: number }).pods)) return null;
                return (
                  <div className="grid grid-cols-2 gap-3 pt-0.5">
                    <UsageBar kind="cpu" used={used.cpu} limit={budget.cpu.limit} request={budget.cpu.request} />
                    <UsageBar kind="mem" used={used.memory} limit={budget.mem.limit} request={budget.mem.request} />
                  </div>
                );
              })()}
              {activeTab === 'deployments' && (
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="rounded-md bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-200">
                    desired {desiredReplicas}
                  </span>
                  <span className="rounded-md bg-emerald-50 px-1.5 py-0.5 font-mono text-[10px] text-emerald-700 ring-1 ring-inset ring-emerald-200">
                    ready {readyReplicas}
                  </span>
                  <span className="rounded-md bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-200">
                    available {(item.status as { availableReplicas?: number })?.availableReplicas ?? 0}
                  </span>
                </div>
              )}
              {activeTab === 'ingresses' && (
                <>
                  <div className="truncate">
                    <span className="text-slate-500 dark:text-slate-400">{t('dashboard.columns.hosts')}:</span>{' '}
                    <span className="font-mono text-slate-700 dark:text-slate-200">
                      {ingressHosts.length > 0 ? ingressHosts.join(', ') : '—'}
                    </span>
                  </div>
                  <div className="truncate">
                    <span className="text-slate-500 dark:text-slate-400">{t('dashboard.columns.paths')}:</span>{' '}
                    <span className="font-mono text-slate-700 dark:text-slate-200">
                      {ingressPaths.length > 0 ? ingressPaths.join(', ') : '—'}
                    </span>
                  </div>
                </>
              )}
              {activeTab === 'secrets' && (
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="truncate rounded-md bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                    {String(item.type ?? '')}
                  </span>
                  <span>{t('secrets.keyCount', { count: ((item.keys as unknown[]) ?? []).length })}</span>
                </div>
              )}
              {activeTab === 'cronjobs' && (
                <>
                  <div>
                    <span className="text-slate-500 dark:text-slate-400">{t('dashboard.columns.schedule')}:</span>{' '}
                    <span className="font-mono text-slate-700 dark:text-slate-200">{cronSchedule}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 dark:text-slate-400">{t('dashboard.columns.lastRun')}:</span>{' '}
                    <span className="font-mono text-slate-700 dark:text-slate-200">{lastSchedule}</span>
                  </div>
                </>
              )}
              {activeTab === 'jobs' && (() => {
                const spec = (item.spec as { completions?: number; parallelism?: number; backoffLimit?: number }) ?? {};
                const st = (item.status as {
                  succeeded?: number; failed?: number; active?: number;
                  startTime?: string; completionTime?: string;
                }) ?? {};
                return (
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span className="rounded-md bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-200">
                      completions {st.succeeded ?? 0}/{spec.completions ?? 1}
                    </span>
                    {(st.active ?? 0) > 0 && (
                      <span className="rounded-md bg-amber-50 px-1.5 py-0.5 font-mono text-[10px] text-amber-800 ring-1 ring-inset ring-amber-200">
                        active {st.active}
                      </span>
                    )}
                    {(st.failed ?? 0) > 0 && (
                      <span className="rounded-md bg-rose-50 px-1.5 py-0.5 font-mono text-[10px] text-rose-700 ring-1 ring-inset ring-rose-200">
                        failed {st.failed}
                      </span>
                    )}
                    {st.completionTime && (
                      <span className="text-slate-500 dark:text-slate-400">
                        done {st.completionTime}
                      </span>
                    )}
                  </div>
                );
              })()}
            </div>

            <div className="mt-auto flex flex-wrap gap-2 pt-1">
              {activeTab === 'pods' && (
                <>
                  {openLogModal && (
                    <Button variant="outline" size="sm" onClick={() => openLogModal(selectedNamespace, name)}>
                      <Terminal size={13} />
                      {t('dashboard.actions.logs')}
                    </Button>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => openEventsModal('pods', selectedNamespace, name)}
                  >
                    <Activity size={13} />
                    {t('dashboard.actions.events')}
                  </Button>
                  {canExecPods && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={(e) => onExec(item, e.currentTarget)}
                    >
                      <Terminal size={13} />
                      {t('dashboard.actions.shell')}
                    </Button>
                  )}
                </>
              )}
              {activeTab === 'deployments' && (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => openYamlModal('deployments', selectedNamespace, name)}
                  >
                    <FileCode2 size={13} />
                    {t('dashboard.actions.yaml')}
                  </Button>
                  {openDeploymentLogs && (
                    <Button variant="outline" size="sm" onClick={() => openDeploymentLogs(selectedNamespace, name)}>
                      <Terminal size={13} />
                      {t('dashboard.actions.logs')}
                    </Button>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      openEventsModal('deployments', selectedNamespace, name)
                    }
                  >
                    <Activity size={13} />
                    {t('dashboard.actions.events')}
                  </Button>
                  {canScaleDeployments && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => onScale(name, desiredReplicas)}
                    >
                      <Scaling size={13} />
                      {t('dashboard.actions.scale')}
                    </Button>
                  )}
                  {canRestartDeployments && (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={actionBusy === `restart:${name}`}
                      onClick={() => onRestart(name)}
                    >
                      <RotateCcw size={13} />
                      {actionBusy === `restart:${name}` ? t('dashboard.actions.restarting') : t('dashboard.actions.restart')}
                    </Button>
                  )}
                </>
              )}
              {activeTab === 'daemonsets' && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => openYamlModal('daemonsets', selectedNamespace, name)}
                >
                  <FileCode2 size={13} />
                  {t('dashboard.actions.yaml')}
                </Button>
              )}
              {activeTab === 'statefulsets' && (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => openYamlModal('statefulsets', selectedNamespace, name)}
                  >
                    <FileCode2 size={13} />
                    {t('dashboard.actions.yaml')}
                  </Button>
                  {canScaleStatefulSets && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => onScaleStatefulSet(name, ((item.spec as { replicas?: number })?.replicas) ?? 0)}
                    >
                      <Scaling size={13} />
                      {t('dashboard.actions.scale')}
                    </Button>
                  )}
                </>
              )}
              {activeTab === 'hpas' && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => openYamlModal('hpas', selectedNamespace, name)}
                >
                  <FileCode2 size={13} />
                  {t('dashboard.actions.yaml')}
                </Button>
              )}
              {activeTab === 'services' && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => openYamlModal('services', selectedNamespace, name)}
                >
                  <FileCode2 size={13} />
                  {t('dashboard.actions.yaml')}
                </Button>
              )}
              {activeTab === 'ingresses' && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => openYamlModal('ingresses', selectedNamespace, name)}
                >
                  <FileCode2 size={13} />
                  {t('dashboard.actions.yaml')}
                </Button>
              )}
              {activeTab === 'configmaps' && (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => openConfigMapDataModal(selectedNamespace, name)}
                  >
                    <FileText size={13} />
                    {t('dashboard.actions.data')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => openYamlModal('configmaps', selectedNamespace, name)}
                  >
                    <FileCode2 size={13} />
                    {t('dashboard.actions.yaml')}
                  </Button>
                </>
              )}
              {activeTab === 'secrets' && (
                <>
                  <Button variant="outline" size="sm" onClick={() => openSecretModal(name)}>
                    <KeyRound size={13} />
                    {t('secrets.keys')}
                  </Button>
                  {/* The YAML carries every value, so it is gated on edit, not get. */}
                  {canEditSecrets && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openYamlModal('secrets', selectedNamespace, name)}
                    >
                      <FileCode2 size={13} />
                      {t('dashboard.actions.yaml')}
                    </Button>
                  )}
                </>
              )}
              {activeTab === 'cronjobs' && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => openYamlModal('cronjobs', selectedNamespace, name)}
                >
                  <FileCode2 size={13} />
                  {t('dashboard.actions.yaml')}
                </Button>
              )}
              {activeTab === 'jobs' && (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => openYamlModal('jobs', selectedNamespace, name)}
                  >
                    <FileCode2 size={13} />
                    {t('dashboard.actions.yaml')}
                  </Button>
                  {openJobLogs && (
                    <Button variant="outline" size="sm" onClick={() => openJobLogs(selectedNamespace, name)}>
                      <Terminal size={13} />
                      {t('dashboard.actions.logs')}
                    </Button>
                  )}
                </>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};
