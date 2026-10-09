import React from 'react';
import {
  Activity,
  FileCode2,
  FileText,
  KeyRound,
  RotateCcw,
  Scaling,
  Terminal,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge } from '../../components/ui';
import { PodNotReadyBadge } from '../../components/PodNotReadyBadge';
import { Column, DataTable, IconButton } from '../../components/DataTable';
import { ageShort } from '../../utils/age';

type Item = Record<string, unknown>;

type Props = {
  activeTab: string;
  items: Item[];
  selectedNamespace: string;
  searchQuery: string;
  loading: boolean;
  canExecPods: boolean;
  canRestartDeployments: boolean;
  canScaleDeployments: boolean;
  canScaleStatefulSets: boolean;
  openYamlModal: (type: string, ns: string, name: string) => void | Promise<void>;
  openEventsModal: (type: 'pods' | 'deployments', ns: string, name: string) => void | Promise<void>;
  openLogModal: (ns: string, name: string) => void;
  openConfigMapDataModal: (ns: string, name: string) => void | Promise<void>;
  openSecretModal: (name: string) => void;
  canEditSecrets: boolean;
  openDeploymentLogs: (ns: string, name: string) => void;
  openJobLogs: (ns: string, name: string) => void;
  onExec: (name: string, containers: string[]) => void;
  onRestart: (name: string) => void;
  onScale: (name: string, current: number) => void;
  onScaleStatefulSet: (name: string, current: number) => void;
};

const nameOf = (item: Item) => ((item.metadata as any)?.name as string) ?? 'Unnamed';
const createdAt = (item: Item) => (item.metadata as any)?.creationTimestamp as string | undefined;

export const ResourceListView: React.FC<Props> = ({
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
  openConfigMapDataModal,
  openSecretModal,
  canEditSecrets,
  openDeploymentLogs,
  openJobLogs,
  onExec,
  onRestart,
  onScale,
  onScaleStatefulSet,
}) => {
  const { t } = useTranslation();
  // Column assembly per-tab. Name always left; actions always right; age is
  // the last data column before actions so it's where operators expect it.
  const columns: Column<Item>[] = React.useMemo(() => {
    const nameCol: Column<Item> = {
      key: 'name',
      header: 'Name',
      sortValue: (it) => nameOf(it).toLowerCase(),
      cell: (it) => (
        <span className="truncate font-mono text-[12.5px] font-medium text-slate-900 dark:text-slate-100">
          {nameOf(it)}
        </span>
      ),
    };
    const ageCol: Column<Item> = {
      key: 'age',
      header: 'Age',
      align: 'right',
      width: '80px',
      // Age sort uses creationTimestamp parsed to epoch ms, so "newer first"
      // works for free. Falls back to 0 when the field is absent.
      sortValue: (it) => {
        const ts = createdAt(it);
        return ts ? Date.parse(ts) : 0;
      },
      cell: (it) => (
        <span
          className="font-mono text-xs text-slate-500 dark:text-slate-400"
          title={createdAt(it) ?? ''}
        >
          {ageShort(createdAt(it))}
        </span>
      ),
    };

    if (activeTab === 'pods') {
      return [
        nameCol,
        {
          key: 'status',
          header: 'Status',
          sortValue: (it) => {
            const cs = ((it.status as any)?.containerStatuses as Array<{ ready?: boolean }>) ?? [];
            const allReady = cs.length > 0 && cs.every((c) => c.ready);
            const running = (it.status as any)?.phase === 'Running';
            return allReady && running ? 1 : 0;
          },
          cell: (it) => {
            const cs =
              ((it.status as any)?.containerStatuses as Array<{ ready?: boolean }>) ?? [];
            const allReady = cs.length > 0 && cs.every((c) => c.ready);
            const running = (it.status as any)?.phase === 'Running';
            const healthy = allReady && running;
            if (healthy) return <Badge variant="success">{t("dashboard.status.running")}</Badge>;
            return (
              <PodNotReadyBadge namespace={selectedNamespace} podName={nameOf(it)} />
            );
          },
        },
        {
          key: 'ready',
          header: 'Ready',
          align: 'center',
          width: '80px',
          sortValue: (it) => {
            const cs = ((it.status as any)?.containerStatuses as Array<{ ready?: boolean }>) ?? [];
            return cs.filter((c) => c.ready).length;
          },
          cell: (it) => {
            const cs = ((it.status as any)?.containerStatuses as Array<{ ready?: boolean }>) ?? [];
            const ready = cs.filter((c) => c.ready).length;
            return (
              <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
                {ready}/{cs.length}
              </span>
            );
          },
        },
        {
          key: 'restarts',
          header: 'Restarts',
          align: 'center',
          width: '90px',
          sortValue: (it) => {
            const cs = ((it.status as any)?.containerStatuses as Array<{ restartCount?: number }>) ?? [];
            return cs.reduce((s, c) => s + (c.restartCount ?? 0), 0);
          },
          cell: (it) => {
            const cs = ((it.status as any)?.containerStatuses as Array<{ restartCount?: number }>) ?? [];
            const r = cs.reduce((s, c) => s + (c.restartCount ?? 0), 0);
            return (
              <span
                className={`font-mono text-xs ${
                  r > 0 ? 'text-amber-600 dark:text-amber-300' : 'text-slate-500 dark:text-slate-400'
                }`}
              >
                {r}
              </span>
            );
          },
        },
        ageCol,
        {
          key: 'actions',
          header: '',
          align: 'right',
          width: canExecPods ? '140px' : '100px',
          cell: (it) => {
            const name = nameOf(it);
            const containers = (((it.spec as any)?.containers as Array<{ name?: string }>) ?? [])
              .map((c) => c.name)
              .filter(Boolean) as string[];
            return (
              <div className="flex justify-end gap-1">
                <IconButton label="Logs" onClick={() => openLogModal(selectedNamespace, name)}>
                  <Terminal size={13} />
                </IconButton>
                <IconButton label="Events" onClick={() => openEventsModal('pods', selectedNamespace, name)}>
                  <Activity size={13} />
                </IconButton>
                {canExecPods && (
                  <IconButton label="Shell" onClick={() => onExec(name, containers)}>
                    <Terminal size={13} />
                  </IconButton>
                )}
              </div>
            );
          },
        },
      ];
    }

    if (activeTab === 'deployments') {
      return [
        nameCol,
        {
          key: 'status',
          header: 'Status',
          width: '130px',
          sortValue: (it) => {
            const desired = ((it.spec as any)?.replicas as number) ?? 0;
            const ready = ((it.status as any)?.readyReplicas as number) ?? 0;
            if (desired === 0) return 0;
            if (ready >= desired) return 2;
            return 1;
          },
          cell: (it) => {
            const desired = ((it.spec as any)?.replicas as number) ?? 0;
            const ready = ((it.status as any)?.readyReplicas as number) ?? 0;
            if (desired === 0) return <Badge variant="default">{t("dashboard.status.scaledToZero")}</Badge>;
            if (ready >= desired) return <Badge variant="success">{t("dashboard.status.available")}</Badge>;
            return <Badge variant="warning">{t("dashboard.status.progressing")}</Badge>;
          },
        },
        {
          key: 'replicas',
          header: 'Replicas',
          align: 'center',
          // Wider than before and the subtitle is a second small line so a
          // 10/10 count on a 1920px screen still fits on one row.
          width: '140px',
          sortValue: (it) => ((it.spec as any)?.replicas as number) ?? 0,
          cell: (it) => {
            const desired = ((it.spec as any)?.replicas as number) ?? 0;
            const ready = ((it.status as any)?.readyReplicas as number) ?? 0;
            const avail = ((it.status as any)?.availableReplicas as number) ?? 0;
            return (
              <div className="flex flex-col items-center leading-tight">
                <span className="font-mono text-xs text-slate-700 dark:text-slate-200 whitespace-nowrap">
                  {ready}/{desired}
                </span>
                <span className="font-mono text-[10px] text-slate-500 dark:text-slate-400 whitespace-nowrap">
                  {avail} avail
                </span>
              </div>
            );
          },
        },
        ageCol,
        {
          key: 'actions',
          header: '',
          align: 'right',
          width: '160px',
          cell: (it) => {
            const name = nameOf(it);
            const desired = ((it.spec as any)?.replicas as number) ?? 0;
            return (
              <div className="flex justify-end gap-1">
                <IconButton label="YAML" onClick={() => openYamlModal('deployments', selectedNamespace, name)}>
                  <FileCode2 size={13} />
                </IconButton>
                <IconButton label="Logs" onClick={() => openDeploymentLogs(selectedNamespace, name)}>
                  <Terminal size={13} />
                </IconButton>
                <IconButton label="Events" onClick={() => openEventsModal('deployments', selectedNamespace, name)}>
                  <Activity size={13} />
                </IconButton>
                {canScaleDeployments && (
                  <IconButton label="Scale" onClick={() => onScale(name, desired)}>
                    <Scaling size={13} />
                  </IconButton>
                )}
                {canRestartDeployments && (
                  <IconButton label="Restart" onClick={() => onRestart(name)}>
                    <RotateCcw size={13} />
                  </IconButton>
                )}
              </div>
            );
          },
        },
      ];
    }

    if (activeTab === 'services') {
      return [
        nameCol,
        {
          key: 'type',
          header: 'Type',
          sortValue: (it) => (((it.spec as any)?.type as string) ?? '').toLowerCase(),
          cell: (it) => (
            <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
              {((it.spec as any)?.type as string) ?? '—'}
            </span>
          ),
        },
        {
          key: 'cluster-ip',
          header: 'Cluster IP',
          sortValue: (it) => ((it.spec as any)?.clusterIP as string) ?? '',
          cell: (it) => (
            <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
              {((it.spec as any)?.clusterIP as string) ?? '—'}
            </span>
          ),
        },
        {
          key: 'ports',
          header: 'Ports',
          cell: (it) => {
            const ports = ((it.spec as any)?.ports as Array<{ port?: number; protocol?: string }>) ?? [];
            if (ports.length === 0) return <span className="text-xs text-slate-400">—</span>;
            return (
              <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
                {ports.map((p) => `${p.port}/${p.protocol ?? 'TCP'}`).join(', ')}
              </span>
            );
          },
        },
        ageCol,
        {
          key: 'actions',
          header: '',
          align: 'right',
          width: '60px',
          cell: (it) => (
            <div className="flex justify-end gap-1">
              <IconButton label="YAML" onClick={() => openYamlModal('services', selectedNamespace, nameOf(it))}>
                <FileCode2 size={13} />
              </IconButton>
            </div>
          ),
        },
      ];
    }

    if (activeTab === 'configmaps') {
      return [
        nameCol,
        {
          key: 'keys',
          header: 'Keys',
          align: 'center',
          width: '80px',
          sortValue: (it) => Object.keys(((it.data as Record<string, string>) ?? {})).length,
          cell: (it) => {
            const data = (it.data as Record<string, string>) ?? {};
            return (
              <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
                {Object.keys(data).length}
              </span>
            );
          },
        },
        ageCol,
        {
          key: 'actions',
          header: '',
          align: 'right',
          width: '100px',
          cell: (it) => (
            <div className="flex justify-end gap-1">
              <IconButton
                label="Data"
                onClick={() => openConfigMapDataModal(selectedNamespace, nameOf(it))}
              >
                <FileText size={13} />
              </IconButton>
              <IconButton
                label="YAML"
                onClick={() => openYamlModal('configmaps', selectedNamespace, nameOf(it))}
              >
                <FileCode2 size={13} />
              </IconButton>
            </div>
          ),
        },
      ];
    }

    if (activeTab === 'secrets') {
      return [
        nameCol,
        {
          key: 'type',
          header: t('secrets.type'),
          sortValue: (it) => String(it.type ?? ''),
          cell: (it) => (
            <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{String(it.type ?? '')}</span>
          ),
        },
        {
          key: 'keys',
          header: t('secrets.keys'),
          align: 'center',
          width: '80px',
          sortValue: (it) => ((it.keys as unknown[]) ?? []).length,
          cell: (it) => (
            <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
              {((it.keys as unknown[]) ?? []).length}
            </span>
          ),
        },
        ageCol,
        {
          key: 'actions',
          header: '',
          align: 'right',
          width: '90px',
          cell: (it) => (
            <div className="flex justify-end gap-1">
              <IconButton label={t('secrets.keys')} onClick={() => openSecretModal(nameOf(it))}>
                <KeyRound size={13} />
              </IconButton>
              {canEditSecrets && (
                <IconButton label="YAML" onClick={() => openYamlModal('secrets', selectedNamespace, nameOf(it))}>
                  <FileCode2 size={13} />
                </IconButton>
              )}
            </div>
          ),
        },
      ];
    }

    if (activeTab === 'ingresses') {
      return [
        nameCol,
        {
          key: 'hosts',
          header: 'Hosts',
          cell: (it) => {
            const rules = ((it.spec as any)?.rules as Array<{ host?: string }>) ?? [];
            const hosts = rules.map((r) => r.host).filter(Boolean) as string[];
            if (hosts.length === 0) return <span className="text-xs text-slate-400">—</span>;
            return (
              <span className="truncate font-mono text-xs text-slate-500 dark:text-slate-400" title={hosts.join(', ')}>
                {hosts.join(', ')}
              </span>
            );
          },
        },
        {
          key: 'paths',
          header: 'Paths',
          cell: (it) => {
            const rules = ((it.spec as any)?.rules as Array<{ http?: { paths?: Array<{ path?: string }> } }>) ?? [];
            const paths = rules.flatMap((r) => r.http?.paths ?? []).map((p) => p.path).filter(Boolean) as string[];
            if (paths.length === 0) return <span className="text-xs text-slate-400">—</span>;
            return (
              <span className="truncate font-mono text-xs text-slate-500 dark:text-slate-400" title={paths.join(', ')}>
                {paths.join(', ')}
              </span>
            );
          },
        },
        ageCol,
        {
          key: 'actions',
          header: '',
          align: 'right',
          width: '60px',
          cell: (it) => (
            <div className="flex justify-end gap-1">
              <IconButton label="YAML" onClick={() => openYamlModal('ingresses', selectedNamespace, nameOf(it))}>
                <FileCode2 size={13} />
              </IconButton>
            </div>
          ),
        },
      ];
    }

    if (activeTab === 'cronjobs') {
      return [
        nameCol,
        {
          key: 'schedule',
          header: 'Schedule',
          sortValue: (it) => ((it.spec as any)?.schedule as string) ?? '',
          cell: (it) => (
            <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
              {((it.spec as any)?.schedule as string) ?? '—'}
            </span>
          ),
        },
        {
          key: 'last',
          header: 'Last run',
          sortValue: (it) => {
            const t = (it.status as any)?.lastScheduleTime as string | undefined;
            return t ? Date.parse(t) : 0;
          },
          cell: (it) => (
            <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
              {((it.status as any)?.lastScheduleTime as string) ?? 'Never'}
            </span>
          ),
        },
        {
          key: 'suspended',
          header: 'Status',
          align: 'center',
          width: '110px',
          sortValue: (it) => (((it.spec as any)?.suspend as boolean) ? 0 : 1),
          cell: (it) =>
            ((it.spec as any)?.suspend as boolean) ? (
              <Badge variant="warning">{t("dashboard.status.suspended")}</Badge>
            ) : (
              <Badge variant="success">{t("dashboard.status.active")}</Badge>
            ),
        },
        ageCol,
        {
          key: 'actions',
          header: '',
          align: 'right',
          width: '60px',
          cell: (it) => (
            <div className="flex justify-end gap-1">
              <IconButton label="YAML" onClick={() => openYamlModal('cronjobs', selectedNamespace, nameOf(it))}>
                <FileCode2 size={13} />
              </IconButton>
            </div>
          ),
        },
      ];
    }

    if (activeTab === 'jobs') {
      return [
        nameCol,
        {
          key: 'status',
          header: 'Status',
          width: '130px',
          sortValue: (it) => {
            const st = (it.status as any) ?? {};
            if ((st.failed ?? 0) > 0) return 0;
            if ((st.active ?? 0) > 0) return 1;
            if ((st.succeeded ?? 0) > 0) return 3;
            return 2;
          },
          cell: (it) => {
            const st = (it.status as any) ?? {};
            const succeeded = (st.succeeded as number) ?? 0;
            const failed = (st.failed as number) ?? 0;
            const active = (st.active as number) ?? 0;
            if (failed > 0) return <Badge variant="error">{t("dashboard.status.failedN", { count: failed })}</Badge>;
            if (active > 0) return <Badge variant="warning">{t("dashboard.status.runningN", { count: active })}</Badge>;
            if (succeeded > 0) return <Badge variant="success">{t("dashboard.status.succeeded")}</Badge>;
            return <Badge variant="default">{t("dashboard.status.pending")}</Badge>;
          },
        },
        {
          key: 'completions',
          header: 'Completions',
          align: 'center',
          width: '120px',
          sortValue: (it) => ((it.status as any)?.succeeded as number) ?? 0,
          cell: (it) => {
            const succeeded = ((it.status as any)?.succeeded as number) ?? 0;
            const want = ((it.spec as any)?.completions as number) ?? 1;
            return (
              <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
                {succeeded}/{want}
              </span>
            );
          },
        },
        ageCol,
        {
          key: 'actions',
          header: '',
          align: 'right',
          width: '100px',
          cell: (it) => (
            <div className="flex justify-end gap-1">
              <IconButton label="YAML" onClick={() => openYamlModal('jobs', selectedNamespace, nameOf(it))}>
                <FileCode2 size={13} />
              </IconButton>
              <IconButton label="Logs" onClick={() => openJobLogs(selectedNamespace, nameOf(it))}>
                <Terminal size={13} />
              </IconButton>
            </div>
          ),
        },
      ];
    }

    if (activeTab === 'daemonsets') {
      return [
        nameCol,
        {
          key: 'status',
          header: 'Status',
          width: '130px',
          sortValue: (it) => {
            const desired = ((it.status as any)?.desiredNumberScheduled as number) ?? 0;
            const ready = ((it.status as any)?.numberReady as number) ?? 0;
            if (desired === 0) return 0;
            if (ready >= desired) return 2;
            return 1;
          },
          cell: (it) => {
            const desired = ((it.status as any)?.desiredNumberScheduled as number) ?? 0;
            const ready = ((it.status as any)?.numberReady as number) ?? 0;
            if (desired === 0) return <Badge variant="default">{t("dashboard.status.noNodes")}</Badge>;
            if (ready >= desired) return <Badge variant="success">{t("dashboard.status.ready", { ready, desired })}</Badge>;
            return <Badge variant="warning">{t("dashboard.status.ready", { ready, desired })}</Badge>;
          },
        },
        {
          key: 'nodes',
          header: 'Nodes',
          align: 'center',
          width: '110px',
          sortValue: (it) => ((it.status as any)?.desiredNumberScheduled as number) ?? 0,
          cell: (it) => {
            const desired = ((it.status as any)?.desiredNumberScheduled as number) ?? 0;
            const current = ((it.status as any)?.currentNumberScheduled as number) ?? 0;
            return (
              <span className="font-mono text-xs text-slate-700 dark:text-slate-200">
                {current}/{desired}
              </span>
            );
          },
        },
        ageCol,
        {
          key: 'actions',
          header: '',
          align: 'right',
          width: '70px',
          cell: (it) => (
            <div className="flex justify-end gap-1">
              <IconButton label="YAML" onClick={() => openYamlModal('daemonsets', selectedNamespace, nameOf(it))}>
                <FileCode2 size={13} />
              </IconButton>
            </div>
          ),
        },
      ];
    }

    if (activeTab === 'statefulsets') {
      return [
        nameCol,
        {
          key: 'status',
          header: 'Status',
          width: '140px',
          sortValue: (it) => {
            const desired = ((it.spec as any)?.replicas as number) ?? 0;
            const ready = ((it.status as any)?.readyReplicas as number) ?? 0;
            if (desired === 0) return 0;
            if (ready >= desired) return 2;
            return 1;
          },
          cell: (it) => {
            const desired = ((it.spec as any)?.replicas as number) ?? 0;
            const ready = ((it.status as any)?.readyReplicas as number) ?? 0;
            if (desired === 0) return <Badge variant="default">{t("dashboard.status.scaledToZero")}</Badge>;
            if (ready >= desired) return <Badge variant="success">{t("dashboard.status.availableCount", { ready, desired })}</Badge>;
            return <Badge variant="warning">{t("dashboard.status.progressingCount", { ready, desired })}</Badge>;
          },
        },
        {
          key: 'replicas',
          header: 'Replicas',
          align: 'center',
          width: '110px',
          sortValue: (it) => ((it.spec as any)?.replicas as number) ?? 0,
          cell: (it) => {
            const desired = ((it.spec as any)?.replicas as number) ?? 0;
            const ready = ((it.status as any)?.readyReplicas as number) ?? 0;
            return (
              <span className="font-mono text-xs text-slate-700 dark:text-slate-200 whitespace-nowrap">
                {ready}/{desired}
              </span>
            );
          },
        },
        ageCol,
        {
          key: 'actions',
          header: '',
          align: 'right',
          width: '110px',
          cell: (it) => {
            const name = nameOf(it);
            const desired = ((it.spec as any)?.replicas as number) ?? 0;
            return (
              <div className="flex justify-end gap-1">
                <IconButton label="YAML" onClick={() => openYamlModal('statefulsets', selectedNamespace, name)}>
                  <FileCode2 size={13} />
                </IconButton>
                {canScaleStatefulSets && (
                  <IconButton label="Scale" onClick={() => onScaleStatefulSet(name, desired)}>
                    <Scaling size={13} />
                  </IconButton>
                )}
              </div>
            );
          },
        },
      ];
    }

    if (activeTab === 'hpas') {
      return [
        nameCol,
        {
          key: 'target',
          header: 'Target',
          sortValue: (it) => {
            const ref = (it.spec as any)?.scaleTargetRef as { kind?: string; name?: string } | undefined;
            return `${ref?.kind ?? ''}/${ref?.name ?? ''}`.toLowerCase();
          },
          cell: (it) => {
            const ref = (it.spec as any)?.scaleTargetRef as { kind?: string; name?: string } | undefined;
            return (
              <span className="font-mono text-xs text-slate-700 dark:text-slate-200">
                {ref?.kind ?? '—'}/{ref?.name ?? '—'}
              </span>
            );
          },
        },
        {
          key: 'range',
          header: 'Min/Max',
          align: 'center',
          width: '110px',
          sortValue: (it) => ((it.spec as any)?.maxReplicas as number) ?? 0,
          cell: (it) => {
            const min = ((it.spec as any)?.minReplicas as number) ?? 1;
            const max = ((it.spec as any)?.maxReplicas as number) ?? 0;
            return (
              <span className="font-mono text-xs text-slate-700 dark:text-slate-200 whitespace-nowrap">
                {min}–{max}
              </span>
            );
          },
        },
        {
          key: 'current',
          header: 'Current',
          align: 'center',
          width: '110px',
          sortValue: (it) => ((it.status as any)?.currentReplicas as number) ?? 0,
          cell: (it) => {
            const cur = ((it.status as any)?.currentReplicas as number) ?? 0;
            const des = ((it.status as any)?.desiredReplicas as number) ?? 0;
            return (
              <span className="font-mono text-xs text-slate-700 dark:text-slate-200 whitespace-nowrap">
                {cur}/{des}
              </span>
            );
          },
        },
        ageCol,
        {
          key: 'actions',
          header: '',
          align: 'right',
          width: '70px',
          cell: (it) => (
            <div className="flex justify-end gap-1">
              <IconButton label="YAML" onClick={() => openYamlModal('hpas', selectedNamespace, nameOf(it))}>
                <FileCode2 size={13} />
              </IconButton>
            </div>
          ),
        },
      ];
    }

    return [nameCol, ageCol];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    activeTab,
    selectedNamespace,
    canExecPods,
    canRestartDeployments,
    canScaleDeployments,
    canScaleStatefulSets,
    canEditSecrets,
    t,
  ]);

  return (
    <div className="p-5">
      <DataTable
        rows={items}
        columns={columns}
        rowKey={(it) => nameOf(it) || JSON.stringify((it.metadata as any)?.uid ?? Math.random())}
        sortStorageKey={`dashboard:${activeTab}`}
        emptyMessage={
          loading
            ? 'Loading…'
            : searchQuery
            ? 'No matching records found.'
            : 'No records available.'
        }
      />
    </div>
  );
};

export default ResourceListView;
