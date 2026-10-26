import React from 'react';
import { FileCode2, History, Terminal } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Drawer } from '../../components/Drawer';
import { Button } from '../../components/ui';
import { PodStatusBadge } from '../../components/PodStatusBadge';
import { getPodEvents, getPodRestarts, getPodUsageHistory, type MetricsSnapshot, type WorkloadKind } from '../../services/api';
import { RestartHistory } from './RestartHistory';
import { UsageBar, UsageHistoryPanel } from '../../components/Usage';
import { parseCpu, parseMem } from '../../utils/format';
import { podResources } from '../../utils/resources';
import { ageShort } from '../../utils/age';
import { exitCodeHint, exitLabel, podOwner, podStatus, type Termination } from '../../utils/podStatus';
import { Conditions, Empty, Events, Fields, Section, type Item } from './DetailParts';

type Props = {
  pod: Item | null;
  namespace: string;
  canExec: boolean;
  onClose: () => void;
  onLogs: (name: string, previousContainer?: string) => void;
  onShell: (pod: Item, anchor: HTMLElement) => void;
  onYaml: (name: string) => void;
  /** Opens the owning Deployment's / StatefulSet's / DaemonSet's drawer. */
  onOpenOwner: (kind: WorkloadKind, name: string) => void;
  metrics: MetricsSnapshot | null;
};

const DRAWER_KIND: Record<string, WorkloadKind> = { Deployment: 'deployments', StatefulSet: 'statefulsets', DaemonSet: 'daemonsets' };

function probeText(p?: Item): string | undefined {
  if (!p) return undefined;
  if (p.httpGet) return `HTTP GET ${p.httpGet.path ?? '/'} :${p.httpGet.port}`;
  if (p.tcpSocket) return `TCP :${p.tcpSocket.port}`;
  if (p.grpc) return `gRPC :${p.grpc.port}`;
  if (p.exec) return `exec ${(p.exec.command ?? []).join(' ')}`;
  return undefined;
}

const TerminationBox: React.FC<{ term: Termination }> = ({ term }) => {
  const { t } = useTranslation();
  const hint = exitCodeHint(term);
  const crash = term.reason === 'OOMKilled' || (term.exitCode !== 0 && term.exitCode !== 143);
  return (
    <div
      className={`rounded-md px-2.5 py-1.5 text-xs ${
        crash
          ? 'bg-rose-50 text-rose-800 dark:bg-rose-500/10 dark:text-rose-200'
          : 'bg-slate-50 text-slate-700 dark:bg-slate-800/60 dark:text-slate-300'
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono font-semibold">
          {t('dashboard.detail.lastExit')}: {exitLabel(term)}
        </span>
        <span className="font-mono text-[10px]" title={term.finishedAt}>
          {t('dashboard.podStatus.ago', { age: ageShort(term.finishedAt) })}
        </span>
      </div>
      <p className="mt-0.5">{t(hint.key, { signal: hint.signal })}</p>
    </div>
  );
};

export const PodDrawer: React.FC<Props> = ({ pod, namespace, canExec, onClose, onLogs, onShell, onYaml, onOpenOwner, metrics }) => {
  const { t } = useTranslation();
  if (!pod) return null;
  const name: string = pod.metadata?.name ?? '';
  const status = podStatus(pod);
  const owner = podOwner(pod);
  const [ownerKind, ownerName] = owner ? owner.split('/') : [];
  const openable = owner ? DRAWER_KIND[ownerKind] : undefined;
  const specs: Item[] = [
    ...(pod.spec?.initContainers ?? []).map((c: Item) => ({ ...c, init: true })),
    ...(pod.spec?.containers ?? []),
  ];
  const statuses: Item[] = [...(pod.status?.initContainerStatuses ?? []), ...(pod.status?.containerStatuses ?? [])];
  const usage = metrics?.available ? metrics.items.find((p) => p.name === name) : undefined;
  const budget = podResources(pod.spec?.containers);

  return (
    <Drawer
      open
      onClose={onClose}
      width="lg"
      title={name}
      description={`${t('dashboard.detail.pod')} · ${namespace} · ${ageShort(pod.metadata?.creationTimestamp)}`}
      footer={
        <>
          <Button variant="outline" size="sm" onClick={() => onYaml(name)}>
            <FileCode2 size={13} />
            {t('dashboard.actions.yaml')}
          </Button>
          {status.lastTermination && (
            <Button variant="outline" size="sm" onClick={() => onLogs(name, status.lastTermination!.container)}>
              <History size={13} />
              {t('dashboard.detail.previousLogs')}
            </Button>
          )}
          {canExec && (
            <Button variant="outline" size="sm" onClick={(e) => onShell(pod, e.currentTarget)}>
              <Terminal size={13} />
              {t('dashboard.actions.shell')}
            </Button>
          )}
          <Button variant="primary" size="sm" onClick={() => onLogs(name)}>
            <Terminal size={13} />
            {t('dashboard.actions.logs')}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-6">
        <Section title={t('dashboard.detail.summary')}>
          <Fields
            rows={[
              [t('dashboard.detail.status'), <PodStatusBadge key="s" namespace={namespace} podName={name} status={status} />],
              [t('dashboard.detail.ready'), `${status.ready}/${status.total}`],
              [t('dashboard.detail.restarts'), String(status.restarts)],
              [t('dashboard.detail.node'), pod.spec?.nodeName],
              [t('dashboard.detail.podIP'), pod.status?.podIP],
              [t('dashboard.detail.qos'), pod.status?.qosClass],
              [
                t('dashboard.detail.owner'),
                openable ? (
                  <button
                    key="o"
                    type="button"
                    onClick={() => onOpenOwner(openable, ownerName)}
                    className="text-brand-600 underline-offset-2 hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 dark:text-brand-300"
                  >
                    {owner}
                  </button>
                ) : (
                  owner
                ),
              ],
            ]}
          />
        </Section>

        <Section title={t('dashboard.detail.containers')}>
          <div className="flex flex-col gap-3">
            {specs.map((c) => {
              const st = statuses.find((s) => s.name === c.name) ?? {};
              const term = status.containers.find((x) => x.name === c.name)?.lastTermination;
              const state = st.state ?? {};
              const stateText = state.running
                ? t('dashboard.detail.runningSince', { age: ageShort(state.running.startedAt) })
                : state.waiting
                  ? `${state.waiting.reason ?? 'Waiting'}${state.waiting.message ? `: ${state.waiting.message}` : ''}`
                  : state.terminated
                    ? `${state.terminated.reason ?? 'Terminated'} (${state.terminated.exitCode})`
                    : '—';
              const res = c.resources ?? {};
              const resText = (kind: 'requests' | 'limits') =>
                res[kind] ? `cpu ${res[kind].cpu ?? '—'} · mem ${res[kind].memory ?? '—'}` : t('dashboard.detail.notSet');
              return (
                <div key={c.name} className="flex flex-col gap-2 rounded-lg border border-slate-200 p-3 dark:border-slate-800">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[13px] font-semibold text-slate-900 dark:text-slate-100">
                      {c.name}
                      {c.init && (
                        <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                          init
                        </span>
                      )}
                    </span>
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      {st.ready ? '✓ ' : ''}
                      {t('dashboard.podStatus.restartsN', { count: st.restartCount ?? 0 })}
                    </span>
                  </div>
                  <Fields
                    rows={[
                      [t('dashboard.detail.image'), c.image],
                      [t('dashboard.detail.state'), stateText],
                      ...(usage?.containers[c.name]
                        ? ([
                            ['CPU', <UsageBar key="c" kind="cpu" used={usage.containers[c.name].cpu} limit={parseCpu(res.limits?.cpu)} request={parseCpu(res.requests?.cpu)} />],
                            [t('dashboard.usage.memory'), <UsageBar key="m" kind="mem" used={usage.containers[c.name].memory} limit={parseMem(res.limits?.memory)} request={parseMem(res.requests?.memory)} />],
                          ] as Array<[string, React.ReactNode]>)
                        : []),
                      [t('dashboard.detail.requests'), resText('requests')],
                      [t('dashboard.detail.limits'), resText('limits')],
                      ...(['livenessProbe', 'readinessProbe', 'startupProbe'] as const)
                        .filter((p) => c[p])
                        .map((p) => [t(`dashboard.detail.${p}`), probeText(c[p])] as [string, React.ReactNode]),
                    ]}
                  />
                  {term && <TerminationBox term={term} />}
                </div>
              );
            })}
            {!specs.length && <Empty>{t('dashboard.detail.none')}</Empty>}
          </div>
        </Section>

        {status.restarts > 0 && (
          <Section title={t('dashboard.restarts.title')}>
            <RestartHistory load={() => getPodRestarts(namespace, name)} reloadKey={`${name}:${status.restarts}`} showPod={false} />
          </Section>
        )}

        <Section title={t('dashboard.usage.title')}>
          {metrics && !metrics.available && metrics.reason && metrics.reason !== 'warming_up' && (
            <Empty>{t(`dashboard.usage.unavailable.${metrics.reason}`, { defaultValue: t('dashboard.usage.unavailable.error') })}</Empty>
          )}
          <UsageHistoryPanel
            load={(range) => getPodUsageHistory(namespace, name, range)}
            cpuLimit={budget.cpu.limit}
            memLimit={budget.mem.limit}
            reloadKey={`${name}:${metrics?.updatedAt}`}
          />
        </Section>

        <Section title={t('dashboard.detail.conditions')}>
          <Conditions items={pod.status?.conditions} />
        </Section>

        <Section title={t('dashboard.detail.events')}>
          <Events load={() => getPodEvents(namespace, name)} version={`${name}:${pod.metadata?.resourceVersion}`} />
        </Section>
      </div>
    </Drawer>
  );
};
