import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Drawer } from '../../components/Drawer';
import { Spinner } from '../../components/ui';
import { PodRestarts, PodStatusBadge } from '../../components/PodStatusBadge';
import { UsageHistoryPanel } from '../../components/Usage';
import { getNode, getNodeUsageHistory, type NodeDetail, type NodePod } from '../../services/api';
import { formatCpu, formatMem, parseCpu, parseMem } from '../../utils/format';
import { ageShort } from '../../utils/age';
import { podStatus, type PodLike } from '../../utils/podStatus';
import { openPod } from '../../utils/openDashboard';
import { Conditions, Empty, Events, Fields, Section } from '../dashboard/DetailParts';
import { NodeMeter, NodeStatus, pct } from './NodeParts';

const SEGMENT =
  'cursor-pointer rounded-md px-2 py-0.5 text-[11px] focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60';
const segment = (on: boolean) =>
  `${SEGMENT} ${on ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200' : 'text-slate-600 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-800'}`;

const Segmented = <T extends string>({ label, value, options, onChange }: {
  label: string;
  value: T;
  options: Array<[T, string]>;
  onChange: (v: T) => void;
}) => (
  <div role="group" aria-label={label} className="inline-flex rounded-lg border border-slate-200 p-0.5 dark:border-slate-700">
    {options.map(([k, text]) => (
      <button key={k} type="button" aria-pressed={value === k} onClick={() => onChange(k)} className={segment(value === k)}>
        {text}
      </button>
    ))}
  </div>
);

const podKey = (p: NodePod) => `${p.metadata?.namespace}/${p.metadata?.name}`;

/** Node detail; `tick` changes with every list refresh, which refetches quietly (not audited). */
export const NodeDrawer: React.FC<{ name: string; tick: string; onClose: () => void }> = ({ name, tick, onClose }) => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [data, setData] = useState<NodeDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [topBy, setTopBy] = useState<'cpu' | 'memory'>('cpu');
  const [podFilter, setPodFilter] = useState<'all' | 'problems'>('all');

  const opened = useRef<string | null>(null);
  useEffect(() => {
    let live = true;
    const auto = opened.current === name;
    if (!auto) setData(null);
    opened.current = name;
    getNode(name, auto)
      .then((d) => live && (setData(d), setError(null)))
      .catch((e: Error) => live && setError(e.message));
    return () => {
      live = false;
    };
  }, [name, tick]);

  const pods = useMemo(
    () => (data?.pods ?? []).map((p) => ({ p, st: podStatus(p as PodLike) })),
    [data],
  );
  const shown = podFilter === 'all' ? pods : pods.filter(({ st }) => st.tone === 'error' || st.tone === 'warn');
  const top = useMemo(
    () =>
      pods
        .filter(({ p }) => p.usage)
        .sort((a, b) => (b.p.usage![topBy] ?? 0) - (a.p.usage![topBy] ?? 0))
        .slice(0, 10),
    [pods, topBy],
  );

  const s = data?.summary;
  const node = data?.node ?? {};
  const info = node.status?.nodeInfo ?? {};
  const addr = (type: string) => (node.status?.addresses ?? []).find((a: { type: string }) => a.type === type)?.address;
  const cap = node.status?.capacity ?? {};
  const alloc = node.status?.allocatable ?? {};
  const topMax = Math.max(1, ...top.map(({ p }) => p.usage![topBy]));
  const fmtTop = topBy === 'cpu' ? formatCpu : formatMem;
  const go = (p: NodePod) => openPod(navigate, p.metadata?.namespace, p.metadata?.name);

  const resourceRows: Array<[string, React.ReactNode[]]> = s
    ? [
        ['CPU', [formatCpu(parseCpu(cap.cpu)), formatCpu(s.cpuAllocatable), formatCpu(s.cpuRequests), formatCpu(s.cpuLimits), s.cpu === undefined ? '—' : formatCpu(s.cpu)]],
        [t('dashboard.usage.memory'), [formatMem(parseMem(cap.memory)), formatMem(s.memoryAllocatable), formatMem(s.memoryRequests), formatMem(s.memoryLimits), s.memory === undefined ? '—' : formatMem(s.memory)]],
        [t('nodes.drawer.pods'), [cap.pods ?? '—', alloc.pods ?? '—', s.pods, '—', '—']],
        [t('nodes.drawer.ephemeral'), [cap['ephemeral-storage'] ? formatMem(parseMem(cap['ephemeral-storage'])) : '—', alloc['ephemeral-storage'] ? formatMem(parseMem(alloc['ephemeral-storage'])) : '—', '—', '—', '—']],
      ]
    : [];

  return (
    <Drawer open onClose={onClose} width="lg" title={name} description={s ? `${s.roles.join(', ') || t('nodes.noRole')} · ${ageShort(s.created)}` : undefined}>
      {error && !data ? (
        <Empty>{t('nodes.drawer.loadFailed', { error })}</Empty>
      ) : !data || !s ? (
        <Spinner size="md" />
      ) : (
        <div className="flex flex-col gap-6">
          <Section title={t('nodes.drawer.summary')}>
            <Fields
              rows={[
                [t('nodes.col.status'), <NodeStatus key="s" node={s} />],
                [t('nodes.col.roles'), s.roles.join(', ') || t('nodes.noRole')],
                ['Kubelet', info.kubeletVersion],
                [t('nodes.drawer.os'), `${info.operatingSystem ?? ''} / ${info.architecture ?? ''}`],
                [t('nodes.drawer.osImage'), info.osImage],
                [t('nodes.drawer.kernel'), info.kernelVersion],
                [t('nodes.drawer.runtime'), info.containerRuntimeVersion],
                [t('nodes.drawer.internalIP'), addr('InternalIP')],
                [t('nodes.drawer.externalIP'), addr('ExternalIP')],
                [t('nodes.drawer.scheduling'), s.unschedulable ? t('nodes.drawer.cordoned') : t('nodes.drawer.schedulable')],
                [t('nodes.col.age'), ageShort(s.created)],
              ]}
            />
          </Section>

          <Section title={t('nodes.drawer.resources')}>
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div className="flex flex-col gap-1">
                <span className="font-medium text-slate-700 dark:text-slate-200">CPU</span>
                <NodeMeter kind="cpu" used={s.cpu} requests={s.cpuRequests} limits={s.cpuLimits} allocatable={s.cpuAllocatable} />
              </div>
              <div className="flex flex-col gap-1">
                <span className="font-medium text-slate-700 dark:text-slate-200">{t('dashboard.usage.memory')}</span>
                <NodeMeter kind="mem" used={s.memory} requests={s.memoryRequests} limits={s.memoryLimits} allocatable={s.memoryAllocatable} />
              </div>
            </div>
            <div className="overflow-x-auto" tabIndex={0} role="region" aria-label={t('nodes.drawer.resources')}>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-[11px] text-slate-500 dark:text-slate-400">
                    <th scope="col" className="py-1 pr-3 font-medium"><span className="sr-only">{t('nodes.drawer.resource')}</span></th>
                    {['capacity', 'allocatable', 'requests', 'limits', 'used'].map((k) => (
                      <th key={k} scope="col" className="py-1 pr-3 text-right font-medium">{t(`nodes.drawer.${k}`)}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {resourceRows.map(([label, cells]) => (
                    <tr key={label}>
                      <th scope="row" className="py-1.5 pr-3 text-left font-medium text-slate-700 dark:text-slate-200">{label}</th>
                      {cells.map((c, i) => (
                        <td key={i} className="py-1.5 pr-3 text-right font-mono text-slate-700 dark:text-slate-200">{c}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>

          <Section title={t('nodes.drawer.history')}>
            <UsageHistoryPanel
              load={(range) => getNodeUsageHistory(name, range)}
              cpuLimit={s.cpuAllocatable || undefined}
              memLimit={s.memoryAllocatable || undefined}
              limitLabel={t('overview.allocatable')}
              reloadKey={`${name}:${tick}`}
            />
          </Section>

          <Section
            title={t('nodes.drawer.topPods')}
            aside={<Segmented label={t('overview.sortBy')} value={topBy} onChange={setTopBy} options={[['cpu', 'CPU'], ['memory', t('dashboard.usage.memory')]]} />}
          >
            {top.length === 0 ? (
              <Empty>{t('nodes.drawer.noUsage')}</Empty>
            ) : (
              <ul className="-mx-2 flex flex-col">
                {top.map(({ p }) => {
                  const v = p.usage![topBy];
                  const share = pct(v, topBy === 'cpu' ? s.cpuAllocatable : s.memoryAllocatable);
                  return (
                    <li key={podKey(p)}>
                      <button
                        type="button"
                        onClick={() => go(p)}
                        className="flex w-full cursor-pointer flex-col gap-1 rounded-lg px-2 py-1.5 text-left hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 dark:hover:bg-slate-800/60"
                      >
                        <span className="flex items-baseline justify-between gap-2 text-xs">
                          <span className="min-w-0 truncate">
                            <span className="font-mono text-slate-800 dark:text-slate-100">{p.metadata?.name}</span>
                            <span className="ml-2 text-[11px] text-slate-500 dark:text-slate-400">{p.metadata?.namespace}</span>
                          </span>
                          <span className="shrink-0 font-mono text-slate-700 dark:text-slate-200">
                            {fmtTop(v)}
                            {share !== null && <span className="text-slate-500 dark:text-slate-400"> · {share}%</span>}
                          </span>
                        </span>
                        <span className="block h-1.5 rounded-full bg-slate-100 dark:bg-slate-800" aria-hidden="true">
                          <span className="block h-full rounded-full bg-brand-500 dark:bg-brand-400" style={{ width: `${(v / topMax) * 100}%` }} />
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </Section>

          <Section
            title={t('nodes.drawer.podsTitle', { count: pods.length })}
            aside={
              <Segmented label={t('nodes.drawer.podFilter')} value={podFilter} onChange={setPodFilter}
                options={[['all', t('nodes.drawer.allPods')], ['problems', t('nodes.drawer.problemPods')]]} />
            }
          >
            {shown.length === 0 ? (
              <Empty>{podFilter === 'all' ? t('dashboard.detail.none') : t('overview.noProblems')}</Empty>
            ) : (
              <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
                {shown.map(({ p, st }) => (
                  <li key={podKey(p)}>
                    <button
                      type="button"
                      onClick={() => go(p)}
                      className="grid w-full cursor-pointer grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 px-3 py-2 text-left hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand-500/60 dark:hover:bg-slate-800/50 sm:grid-cols-[1fr_auto_auto_auto]"
                    >
                      <span className="min-w-0 truncate text-xs">
                        <span className="font-mono text-slate-900 dark:text-slate-100">{p.metadata?.name}</span>
                        <span className="ml-2 text-[11px] text-slate-500 dark:text-slate-400">{p.metadata?.namespace}</span>
                      </span>
                      <PodStatusBadge namespace={p.metadata?.namespace} podName={p.metadata?.name} status={st} />
                      <PodRestarts status={st} />
                      <span className="whitespace-nowrap font-mono text-[11px] text-slate-500 dark:text-slate-400" title={t('nodes.drawer.requestsTitle')}>
                        {formatCpu(p.cpuRequests)} · {formatMem(p.memoryRequests)}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Section>

          <Section title={t('dashboard.detail.conditions')}>
            <Conditions items={node.status?.conditions} okWhenFalse={(type) => type !== 'Ready'} />
          </Section>

          <Section title={t('nodes.drawer.taints')}>
            {(node.spec?.taints ?? []).length === 0 ? (
              <Empty>{t('nodes.drawer.noTaints')}</Empty>
            ) : (
              <ul className="flex flex-col gap-1 font-mono text-xs text-slate-700 dark:text-slate-200">
                {node.spec.taints.map((tt: { key: string; value?: string; effect: string }) => (
                  <li key={`${tt.key}:${tt.effect}`} className="break-all">
                    {tt.key}{tt.value ? `=${tt.value}` : ''}:{tt.effect}
                  </li>
                ))}
              </ul>
            )}
          </Section>

          {(['labels', 'annotations'] as const).map((k) => {
            const entries = Object.entries((node.metadata?.[k] ?? {}) as Record<string, string>);
            return (
              <details key={k} className="group">
                <summary className="cursor-pointer rounded text-[11px] font-semibold uppercase tracking-wide text-slate-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 dark:text-slate-400">
                  {t(`nodes.drawer.${k}`)} ({entries.length})
                </summary>
                <ul className="mt-2 flex flex-col gap-1 font-mono text-[11px] text-slate-700 dark:text-slate-200">
                  {entries.map(([key, v]) => (
                    <li key={key} className="break-all">
                      <span className="text-slate-500 dark:text-slate-400">{key}</span>
                      {v ? `=${v}` : ''}
                    </li>
                  ))}
                </ul>
              </details>
            );
          })}

          <Section title={t('dashboard.detail.events')}>
            <Events load={() => Promise.resolve({ items: data.events })} version={data} />
          </Section>
        </div>
      )}
    </Drawer>
  );
};
