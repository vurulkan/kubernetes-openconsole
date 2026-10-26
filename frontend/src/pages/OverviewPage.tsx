import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Activity,
  AlertTriangle,
  Boxes,
  CheckCircle2,
  Cpu,
  Gauge,
  LayoutGrid,
  MemoryStick,
  RefreshCw,
  RotateCcw,
  Server,
  XCircle,
} from 'lucide-react';
import Layout from '../components/Layout';
import LiveEventsPanel from '../components/LiveEventsPanel';
import { EVENTS_PANEL_EVENT_NAME } from '../hooks/useGlobalShortcuts';
import { Button, Spinner } from '../components/ui';
import { PodStatusBadge } from '../components/PodStatusBadge';
import { LineChart } from '../components/Usage';
import { getOverview, getOverviewHistory, type Overview, type UsageHistory, type User } from '../services/api';
import { exitLabel, podStatus, type PodLike } from '../utils/podStatus';
import { formatCpu, formatMem } from '../utils/format';
import { ageShort } from '../utils/age';
import { HourlyBars, Sparkline } from './overview/Charts';

const REFRESH_MS = 15000;

// Glass card: translucent surface, hairline border, soft depth.
const CARD =
  'rounded-2xl border border-slate-200/80 bg-white/80 shadow-card backdrop-blur-md dark:border-white/10 dark:bg-slate-900/60';

const pct = (used: number, of: number) => (of > 0 ? Math.round((used / of) * 100) : null);
// Status colors carry state only: >= 90 % red, >= 70 % amber.
const meterTone = (p: number) => (p >= 90 ? 'bg-rose-500' : p >= 70 ? 'bg-amber-500' : 'bg-brand-500');

/** Stage a Dashboard view (as saved views do) and go there. */
const openDashboard = (navigate: (p: string) => void, stage: Record<string, string>) => {
  try {
    Object.entries(stage).forEach(([k, v]) => localStorage.setItem(k, v));
  } catch {
    /* ignore */
  }
  navigate('/');
};

const ownerTab: Record<string, string> = { Deployment: 'deployments', StatefulSet: 'statefulsets', DaemonSet: 'daemonsets', Job: 'jobs' };

const Section: React.FC<{ id: string; title: string; icon: React.ReactNode; aside?: React.ReactNode; className?: string; children: React.ReactNode }> = ({
  id, title, icon, aside, className = '', children,
}) => (
  <section id={id} aria-labelledby={`${id}-title`} tabIndex={-1} className={`${CARD} flex min-w-0 flex-col focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 ${className}`}>
    <header className="flex items-center justify-between gap-2 rounded-t-2xl border-b border-slate-200/70 bg-gradient-to-b from-white/70 to-transparent px-4 py-3 dark:border-white/5 dark:from-white/[0.04]">
      <h2 id={`${id}-title`} className="flex items-center gap-2 text-sm font-semibold text-slate-800 dark:text-slate-100">
        <span className="text-slate-400 dark:text-slate-500" aria-hidden="true">{icon}</span>
        {title}
      </h2>
      {aside}
    </header>
    <div className="flex min-h-0 flex-1 flex-col p-4">{children}</div>
  </section>
);

const Empty: React.FC<{ children: React.ReactNode; ok?: boolean }> = ({ children, ok }) => (
  <p className="flex flex-1 items-center justify-center gap-2 py-6 text-center text-sm text-slate-500 dark:text-slate-400">
    {ok && <CheckCircle2 size={16} className="text-emerald-600 dark:text-emerald-400" aria-hidden="true" />}
    {children}
  </p>
);

const Kpi: React.FC<{
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  icon: React.ReactNode;
  trend: number[];
  trendSummary: string;
  meter?: number | null;
  onClick: () => void;
}> = ({ label, value, sub, icon, trend, trendSummary, meter, onClick }) => (
  <button
    type="button"
    onClick={onClick}
    className={`${CARD} group flex cursor-pointer flex-col gap-2 p-4 text-left transition-all duration-200 hover:-translate-y-0.5 hover:shadow-elevated focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 motion-reduce:transition-none motion-reduce:hover:translate-y-0`}
  >
    <span className="flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
      {label}
      <span className="text-slate-400 transition-colors group-hover:text-brand-500 dark:text-slate-500" aria-hidden="true">{icon}</span>
    </span>
    <span className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">{value}</span>
    <span className="min-h-[1rem] text-xs text-slate-500 dark:text-slate-400">{sub}</span>
    {meter !== undefined && meter !== null && (
      <span className="block h-1 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800" aria-hidden="true">
        <span className={`block h-full rounded-full ${meterTone(meter)}`} style={{ width: `${Math.min(meter, 100)}%` }} />
      </span>
    )}
    <span className="relative mt-auto block">
      <Sparkline values={trend} summary={trendSummary} />
    </span>
  </button>
);

const OverviewPage: React.FC<{ user: User }> = ({ user }) => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [data, setData] = useState<Overview | null>(null);
  const [history, setHistory] = useState<UsageHistory | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());
  const [nsSort, setNsSort] = useState<'cpu' | 'memory'>('cpu');
  // Live events of the whole cluster, opened on warnings (the page is admins only).
  const [eventsOpen, setEventsOpen] = useState(false);
  const [eventsLive, setEventsLive] = useState(false);
  useEffect(() => {
    const toggle = () => setEventsOpen((v) => !v);
    window.addEventListener(EVENTS_PANEL_EVENT_NAME, toggle);
    return () => window.removeEventListener(EVENTS_PANEL_EVENT_NAME, toggle);
  }, []);

  // The first load is audited; the page's own refreshes say so and are not.
  const load = useCallback((auto: boolean) => {
    getOverview(auto)
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e: Error) => setError(e.message));
    getOverviewHistory()
      .then(setHistory)
      .catch(() => undefined); // the charts keep their last answer
  }, []);
  useEffect(() => {
    load(false);
    const tick = () => {
      if (document.visibilityState === 'visible') load(true);
    };
    const poll = setInterval(tick, REFRESH_MS);
    const clock = setInterval(() => setNow(Date.now()), 5000);
    document.addEventListener('visibilitychange', tick);
    return () => {
      clearInterval(poll);
      clearInterval(clock);
      document.removeEventListener('visibilitychange', tick);
    };
  }, [load]);

  const problems = useMemo(() => {
    const rows = (data?.attention ?? []).map((pod) => {
      const meta = pod.metadata as { name: string; namespace: string };
      return { pod, name: meta.name, namespace: meta.namespace, st: podStatus(pod as PodLike) };
    });
    return rows
      .filter((r) => r.st.tone === 'error' || r.st.tone === 'warn')
      .sort((a, b) => (a.st.tone === b.st.tone ? 0 : a.st.tone === 'error' ? -1 : 1));
  }, [data]);
  const red = problems.filter((p) => p.st.tone === 'error').length;

  const jump = (id: string) => {
    const el = document.getElementById(id);
    el?.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
    el?.focus({ preventScroll: true });
  };

  if (!data) {
    return (
      <Layout user={user}>
        <div className="flex min-h-[50vh] flex-col items-center justify-center gap-3 text-sm text-slate-500 dark:text-slate-400">
          {error ? (
            <>
              <p>{t('overview.loadFailed', { error })}</p>
              <Button variant="outline" size="sm" onClick={() => load(false)}>
                <RefreshCw size={14} />
                {t('overview.retry')}
              </Button>
            </>
          ) : (
            <Spinner size="lg" />
          )}
        </div>
      </Layout>
    );
  }

  const u = data.usage;
  const cpuPct = u ? pct(u.cpu, u.cpuAllocatable) : null;
  const memPct = u ? pct(u.memory, u.memoryAllocatable) : null;
  const counts = data.counts;
  const ago = Math.max(0, Math.round((now - Date.parse(data.generatedAt)) / 1000));
  const points = history?.points ?? [];
  const range = (vals: number[], f: (n: number) => string = String) =>
    vals.length ? t('overview.trendSummary', { min: f(Math.min(...vals)), max: f(Math.max(...vals)) }) : t('overview.noTrend');
  const noMetrics = t(`overview.metricsNote.${data.metricsNote || 'none'}`, { defaultValue: t('overview.metricsNote.none') });
  const sortedNs = [...data.namespaces].sort((a, b) => (nsSort === 'cpu' ? b.cpu - a.cpu : b.memory - a.memory)).slice(0, 8);
  const nsMax = Math.max(1, ...sortedNs.map((n) => (nsSort === 'cpu' ? n.cpu : n.memory)));
  const restartMax = Math.max(1, ...data.topRestarts.map((r) => r.restarts));
  const source =
    history?.source === 'prometheus' ? 'Prometheus' : data.metricsSource === 'memory' ? t('overview.sourceMemory') : t('overview.sourceNone');

  return (
    <Layout user={user} liveEvents={{ open: eventsOpen, connected: eventsLive }}>
      <div className="relative">
        <div className="pointer-events-none absolute inset-x-0 -top-6 lg:-inset-x-8 h-80 bg-brand-radial opacity-70 [mask-image:linear-gradient(to_bottom,black,transparent)] dark:opacity-100" aria-hidden="true" />
        <div className="relative flex flex-col gap-5 motion-safe:animate-slide-up">
          {/* ── Header strip ─────────────────────────────────────────── */}
          <header className={`${CARD} flex flex-wrap items-center gap-x-5 gap-y-2 px-5 py-4`}>
            <h1 className="flex items-center gap-2 text-lg font-semibold tracking-tight text-slate-900 dark:text-slate-50">
              <Gauge size={20} className="text-brand-500" aria-hidden="true" />
              {data.cluster.name}
            </h1>
            <dl className="flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-slate-600 dark:text-slate-300">
              <div className="flex gap-1.5"><dt className="text-slate-500 dark:text-slate-400">Kubernetes</dt><dd className="font-mono">{data.cluster.version || '—'}</dd></div>
              <div className="flex gap-1.5"><dt className="text-slate-500 dark:text-slate-400">{t('overview.nodes')}</dt><dd className="font-mono">{data.nodesNote ? '—' : data.cluster.nodes}</dd></div>
              <div className="flex items-center gap-1.5">
                <dt className="sr-only">{t('overview.connection')}</dt>
                <dd className="inline-flex items-center gap-1.5 text-emerald-700 dark:text-emerald-400">
                  <CheckCircle2 size={13} aria-hidden="true" />
                  {t('overview.connected')}
                </dd>
              </div>
              <div className="flex gap-1.5"><dt className="text-slate-500 dark:text-slate-400">{t('overview.metrics')}</dt><dd>{source}</dd></div>
            </dl>
            <div className="ml-auto flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400">
              <span className="inline-flex items-center gap-1.5" aria-live="off">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 motion-safe:animate-pulse-dot" aria-hidden="true" />
                {t('overview.updated', { seconds: ago })}
              </span>
              <Button variant="outline" size="sm" onClick={() => load(true)} aria-label={t('overview.refresh')}>
                <RefreshCw size={14} />
              </Button>
            </div>
          </header>
          {error && <p className="text-xs text-amber-700 dark:text-amber-400">{t('overview.refreshFailed', { error })}</p>}

          {/* ── KPIs ─────────────────────────────────────────────────── */}
          <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
            <Kpi
              label={t('overview.kpi.pods')}
              value={`${data.pods.running} / ${data.pods.total}`}
              sub={t('overview.kpi.podsSub')}
              icon={<Boxes size={16} />}
              trend={counts.map((c) => c.podsRunning)}
              trendSummary={range(counts.map((c) => c.podsRunning))}
              onClick={() => jump('ov-problems')}
            />
            <Kpi
              label={t('overview.kpi.problems')}
              value={problems.length}
              sub={
                problems.length ? (
                  <span className="inline-flex items-center gap-2">
                    <span className="inline-flex items-center gap-1"><XCircle size={12} className="text-rose-600 dark:text-rose-400" aria-hidden="true" />{t('overview.kpi.red', { count: red })}</span>
                    <span className="inline-flex items-center gap-1"><AlertTriangle size={12} className="text-amber-600 dark:text-amber-400" aria-hidden="true" />{t('overview.kpi.amber', { count: problems.length - red })}</span>
                  </span>
                ) : t('overview.kpi.allHealthy')
              }
              icon={<AlertTriangle size={16} />}
              trend={counts.map((c) => c.podsAttention)}
              trendSummary={range(counts.map((c) => c.podsAttention))}
              onClick={() => jump('ov-problems')}
            />
            <Kpi
              label={t('overview.kpi.restarts')}
              value={data.restarts24h}
              sub={t('overview.kpi.last24h')}
              icon={<RotateCcw size={16} />}
              trend={data.restartsHourly}
              trendSummary={range(data.restartsHourly)}
              onClick={() => jump('ov-restarts')}
            />
            <Kpi
              label={t('overview.kpi.deployments')}
              value={`${data.deployments.ready} / ${data.deployments.total}`}
              sub={t('overview.kpi.deploymentsSub')}
              icon={<LayoutGrid size={16} />}
              trend={counts.map((c) => c.deploysReady)}
              trendSummary={range(counts.map((c) => c.deploysReady))}
              onClick={() => openDashboard(navigate, { dashboardResourceTab: 'deployments' })}
            />
            <Kpi
              label="CPU"
              value={u ? (cpuPct !== null ? `${cpuPct}%` : formatCpu(u.cpu)) : '—'}
              sub={u ? (cpuPct !== null ? t('overview.kpi.ofAllocatable', { used: formatCpu(u.cpu), total: formatCpu(u.cpuAllocatable) }) : t('overview.kpi.noAllocatable')) : noMetrics}
              meter={cpuPct}
              icon={<Cpu size={16} />}
              trend={points.map((p) => p.cpu)}
              trendSummary={range(points.map((p) => p.cpu), formatCpu)}
              onClick={() => { setNsSort('cpu'); jump('ov-namespaces'); }}
            />
            <Kpi
              label={t('overview.kpi.memory')}
              value={u ? (memPct !== null ? `${memPct}%` : formatMem(u.memory)) : '—'}
              sub={u ? (memPct !== null ? t('overview.kpi.ofAllocatable', { used: formatMem(u.memory), total: formatMem(u.memoryAllocatable) }) : t('overview.kpi.noAllocatable')) : noMetrics}
              meter={memPct}
              icon={<MemoryStick size={16} />}
              trend={points.map((p) => p.memory)}
              trendSummary={range(points.map((p) => p.memory), formatMem)}
              onClick={() => { setNsSort('memory'); jump('ov-namespaces'); }}
            />
          </div>

          {/* ── Usage + problems ─────────────────────────────────────── */}
          <div className="grid gap-4 xl:grid-cols-3">
            <Section id="ov-usage" title={t('overview.usageTitle')} icon={<Activity size={16} />} className="xl:col-span-2"
              aside={<span className="text-[11px] text-slate-500 dark:text-slate-400">{history?.note === 'prometheus_unreachable' ? t('overview.metricsNote.prometheus_unreachable') : source}</span>}>
              {!history ? (
                <div className="flex flex-1 items-center justify-center py-6"><Spinner size="md" /></div>
              ) : points.length ? (
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 [&>*]:min-w-0">
                  <LineChart kind="cpu" title="CPU" points={points.map((p) => ({ t: p.t, v: p.cpu }))}
                    limit={u?.cpuAllocatable || undefined} limitLabel={t('overview.allocatable')} />
                  <LineChart kind="mem" title={t('overview.kpi.memory')} points={points.map((p) => ({ t: p.t, v: p.memory }))}
                    limit={u?.memoryAllocatable || undefined} limitLabel={t('overview.allocatable')} />
                </div>
              ) : (
                <Empty>{data.metricsSource === 'none' ? noMetrics : t('overview.noHistoryYet')}</Empty>
              )}
            </Section>

            <Section id="ov-problems" title={t('overview.problemsTitle')} icon={<AlertTriangle size={16} />}
              aside={problems.length ? <span className="text-[11px] text-slate-500 dark:text-slate-400">{problems.length}</span> : undefined}>
              {problems.length === 0 ? (
                <Empty ok>{t('overview.noProblems')}</Empty>
              ) : (
                <ul className="-mx-2 flex max-h-56 flex-col overflow-auto" tabIndex={0} aria-label={t('overview.problemsTitle')}>
                  {problems.map(({ name, namespace, st }) => (
                    <li key={`${namespace}/${name}`} className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800/60">
                      <PodStatusBadge namespace={namespace} podName={name} status={st} />
                      <button
                        type="button"
                        onClick={() => openDashboard(navigate, { dashboardNamespace: namespace, dashboardResourceTab: 'pods', dashboardPendingSearch: name, dashboardPendingPod: name })}
                        className="min-w-0 flex-1 cursor-pointer truncate text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60"
                        title={`${namespace}/${name}`}
                      >
                        <span className="font-mono text-xs text-slate-800 dark:text-slate-100">{name}</span>
                        <span className="ml-2 text-[11px] text-slate-500 dark:text-slate-400">{namespace}</span>
                      </button>
                      {st.lastTermination && (
                        <span className="shrink-0 font-mono text-[11px] text-slate-500 dark:text-slate-400" title={t('overview.lastExit')}>
                          {exitLabel(st.lastTermination)}
                        </span>
                      )}
                    </li>
                  ))}
                  {data.attentionTotal > data.attention.length && (
                    <li className="px-2 py-1.5 text-[11px] text-slate-500 dark:text-slate-400">{t('overview.moreProblems', { count: data.attentionTotal - data.attention.length })}</li>
                  )}
                </ul>
              )}
            </Section>
          </div>

          {/* ── Restarts + namespaces ───────────────────────────────── */}
          <div className="grid gap-4 xl:grid-cols-3">
            <Section id="ov-restarts" title={t('overview.topRestartsTitle')} icon={<RotateCcw size={16} />}>
              {data.topRestarts.length === 0 ? (
                <Empty ok>{t('overview.noRestarts')}</Empty>
              ) : (
                <ul className="-mx-2 flex flex-col">
                  {data.topRestarts.map((r) => {
                    const [kind, name] = r.owner.split('/');
                    return (
                      <li key={`${r.namespace}/${r.owner}`}>
                        <button
                          type="button"
                          onClick={() =>
                            openDashboard(navigate, kind === 'Pod'
                              ? { dashboardNamespace: r.namespace, dashboardResourceTab: 'pods', dashboardPendingSearch: name, dashboardPendingPod: name }
                              : { dashboardNamespace: r.namespace, dashboardResourceTab: ownerTab[kind] ?? 'pods', dashboardPendingSearch: name })
                          }
                          className="flex w-full cursor-pointer flex-col gap-1 rounded-lg px-2 py-1.5 text-left hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 dark:hover:bg-slate-800/60"
                        >
                          <span className="flex items-baseline justify-between gap-2 text-xs">
                            <span className="min-w-0 truncate">
                              <span className="font-mono text-slate-800 dark:text-slate-100">{r.owner}</span>
                              <span className="ml-2 text-[11px] text-slate-500 dark:text-slate-400">{r.namespace}</span>
                            </span>
                            <span className="shrink-0 font-mono text-slate-700 dark:text-slate-200">{r.restarts}</span>
                          </span>
                          <span className="flex items-center gap-2">
                            <span className="block h-1.5 flex-1 rounded-full bg-slate-100 dark:bg-slate-800" aria-hidden="true">
                              <span className="block h-full rounded-full bg-brand-500 dark:bg-brand-400" style={{ width: `${(r.restarts / restartMax) * 100}%` }} />
                            </span>
                            <span className="shrink-0 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                              {r.share}× {exitLabel({ exitCode: r.exitCode, reason: r.reason })}
                            </span>
                          </span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </Section>

            <Section id="ov-restarts-time" title={t('overview.restartsOverTime')} icon={<Activity size={16} />}>
              <HourlyBars
                counts={data.restartsHourly}
                hourStart={data.hourStart}
                title={t('overview.restartsPerHour')}
                valueLabel={(n) => t('overview.restartCount', { count: n })}
              />
            </Section>

            <Section
              id="ov-namespaces"
              title={t('overview.namespacesTitle')}
              icon={<LayoutGrid size={16} />}
              aside={
                <div role="group" aria-label={t('overview.sortBy')} className="inline-flex rounded-lg border border-slate-200 p-0.5 dark:border-slate-700">
                  {(['cpu', 'memory'] as const).map((k) => (
                    <button
                      key={k}
                      type="button"
                      aria-pressed={nsSort === k}
                      onClick={() => setNsSort(k)}
                      className={`cursor-pointer rounded-md px-2 py-0.5 text-[11px] focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 ${
                        nsSort === k ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200' : 'text-slate-600 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-800'
                      }`}
                    >
                      {k === 'cpu' ? 'CPU' : t('overview.kpi.memory')}
                    </button>
                  ))}
                </div>
              }
            >
              {sortedNs.length === 0 ? (
                <Empty>{noMetrics}</Empty>
              ) : (
                <ul className="-mx-2 flex flex-col">
                  {sortedNs.map((n) => {
                    const v = nsSort === 'cpu' ? n.cpu : n.memory;
                    return (
                      <li key={n.name}>
                        <button
                          type="button"
                          onClick={() => openDashboard(navigate, { dashboardNamespace: n.name, dashboardResourceTab: 'pods' })}
                          className="flex w-full cursor-pointer flex-col gap-1 rounded-lg px-2 py-1.5 text-left hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 dark:hover:bg-slate-800/60"
                        >
                          <span className="flex items-baseline justify-between gap-2 text-xs">
                            <span className="min-w-0 truncate font-mono text-slate-800 dark:text-slate-100">{n.name}</span>
                            <span className="flex shrink-0 items-center gap-2">
                              {n.nearLimit > 0 && (
                                <span className="inline-flex items-center gap-1 text-[11px] text-amber-700 dark:text-amber-400">
                                  <AlertTriangle size={11} aria-hidden="true" />
                                  {t('overview.nearLimit', { count: n.nearLimit })}
                                </span>
                              )}
                              <span className="font-mono text-slate-700 dark:text-slate-200">{nsSort === 'cpu' ? formatCpu(v) : formatMem(v)}</span>
                            </span>
                          </span>
                          <span className="block h-1.5 rounded-full bg-slate-100 dark:bg-slate-800" aria-hidden="true">
                            <span className="block h-full rounded-full bg-brand-500 dark:bg-brand-400" style={{ width: `${(v / nsMax) * 100}%` }} />
                          </span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </Section>
          </div>

          {/* ── Warnings + nodes ─────────────────────────────────────── */}
          <div className="grid gap-4 xl:grid-cols-3">
            <Section
              id="ov-warnings"
              title={t('overview.warningsTitle')}
              icon={<AlertTriangle size={16} />}
              className="xl:col-span-2"
              aside={
                <button
                  type="button"
                  onClick={() => setEventsOpen(true)}
                  className="cursor-pointer text-[11px] font-medium text-brand-700 underline-offset-2 hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 dark:text-brand-300"
                >
                  {t('overview.openLiveEvents')}
                </button>
              }
            >
              {data.warnings.length === 0 ? (
                <Empty ok>{t('overview.noWarnings')}</Empty>
              ) : (
                <ul className="flex flex-col divide-y divide-slate-100 dark:divide-slate-800">
                  {data.warnings.map((w, i) => (
                    <li key={i} className="flex items-start gap-3 py-2 text-xs">
                      <AlertTriangle size={14} className="mt-0.5 shrink-0 text-amber-600 dark:text-amber-400" aria-hidden="true" />
                      <div className="min-w-0 flex-1">
                        <p className="flex flex-wrap items-baseline gap-x-2">
                          <span className="font-semibold text-slate-800 dark:text-slate-100">{w.reason}</span>
                          <span className="font-mono text-slate-600 dark:text-slate-300">{w.kind}/{w.name}</span>
                          <span className="text-[11px] text-slate-500 dark:text-slate-400">{w.namespace}</span>
                        </p>
                        <p className="line-clamp-2 text-slate-600 dark:text-slate-300">{w.message}</p>
                      </div>
                      <span className="shrink-0 text-right font-mono text-[11px] text-slate-500 dark:text-slate-400">
                        {ageShort(w.at)}
                        {w.count > 1 && <span className="block">×{w.count}</span>}
                      </span>
                    </li>
                  ))}
                  {data.warningsTotal > data.warnings.length && (
                    <li className="py-2 text-[11px] text-slate-500 dark:text-slate-400">{t('overview.moreWarnings', { count: data.warningsTotal - data.warnings.length })}</li>
                  )}
                </ul>
              )}
            </Section>

            <Section id="ov-nodes" title={t('overview.nodesTitle')} icon={<Server size={16} />}>
              {data.nodesNote || data.nodes.length === 0 ? (
                <Empty>{t('overview.nodesUnavailable')}</Empty>
              ) : (
                <ul className="-mx-2 flex max-h-80 flex-col overflow-auto">
                  {data.nodes.map((n) => {
                    const c = n.cpu !== undefined ? pct(n.cpu, n.cpuAllocatable) : null;
                    const m = n.memory !== undefined ? pct(n.memory, n.memoryAllocatable) : null;
                    const state = !n.ready ? 'notReady' : n.pressure.length ? 'pressure' : 'ready';
                    return (
                      <li key={n.name} className="flex flex-col gap-1 rounded-lg px-2 py-1.5">
                        <span className="flex items-center justify-between gap-2 text-xs">
                          <span className="min-w-0 truncate font-mono text-slate-800 dark:text-slate-100">{n.name}</span>
                          <span
                            className={`inline-flex shrink-0 items-center gap-1 text-[11px] ${
                              state === 'ready' ? 'text-emerald-700 dark:text-emerald-400' : state === 'pressure' ? 'text-amber-700 dark:text-amber-400' : 'text-rose-700 dark:text-rose-400'
                            }`}
                          >
                            {state === 'ready' ? <CheckCircle2 size={12} aria-hidden="true" /> : state === 'pressure' ? <AlertTriangle size={12} aria-hidden="true" /> : <XCircle size={12} aria-hidden="true" />}
                            {state === 'pressure' ? n.pressure.join(', ') : t(`overview.node.${state}`)}
                            {n.unschedulable && ` · ${t('overview.node.cordoned')}`}
                          </span>
                        </span>
                        {[['CPU', c], [t('overview.kpi.memory'), m]].map(([label, p]) => (
                          <span key={label as string} className="flex items-center gap-2 text-[11px] text-slate-500 dark:text-slate-400">
                            <span className="w-12 shrink-0">{label}</span>
                            <span className="block h-1 flex-1 rounded-full bg-slate-100 dark:bg-slate-800" aria-hidden="true">
                              {p !== null && <span className={`block h-full rounded-full ${meterTone(p as number)}`} style={{ width: `${Math.min(p as number, 100)}%` }} />}
                            </span>
                            <span className="w-9 shrink-0 text-right font-mono">{p === null ? '—' : `${p}%`}</span>
                          </span>
                        ))}
                      </li>
                    );
                  })}
                </ul>
              )}
            </Section>
          </div>
        </div>
      </div>
      <LiveEventsPanel
        namespace={null}
        open={eventsOpen}
        onClose={() => setEventsOpen(false)}
        initialFilter="warnings"
        onConnectedChange={setEventsLive}
      />
    </Layout>
  );
};

export default OverviewPage;
