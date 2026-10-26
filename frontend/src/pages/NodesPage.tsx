import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { RefreshCw, Search as SearchIcon, Server } from 'lucide-react';
import Layout from '../components/Layout';
import LiveEventsPanel from '../components/LiveEventsPanel';
import { DataTable, type Column } from '../components/DataTable';
import { Alert, Button, Input, Spinner } from '../components/ui';
import { EVENTS_PANEL_EVENT_NAME } from '../hooks/useGlobalShortcuts';
import { listNodes, type NodeList, type NodeRow, type User } from '../services/api';
import { ageShort } from '../utils/age';
import { NodeDrawer } from './nodes/NodeDrawer';
import { matchNode, NodeMeter, nodeRank, NodeStatus, pct } from './nodes/NodeParts';

const REFRESH_MS = 15000;

/** Below md the table keeps name, status, CPU and memory. */
function useNarrow() {
  const query = '(max-width: 767px)';
  const [narrow, setNarrow] = useState(() => window.matchMedia?.(query)?.matches ?? false);
  useEffect(() => {
    const mq = window.matchMedia?.(query);
    if (!mq) return;
    const on = () => setNarrow(mq.matches);
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, []);
  return narrow;
}

const NodesPage: React.FC<{ user: User }> = ({ user }) => {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const selected = params.get('node');
  const [data, setData] = useState<NodeList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [now, setNow] = useState(Date.now());
  const narrow = useNarrow();
  // Live events of the whole cluster (admins only), as on the overview.
  const [eventsOpen, setEventsOpen] = useState(false);
  const [eventsLive, setEventsLive] = useState(false);
  useEffect(() => {
    const toggle = () => setEventsOpen((v) => !v);
    window.addEventListener(EVENTS_PANEL_EVENT_NAME, toggle);
    return () => window.removeEventListener(EVENTS_PANEL_EVENT_NAME, toggle);
  }, []);

  // The first load is audited; the page's own refreshes say so and are not.
  const load = useCallback((auto: boolean) => {
    listNodes(auto)
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e: Error) => setError(e.message));
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

  const rows = useMemo(() => (data?.nodes ?? []).filter((n) => matchNode(n, query)), [data, query]);
  const open = (name: string | null) => setParams(name ? { node: name } : {}, { replace: !name });

  const columns: Column<NodeRow>[] = [
    {
      key: 'name',
      header: t('nodes.col.name'),
      sortValue: (n) => n.name,
      cell: (n) => (
        <span className="flex flex-col gap-1">
          <span className="break-all font-mono text-xs font-medium text-slate-900 dark:text-slate-100">{n.name}</span>
          {narrow && <NodeStatus node={n} />}
        </span>
      ),
    },
    ...(narrow
      ? ([
          {
            key: 'usage',
            header: `CPU · ${t('dashboard.usage.memory')}`,
            descFirst: true,
            sortValue: (n) => pct(n.cpu, n.cpuAllocatable) ?? pct(n.cpuRequests, n.cpuAllocatable),
            cell: (n) => (
              <span className="flex flex-col gap-1.5">
                <NodeMeter compact kind="cpu" used={n.cpu} requests={n.cpuRequests} limits={n.cpuLimits} allocatable={n.cpuAllocatable} />
                <NodeMeter compact kind="mem" used={n.memory} requests={n.memoryRequests} limits={n.memoryLimits} allocatable={n.memoryAllocatable} />
              </span>
            ),
          },
        ] as Column<NodeRow>[])
      : ([
          { key: 'status', header: t('nodes.col.status'), sortValue: nodeRank, descFirst: true, cell: (n) => <NodeStatus node={n} /> },
          { key: 'roles', header: t('nodes.col.roles'), sortValue: (n) => n.roles.join(','), cell: (n) => <span className="text-xs">{n.roles.join(', ') || '—'}</span> },
          { key: 'kubelet', header: 'Kubelet', sortValue: (n) => n.kubeletVersion, cell: (n) => <span className="font-mono text-xs">{n.kubeletVersion}</span> },
          { key: 'os', header: t('nodes.col.os'), sortValue: (n) => `${n.os}/${n.arch}`, cell: (n) => <span className="font-mono text-xs">{n.os}/{n.arch}</span> },
          { key: 'age', header: t('nodes.col.age'), sortValue: (n) => -Date.parse(n.created), descFirst: true, cell: (n) => <span className="font-mono text-xs">{ageShort(n.created)}</span> },
          {
            key: 'pods',
            header: t('nodes.col.pods'),
            align: 'right',
            descFirst: true,
            sortValue: (n) => n.pods / Math.max(1, n.podCapacity),
            cell: (n) => <span className="whitespace-nowrap font-mono text-xs">{n.pods} / {n.podCapacity}</span>,
          },
          {
            key: 'cpu',
            header: 'CPU',
            descFirst: true,
            sortValue: (n) => pct(n.cpu, n.cpuAllocatable) ?? pct(n.cpuRequests, n.cpuAllocatable),
            cell: (n) => <NodeMeter kind="cpu" used={n.cpu} requests={n.cpuRequests} limits={n.cpuLimits} allocatable={n.cpuAllocatable} />,
          },
          {
            key: 'memory',
            header: t('dashboard.usage.memory'),
            descFirst: true,
            sortValue: (n) => pct(n.memory, n.memoryAllocatable) ?? pct(n.memoryRequests, n.memoryAllocatable),
            cell: (n) => <NodeMeter kind="mem" used={n.memory} requests={n.memoryRequests} limits={n.memoryLimits} allocatable={n.memoryAllocatable} />,
          },
        ] as Column<NodeRow>[])),
  ];

  const ago = data ? Math.max(0, Math.round((now - Date.parse(data.generatedAt)) / 1000)) : 0;
  const notReady = (data?.nodes ?? []).filter((n) => !n.ready).length;

  return (
    <Layout user={user} liveEvents={{ open: eventsOpen, connected: eventsLive }}>
      <div className="flex flex-col gap-4">
        <header className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <h1 className="flex items-center gap-2 text-lg font-semibold tracking-tight text-slate-900 dark:text-slate-50">
            <Server size={20} className="text-brand-500" aria-hidden="true" />
            {t('nodes.title')}
          </h1>
          {data && (
            <span className="text-xs text-slate-500 dark:text-slate-400">
              {t('nodes.count', { count: data.nodes.length })}
              {notReady > 0 && ` · ${t('nodes.notReadyCount', { count: notReady })}`}
            </span>
          )}
          <div className="ml-auto flex w-full items-center gap-3 sm:w-auto">
            <div className="relative flex-1 sm:flex-none">
              <SearchIcon size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500 dark:text-slate-400" aria-hidden="true" />
              <Input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t('nodes.search')}
                aria-label={t('nodes.search')}
                title={t('nodes.searchHint')}
                className="h-9 w-full pl-8 sm:w-72"
              />
            </div>
            {data && (
              <span className="hidden items-center gap-1.5 whitespace-nowrap text-xs text-slate-500 dark:text-slate-400 md:inline-flex" aria-live="off">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 motion-safe:animate-pulse-dot" aria-hidden="true" />
                {t('overview.updated', { seconds: ago })}
              </span>
            )}
            <Button variant="outline" size="sm" onClick={() => load(true)} aria-label={t('overview.refresh')}>
              <RefreshCw size={14} />
            </Button>
          </div>
        </header>

        {error && (
          <Alert severity={data ? 'warning' : 'error'}>
            {data ? t('overview.refreshFailed', { error }) : t('nodes.loadFailed', { error })}
          </Alert>
        )}
        {data?.note && <Alert severity="warning">{t(`nodes.note.${data.note}`, { defaultValue: t('nodes.note.error') })}</Alert>}
        {data?.metricsNote && <Alert severity="info">{t('nodes.metricsUnavailable')}</Alert>}

        {!data ? (
          !error && (
            <div className="flex min-h-[30vh] items-center justify-center">
              <Spinner size="lg" />
            </div>
          )
        ) : (
          <DataTable
            rows={rows}
            columns={columns}
            rowKey={(n) => n.name}
            onRowClick={(n) => open(n.name)}
            keyboardNav={!selected}
            pageSize={50}
            sortStorageKey="nodes"
            emptyMessage={query ? t('nodes.noMatch') : t('nodes.empty')}
          />
        )}
      </div>
      {selected && <NodeDrawer name={selected} tick={data?.generatedAt ?? ''} onClose={() => open(null)} />}
      <LiveEventsPanel namespace={null} open={eventsOpen} onClose={() => setEventsOpen(false)} initialFilter="warnings" onConnectedChange={setEventsLive} />
    </Layout>
  );
};

export default NodesPage;
