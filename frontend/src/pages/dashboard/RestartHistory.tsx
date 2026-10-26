import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Spinner } from '../../components/ui';
import type { ContainerTermination } from '../../services/api';
import { ageShort } from '../../utils/age';
import { exitCodeHint, exitLabel } from '../../utils/podStatus';
import { Empty } from './DetailParts';

const DAY = 24 * 60 * 60 * 1000;
const clock = (iso: string) => new Date(iso).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
const isCrash = (t: ContainerTermination) => t.reason === 'OOMKilled' || (t.exitCode !== 0 && t.exitCode !== 143);

/**
 * Restart history recorded by OpenConsole (kept after the pod is gone): a
 * last-24-hours summary by cause, then the runs of identical exits.
 */
export const RestartHistory: React.FC<{
  load: () => Promise<{ items: ContainerTermination[] }>;
  reloadKey: unknown;
  showPod: boolean;
}> = ({ load, reloadKey, showPod }) => {
  const { t } = useTranslation();
  const [items, setItems] = useState<ContainerTermination[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [all, setAll] = useState(false);
  useEffect(() => {
    let live = true;
    load()
      .then((r) => live && (setItems(r.items), setFailed(false)))
      .catch(() => live && setFailed(true));
    return () => {
      live = false;
    };
    // load is a new closure on every render; reloadKey says when to refetch.
  }, [reloadKey]);

  if (failed) return <Empty>{t('dashboard.restarts.failed')}</Empty>;
  if (!items) return <Spinner size="sm" />;
  if (!items.length) return <Empty>{t('dashboard.restarts.none')}</Empty>;

  // Runs that ended in the last day; a run's count may include older exits, which is fine for a summary.
  const recent = items.filter((i) => Date.now() - Date.parse(i.lastAt) < DAY);
  const byCause = new Map<string, number>();
  for (const i of recent) {
    const key = exitLabel(i);
    byCause.set(key, (byCause.get(key) ?? 0) + i.count);
  }
  const total = [...byCause.values()].reduce((a, b) => a + b, 0);
  const shown = all ? items : items.slice(0, 10);

  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs text-slate-600 dark:text-slate-300">
        {total
          ? t('dashboard.restarts.summary', {
              count: total,
              causes: [...byCause.entries()].sort((a, b) => b[1] - a[1]).map(([k, n]) => `${n}× ${k}`).join(', '),
            })
          : t('dashboard.restarts.quietDay')}
      </p>
      <ul className="flex flex-col gap-1.5">
        {shown.map((i) => {
          const hint = exitCodeHint(i);
          return (
            <li
              key={`${i.pod}/${i.container}/${i.lastAt}`}
              className="rounded-md border border-slate-200 px-2.5 py-1.5 text-xs dark:border-slate-800"
              title={t(hint.key, { signal: hint.signal })}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="min-w-0 truncate font-mono">
                  <span className={isCrash(i) ? 'text-rose-600 dark:text-rose-300' : 'text-slate-600 dark:text-slate-300'}>
                    {exitLabel(i)}
                  </span>
                  {i.count > 1 && <span className="ml-1.5 text-amber-700 dark:text-amber-300">×{i.count}</span>}
                  <span className="ml-2 text-slate-500 dark:text-slate-400">
                    {showPod ? `${i.pod} / ` : ''}
                    {i.container}
                  </span>
                </span>
                <span className="shrink-0 font-mono text-[10px] text-slate-500 dark:text-slate-400">
                  {i.count > 1 ? `${clock(i.firstAt)} – ${clock(i.lastAt)}` : t('dashboard.podStatus.ago', { age: ageShort(i.lastAt) })}
                </span>
              </div>
            </li>
          );
        })}
      </ul>
      {items.length > shown.length && (
        <div>
          <Button variant="ghost" size="sm" onClick={() => setAll(true)}>
            {t('dashboard.restarts.showAll', { count: items.length })}
          </Button>
        </div>
      )}
    </div>
  );
};
