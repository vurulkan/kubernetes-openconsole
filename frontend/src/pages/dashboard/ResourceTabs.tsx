import React from 'react';
import {
  Boxes,
  Calendar,
  Database,
  FileText,
  Gauge,
  Globe,
  HardDrive,
  KeyRound,
  LayoutGrid,
  List as ListIcon,
  ListChecks,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';

const RESOURCE_META: Record<
  string,
  { label: string; icon: React.ComponentType<{ size?: number | string; className?: string }> }
> = {
  pods: { label: 'Pods', icon: Boxes },
  deployments: { label: 'Deployments', icon: LayoutGrid },
  daemonsets: { label: 'DaemonSets', icon: HardDrive },
  statefulsets: { label: 'StatefulSets', icon: Database },
  hpas: { label: 'HPAs', icon: Gauge },
  services: { label: 'Services', icon: Globe },
  configmaps: { label: 'ConfigMaps', icon: FileText },
  secrets: { label: 'Secrets', icon: KeyRound },
  ingresses: { label: 'Ingresses', icon: Globe },
  cronjobs: { label: 'CronJobs', icon: Calendar },
  jobs: { label: 'Jobs', icon: ListChecks },
};

/** The Dashboard's tab bar: one tab per resource the user may list here, then the card / list switch. */
export const ResourceTabs: React.FC<{
  resources: string[];
  active: string;
  onSelect: (resource: string) => void;
  viewMode: 'card' | 'list';
  onViewMode: (mode: 'card' | 'list') => void;
}> = ({ resources, active: activeTab, onSelect, viewMode, onViewMode }) => {
  const { t } = useTranslation();
  return (
    <div className="border-b border-slate-200 dark:border-slate-800/70 bg-white dark:bg-slate-900">
      <div className="flex items-center gap-1 overflow-x-auto px-3 py-2">
        {resources.length === 0 && (
          <p className="px-2 py-2 text-xs text-slate-500 dark:text-slate-400">
            {t('dashboard.noResourcePerms')}
          </p>
        )}
        {resources.map((resource) => {
          const meta = RESOURCE_META[resource];
          const Icon = meta?.icon ?? Boxes;
          const active = activeTab === resource;
          return (
            <button
              key={resource}
              onClick={() => onSelect(resource)}
              className={`group inline-flex shrink-0 items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold uppercase tracking-wide transition-all duration-150 focus:outline-none ${
                active
                  ? 'bg-brand-50 dark:bg-brand-500/15 text-brand-700 dark:text-brand-200 ring-1 ring-inset ring-brand-200 dark:ring-brand-500/30'
                  : 'text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 dark:bg-slate-800 hover:text-slate-800 dark:hover:text-slate-100 dark:text-slate-100'
              }`}
            >
              <Icon
                size={14}
                className={active ? 'text-brand-600 dark:text-brand-300' : 'text-slate-500 dark:text-slate-400 group-hover:text-slate-600 dark:text-slate-300'}
              />
              {t(`resources.${resource}`, { defaultValue: meta?.label ?? resource })}
            </button>
          );
        })}

        {resources.length > 0 && (
          <div className="ml-auto flex shrink-0 items-center gap-0.5 rounded-lg border border-slate-200 bg-white p-0.5 dark:border-slate-700 dark:bg-slate-800">
            <button
              type="button"
              onClick={() => onViewMode('card')}
              aria-pressed={viewMode === 'card'}
              aria-label={t('dashboard.cardView')}
              title={t('dashboard.cardView')}
              className={`flex h-7 w-7 items-center justify-center rounded-md transition-colors ${
                viewMode === 'card'
                  ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200'
                  : 'text-slate-500 hover:bg-slate-100 hover:text-slate-800 dark:text-slate-400 dark:hover:bg-slate-700 dark:hover:text-slate-100'
              }`}
            >
              <LayoutGrid size={14} />
            </button>
            <button
              type="button"
              onClick={() => onViewMode('list')}
              aria-pressed={viewMode === 'list'}
              aria-label={t('dashboard.listView')}
              title={t('dashboard.listView')}
              className={`flex h-7 w-7 items-center justify-center rounded-md transition-colors ${
                viewMode === 'list'
                  ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200'
                  : 'text-slate-500 hover:bg-slate-100 hover:text-slate-800 dark:text-slate-400 dark:hover:bg-slate-700 dark:hover:text-slate-100'
              }`}
            >
              <ListIcon size={14} />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
