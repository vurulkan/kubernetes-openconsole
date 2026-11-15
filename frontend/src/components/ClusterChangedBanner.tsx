import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CLUSTER_PICK_KEY, listClustersPublic, tabClusterId } from '../services/api';
import { Alert, Button } from './ui';

type Change = { name: string; current: string };

/**
 * Another tab picked a cluster: this tab keeps working on the cluster it
 * shows (every request names it) and says so, with a way to follow.
 */
const ClusterChangedBanner: React.FC = () => {
  const { t } = useTranslation();
  const [change, setChange] = useState<Change | null>(null);

  useEffect(() => {
    const onStorage = async (e: StorageEvent) => {
      if (e.key !== CLUSTER_PICK_KEY || !e.newValue) return;
      const tab = tabClusterId();
      if (!tab) return;
      try {
        const pick = JSON.parse(e.newValue) as { id: number };
        const { items } = await listClustersPublic();
        // id 0 = back to the default cluster.
        const picked = pick.id > 0 ? items.find((c) => c.id === pick.id) : items.find((c) => c.isActive);
        const current = items.find((c) => c.id === tab);
        if (!picked || !current || picked.id === tab) {
          setChange(null);
          return;
        }
        setChange({ name: picked.name, current: current.name });
      } catch {
        /* nothing to show */
      }
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  if (!change) return null;
  return (
    <Alert severity="warning" className="mb-4">
      <div role="status" className="flex flex-wrap items-center gap-3">
        <span className="flex-1">{t('clusterSwitcher.otherTab', change)}</span>
        <Button size="sm" onClick={() => window.location.reload()}>
          {t('clusterSwitcher.follow', change)}
        </Button>
        <Button size="sm" variant="ghost" onClick={() => setChange(null)}>
          {t('clusterSwitcher.dismiss', change)}
        </Button>
      </div>
    </Alert>
  );
};

export default ClusterChangedBanner;
