import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Activity, Boxes, Pencil, Power, PowerOff, Trash2 } from 'lucide-react';
import { Alert, Badge, Button, Checkbox, Input, Modal, NativeSelect } from '../../components/ui';
import { confirm } from '../../components/ConfirmDialog';
import {
  activateCluster,
  createCluster,
  deactivateCluster,
  deleteClusterRow,
  listClustersAdmin,
  updateClusterRow,
  type ClusterListItem,
} from '../../services/api';
import { PrometheusSettingsModal } from './PrometheusSettings';
import { SectionCard } from './SectionCard';

type Method = 'kubeconfig' | 'token';

type EditCluster = {
  id: number;
  name: string;
  description: string;
  method: Method;
  replaceSecrets: boolean;
  kubeconfigBase64: string;
  kubeconfigName: string;
  token: string;
  server: string;
  caCertBase64: string;
  removeCaCert: boolean;
  error: string;
};

/** Reads a picked file as base64 (the data URL without its prefix). */
const readBase64 = (file: File, done: (base64: string) => void) => {
  const reader = new FileReader();
  reader.onload = () => {
    const result = reader.result?.toString() ?? '';
    done(result.includes(',') ? result.split(',')[1] : result);
  };
  reader.readAsDataURL(file);
};

const fileButton =
  'inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800';

/**
 * Admin → Clusters: the saved clusters (set as default / stop being the
 * default, edit, Prometheus, delete) and the add form. Loads only the cluster list.
 */
export const ClustersSection: React.FC = () => {
  const { t: tr } = useTranslation();
  const [clusters, setClusters] = useState<ClusterListItem[]>([]);
  const [status, setStatus] = useState<{ status: 'success' | 'error'; message: string } | null>(null);
  const [busy, setBusy] = useState<number | 'create' | null>(null);
  const [promCluster, setPromCluster] = useState<{ id: number; name: string } | null>(null);
  const [editCluster, setEditCluster] = useState<EditCluster | null>(null);
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newMethod, setNewMethod] = useState<Method>('kubeconfig');
  const [newKubeconfig, setNewKubeconfig] = useState('');
  const [newKubeconfigName, setNewKubeconfigName] = useState('');
  const [newToken, setNewToken] = useState('');
  const [newServer, setNewServer] = useState('');
  const [newCA, setNewCA] = useState('');

  const reload = async () => {
    const refreshed = await listClustersAdmin();
    setClusters(refreshed.items ?? []);
  };

  useEffect(() => {
    listClustersAdmin()
      .then((r) => setClusters(r.items ?? []))
      .catch(() => setClusters([]));
  }, []);

  // Setting / unsetting the default reloads the app: every screen follows it.
  const switchDefault = async (c: ClusterListItem, on: boolean) => {
    setBusy(c.id);
    setStatus(null);
    try {
      if (on) await activateCluster(c.id);
      else await deactivateCluster(c.id);
      const done = on ? tr('common.activated', { name: c.name }) : tr('common.deactivated', { name: c.name });
      setStatus({ status: 'success', message: done });
      setTimeout(() => window.location.reload(), 600);
    } catch (err) {
      const failed = on ? tr('common.activateFailed', { name: c.name }) : tr('common.deactivateFailed', { name: c.name });
      setStatus({ status: 'error', message: (err as Error).message || failed });
    } finally {
      setBusy(null);
    }
  };

  const remove = async (c: ClusterListItem) => {
    const ok = await confirm({
      title: tr('common.deleteCluster', { name: c.name }),
      message: tr('admin.clusters.deleteConfirm'),
      confirmText: tr('actions.delete'),
      variant: 'danger',
    });
    if (!ok) return;
    setBusy(c.id);
    setStatus(null);
    try {
      await deleteClusterRow(c.id);
      await reload();
    } catch (err) {
      setStatus({ status: 'error', message: (err as Error).message || tr('common.deleteFailed') });
    } finally {
      setBusy(null);
    }
  };

  const create = async () => {
    setBusy('create');
    setStatus(null);
    try {
      await createCluster({
        name: newName,
        description: newDesc,
        method: newMethod,
        kubeconfigBase64: newKubeconfig || undefined,
        token: newToken || undefined,
        server: newServer || undefined,
        caCertBase64: newCA || undefined,
      });
      setNewName('');
      setNewDesc('');
      setNewKubeconfig('');
      setNewKubeconfigName('');
      setNewToken('');
      setNewServer('');
      setNewCA('');
      await reload();
      setStatus({ status: 'success', message: tr('common.clusterAdded') });
    } catch (err) {
      setStatus({ status: 'error', message: (err as Error).message || tr('common.createFailed') });
    } finally {
      setBusy(null);
    }
  };

  const saveEdit = async () => {
    if (!editCluster) return;
    setBusy(editCluster.id);
    setStatus(null);
    setEditCluster((c) => c && { ...c, error: '' });
    try {
      await updateClusterRow(editCluster.id, {
        name: editCluster.name,
        description: editCluster.description,
        method: editCluster.method,
        replaceSecrets: editCluster.replaceSecrets,
        kubeconfigBase64: editCluster.replaceSecrets ? editCluster.kubeconfigBase64 || undefined : undefined,
        token: editCluster.replaceSecrets ? editCluster.token || undefined : undefined,
        server: editCluster.replaceSecrets ? editCluster.server || undefined : undefined,
        caCertBase64: editCluster.replaceSecrets ? editCluster.caCertBase64 || undefined : undefined,
        removeCaCert: editCluster.replaceSecrets && editCluster.removeCaCert,
      });
      await reload();
      setStatus({ status: 'success', message: tr('common.clusterUpdated') });
      setEditCluster(null);
    } catch (err) {
      // Shown in the dialog, which stays open for a fix.
      setEditCluster((c) => c && { ...c, error: (err as Error).message || tr('common.updateFailed') });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="flex flex-col gap-5">
      <SectionCard title={tr('admin.cards.configuredClusters')} description={tr('admin.cards.configuredClustersDesc')}>
        {status && (
          <Alert severity={status.status} className="mb-4">
            {status.message}
          </Alert>
        )}
        {clusters.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">{tr('admin.clusters.noneSaved')}</p>
        ) : (
          <div className="flex flex-col gap-2">
            {clusters.map((c) => (
              <div
                key={c.id}
                className={`flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3 ${
                  c.isActive
                    ? 'border-brand-200 bg-brand-50/40 dark:border-brand-500/30 dark:bg-brand-500/10'
                    : 'border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900/40'
                }`}
              >
                <div className="flex min-w-0 items-center gap-3">
                  <div
                    className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md ${
                      c.isActive ? 'bg-brand-500 text-white' : 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400'
                    }`}
                  >
                    <Boxes size={14} />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">{c.name}</span>
                      {c.isActive && <Badge variant="success">{tr('common.defaultCluster')}</Badge>}
                    </div>
                    <div className="truncate text-xs text-slate-500 dark:text-slate-400">
                      {c.description || c.server || tr('common.methodLabel', { method: c.method })}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {c.isActive ? (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={busy !== null}
                      onClick={async () => {
                        const ok = await confirm({
                          title: tr('common.deactivateTitle', { name: c.name }),
                          message: tr('common.deactivateMessage'),
                          confirmText: tr('common.deactivate'),
                          variant: 'danger',
                        });
                        if (ok) await switchDefault(c, false);
                      }}
                    >
                      <PowerOff size={13} />
                      {tr('common.deactivate')}
                    </Button>
                  ) : (
                    <Button variant="outline" size="sm" disabled={busy !== null} onClick={() => switchDefault(c, true)}>
                      <Power size={13} />
                      {tr('common.activate')}
                    </Button>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={busy !== null}
                    onClick={() =>
                      setEditCluster({
                        id: c.id,
                        name: c.name,
                        description: c.description ?? '',
                        method: (c.method as Method) || 'kubeconfig',
                        replaceSecrets: false,
                        kubeconfigBase64: '',
                        kubeconfigName: '',
                        token: '',
                        server: c.server ?? '',
                        caCertBase64: '',
                        removeCaCert: false,
                        error: '',
                      })
                    }
                  >
                    <Pencil size={13} />
                    {tr('actions.edit')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={busy !== null}
                    onClick={() => setPromCluster({ id: c.id, name: c.name })}
                  >
                    <Activity size={13} />
                    {tr('prometheus.button')}
                  </Button>
                  <Button variant="danger" size="sm" disabled={c.isActive || busy !== null} onClick={() => remove(c)}>
                    <Trash2 size={13} />
                    {tr('actions.delete')}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </SectionCard>

      <SectionCard title={tr('admin.cards.addCluster')} description={tr('admin.cards.addClusterDesc')}>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Input
            label={tr('common.name')}
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder={tr('common.clusterNamePlaceholder')}
          />
          <Input
            label={tr('common.description')}
            value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)}
            placeholder={tr('common.optional')}
          />
          <NativeSelect label={tr('common.method')} value={newMethod} onChange={(e) => setNewMethod(e.target.value as Method)}>
            <option value="kubeconfig">{tr('common.kubeconfig')}</option>
            <option value="token">{tr('common.serviceAccountToken')}</option>
          </NativeSelect>
          {newMethod === 'kubeconfig' && (
            <div className="flex flex-col gap-1">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                {tr('common.kubeconfigFile')}
              </span>
              <label className={fileButton}>
                {tr('common.uploadKubeconfig')}
                <input
                  type="file"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (!file) {
                      setNewKubeconfig('');
                      setNewKubeconfigName('');
                      return;
                    }
                    readBase64(file, (base64) => {
                      setNewKubeconfig(base64);
                      setNewKubeconfigName(file.name);
                    });
                  }}
                />
              </label>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                {newKubeconfigName || tr('common.noFileSelected')}
              </span>
            </div>
          )}
          {newMethod === 'token' && (
            <>
              <Input
                label={tr('common.apiServer')}
                value={newServer}
                onChange={(e) => setNewServer(e.target.value)}
                placeholder={tr('common.httpsExample')}
              />
              <Input label={tr('common.token')} value={newToken} onChange={(e) => setNewToken(e.target.value)} />
              <Input label={tr('common.caCert')} value={newCA} onChange={(e) => setNewCA(e.target.value)} />
            </>
          )}
        </div>
        <Button variant="primary" size="sm" className="mt-4" disabled={busy !== null || !newName} onClick={create}>
          {tr('common.saveCluster')}
        </Button>
      </SectionCard>

      {promCluster && <PrometheusSettingsModal cluster={promCluster} onClose={() => setPromCluster(null)} />}

      {/* ── Edit cluster modal ───────────────────────────────────── */}
      {editCluster && (
        <Modal
          open={editCluster !== null}
          onClose={() => setEditCluster(null)}
          title={tr('common.editClusterTitle', { name: editCluster.name })}
          size="md"
          footer={
            <>
              <Button variant="outline" size="sm" onClick={() => setEditCluster(null)}>
                {tr('actions.cancel')}
              </Button>
              <Button variant="primary" size="sm" disabled={busy !== null || !editCluster.name} onClick={saveEdit}>
                {tr('common.saveChanges')}
              </Button>
            </>
          }
        >
          <div className="flex flex-col gap-3">
            <Input
              label={tr('common.name')}
              value={editCluster.name}
              onChange={(e) => setEditCluster({ ...editCluster, name: e.target.value })}
            />
            <Input
              label={tr('common.description')}
              value={editCluster.description}
              onChange={(e) => setEditCluster({ ...editCluster, description: e.target.value })}
            />
            <Checkbox
              checked={editCluster.replaceSecrets}
              onChange={(v) => setEditCluster({ ...editCluster, replaceSecrets: v })}
              label={tr('common.replaceCreds')}
            />
            {editCluster.replaceSecrets && (
              <>
                <NativeSelect
                  label={tr('common.method')}
                  value={editCluster.method}
                  onChange={(e) => setEditCluster({ ...editCluster, method: e.target.value as Method })}
                >
                  <option value="kubeconfig">{tr('common.kubeconfig')}</option>
                  <option value="token">{tr('common.serviceAccountToken')}</option>
                </NativeSelect>
                {editCluster.method === 'kubeconfig' && (
                  <div className="flex flex-col gap-1">
                    <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                      {tr('common.newKubeconfig')}
                    </span>
                    <label className={fileButton}>
                      {tr('common.uploadKubeconfig')}
                      <input
                        type="file"
                        className="hidden"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          if (!file) {
                            setEditCluster({ ...editCluster, kubeconfigBase64: '', kubeconfigName: '' });
                            return;
                          }
                          readBase64(file, (base64) =>
                            setEditCluster({ ...editCluster, kubeconfigBase64: base64, kubeconfigName: file.name }),
                          );
                        }}
                      />
                    </label>
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      {editCluster.kubeconfigName || tr('common.noFileSelected')}
                    </span>
                  </div>
                )}
                {editCluster.method === 'token' && (
                  <>
                    <Input
                      label={tr('common.apiServer')}
                      value={editCluster.server}
                      onChange={(e) => setEditCluster({ ...editCluster, server: e.target.value })}
                    />
                    <Input
                      label={tr('common.token')}
                      value={editCluster.token}
                      onChange={(e) => setEditCluster({ ...editCluster, token: e.target.value })}
                    />
                    <Input
                      label={tr('common.caCert')}
                      value={editCluster.caCertBase64}
                      disabled={editCluster.removeCaCert}
                      aria-describedby="edit-cluster-ca-hint"
                      onChange={(e) => setEditCluster({ ...editCluster, caCertBase64: e.target.value })}
                    />
                    <p id="edit-cluster-ca-hint" className="-mt-2 text-xs text-slate-500 dark:text-slate-400">
                      {tr('common.caKeepHint')}
                    </p>
                    <Checkbox
                      checked={editCluster.removeCaCert}
                      onChange={(v) => setEditCluster({ ...editCluster, removeCaCert: v, caCertBase64: '' })}
                      label={tr('common.removeCa')}
                    />
                  </>
                )}
              </>
            )}
            {editCluster.error && <Alert severity="error">{editCluster.error}</Alert>}
          </div>
        </Modal>
      )}
    </div>
  );
};

export default ClustersSection;
