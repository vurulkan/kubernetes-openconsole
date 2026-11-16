import React, { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, DatabaseBackup, Download, RefreshCw } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Alert, Button } from '../../components/ui';
import { Column, DataTable, IconButton } from '../../components/DataTable';
import {
  BackupInfo,
  BackupList,
  createBackup,
  downloadBackup,
  listBackups,
} from '../../services/api';
import { formatBytes, formatDuration } from '../../utils/format';

// Admin → Backups: copies of the database the server makes on a schedule,
// before an upgrade, and on demand here. A copy holds every stored
// credential, so downloading is off unless BACKUP_ALLOW_DOWNLOAD=true is set
// on the Deployment (not here: an admin account alone can't turn it on).
export const BackupsSection: React.FC = () => {
  const { t } = useTranslation();
  const [data, setData] = useState<BackupList | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await listBackups());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const backUpNow = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const made = await createBackup();
      setNotice(t('backups.made', { name: made.name }));
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const download = async (row: BackupInfo) => {
    setError(null);
    try {
      await downloadBackup(row.name);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const columns: Column<BackupInfo>[] = [
    {
      key: 'name',
      header: t('backups.file'),
      cell: (row) => (
        <span className="font-mono text-[13px] text-slate-900 dark:text-slate-100">{row.name}</span>
      ),
    },
    {
      key: 'created',
      header: t('backups.created'),
      cell: (row) => (
        <span className="font-mono text-[12px] text-slate-600 dark:text-slate-300">
          {new Date(row.createdAt).toLocaleString()}
        </span>
      ),
    },
    {
      key: 'size',
      header: t('backups.size'),
      align: 'right',
      cell: (row) => (
        <span className="font-mono text-[12px] text-slate-600 dark:text-slate-300">{formatBytes(row.sizeBytes)}</span>
      ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      width: '56px',
      cell: (row) =>
        data?.allowDownload ? (
          <IconButton label={t('backups.download', { name: row.name })} onClick={() => download(row)}>
            <Download size={14} />
          </IconButton>
        ) : (
          <span className="text-xs text-slate-300 dark:text-slate-600">—</span>
        ),
    },
  ];

  const schedule =
    data && data.intervalSeconds > 0
      ? t('backups.schedule', { every: formatDuration(data.intervalSeconds * 1000), keep: data.keep, dir: data.dir })
      : data
        ? t('backups.noSchedule', { keep: data.keep, dir: data.dir })
        : '';

  return (
    <div className="flex flex-col gap-3">
      {data && !data.keyExternal && (
        <Alert severity="warning">
          <AlertTriangle size={14} className="mr-1 inline" />
          {t('backups.keyInside')}
        </Alert>
      )}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-col gap-1 text-xs text-slate-500 dark:text-slate-400">
          <span>{schedule}</span>
          {data && <span>{data.allowDownload ? t('backups.downloadOn') : t('backups.downloadOff')}</span>}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={refresh} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            {t('dashboard.refresh')}
          </Button>
          <Button size="sm" onClick={backUpNow} disabled={busy}>
            <DatabaseBackup size={14} />
            {busy ? t('backups.working') : t('backups.now')}
          </Button>
        </div>
      </div>

      {error && (
        <Alert severity="error">
          <AlertTriangle size={14} className="mr-1 inline" />
          {error}
        </Alert>
      )}
      {notice && <Alert severity="success">{notice}</Alert>}

      <DataTable keyboardNav rows={data?.items ?? []} columns={columns} rowKey={(r) => r.name} emptyMessage={t('backups.none')} />
    </div>
  );
};

export default BackupsSection;
