import React, { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Download, Play, RefreshCw, Save, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Alert, Badge, Button, Input, NativeSelect, Toggle } from '../../components/ui';
import { Column, DataTable, IconButton } from '../../components/DataTable';
import { confirm } from '../../components/ConfirmDialog';
import CastPlayerModal from '../../components/CastPlayerModal';
import {
  deleteRecording,
  downloadRecordingCast,
  getRecordingSettings,
  listRecordings,
  RecordingDiskPolicy,
  RecordingFilter,
  RecordingSettings,
  RecordingUsage,
  SessionRecording,
  updateRecordingSettings,
} from '../../services/api';
import { formatBytes, formatDuration } from '../../utils/format';

const PAGE_SIZE = 50;

// ─── Settings ────────────────────────────────────────────────────────────────

export const RecordingSettingsPanel: React.FC = () => {
  const { t } = useTranslation();
  const [settings, setSettings] = useState<RecordingSettings | null>(null);
  const [usage, setUsage] = useState<RecordingUsage | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await getRecordingSettings();
      setSettings(res.settings);
      setUsage(res.usage);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const save = async () => {
    if (!settings) return;
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const res = await updateRecordingSettings(settings);
      setSettings(res.settings);
      setNotice(t('recordings.settingsSaved'));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  if (!settings) {
    return error ? <Alert severity="error">{error}</Alert> : null;
  }

  const num = (key: keyof RecordingSettings) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setSettings({ ...settings, [key]: Number.parseInt(e.target.value, 10) || 0 });

  const usedPct = usage && usage.maxTotalBytes > 0
    ? Math.min(100, Math.round((usage.usedBytes / usage.maxTotalBytes) * 100))
    : 0;

  return (
    <div className="flex flex-col gap-4">
      {usage && !usage.dirWritable && (
        <Alert severity="error">
          <AlertTriangle size={14} className="mr-1 inline" />
          {t('recordings.dirUnwritable', { dir: usage.dir, error: usage.dirError ?? '' })}
        </Alert>
      )}
      {usage?.limitReached && (
        <Alert severity="warning">
          <AlertTriangle size={14} className="mr-1 inline" />
          {settings.diskPolicy === 'stop' ? t('recordings.limitReachedStop') : t('recordings.limitReachedEvict')}
        </Alert>
      )}

      <Toggle
        checked={settings.enabled}
        onChange={(enabled) => setSettings({ ...settings, enabled })}
        label={t('recordings.enabled')}
      />

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Input
          type="number"
          min={0}
          label={t('recordings.retentionDays')}
          value={settings.retentionDays}
          onChange={num('retentionDays')}
        />
        <Input
          type="number"
          min={1}
          max={1024}
          label={t('recordings.maxSessionMb')}
          value={settings.maxSessionMb}
          onChange={num('maxSessionMb')}
        />
        <Input
          type="number"
          min={1}
          label={t('recordings.maxTotalMb')}
          value={settings.maxTotalMb}
          onChange={num('maxTotalMb')}
        />
        <Input
          type="number"
          min={0}
          label={t('recordings.minFreeMb')}
          value={settings.minFreeMb}
          onChange={num('minFreeMb')}
        />
        <NativeSelect
          label={t('recordings.diskPolicy')}
          value={settings.diskPolicy}
          onChange={(e) => setSettings({ ...settings, diskPolicy: e.target.value as RecordingDiskPolicy })}
        >
          <option value="evict_oldest">{t('recordings.policyEvict')}</option>
          <option value="stop">{t('recordings.policyStop')}</option>
        </NativeSelect>
      </div>
      <p className="text-xs text-slate-500 dark:text-slate-400">
        {t('recordings.settingsHelp')}
      </p>

      {usage && (
        <div className="flex flex-col gap-1.5">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600 dark:text-slate-300">
            <span>
              {t('recordings.usage', {
                used: formatBytes(usage.usedBytes),
                max: formatBytes(usage.maxTotalBytes),
                count: usage.count,
              })}
              {usage.activeCount > 0 && ` · ${t('recordings.activeNow', { count: usage.activeCount })}`}
            </span>
            <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
              {usage.freeBytes >= 0 && t('recordings.diskFree', { free: formatBytes(usage.freeBytes) })} · {usage.dir}
            </span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
            <div
              className={`h-full rounded-full ${usedPct >= 90 ? 'bg-rose-500' : usedPct >= 70 ? 'bg-amber-500' : 'bg-brand-500'}`}
              style={{ width: `${usedPct}%` }}
            />
          </div>
        </div>
      )}

      {error && <Alert severity="error">{error}</Alert>}
      {notice && <Alert severity="success">{notice}</Alert>}

      <div className="flex justify-end">
        <Button variant="primary" size="sm" onClick={save} disabled={saving}>
          <Save size={14} />
          {t('actions.save')}
        </Button>
      </div>
    </div>
  );
};

// ─── List ────────────────────────────────────────────────────────────────────

const emptyFilter: RecordingFilter = { user: '', namespace: '', pod: '', from: '', to: '' };

export const RecordingsSection: React.FC = () => {
  const { t } = useTranslation();
  const [rows, setRows] = useState<SessionRecording[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [draft, setDraft] = useState<RecordingFilter>(emptyFilter);
  const [filter, setFilter] = useState<RecordingFilter>(emptyFilter);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [playing, setPlaying] = useState<SessionRecording | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await listRecordings({ ...filter, limit: PAGE_SIZE, offset });
      setRows(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [filter, offset]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const applyFilter = (e?: React.FormEvent) => {
    e?.preventDefault();
    setOffset(0);
    setFilter({ ...draft });
  };

  const clearFilter = () => {
    setDraft(emptyFilter);
    setOffset(0);
    setFilter(emptyFilter);
  };

  const handleDelete = async (row: SessionRecording) => {
    const ok = await confirm({
      title: t('recordings.deleteTitle'),
      message: t('recordings.deleteBody', {
        user: row.user,
        target: `${row.namespace}/${row.pod}`,
        started: new Date(row.startedAt).toLocaleString(),
      }),
      confirmText: t('actions.delete'),
      variant: 'danger',
    });
    if (!ok) return;
    try {
      await deleteRecording(row.id);
      setNotice(t('recordings.deleted'));
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleDownload = async (row: SessionRecording) => {
    try {
      await downloadRecordingCast(row.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const columns: Column<SessionRecording>[] = [
    {
      key: 'user',
      header: t('recordings.user'),
      cell: (row) => (
        <span className="font-mono text-[13px] font-medium text-slate-900 dark:text-slate-100">{row.user}</span>
      ),
    },
    {
      key: 'target',
      header: t('recordings.target'),
      cell: (row) => (
        <div className="flex flex-col text-[12px] leading-tight">
          <span className="font-mono text-slate-800 dark:text-slate-100">
            {row.namespace}/{row.pod}
          </span>
          <span className="text-[11px] text-slate-500 dark:text-slate-400">
            {[row.container, row.cluster].filter(Boolean).join(' · ') || '—'}
          </span>
        </div>
      ),
    },
    {
      key: 'started',
      header: t('recordings.started'),
      align: 'right',
      cell: (row) => (
        <span className="font-mono text-[11px] text-slate-600 dark:text-slate-300" title={row.startedAt}>
          {new Date(row.startedAt).toLocaleString()}
        </span>
      ),
    },
    {
      key: 'duration',
      header: t('recordings.duration'),
      align: 'right',
      cell: (row) =>
        row.endedAt ? (
          <span className="font-mono text-[11px]">{formatDuration(row.durationMs)}</span>
        ) : (
          <Badge variant="info">{t('recordings.inProgress')}</Badge>
        ),
    },
    {
      key: 'size',
      header: t('recordings.size'),
      align: 'right',
      cell: (row) => (
        <div className="flex items-center justify-end gap-1.5">
          {row.truncated && <Badge variant="warning">{t('recordings.truncated')}</Badge>}
          <span className="font-mono text-[11px]">{row.endedAt ? formatBytes(row.sizeBytes) : '—'}</span>
        </div>
      ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      width: '120px',
      cell: (row) => (
        <div className="flex justify-end gap-1">
          <IconButton label={t('recordings.play')} onClick={() => setPlaying(row)}>
            <Play size={14} />
          </IconButton>
          <IconButton label={t('recordings.download')} onClick={() => handleDownload(row)}>
            <Download size={14} />
          </IconButton>
          {row.endedAt && (
            <IconButton label={t('recordings.delete')} variant="danger" onClick={() => handleDelete(row)}>
              <Trash2 size={14} />
            </IconButton>
          )}
        </div>
      ),
    },
  ];

  const setField = (key: keyof RecordingFilter) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setDraft({ ...draft, [key]: e.target.value });

  return (
    <div className="flex flex-col gap-3">
      <form onSubmit={applyFilter} className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-6">
        <Input placeholder={t('recordings.user')} value={draft.user} onChange={setField('user')} />
        <Input placeholder={t('recordings.namespace')} value={draft.namespace} onChange={setField('namespace')} />
        <Input placeholder={t('recordings.pod')} value={draft.pod} onChange={setField('pod')} />
        <Input type="date" aria-label={t('recordings.from')} title={t('recordings.from')} value={draft.from} onChange={setField('from')} />
        <Input type="date" aria-label={t('recordings.to')} title={t('recordings.to')} value={draft.to} onChange={setField('to')} />
        <div className="flex gap-2">
          <Button type="submit" variant="primary" size="sm" className="flex-1">
            {t('recordings.applyFilter')}
          </Button>
          <Button type="button" variant="outline" size="sm" onClick={clearFilter}>
            {t('recordings.clearFilter')}
          </Button>
        </div>
      </form>

      <div className="flex items-center justify-between gap-3">
        <span className="text-xs text-slate-500 dark:text-slate-400">
          {total > 0
            ? t('recordings.range', { from: offset + 1, to: Math.min(offset + PAGE_SIZE, total), total })
            : t('recordings.none')}
        </span>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
            {t('admin.audit.prev')}
          </Button>
          <Button variant="outline" size="sm" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
            {t('admin.audit.next')}
          </Button>
          <Button variant="outline" size="sm" onClick={refresh} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            {t('actions.refresh')}
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

      <DataTable
        rows={rows}
        columns={columns}
        rowKey={(r) => r.id}
        pageSize={PAGE_SIZE}
        emptyMessage={t('recordings.none')}
      />

      <CastPlayerModal recording={playing} onClose={() => setPlaying(null)} />
    </div>
  );
};

export default RecordingsSection;
