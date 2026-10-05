import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Eye, Pencil, PlayCircle, Save } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Alert, Badge, Button, Modal } from './ui';
import { confirm } from './ConfirmDialog';
import { YamlDiff, YamlEditor } from './MonacoYaml';
import { applyYaml } from '../services/api';

type YamlFetcher = (namespace: string, name: string) => Promise<{ yaml: string }>;

export type YamlEditTarget = {
  resource: string; // URL segment, e.g. "deployments"
  resourceLabel: string; // human label, e.g. "Deployment"
  namespace: string;
  name: string;
  fetchYaml: YamlFetcher;
  // If false, Edit toggle is hidden — view-only for operators without the
  // edit permission on this resource.
  canEdit: boolean;
};

type Props = {
  target: YamlEditTarget | null;
  onClose: () => void;
  // Called after a successful write so the Dashboard can refresh the list.
  onApplied?: () => void;
  theme: 'light' | 'dark';
};

/**
 * Single modal that handles view, edit, dry-run and apply for every workload
 * the backend accepts at POST /api/.../{resource}/{name}/apply. Opens in view
 * mode by default so a quick "look at the YAML" doesn't risk unintended edits;
 * the Edit toggle flips the body to a side-by-side diff whose right pane is
 * the editable Monaco buffer.
 */
export const YamlEditModal: React.FC<Props> = ({ target, onClose, onApplied, theme }) => {
  const { t } = useTranslation();
  const [originalYaml, setOriginalYaml] = useState('');
  const [draftYaml, setDraftYaml] = useState('');
  const [mode, setMode] = useState<'view' | 'edit'>('view');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [dryRunPreview, setDryRunPreview] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);

  // Reset per target. Each time the Dashboard opens a different resource we
  // start fresh in view mode so an edit in flight on resource A doesn't bleed
  // into resource B.
  useEffect(() => {
    if (!target) return;
    setMode('view');
    setDryRunPreview(null);
    setError(null);
    setNotice(null);
    setOriginalYaml('');
    setDraftYaml('');
    setLoading(true);
    target
      .fetchYaml(target.namespace, target.name)
      .then((res) => {
        setOriginalYaml(res.yaml);
        setDraftYaml(res.yaml);
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load YAML'))
      .finally(() => setLoading(false));
  }, [target]);

  const dirty = draftYaml !== originalYaml;

  const handleReset = useCallback(() => {
    setDraftYaml(originalYaml);
    setDryRunPreview(null);
  }, [originalYaml]);

  const handleReload = useCallback(async () => {
    if (!target) return;
    setLoading(true);
    setError(null);
    setNotice(null);
    setDryRunPreview(null);
    try {
      const { yaml } = await target.fetchYaml(target.namespace, target.name);
      setOriginalYaml(yaml);
      setDraftYaml(yaml);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Reload failed');
    } finally {
      setLoading(false);
    }
  }, [target]);

  const handleDryRun = useCallback(async () => {
    if (!target) return;
    setApplying(true);
    setError(null);
    setNotice(null);
    try {
      const res = await applyYaml(target.resource, target.namespace, target.name, draftYaml, true);
      setDryRunPreview(res.applied);
      setNotice(t('yamlEditor.dryRunOk'));
    } catch (err) {
      setDryRunPreview(null);
      setError(err instanceof Error ? err.message : 'Dry-run failed');
    } finally {
      setApplying(false);
    }
  }, [target, draftYaml]);

  const handleApply = useCallback(async () => {
    if (!target) return;
    const ok = await confirm({
      title: t('yamlEditor.confirmTitle', { kind: target.resourceLabel, name: target.name }),
      message: dryRunPreview
        ? t('yamlEditor.confirmDryOk')
        : t('yamlEditor.confirmNoDry'),
      confirmText: t('yamlEditor.apply'),
      variant: 'danger',
    });
    if (!ok) return;
    setApplying(true);
    setError(null);
    setNotice(null);
    try {
      const res = await applyYaml(target.resource, target.namespace, target.name, draftYaml, false);
      // Server returns the canonicalized object — swap it in so the next edit
      // starts from the fresh resourceVersion automatically.
      setOriginalYaml(res.applied);
      setDraftYaml(res.applied);
      setDryRunPreview(null);
      setNotice(t('yamlEditor.applied'));
      if (onApplied) onApplied();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Apply failed');
    } finally {
      setApplying(false);
    }
  }, [target, draftYaml, dryRunPreview, onApplied]);

  const monacoTheme = theme === 'dark' ? 'vs-dark' : 'vs';

  const headerBadge = useMemo(() => {
    if (loading) return <Badge variant="default">{t('common.loading')}</Badge>;
    if (mode === 'edit' && dirty) return <Badge variant="warning">{t('yamlEditor.editedBadge')}</Badge>;
    if (mode === 'edit') return <Badge variant="info">{t('yamlEditor.editingBadge')}</Badge>;
    return <Badge variant="default">{t('yamlEditor.readOnlyBadge')}</Badge>;
  }, [loading, mode, dirty, t]);

  if (!target) return null;

  return (
    <Modal
      open
      size="full"
      onClose={applying ? () => {} : onClose}
      title={t('yamlEditor.titleView', { kind: target.resourceLabel, name: target.name })}
      footer={
        <div className="flex flex-1 flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-[11px] text-slate-500 dark:text-slate-400">
            {headerBadge}
            <span className="font-mono">{target.namespace}/{target.name}</span>
          </div>
          <div className="flex items-center gap-2">
            {mode === 'edit' && (
              <>
                <Button variant="ghost" size="sm" onClick={handleReset} disabled={!dirty || applying}>
                  {t('yamlEditor.reset')}
                </Button>
                <Button variant="outline" size="sm" onClick={handleDryRun} disabled={applying || loading}>
                  <PlayCircle size={13} />
                  {t('yamlEditor.dryRun')}
                </Button>
                <Button variant="primary" size="sm" onClick={handleApply} disabled={applying || loading}>
                  <Save size={13} />
                  {applying ? t('yamlEditor.applying') : t('yamlEditor.apply')}
                </Button>
              </>
            )}
            {mode === 'view' && (
              <>
                <Button variant="outline" size="sm" onClick={handleReload} disabled={loading}>
                  {t('yamlEditor.reload')}
                </Button>
                {target.canEdit && (
                  <Button variant="primary" size="sm" onClick={() => setMode('edit')} disabled={loading}>
                    <Pencil size={13} />
                    {t('yamlEditor.edit')}
                  </Button>
                )}
              </>
            )}
            <Button variant="ghost" size="sm" onClick={onClose} disabled={applying}>
              {t('yamlEditor.close')}
            </Button>
          </div>
        </div>
      }
    >
      <div className="flex h-full flex-col gap-2">
        {error && (
          <Alert severity="error" className="shrink-0">
            {error}
          </Alert>
        )}
        {notice && !error && (
          <Alert severity="success" className="shrink-0">
            {notice}
          </Alert>
        )}
        {mode === 'view' && target.canEdit && (
          <div className="shrink-0 rounded-md border border-slate-200 bg-slate-50 px-3 py-1.5 text-[11px] text-slate-500 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
            <Eye size={11} className="inline" /> {t('yamlEditor.readOnlyNotice')}
          </div>
        )}
        <div className="min-h-0 flex-1 overflow-hidden rounded-md border border-slate-200 dark:border-slate-800">
          {mode === 'view' ? (
            <YamlEditor value={originalYaml} readOnly theme={monacoTheme} />
          ) : (
            <YamlDiff
              original={dryRunPreview ?? originalYaml}
              modified={draftYaml}
              onModifiedChange={setDraftYaml}
              theme={monacoTheme}
            />
          )}
        </div>
      </div>
    </Modal>
  );
};

export default YamlEditModal;
