import React, { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, Plus, Search, Trash2, XCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Input, Modal, NativeSelect, Spinner } from '../../components/ui';
import {
  discoverPrometheus,
  getPrometheusSettings,
  savePrometheusSettings,
  testPrometheus,
  type PrometheusConfig,
  type PrometheusDiagnosis,
} from '../../services/api';

const MASK = '••••••••';

const TextArea: React.FC<{ label: string; value?: string; onChange: (v: string) => void; placeholder?: string }> = ({
  label,
  value,
  onChange,
  placeholder,
}) => {
  const id = React.useId();
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {label}
      </label>
      <textarea
        id={id}
        rows={3}
        value={value ?? ''}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-xs text-slate-900 focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/30 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
      />
    </div>
  );
};

/** Per-cluster Prometheus: in-cluster Service through the API server proxy, or a direct URL. */
export const PrometheusSettingsModal: React.FC<{ cluster: { id: number; name: string }; onClose: () => void }> = ({
  cluster,
  onClose,
}) => {
  const { t } = useTranslation();
  const [cfg, setCfg] = useState<PrometheusConfig | null>(null);
  const [busy, setBusy] = useState<'save' | 'test' | 'find' | null>(null);
  const [status, setStatus] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  const [diag, setDiag] = useState<PrometheusDiagnosis | null>(null);
  const [found, setFound] = useState<Array<{ namespace: string; service: string; port: string }> | null>(null);

  useEffect(() => {
    getPrometheusSettings(cluster.id)
      .then(setCfg)
      .catch((err: Error) => setStatus({ kind: 'error', text: err.message }));
  }, [cluster.id]);

  const set = (patch: Partial<PrometheusConfig>) => {
    setCfg((c) => ({ ...(c as PrometheusConfig), ...patch }));
    setDiag(null);
  };
  const secretHint = (v?: string) => (v === MASK ? t('prometheus.secretKept') : undefined);

  const run = async (kind: 'save' | 'test') => {
    if (!cfg) return;
    setBusy(kind);
    setStatus(null);
    try {
      if (kind === 'save') {
        setCfg(await savePrometheusSettings(cluster.id, cfg));
        setStatus({ kind: 'success', text: t('prometheus.saved') });
      } else {
        setDiag(await testPrometheus(cluster.id, cfg));
      }
    } catch (err) {
      setStatus({ kind: 'error', text: (err as Error).message });
    } finally {
      setBusy(null);
    }
  };

  const find = async () => {
    setBusy('find');
    try {
      const r = await discoverPrometheus(cluster.id);
      setFound(r.items);
      if (r.items.length && !cfg?.service) set({ ...r.items[0] });
    } catch (err) {
      setStatus({ kind: 'error', text: (err as Error).message });
    } finally {
      setBusy(null);
    }
  };

  const headers = cfg?.headers ?? [];

  return (
    <Modal
      open
      onClose={onClose}
      title={t('prometheus.title', { name: cluster.name })}
      size="md"
      footer={
        <>
          <Button variant="outline" size="sm" onClick={onClose}>
            {t('common.close', { defaultValue: 'Close' })}
          </Button>
          {cfg?.mode && (
            <Button variant="outline" size="sm" disabled={busy !== null} onClick={() => run('test')}>
              {busy === 'test' ? t('prometheus.testing') : t('prometheus.test')}
            </Button>
          )}
          <Button variant="primary" size="sm" disabled={busy !== null || !cfg} onClick={() => run('save')}>
            {t('prometheus.save')}
          </Button>
        </>
      }
    >
      {!cfg ? (
        status ? <Alert severity="error">{status.text}</Alert> : <Spinner size="sm" />
      ) : (
        <div className="flex flex-col gap-4">
          <div role="radiogroup" aria-label={t('prometheus.mode')} className="flex flex-wrap gap-2">
            {(['', 'proxy', 'url'] as const).map((m) => (
              <button
                key={m || 'off'}
                type="button"
                role="radio"
                aria-checked={cfg.mode === m}
                onClick={() => set({ mode: m })}
                className={`rounded-lg border px-3 py-1.5 text-xs font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 ${
                  cfg.mode === m
                    ? 'border-brand-300 bg-brand-50 text-brand-700 dark:border-brand-500/40 dark:bg-brand-500/15 dark:text-brand-200'
                    : 'border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800'
                }`}
              >
                {m === '' ? t('prometheus.off') : m === 'proxy' ? t('prometheus.proxy') : t('prometheus.url')}
              </button>
            ))}
          </div>

          {cfg.mode === '' && <Alert severity="info">{t('prometheus.notConfigured')}</Alert>}

          {cfg.mode === 'proxy' && (
            <>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('prometheus.proxyHelp')}</p>
              <div>
                <Button variant="outline" size="sm" disabled={busy !== null} onClick={find}>
                  <Search size={13} />
                  {busy === 'find' ? t('prometheus.finding') : t('prometheus.find')}
                </Button>
                {found && !found.length && <p className="mt-2 text-xs text-slate-500">{t('prometheus.noneFound')}</p>}
                {found && found.length > 0 && (
                  <ul className="mt-2 flex flex-wrap gap-2">
                    {found.map((f) => (
                      <li key={`${f.namespace}/${f.service}`}>
                        <button
                          type="button"
                          onClick={() => set({ ...f })}
                          aria-pressed={cfg.namespace === f.namespace && cfg.service === f.service}
                          className="rounded-md border border-slate-200 px-2 py-1 font-mono text-[11px] text-slate-700 hover:bg-slate-50 aria-pressed:border-brand-300 aria-pressed:bg-brand-50 dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800 dark:aria-pressed:bg-brand-500/15"
                        >
                          {f.namespace}/{f.service}:{f.port}
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Input label={t('prometheus.namespace')} value={cfg.namespace ?? ''} onChange={(e) => set({ namespace: e.target.value })} />
                <Input label={t('prometheus.service')} value={cfg.service ?? ''} onChange={(e) => set({ service: e.target.value })} />
                <Input label={t('prometheus.port')} value={cfg.port ?? ''} placeholder="9090" onChange={(e) => set({ port: e.target.value })} />
                <NativeSelect label={t('prometheus.scheme')} value={cfg.scheme ?? 'http'} onChange={(e) => set({ scheme: e.target.value as 'http' | 'https' })}>
                  <option value="http">http</option>
                  <option value="https">https</option>
                </NativeSelect>
              </div>
            </>
          )}

          {cfg.mode === 'url' && (
            <>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('prometheus.urlHelp')}</p>
              <Input label="URL" value={cfg.url ?? ''} placeholder="https://prometheus.example.com" onChange={(e) => set({ url: e.target.value })} />
              <NativeSelect label={t('prometheus.auth')} value={cfg.auth ?? 'none'} onChange={(e) => set({ auth: e.target.value as PrometheusConfig['auth'] })}>
                <option value="none">{t('prometheus.authNone')}</option>
                <option value="basic">{t('prometheus.authBasic')}</option>
                <option value="bearer">{t('prometheus.authBearer')}</option>
                <option value="azure">{t('prometheus.authAzure')}</option>
                <option value="mtls">{t('prometheus.authMtls')}</option>
              </NativeSelect>
              {cfg.auth === 'basic' && (
                <div className="grid grid-cols-2 gap-3">
                  <Input label={t('prometheus.username')} value={cfg.username ?? ''} onChange={(e) => set({ username: e.target.value })} />
                  <Input label={t('prometheus.password')} type="password" value={cfg.password ?? ''} error={secretHint(cfg.password)} onChange={(e) => set({ password: e.target.value })} />
                </div>
              )}
              {cfg.auth === 'bearer' && (
                <Input label={t('prometheus.token')} type="password" value={cfg.token ?? ''} error={secretHint(cfg.token)} onChange={(e) => set({ token: e.target.value })} />
              )}
              {cfg.auth === 'azure' && (
                <div className="grid grid-cols-2 gap-3">
                  <Input label={t('prometheus.tenantId')} value={cfg.azureTenantId ?? ''} onChange={(e) => set({ azureTenantId: e.target.value })} />
                  <Input label={t('prometheus.clientId')} value={cfg.azureClientId ?? ''} onChange={(e) => set({ azureClientId: e.target.value })} />
                  <Input label={t('prometheus.clientSecret')} type="password" value={cfg.azureClientSecret ?? ''} error={secretHint(cfg.azureClientSecret)} onChange={(e) => set({ azureClientSecret: e.target.value })} />
                </div>
              )}
              {cfg.auth === 'mtls' && (
                <>
                  <TextArea label={t('prometheus.clientCert')} value={cfg.clientCert} onChange={(v) => set({ clientCert: v })} />
                  <TextArea label={t('prometheus.clientKey')} value={cfg.clientKey} onChange={(v) => set({ clientKey: v })} placeholder={secretHint(cfg.clientKey)} />
                </>
              )}
              <TextArea label={t('prometheus.caCert')} value={cfg.caCert} onChange={(v) => set({ caCert: v })} />
              <Checkbox checked={!!cfg.insecureSkipVerify} onChange={(v) => set({ insecureSkipVerify: v })} label={t('prometheus.insecure')} />
              <div className="flex flex-col gap-2">
                <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{t('prometheus.headers')}</span>
                {headers.map((h, i) => (
                  <div key={i} className="grid grid-cols-[1fr_1fr_auto] items-end gap-2">
                    <Input aria-label={t('prometheus.headerName')} placeholder="X-Scope-OrgID" value={h.name} onChange={(e) => set({ headers: headers.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)) })} />
                    <Input aria-label={t('prometheus.headerValue')} type="password" value={h.value} onChange={(e) => set({ headers: headers.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)) })} />
                    <Button variant="ghost" size="sm" aria-label={t('prometheus.remove')} onClick={() => set({ headers: headers.filter((_, j) => j !== i) })}>
                      <Trash2 size={13} />
                    </Button>
                  </div>
                ))}
                <div>
                  <Button variant="outline" size="sm" onClick={() => set({ headers: [...headers, { name: '', value: '' }] })}>
                    <Plus size={13} />
                    {t('prometheus.addHeader')}
                  </Button>
                </div>
              </div>
            </>
          )}

          {cfg.mode && (
            <fieldset className="flex flex-col gap-2 rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <legend className="px-1 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{t('prometheus.multiCluster')}</legend>
              <div className="grid grid-cols-2 gap-3">
                <Input label={t('prometheus.clusterLabel')} placeholder="cluster" value={cfg.clusterLabel ?? ''} onChange={(e) => set({ clusterLabel: e.target.value })} />
                {diag?.clusterValues && diag.clusterValues.length > 1 ? (
                  <NativeSelect label={t('prometheus.clusterValue')} value={cfg.clusterValue ?? ''} onChange={(e) => set({ clusterValue: e.target.value, clusterLabel: cfg.clusterLabel || 'cluster' })}>
                    <option value="">—</option>
                    {diag.clusterValues.map((v) => (
                      <option key={v} value={v}>{v}</option>
                    ))}
                  </NativeSelect>
                ) : (
                  <Input label={t('prometheus.clusterValue')} value={cfg.clusterValue ?? ''} onChange={(e) => set({ clusterValue: e.target.value })} />
                )}
              </div>
            </fieldset>
          )}

          {diag && (
            <ul className="flex flex-col gap-1.5 rounded-lg border border-slate-200 p-3 text-xs dark:border-slate-800" aria-live="polite">
              {diag.steps.map((s) => (
                <li key={s.id} className="flex items-start gap-2">
                  {s.status === 'ok' ? (
                    <CheckCircle2 size={14} aria-label="OK" className="mt-px shrink-0 text-emerald-500" />
                  ) : s.status === 'warn' ? (
                    <AlertTriangle size={14} aria-label="Warning" className="mt-px shrink-0 text-amber-500" />
                  ) : (
                    <XCircle size={14} aria-label="Failed" className="mt-px shrink-0 text-rose-500" />
                  )}
                  <div className="min-w-0">
                    <span className="font-medium text-slate-800 dark:text-slate-200">{t(`prometheus.steps.${s.id}`, { defaultValue: s.id })}</span>
                    {s.reason && (
                      <p className="mt-0.5 text-slate-600 dark:text-slate-300">
                        {t(`prometheus.reasons.${s.reason}`, { detail: s.detail, defaultValue: s.reason })}
                      </p>
                    )}
                    {s.status === 'fail' && s.detail && !s.reason?.startsWith('multiple') && (
                      <p className="mt-0.5 break-all font-mono text-[11px] text-slate-500 dark:text-slate-400">{s.detail}</p>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}

          {status && <Alert severity={status.kind}>{status.text}</Alert>}
        </div>
      )}
    </Modal>
  );
};
