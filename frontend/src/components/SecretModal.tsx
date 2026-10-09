import React, { useEffect, useState } from 'react';
import { AlertTriangle, Check, Copy, Eye, EyeOff, Lock, ShieldAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Alert, Badge, Button, Modal, Spinner } from './ui';
import { getSecret, revealSecretKey, SecretSummary } from '../services/api';
import { formatBytes } from '../utils/format';

type Props = {
  open: boolean;
  namespace: string;
  name: string;
  /** secrets:reveal in this namespace — hides the reveal buttons when false. */
  canReveal: boolean;
  onClose: () => void;
};

type Revealed = { value: string; encoding: 'text' | 'base64' };

// Shows a Secret's metadata and key list. Values are never fetched up front:
// each "Show" click calls the audited reveal endpoint for that one key, and
// everything revealed is dropped from memory when the modal closes.
export const SecretModal: React.FC<Props> = ({ open, namespace, name, canReveal, onClose }) => {
  const { t } = useTranslation();
  const [secret, setSecret] = useState<SecretSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<Record<string, Revealed>>({});
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    setRevealed({});
    setCopiedKey(null);
    setError(null);
    if (!open) {
      setSecret(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    getSecret(namespace, name)
      .then((res) => !cancelled && setSecret(res))
      .catch((err) => !cancelled && setError(err instanceof Error ? err.message : String(err)))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [open, namespace, name]);

  const reveal = async (key: string) => {
    setBusyKey(key);
    setError(null);
    try {
      const res = await revealSecretKey(namespace, name, key);
      setRevealed((prev) => ({ ...prev, [key]: { value: res.value, encoding: res.encoding } }));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyKey(null);
    }
  };

  const hide = (key: string) =>
    setRevealed((prev) => {
      const next = { ...prev };
      delete next[key];
      return next;
    });

  const copy = async (key: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey((k) => (k === key ? null : k)), 1500);
    } catch {
      setError(t('secrets.copyFailed'));
    }
  };

  const labels = Object.entries(secret?.metadata.labels ?? {});
  const annotations = Object.entries(secret?.metadata.annotations ?? {});

  return (
    <Modal open={open} onClose={onClose} title={t('secrets.title', { name })} size="lg">
      <div className="flex flex-col gap-4">
        <Alert severity="warning">
          <ShieldAlert size={14} className="mr-1 inline" />
          {canReveal ? t('secrets.revealNotice') : t('secrets.noRevealNotice')}
        </Alert>

        {error && (
          <Alert severity="error">
            <AlertTriangle size={14} className="mr-1 inline" />
            {error}
          </Alert>
        )}

        {loading && (
          <div className="flex justify-center py-6">
            <Spinner />
          </div>
        )}

        {secret && (
          <>
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-300">
              <Badge variant="default">{secret.type}</Badge>
              {secret.immutable && (
                <Badge variant="info">
                  <Lock size={10} />
                  {t('secrets.immutable')}
                </Badge>
              )}
              <span className="font-mono text-slate-500 dark:text-slate-400">
                {namespace}/{secret.metadata.name}
              </span>
              <span>· {new Date(secret.metadata.creationTimestamp).toLocaleString()}</span>
            </div>

            {(labels.length > 0 || annotations.length > 0) && (
              <div className="flex flex-col gap-1.5">
                {[...labels.map(([k, v]) => ({ k, v, kind: 'label' })), ...annotations.map(([k, v]) => ({ k, v, kind: 'annotation' }))].map(
                  ({ k, v, kind }) => (
                    <div key={kind + k} className="flex min-w-0 gap-2 text-[11px]">
                      <span className="shrink-0 text-slate-500 dark:text-slate-400">
                        {kind === 'label' ? t('secrets.label') : t('secrets.annotation')}
                      </span>
                      <span className="truncate font-mono text-slate-700 dark:text-slate-200" title={`${k}=${v}`}>
                        {k}={v}
                      </span>
                    </div>
                  ),
                )}
              </div>
            )}

            <div className="overflow-hidden rounded-xl border border-slate-200 dark:border-slate-800">
              <div className="grid grid-cols-[1fr_auto_auto] gap-3 border-b border-slate-200 bg-slate-50 px-4 py-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:border-slate-800 dark:bg-slate-800/40 dark:text-slate-400">
                <span>{t('secrets.key')}</span>
                <span className="text-right">{t('secrets.size')}</span>
                <span />
              </div>
              {secret.keys.length === 0 && (
                <div className="px-4 py-4 text-xs text-slate-500 dark:text-slate-400">{t('secrets.noKeys')}</div>
              )}
              {secret.keys.map(({ name: key, size }) => {
                const shown = revealed[key];
                return (
                  <div key={key} className="border-b border-slate-100 px-4 py-2.5 last:border-b-0 dark:border-slate-800/70">
                    <div className="grid grid-cols-[1fr_auto_auto] items-center gap-3">
                      <span className="truncate font-mono text-[13px] text-slate-900 dark:text-slate-100" title={key}>
                        {key}
                      </span>
                      <span className="text-right font-mono text-[11px] text-slate-500 dark:text-slate-400">
                        {formatBytes(size)}
                      </span>
                      <div className="flex justify-end gap-1.5">
                        {canReveal && !shown && (
                          <Button variant="outline" size="sm" onClick={() => reveal(key)} disabled={busyKey === key}>
                            <Eye size={13} />
                            {t('secrets.show')}
                          </Button>
                        )}
                        {shown && (
                          <>
                            <Button variant="outline" size="sm" onClick={() => copy(key, shown.value)}>
                              {copiedKey === key ? <Check size={13} /> : <Copy size={13} />}
                              {copiedKey === key ? t('secrets.copied') : t('secrets.copy')}
                            </Button>
                            <Button variant="outline" size="sm" onClick={() => hide(key)}>
                              <EyeOff size={13} />
                              {t('secrets.hide')}
                            </Button>
                          </>
                        )}
                      </div>
                    </div>
                    {shown && (
                      <div className="mt-2">
                        {shown.encoding === 'base64' && (
                          <div className="mb-1 text-[11px] text-amber-700 dark:text-amber-300">{t('secrets.binaryNote')}</div>
                        )}
                        <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-slate-950 p-3 font-mono text-[12px] text-slate-100">
                          {shown.value}
                        </pre>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </Modal>
  );
};

export default SecretModal;
