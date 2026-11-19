import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Download } from 'lucide-react';
import { Alert, Button, Spinner } from '../../components/ui';
import { CodeInput } from './CodeInput';
import { CopyRow } from '../apikeys/ApiKeyParts';
import { confirmTwoFactor, setupTwoFactor, TwoFactorSetup as Setup } from '../../services/api';

/** The recovery codes, shown once: copy, download, then "I saved them". */
export const RecoveryCodes: React.FC<{ codes: string[]; onDone: () => void }> = ({ codes, onDone }) => {
  const { t } = useTranslation();
  const text = codes.join('\n');
  const download = () => {
    const url = URL.createObjectURL(new Blob([text + '\n'], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'openconsole-recovery-codes.txt';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t('twoFactor.codesTitle')}</h3>
      <p className="text-sm text-slate-600 dark:text-slate-300">{t('twoFactor.codesHelp')}</p>
      <CopyRow value={text} label={t('twoFactor.copy')} multiline />
      <div className="flex gap-2">
        <Button variant="outline" size="sm" onClick={download}>
          <Download size={14} />
          {t('twoFactor.download')}
        </Button>
        <Button variant="primary" size="sm" onClick={onDone}>
          {t('twoFactor.codesSaved')}
        </Button>
      </div>
    </div>
  );
};

/**
 * Setting up: QR code + key, then a code from the app turns it on. The answer
 * starts a new session (the server ended the others), stored here; then the
 * recovery codes, and onDone.
 */
export const TwoFactorSetupFlow: React.FC<{ onDone: () => void }> = ({ onDone }) => {
  const { t } = useTranslation();
  const [setup, setSetup] = useState<Setup | null>(null);
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    // Only the last request's secret is the stored one (StrictMode runs this twice in development).
    let live = true;
    setupTwoFactor()
      .then((s) => live && setSetup(s))
      .catch((err: Error) => live && setError(err.message));
    return () => {
      live = false;
    };
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await confirmTwoFactor(code.trim());
      localStorage.setItem('authToken', res.token);
      setCodes(res.recoveryCodes);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (codes) return <RecoveryCodes codes={codes} onDone={onDone} />;
  if (!setup) return error ? <Alert severity="error">{error}</Alert> : <Spinner />;
  return (
    <form onSubmit={submit} className="space-y-4">
      <p className="text-sm text-slate-600 dark:text-slate-300">{t('twoFactor.scan')}</p>
      {/* The QR code stays dark on white in both themes, so every camera reads it. */}
      <img src={setup.qr} alt={t('twoFactor.qrAlt')} className="h-44 w-44 rounded-lg bg-white p-1 ring-1 ring-slate-200" />
      <div className="space-y-1">
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('twoFactor.manual')}</p>
        <CopyRow value={setup.secret} label={t('twoFactor.copy')} />
      </div>
      <p className="text-sm text-slate-600 dark:text-slate-300">{t('twoFactor.enterCode')}</p>
      <CodeInput value={code} onChange={setCode} />
      {error && <Alert severity="error">{error}</Alert>}
      <Button type="submit" variant="primary" disabled={busy || code.trim().length !== 6}>
        {t('twoFactor.confirm')}
      </Button>
    </form>
  );
};
