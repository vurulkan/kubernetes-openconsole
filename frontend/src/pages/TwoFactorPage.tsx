import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldCheck } from 'lucide-react';
import Layout from '../components/Layout';
import { Alert, Badge, Button } from '../components/ui';
import { disableTwoFactor, newRecoveryCodes, User } from '../services/api';
import { SectionCard } from './admin/SectionCard';
import { CodeInput } from './account/CodeInput';
import { RecoveryCodes, TwoFactorSetupFlow } from './account/TwoFactorParts';

type Mode = '' | 'setup' | 'codes' | 'off';

/** Account → Two-factor authentication: status, set up, new recovery codes, turn off. */
const TwoFactorPage: React.FC<{ user: User; onChanged: () => Promise<void> }> = ({ user, onChanged }) => {
  const { t } = useTranslation();
  const tf = user.twoFactor;
  const [mode, setMode] = useState<Mode>('');
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const open = (m: Mode) => {
    setMode(m);
    setCode('');
    setCodes(null);
    setError(null);
    setNotice(null);
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === 'codes') {
        setCodes((await newRecoveryCodes(code.trim())).recoveryCodes);
      } else {
        await disableTwoFactor(code.trim());
        setMode('');
        setNotice(t('twoFactor.turnedOff'));
        await onChanged();
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const done = () => {
    open('');
    void onChanged();
  };

  const left = tf?.recoveryCodesLeft ?? 0;
  const off = !tf || tf.policy === 'off' || user.authSource === 'azure';

  return (
    <Layout user={user}>
      <div className="flex max-w-2xl flex-col gap-4">
        <header>
          <h1 className="flex items-center gap-2 text-lg font-semibold tracking-tight text-slate-900 dark:text-slate-50">
            <ShieldCheck size={20} className="text-brand-500" aria-hidden="true" />
            {t('twoFactor.title')}
          </h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{t('twoFactor.intro')}</p>
        </header>
        {notice && <Alert severity="success">{notice}</Alert>}
        {off ? (
          <Alert severity="info">{user.authSource === 'azure' ? t('twoFactor.azureNote') : t('apiErrors.two_factor_off')}</Alert>
        ) : (
          <SectionCard title={t('twoFactor.statusLabel')}>
            <div className="flex flex-wrap items-center gap-3">
              <Badge variant={tf.enabled ? 'success' : 'default'}>{tf.enabled ? t('twoFactor.statusOn') : t('twoFactor.statusOff')}</Badge>
              {tf.enabled && (
                <span className={`text-sm ${left <= 2 ? 'text-amber-700 dark:text-amber-300' : 'text-slate-600 dark:text-slate-300'}`}>
                  {left <= 2 ? t('twoFactor.codesLow', { count: left }) : t('twoFactor.codesLeft', { count: left })}
                </span>
              )}
            </div>
            {tf.required && <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">{t('twoFactor.requiredNote')}</p>}
            {mode === '' && (
              <div className="mt-4 flex flex-wrap gap-2">
                {!tf.enabled && (
                  <Button variant="primary" size="sm" onClick={() => open('setup')}>
                    {t('twoFactor.turnOn')}
                  </Button>
                )}
                {tf.enabled && (
                  <Button variant="outline" size="sm" onClick={() => open('codes')}>
                    {t('twoFactor.newCodes')}
                  </Button>
                )}
                {tf.enabled && !tf.required && (
                  <Button variant="danger" size="sm" onClick={() => open('off')}>
                    {t('twoFactor.turnOff')}
                  </Button>
                )}
              </div>
            )}
            {mode === 'setup' && (
              <div className="mt-4">
                <TwoFactorSetupFlow onDone={done} />
              </div>
            )}
            {(mode === 'codes' || mode === 'off') && !codes && (
              <form onSubmit={submit} className="mt-4 space-y-3">
                <p className="text-sm text-slate-600 dark:text-slate-300">
                  {mode === 'codes' ? t('twoFactor.newCodesHelp') : t('twoFactor.turnOffConfirm')}
                </p>
                {/* Turning off takes a recovery code too (a lost phone); new codes only the app's. */}
                <CodeInput value={code} onChange={setCode} recovery={mode === 'off'} label={t('twoFactor.code')} autoFocus />
                {error && <Alert severity="error">{error}</Alert>}
                <div className="flex gap-2">
                  <Button type="submit" variant={mode === 'off' ? 'danger' : 'primary'} size="sm" disabled={busy || !code.trim()}>
                    {mode === 'codes' ? t('twoFactor.newCodes') : t('twoFactor.turnOff')}
                  </Button>
                  <Button type="button" variant="outline" size="sm" onClick={() => open('')}>
                    {t('actions.cancel')}
                  </Button>
                </div>
              </form>
            )}
            {codes && (
              <div className="mt-4">
                <RecoveryCodes codes={codes} onDone={done} />
              </div>
            )}
          </SectionCard>
        )}
      </div>
    </Layout>
  );
};

export default TwoFactorPage;
