import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Input } from '../../components/ui';
import { confirm } from '../../components/ConfirmDialog';
import { getSession, TwoFactorPolicy, updateSession } from '../../services/api';
import { SectionCard } from './SectionCard';

/**
 * Admin → Session: the inactivity timeout and, with API keys on, the API key
 * expiry policy. Both cards save the same settings. Loads only those settings.
 */
export const SessionSettingsSection: React.FC<{ apiKeysOn: boolean }> = ({ apiKeysOn }) => {
  const { t: tr } = useTranslation();
  const [sessionMinutes, setSessionMinutes] = useState(60);
  const [apiKeyMaxDays, setApiKeyMaxDays] = useState(0);
  const [apiKeyAllowNoExpiry, setApiKeyAllowNoExpiry] = useState(true);
  const [policy, setPolicy] = useState<TwoFactorPolicy>('off');
  const [savedPolicy, setSavedPolicy] = useState<TwoFactorPolicy>('off');
  const [unenrolled, setUnenrolled] = useState<Partial<Record<TwoFactorPolicy, number>>>({});
  // The outcome of a save shows in the card whose Save was pressed.
  const [result, setResult] = useState<{ card: Card; ok: boolean; message: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const s = await getSession();
      setSessionMinutes(s.sessionMinutes);
      setApiKeyMaxDays(s.apiKeyMaxDays);
      setApiKeyAllowNoExpiry(s.apiKeyAllowNoExpiry);
      setPolicy(s.twoFactorPolicy ?? 'off');
      setSavedPolicy(s.twoFactorPolicy ?? 'off');
      setUnenrolled(s.twoFactorUnenrolled ?? {});
    } catch {
      /* the form keeps what it shows */
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async (card: Card) => {
    setResult(null);
    // A newly required policy: say how many will have to set it up on their next sign-in.
    const count = unenrolled[policy] ?? 0;
    if (card === 'twoFactor' && policy !== savedPolicy && (policy === 'admins' || policy === 'all') && count > 0) {
      const ok = await confirm({
        title: tr('twoFactor.admin.confirmTitle'),
        message: tr('twoFactor.admin.confirmBody', { count }),
        confirmText: tr('actions.save'),
      });
      if (!ok) return;
    }
    try {
      await updateSession({ sessionMinutes, apiKeyMaxDays, apiKeyAllowNoExpiry, twoFactorPolicy: card === 'twoFactor' ? policy : savedPolicy });
    } catch (err) {
      setResult({ card, ok: false, message: (err as Error).message });
      return;
    }
    await load();
    setResult({ card, ok: true, message: tr('admin.session.saved') });
  };

  const outcome = (card: Card) =>
    result?.card === card && (
      <Alert severity={result.ok ? 'success' : 'error'} className="mt-3">
        {result.message}
      </Alert>
    );

  return (
    <>
      <SectionCard title={tr('admin.sections.sessionSettings')} description={tr('admin.cards.sessionDesc')}>
        <Input
          label={tr('common.sessionLifetime')}
          type="number"
          value={sessionMinutes}
          onChange={(e) => setSessionMinutes(Number(e.target.value))}
          className="w-60"
        />
        <Button variant="primary" size="sm" className="mt-4" onClick={() => void save('session')}>
          {tr('admin.session.save')}
        </Button>
        {outcome('session')}
      </SectionCard>
      {apiKeysOn && (
        <SectionCard title={tr('admin.sections.apiKeyExpiry')} description={tr('admin.cards.apiKeyExpiryDesc')}>
          <div className="flex flex-col gap-3">
            <Input
              label={tr('admin.apiKeyMaxDays')}
              type="number"
              min={0}
              max={3650}
              value={apiKeyMaxDays || ''}
              placeholder={tr('admin.apiKeyNoLimit')}
              onChange={(e) => setApiKeyMaxDays(Math.max(0, Number(e.target.value) || 0))}
              className="w-60"
            />
            <Checkbox checked={apiKeyAllowNoExpiry} onChange={setApiKeyAllowNoExpiry} label={tr('admin.apiKeyAllowNoExpiry')} />
            <p className="text-xs text-slate-500 dark:text-slate-400">{tr('admin.apiKeyExpiryExisting')}</p>
          </div>
          <Button variant="primary" size="sm" className="mt-4" onClick={() => void save('expiry')}>
            {tr('actions.save')}
          </Button>
          {outcome('expiry')}
        </SectionCard>
      )}
      <SectionCard title={tr('twoFactor.admin.title')} description={tr('twoFactor.admin.desc')}>
        <fieldset className="flex flex-col gap-2">
          <legend className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
            {tr('twoFactor.admin.policy')}
          </legend>
          {POLICIES.map((p) => (
            <label key={p} className="flex cursor-pointer items-start gap-2 text-sm">
              <input
                type="radio"
                name="twoFactorPolicy"
                value={p}
                checked={policy === p}
                onChange={() => setPolicy(p)}
                className="mt-1 accent-brand-600"
              />
              <span>
                <span className="font-medium text-slate-900 dark:text-slate-100">{tr(`twoFactor.admin.${p}`)}</span>
                <span className="block text-xs text-slate-500 dark:text-slate-400">{tr(`twoFactor.admin.${p}Desc`)}</span>
              </span>
            </label>
          ))}
        </fieldset>
        <Button variant="primary" size="sm" className="mt-4" onClick={() => void save('twoFactor')}>
          {tr('actions.save')}
        </Button>
        {outcome('twoFactor')}
      </SectionCard>
    </>
  );
};

type Card = 'session' | 'expiry' | 'twoFactor';
const POLICIES: TwoFactorPolicy[] = ['off', 'optional', 'admins', 'all'];

export default SessionSettingsSection;
