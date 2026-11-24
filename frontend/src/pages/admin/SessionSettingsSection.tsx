import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Input } from '../../components/ui';
import { getSession, updateSession } from '../../services/api';
import { SectionCard } from './SectionCard';

/**
 * Admin → Session: the inactivity timeout and, with API keys on, the API key
 * expiry policy. Both cards save the same settings. Loads only those settings.
 */
export const SessionSettingsSection: React.FC<{ apiKeysOn: boolean }> = ({ apiKeysOn }) => {
  const { t: tr } = useTranslation();
  const [sessionMinutes, setSessionMinutes] = useState(60);
  // Text, so the field can be empty while typing; required, 1–3650 days.
  const [apiKeyMaxDays, setApiKeyMaxDays] = useState('365');
  const [apiKeyAllowNoExpiry, setApiKeyAllowNoExpiry] = useState(true);
  // The outcome of a save shows in the card whose Save was pressed.
  const [result, setResult] = useState<{ card: Card; ok: boolean; message: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const s = await getSession();
      setSessionMinutes(s.sessionMinutes);
      setApiKeyMaxDays(String(s.apiKeyMaxDays));
      setApiKeyAllowNoExpiry(s.apiKeyAllowNoExpiry);
    } catch {
      /* the form keeps what it shows */
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async (card: Card) => {
    setResult(null);
    try {
      // Each card sends its own fields; the rest (and the two-factor policy, its own tab) keep their value.
      await updateSession(
        card === 'session' ? { sessionMinutes } : { apiKeyMaxDays: Number(apiKeyMaxDays), apiKeyAllowNoExpiry },
      );
    } catch (err) {
      setResult({ card, ok: false, message: (err as Error).message });
      return;
    }
    await load();
    setResult({ card, ok: true, message: tr('admin.session.saved') });
  };

  const maxDaysOk = /^\d+$/.test(apiKeyMaxDays) && Number(apiKeyMaxDays) >= 1 && Number(apiKeyMaxDays) <= 3650;

  const outcome = (card: Card) =>
    result?.card === card && (
      <Alert severity={result.ok ? 'success' : 'error'} className="mt-3">
        {result.message}
      </Alert>
    );

  return (
    <div className="flex flex-col gap-5">
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
              required
              min={1}
              max={3650}
              value={apiKeyMaxDays}
              error={maxDaysOk ? undefined : tr('admin.apiKeyMaxDaysRange')}
              onChange={(e) => setApiKeyMaxDays(e.target.value)}
              className="w-60"
            />
            <Checkbox checked={apiKeyAllowNoExpiry} onChange={setApiKeyAllowNoExpiry} label={tr('admin.apiKeyAllowNoExpiry')} />
            <p className="text-xs text-slate-500 dark:text-slate-400">{tr('admin.apiKeyExpiryExisting')}</p>
          </div>
          <Button variant="primary" size="sm" className="mt-4" disabled={!maxDaysOk} onClick={() => void save('expiry')}>
            {tr('actions.save')}
          </Button>
          {outcome('expiry')}
        </SectionCard>
      )}
    </div>
  );
};

type Card = 'session' | 'expiry';

export default SessionSettingsSection;
