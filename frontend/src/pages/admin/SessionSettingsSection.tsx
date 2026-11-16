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
  const [apiKeyMaxDays, setApiKeyMaxDays] = useState(0);
  const [apiKeyAllowNoExpiry, setApiKeyAllowNoExpiry] = useState(true);
  // The outcome of a save shows in the card whose Save was pressed.
  const [result, setResult] = useState<{ card: 'session' | 'expiry'; ok: boolean; message: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const s = await getSession();
      setSessionMinutes(s.sessionMinutes);
      setApiKeyMaxDays(s.apiKeyMaxDays);
      setApiKeyAllowNoExpiry(s.apiKeyAllowNoExpiry);
    } catch {
      /* the form keeps what it shows */
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async (card: 'session' | 'expiry') => {
    setResult(null);
    try {
      await updateSession({ sessionMinutes, apiKeyMaxDays, apiKeyAllowNoExpiry });
    } catch (err) {
      setResult({ card, ok: false, message: (err as Error).message });
      return;
    }
    await load();
    setResult({ card, ok: true, message: tr('admin.session.saved') });
  };

  const outcome = (card: 'session' | 'expiry') =>
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
    </>
  );
};

export default SessionSettingsSection;
