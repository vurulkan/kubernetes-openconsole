import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button } from '../../components/ui';
import { confirm } from '../../components/ConfirmDialog';
import { getSession, TwoFactorPolicy, updateSession } from '../../services/api';
import { SectionCard } from './SectionCard';

const POLICIES: TwoFactorPolicy[] = ['off', 'optional', 'admins', 'all'];

/** Admin → Two-factor authentication: the policy (stored with the session settings). */
export const TwoFactorSection: React.FC = () => {
  const { t: tr } = useTranslation();
  const [policy, setPolicy] = useState<TwoFactorPolicy>('off');
  const [saved, setSaved] = useState<TwoFactorPolicy>('off');
  const [unenrolled, setUnenrolled] = useState<Partial<Record<TwoFactorPolicy, number>>>({});
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const s = await getSession();
      setPolicy(s.twoFactorPolicy ?? 'off');
      setSaved(s.twoFactorPolicy ?? 'off');
      setUnenrolled(s.twoFactorUnenrolled ?? {});
    } catch {
      /* the form keeps what it shows */
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async () => {
    setResult(null);
    // A newly required policy: say how many will have to set it up on their next sign-in.
    const count = unenrolled[policy] ?? 0;
    if (policy !== saved && (policy === 'admins' || policy === 'all') && count > 0) {
      const ok = await confirm({
        title: tr('twoFactor.admin.confirmTitle'),
        message: tr('twoFactor.admin.confirmBody', { count }),
        confirmText: tr('actions.save'),
      });
      if (!ok) return;
    }
    try {
      await updateSession({ twoFactorPolicy: policy });
    } catch (err) {
      setResult({ ok: false, message: (err as Error).message });
      return;
    }
    await load();
    setResult({ ok: true, message: tr('admin.session.saved') });
  };

  return (
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
      <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">{tr('twoFactor.admin.azureHint')}</p>
      <Button variant="primary" size="sm" className="mt-4" onClick={() => void save()}>
        {tr('actions.save')}
      </Button>
      {result && (
        <Alert severity={result.ok ? 'success' : 'error'} className="mt-3">
          {result.message}
        </Alert>
      )}
    </SectionCard>
  );
};

export default TwoFactorSection;
