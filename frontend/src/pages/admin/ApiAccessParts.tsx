import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Ban, KeyRound } from 'lucide-react';
import { confirm } from '../../components/ConfirmDialog';
import { Alert, Badge, Button, Segmented, Spinner } from '../../components/ui';
import {
  getUserApiAccess,
  revokeUserApiKeys,
  type ApiAccess,
  type ApiAccessOverride,
  type UserApiAccess,
} from '../../services/api';

/**
 * API key policy (M15): a role's "API access" mode, a user's override, and what the user's keys may
 * reach under them. The server computes the reach (one definition of safe read-only, in rbac).
 */

export const API_ACCESS: ApiAccess[] = ['off', 'safe_read', 'full'];

const BADGE: Record<ApiAccess, 'default' | 'success' | 'warning'> = { off: 'default', safe_read: 'success', full: 'warning' };

/** off slate, safe read green, full amber (it can include exec / edit). "" = by roles. */
export const ApiAccessBadge: React.FC<{ value: ApiAccessOverride }> = ({ value }) => {
  const { t } = useTranslation();
  if (!value) return <span className="text-xs text-slate-500 dark:text-slate-400">{t('apiAccess.roles')}</span>;
  return <Badge variant={BADGE[value]}>{t(`apiAccess.${value}`)}</Badge>;
};

/** The role form's choice: three segments and a line on what it means. */
export const RoleApiAccessField: React.FC<{ value: ApiAccess; onChange: (v: ApiAccess) => void }> = ({ value, onChange }) => {
  const { t } = useTranslation();
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{t('apiAccess.label')}</span>
      <Segmented
        label={t('apiAccess.label')}
        value={value}
        options={API_ACCESS.map((m) => [m, t(`apiAccess.${m}`)])}
        onChange={(v) => onChange(v as ApiAccess)}
      />
      <p className="text-xs text-slate-500 dark:text-slate-400">{t(`apiAccess.hint.${value}`)}</p>
    </div>
  );
};

/** Above the Role Permissions matrix: what this role's grants give API keys. */
export const RoleApiAccessLine: React.FC<{ value: ApiAccess }> = ({ value }) => {
  const { t } = useTranslation();
  return (
    <p className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-300">
      <KeyRound size={13} className="shrink-0 text-slate-400" aria-hidden="true" />
      {t('apiAccess.panelLine')}
      <ApiAccessBadge value={value} />
    </p>
  );
};

/**
 * The user dialog's part: the override (4 choices), a preview of what the user's keys may reach under
 * the choice (not saved yet), the number of active keys and "Revoke all their keys".
 */
export const UserApiAccessField: React.FC<{
  userId: number;
  value: ApiAccessOverride;
  onChange: (v: ApiAccessOverride) => void;
}> = ({ userId, value, onChange }) => {
  const { t } = useTranslation();
  const [preview, setPreview] = useState<UserApiAccess | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revoked, setRevoked] = useState<number | null>(null);

  useEffect(() => {
    let alive = true;
    setError(null);
    getUserApiAccess(userId, value)
      .then((p) => alive && setPreview(p))
      .catch((e) => alive && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      alive = false;
    };
  }, [userId, value, revoked]);

  const revokeAll = async () => {
    const ok = await confirm({
      title: t('apiAccess.revokeAllTitle'),
      message: t('apiAccess.revokeAllMessage', { count: preview?.activeKeys ?? 0 }),
      confirmText: t('apiAccess.revokeAll'),
      variant: 'danger',
    });
    if (!ok) return;
    try {
      setRevoked((await revokeUserApiKeys(userId)).revoked);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const multiCluster = (preview?.clusters?.length ?? 0) > 1;
  const clusterName = (id: number) => preview?.clusters?.find((c) => c.id === id)?.name ?? String(id);

  return (
    <section className="flex flex-col gap-2 rounded-lg border border-slate-200 p-3 dark:border-slate-800" aria-label={t('apiAccess.label')}>
      <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{t('apiAccess.label')}</span>
      <Segmented
        label={t('apiAccess.label')}
        value={value || 'roles'}
        options={[
          ['roles', t('apiAccess.roles')],
          ['off', t('apiAccess.off')],
          ['safe_read', t('apiAccess.safe_read')],
          ['full', t('apiAccess.fullUser')],
        ]}
        onChange={(v) => onChange((v === 'roles' ? '' : v) as ApiAccessOverride)}
      />
      <p className="text-xs text-slate-500 dark:text-slate-400">{t(`apiAccess.userHint.${value || 'roles'}`)}</p>
      <div className="rounded-md bg-slate-50 px-3 py-2 text-xs text-slate-700 dark:bg-slate-800/60 dark:text-slate-200" aria-live="polite">
        <span className="mr-1 font-medium text-slate-500 dark:text-slate-400">{t('apiAccess.preview')}:</span>
        {error ? (
          <span className="text-rose-700 dark:text-rose-300">{error}</span>
        ) : !preview ? (
          <Spinner size="sm" className="inline-block align-middle" />
        ) : preview.refused ? (
          t('apiAccess.refused')
        ) : preview.isAdmin ? (
          <>
            {t('apiAccess.adminEvery', { mode: t(`apiAccess.level.${preview.adminMode === 'full' ? 'all' : preview.adminMode === 'safe_read' ? 'read' : 'none'}`) })}
            {preview.adminMode !== 'full' && ` · ${t('apiAccess.noAdminApi')}`}
          </>
        ) : (preview.namespaces ?? []).length === 0 ? (
          t('apiAccess.noNamespaces')
        ) : (
          (preview.namespaces ?? [])
            .map((n) => `${multiCluster ? `${clusterName(n.clusterId)}/` : ''}${n.namespace}: ${t(`apiAccess.level.${n.level}`)}`)
            .join(' · ')
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-slate-600 dark:text-slate-300">
          {preview ? t('apiAccess.activeKeys', { count: preview.activeKeys }) : null}
        </span>
        {revoked !== null && <Alert severity="success">{t('apiAccess.revokedCount', { count: revoked })}</Alert>}
        {preview && preview.activeKeys > 0 && (
          <Button variant="outline" size="sm" className="ml-auto !text-rose-600 dark:!text-rose-300" onClick={() => void revokeAll()}>
            <Ban size={13} />
            {t('apiAccess.revokeAll')}
          </Button>
        )}
      </div>
    </section>
  );
};
