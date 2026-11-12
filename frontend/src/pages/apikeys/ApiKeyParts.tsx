import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Check, Copy } from 'lucide-react';
import { Alert, Badge, Button, Input } from '../../components/ui';
import { RESOURCE_CATALOG } from '../../components/PermissionMatrix';
import type { ApiKey, ApiKeyCeiling } from '../../services/api';

const DAY_MS = 24 * 60 * 60 * 1000;
const READ_ACTIONS = ['list', 'get', 'logs'];

/** Templates fill the matrix; changing a cell by hand makes it "custom". */
export type KeyTemplate = 'safeRead' | 'readAll' | 'all' | 'custom';
export const TEMPLATES: KeyTemplate[] = ['safeRead', 'readAll', 'all', 'custom'];

export const CATALOG_GRANTS = RESOURCE_CATALOG.flatMap((r) => r.actions.map((a) => `${r.resource}:${a.key}`));

/**
 * safeRead: list / get / logs, no ConfigMaps or Secrets. readAll: list / get / logs everywhere plus
 * Secret reveal. all: everything the owner has.
 */
export const inTemplate = (tpl: KeyTemplate, grant: string): boolean => {
  const [resource, action] = grant.split(':');
  if (tpl === 'safeRead') return READ_ACTIONS.includes(action) && resource !== 'configmaps' && resource !== 'secrets';
  if (tpl === 'readAll') return READ_ACTIONS.includes(action) || grant === 'secrets:reveal';
  return tpl === 'all';
};

/** The grants a template gives, limited to what the owner can give. */
export const templateGrants = (tpl: KeyTemplate, available: Set<string>) =>
  CATALOG_GRANTS.filter((g) => available.has(g) && inTemplate(tpl, g));

/** Names a key's grants: a read template when it stays inside one, "all" when it holds everything available. */
export const classify = (grants: string[], available?: Set<string>): KeyTemplate => {
  if (grants.length > 0 && grants.every((g) => inTemplate('safeRead', g))) return 'safeRead';
  if (grants.length > 0 && grants.every((g) => inTemplate('readAll', g))) return 'readAll';
  if (available && available.size > 0 && [...available].every((g) => grants.includes(g))) return 'all';
  return 'custom';
};

/** The risky parts of a key, shown as their own badges. */
export const dangerous = (grants: string[], adminScope: boolean) => [
  ...(grants.includes('pods:exec') ? ['exec'] : []),
  ...(grants.some((g) => g.endsWith(':edit')) ? ['edit'] : []),
  ...(grants.includes('secrets:reveal') ? ['reveal'] : []),
  ...(adminScope ? ['Admin API'] : []),
];

/** The (cluster, namespace) pairs a selection reaches today. Cluster 0 = all. */
export const scopePairs = (ceiling: ApiKeyCeiling, clusters: number[], allNamespaces: boolean, namespaces: string[]) =>
  ceiling.namespaces.filter(
    (n) => (clusters.includes(0) || clusters.includes(n.clusterId)) && (allNamespaces || namespaces.includes(n.namespace)),
  );

export type ExpiryState = { kind: 'revoked' | 'expired' | 'never' | 'active'; days: number };

export const expiryState = (k: Pick<ApiKey, 'revokedAt' | 'expiresAt'>, now = Date.now()): ExpiryState => {
  if (k.revokedAt) return { kind: 'revoked', days: 0 };
  if (!k.expiresAt) return { kind: 'never', days: 0 };
  const left = Date.parse(k.expiresAt) - now;
  return left <= 0 ? { kind: 'expired', days: 0 } : { kind: 'active', days: Math.ceil(left / DAY_MS) };
};

export const ExpiryBadge: React.FC<{ apiKey: ApiKey }> = ({ apiKey }) => {
  const { t } = useTranslation();
  const st = expiryState(apiKey);
  const [variant, label] =
    st.kind === 'revoked'
      ? (['error', t('apiKeys.revoked')] as const)
      : st.kind === 'expired'
      ? (['error', t('apiKeys.expired')] as const)
      : st.kind === 'never'
      ? (['default', t('apiKeys.noExpiry')] as const)
      : ([st.days > 7 ? 'success' : 'warning', t('apiKeys.daysLeft', { count: st.days })] as const);
  const when = apiKey.revokedAt ?? apiKey.expiresAt;
  return (
    <span title={when ? new Date(when).toLocaleString() : undefined}>
      <Badge variant={variant}>
        <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
        {label}
      </Badge>
    </span>
  );
};

export type ExpiryChoice = '7' | '30' | '60' | '90' | 'custom' | 'never';
const CHOICES: ExpiryChoice[] = ['7', '30', '60', '90', 'custom', 'never'];

const localDate = (d: Date) =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;

/** The expiry to send: N days from now, the end of the picked day (local time), null = never, undefined = not valid yet. */
export const expiryFromChoice = (choice: ExpiryChoice, date: string, now = new Date()): string | null | undefined => {
  if (choice === 'never') return null;
  if (choice !== 'custom') return new Date(now.getTime() + Number(choice) * DAY_MS).toISOString();
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
  if (!m) return undefined;
  const end = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 59);
  return end.getTime() > now.getTime() ? end.toISOString() : undefined;
};

/** 7 / 30 / 60 / 90 days, a date, or never (with a warning). Shared by the form and Regenerate. */
export const ExpiryPicker: React.FC<{
  choice: ExpiryChoice;
  date: string;
  onChange: (choice: ExpiryChoice, date: string) => void;
  /** The surrounding section already says "Expiry". */
  hideLegend?: boolean;
}> = ({ choice, date, onChange, hideLegend }) => {
  const { t } = useTranslation();
  return (
    <fieldset className="space-y-2">
      <legend className={hideLegend ? 'sr-only' : 'mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400'}>
        {t('apiKeys.expiry')}
      </legend>
      <div className="flex flex-wrap items-center gap-1.5">
        {CHOICES.map((c) => (
          <button
            key={c}
            type="button"
            aria-pressed={choice === c}
            onClick={() => onChange(c, date)}
            className={`cursor-pointer rounded-md border px-2.5 py-1 text-xs font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40 ${
              choice === c
                ? 'border-brand-400 bg-brand-50 text-brand-700 dark:border-brand-500/50 dark:bg-brand-500/15 dark:text-brand-200'
                : 'border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800'
            }`}
          >
            {c === 'custom' ? t('apiKeys.expiryCustom') : c === 'never' ? t('apiKeys.noExpiry') : t('apiKeys.days', { count: Number(c) })}
          </button>
        ))}
        {choice === 'custom' && (
          <Input
            type="date"
            aria-label={t('apiKeys.expiryDate')}
            value={date}
            min={localDate(new Date(Date.now() + DAY_MS))}
            onChange={(e) => onChange('custom', e.target.value)}
            className="h-8 w-44"
          />
        )}
      </div>
      {choice === 'never' && (
        <Alert severity="warning">
          <span className="inline-flex items-start gap-2">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
            {t('apiKeys.noExpiryWarning')}
          </span>
        </Alert>
      )}
    </fieldset>
  );
};

/** The new secret, shown once: copy button, a curl example, gone when the page is left. */
export const SecretBox: React.FC<{ secret: string; cluster?: string }> = ({ secret, cluster }) => {
  const { t } = useTranslation();
  const [copied, setCopied] = useState('');
  const [failed, setFailed] = useState(false);
  const curl =
    `curl -H "Authorization: Bearer $OPENCONSOLE_API_KEY"` +
    (cluster ? ` -H "X-OpenConsole-Cluster: ${cluster}"` : '') +
    ` ${window.location.origin}/api/namespaces`;
  const copy = async (what: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(what);
      setTimeout(() => setCopied((c) => (c === what ? '' : c)), 1500);
    } catch {
      setFailed(true);
    }
  };
  const row = (what: string, value: string, label: string) => (
    <div className="flex items-center gap-2">
      <code className="min-w-0 flex-1 break-all rounded-md border border-emerald-200 bg-white px-2.5 py-1.5 font-mono text-xs text-slate-900 dark:border-emerald-500/30 dark:bg-slate-950 dark:text-slate-100">
        {value}
      </code>
      <Button variant="outline" size="sm" onClick={() => copy(what, value)} aria-label={label}>
        {copied === what ? <Check size={14} /> : <Copy size={14} />}
        {copied === what ? t('apiKeys.copied') : t('apiKeys.copy')}
      </Button>
    </div>
  );
  return (
    <section
      aria-label={t('apiKeys.newSecret')}
      className="space-y-3 rounded-xl border border-emerald-300 bg-emerald-50 p-4 dark:border-emerald-500/40 dark:bg-emerald-500/10"
    >
      <p className="text-sm font-semibold text-emerald-900 dark:text-emerald-100">{t('apiKeys.newSecret')}</p>
      {row('secret', secret, t('apiKeys.copySecret'))}
      <p className="text-xs font-medium text-emerald-900 dark:text-emerald-100">{t('apiKeys.onceOnly')}</p>
      <p className="text-xs text-emerald-900 dark:text-emerald-100">{t('apiKeys.curlHint')}</p>
      {row('curl', curl, t('apiKeys.copyCurl'))}
      {failed && <Alert severity="error">{t('apiKeys.copyFailed')}</Alert>}
    </section>
  );
};
