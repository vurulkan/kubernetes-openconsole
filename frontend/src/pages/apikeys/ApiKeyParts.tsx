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
 * safeRead: the server's list (ceiling.safeRead, the same definition as the "Safe read-only" API access
 * mode). readAll: list / get / logs everywhere plus Secret reveal. all: everything the owner has.
 */
export const inTemplate = (tpl: KeyTemplate, grant: string, safeRead: string[]): boolean => {
  if (tpl === 'safeRead') return safeRead.includes(grant);
  if (tpl === 'readAll') return READ_ACTIONS.includes(grant.split(':')[1]) || grant === 'secrets:reveal';
  return tpl === 'all';
};

/** The grants a template gives, limited to what the owner can give. */
export const templateGrants = (tpl: KeyTemplate, available: Set<string>, safeRead: string[]) =>
  CATALOG_GRANTS.filter((g) => available.has(g) && inTemplate(tpl, g, safeRead));

/** Names a key's grants: a read template when it stays inside one, "all" when it holds everything available. */
export const classify = (grants: string[], safeRead: string[], available?: Set<string>): KeyTemplate => {
  if (grants.length > 0 && grants.every((g) => inTemplate('safeRead', g, safeRead))) return 'safeRead';
  if (grants.length > 0 && grants.every((g) => inTemplate('readAll', g, safeRead))) return 'readAll';
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

/** The admin's expiry policy for new and regenerated keys (maxDays 0 = no limit). */
export type ExpiryPolicy = { maxDays: number; allowNoExpiry: boolean };

/** The choices the policy allows: no preset beyond the limit, no "never" unless allowed. */
export const allowedChoices = (p: ExpiryPolicy) =>
  CHOICES.filter((c) => (c === 'never' ? p.allowNoExpiry : c === 'custom' || p.maxDays === 0 || Number(c) <= p.maxDays));

/** 30 days, or the longest preset the policy allows, else a date. */
export const defaultChoice = (p: ExpiryPolicy): ExpiryChoice =>
  allowedChoices(p).includes('30') ? '30' : allowedChoices(p).filter((c) => c !== 'custom' && c !== 'never').pop() ?? 'custom';

const localDate = (d: Date) =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;

/** The last day whose end (23:59:59 local) is within maxDays of now. */
const lastDay = (maxDays: number, now: Date) => {
  const limit = new Date(now.getTime() + maxDays * DAY_MS);
  const end = new Date(limit.getFullYear(), limit.getMonth(), limit.getDate(), 23, 59, 59);
  if (end > limit) end.setDate(end.getDate() - 1);
  return end;
};

/**
 * The expiry to send: N days from now, the end of the picked day (local time), null = never,
 * undefined = not valid (yet), e.g. a date beyond the policy's limit.
 */
export const expiryFromChoice = (choice: ExpiryChoice, date: string, maxDays = 0, now = new Date()): string | null | undefined => {
  if (choice === 'never') return null;
  if (choice !== 'custom') return new Date(now.getTime() + Number(choice) * DAY_MS).toISOString();
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
  if (!m) return undefined;
  const end = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 59);
  if (maxDays > 0 && end > lastDay(maxDays, now)) return undefined;
  return end.getTime() > now.getTime() ? end.toISOString() : undefined;
};

/**
 * 7 / 30 / 60 / 90 days, a date, or never (with a warning), as far as the admin's policy allows.
 * Shared by the form and Regenerate.
 */
export const ExpiryPicker: React.FC<{
  choice: ExpiryChoice;
  date: string;
  onChange: (choice: ExpiryChoice, date: string) => void;
  policy: ExpiryPolicy;
  /** The surrounding section already says "Expiry". */
  hideLegend?: boolean;
}> = ({ choice, date, onChange, policy, hideLegend }) => {
  const { t } = useTranslation();
  const max = policy.maxDays > 0 ? localDate(lastDay(policy.maxDays, new Date())) : undefined;
  return (
    <fieldset className="space-y-2">
      <legend className={hideLegend ? 'sr-only' : 'mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400'}>
        {t('apiKeys.expiry')}
      </legend>
      <div className="flex flex-wrap items-center gap-1.5">
        {allowedChoices(policy).map((c) => (
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
            max={max}
            onChange={(e) => onChange('custom', e.target.value)}
            className="h-8 w-44"
          />
        )}
      </div>
      {policy.maxDays > 0 && (
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('apiKeys.expiryLimit', { count: policy.maxDays })}</p>
      )}
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
/** A value in a mono box with a Copy button (the API key, curl lines, the agent text). */
export const CopyRow: React.FC<{ value: string; label: string; multiline?: boolean; tone?: 'success' | 'plain' }> = ({
  value,
  label,
  multiline,
  tone = 'plain',
}) => {
  const { t } = useTranslation();
  const [state, setState] = useState<'' | 'copied' | 'failed'>('');
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setState('copied');
      setTimeout(() => setState((s) => (s === 'copied' ? '' : s)), 1500);
    } catch {
      setState('failed');
    }
  };
  const box =
    tone === 'success'
      ? 'border-emerald-200 bg-white dark:border-emerald-500/30 dark:bg-slate-950'
      : 'border-slate-200 bg-slate-50 dark:border-slate-700 dark:bg-slate-950';
  return (
    <div className="space-y-1">
      <div className={`flex gap-2 ${multiline ? 'items-start' : 'items-center'}`}>
        <code
          className={`min-w-0 flex-1 rounded-md border px-2.5 py-1.5 font-mono text-xs text-slate-900 dark:text-slate-100 ${box} ${
            multiline ? 'whitespace-pre-wrap break-words' : 'break-all'
          }`}
        >
          {value}
        </code>
        <Button variant="outline" size="sm" onClick={copy} aria-label={label}>
          {state === 'copied' ? <Check size={14} /> : <Copy size={14} />}
          {state === 'copied' ? t('apiKeys.copied') : t('apiKeys.copy')}
        </Button>
      </div>
      {state === 'failed' && <Alert severity="error">{t('apiKeys.copyFailed')}</Alert>}
    </div>
  );
};

/** A curl line for an API key call, with the cluster header when one is named. */
export const curlLine = (path: string, cluster?: string, method = 'GET', body?: string) =>
  `curl${method === 'GET' ? '' : ` -X ${method}`} -H "Authorization: Bearer $OPENCONSOLE_API_KEY"` +
  (cluster ? ` -H "X-OpenConsole-Cluster: ${cluster}"` : '') +
  (body ? ` -H "Content-Type: application/json" -d '${body}'` : '') +
  ` ${window.location.origin}${path}`;

export const SecretBox: React.FC<{ secret: string; cluster?: string }> = ({ secret, cluster }) => {
  const { t } = useTranslation();
  return (
    <section
      aria-label={t('apiKeys.newSecret')}
      className="space-y-3 rounded-xl border border-emerald-300 bg-emerald-50 p-4 dark:border-emerald-500/40 dark:bg-emerald-500/10"
    >
      <p className="text-sm font-semibold text-emerald-900 dark:text-emerald-100">{t('apiKeys.newSecret')}</p>
      <CopyRow value={secret} label={t('apiKeys.copySecret')} tone="success" />
      <p className="text-xs font-medium text-emerald-900 dark:text-emerald-100">{t('apiKeys.onceOnly')}</p>
      <p className="text-xs text-emerald-900 dark:text-emerald-100">{t('apiKeys.curlHint')}</p>
      <CopyRow value={curlLine('/api/namespaces', cluster)} label={t('apiKeys.copyCurl')} tone="success" />
    </section>
  );
};
