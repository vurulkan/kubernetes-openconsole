import React, { useEffect, useId, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ArrowLeft, KeyRound, ShieldAlert } from 'lucide-react';
import Layout from '../../components/Layout';
import Combobox from '../../components/Combobox';
import { PermissionMatrix, emptyMatrix, type Matrix } from '../../components/PermissionMatrix';
import { Alert, Button, Checkbox, Input, MultiSelect, Spinner } from '../../components/ui';
import {
  createApiKey,
  getApiKeyCeiling,
  listApiKeys,
  updateApiKey,
  type ApiKey,
  type ApiKeyCeiling,
  type User,
} from '../../services/api';
import {
  CATALOG_GRANTS,
  ExpiryPicker,
  SecretBox,
  TEMPLATES,
  classify,
  dangerous,
  expiryFromChoice,
  scopePairs,
  templateGrants,
  type ExpiryChoice,
  type KeyTemplate,
} from './ApiKeyParts';

const labelClass = 'text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400';

const toMatrix = (grants: string[]): Matrix => {
  const m = emptyMatrix();
  grants.forEach((g) => {
    const [r, a] = g.split(':');
    if (m[r] && a in m[r]) m[r][a] = true;
  });
  return m;
};
const fromMatrix = (m: Matrix) => CATALOG_GRANTS.filter((g) => m[g.split(':')[0]]?.[g.split(':')[1]]);

/** Two-way choice ("All" / "Selected") as a segmented pair of toggle buttons. */
const Segmented: React.FC<{ label: string; value: string; options: Array<[string, string]>; onChange: (v: string) => void }> = ({
  label,
  value,
  options,
  onChange,
}) => (
  <div role="group" aria-label={label} className="inline-flex self-start rounded-lg border border-slate-200 p-0.5 dark:border-slate-700">
    {options.map(([v, text]) => (
      <button
        key={v}
        type="button"
        aria-pressed={value === v}
        onClick={() => onChange(v)}
        className={`cursor-pointer rounded-md px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40 ${
          value === v
            ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200'
            : 'text-slate-600 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-800'
        }`}
      >
        {text}
      </button>
    ))}
  </div>
);

const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <section className="space-y-3 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900/60">
    <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
    {children}
  </section>
);

/**
 * /account/api-keys/new and /account/api-keys/:id. A full page (the matrix is long): name and note,
 * expiry (create only), clusters × namespaces, a template, the permission matrix limited to what the
 * caller holds, the admin scope for admins. On create the secret is shown once, here.
 */
const ApiKeyFormPage: React.FC<{ user: User }> = ({ user }) => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { id } = useParams();
  const editId = id && id !== 'new' ? Number(id) : null;
  const noteId = useId();

  const [ceiling, setCeiling] = useState<ApiKeyCeiling | null>(null);
  const [editing, setEditing] = useState<ApiKey | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<{ secret: string; cluster?: string } | null>(null);

  const [name, setName] = useState('');
  const [note, setNote] = useState('');
  const [choice, setChoice] = useState<ExpiryChoice>('30');
  const [date, setDate] = useState('');
  const [allClusters, setAllClusters] = useState(true);
  const [clusterName, setClusterName] = useState('');
  const [allNamespaces, setAllNamespaces] = useState(false);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [template, setTemplate] = useState<KeyTemplate>('safeRead');
  const [matrix, setMatrix] = useState<Matrix>(emptyMatrix());
  const [adminScope, setAdminScope] = useState(false);
  const [dropped, setDropped] = useState<string[]>([]);

  useEffect(() => {
    (async () => {
      try {
        const [c, list] = await Promise.all([getApiKeyCeiling(), editId ? listApiKeys() : Promise.resolve(null)]);
        setCeiling(c);
        const k = list?.items.find((x) => x.id === editId) ?? null;
        if (editId && !k) {
          setError(t('apiKeys.notFound'));
          return;
        }
        if (k) {
          setEditing(k);
          setName(k.name);
          setNote(k.note);
          setAllClusters(k.clusters.includes(0));
          setClusterName(c.clusters.find((x) => x.id === k.clusters[0])?.name ?? '');
          setAllNamespaces(k.allNamespaces);
          setNamespaces(k.namespaces);
          setMatrix(toMatrix(k.grants));
          setAdminScope(k.adminScope);
          setTemplate(classify(k.grants, new Set(c.namespaces.flatMap((n) => n.grants))));
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
  }, [editId, t]);

  const clusterId = allClusters ? 0 : ceiling?.clusters.find((c) => c.name === clusterName)?.id;
  const clusters = clusterId === undefined ? [] : [clusterId];
  // The namespaces the chosen clusters offer, and the pairs the selection reaches (all of them while none is picked).
  const nsOptions = useMemo(
    () => [...new Set(ceiling ? scopePairs(ceiling, clusters, true, []).map((n) => n.namespace) : [])].sort(),
    [ceiling, clusterId],
  );
  const pairs = useMemo(() => {
    if (!ceiling) return [];
    const picked = allNamespaces || namespaces.length > 0;
    return scopePairs(ceiling, clusters, !picked || allNamespaces, namespaces);
  }, [ceiling, clusterId, allNamespaces, namespaces]);
  const available = useMemo(() => new Set(pairs.flatMap((p) => p.grants)), [pairs]);

  // A grant the selection no longer reaches is dropped (and listed, so the change isn't silent).
  useEffect(() => {
    if (!ceiling) return;
    const lost = fromMatrix(matrix).filter((g) => !available.has(g));
    if (lost.length === 0) return;
    setDropped((d) => [...new Set([...d, ...lost])]);
    const m = { ...matrix };
    lost.forEach((g) => {
      const [r, a] = g.split(':');
      m[r] = { ...m[r], [a]: false };
    });
    setMatrix(m);
  }, [available, ceiling]);

  // A new key starts from the safe read template once the ceiling is known.
  useEffect(() => {
    if (ceiling && !editId) setMatrix(toMatrix(templateGrants('safeRead', new Set(ceiling.namespaces.flatMap((n) => n.grants)))));
  }, [ceiling, editId]);

  const applyTemplate = (tpl: KeyTemplate) => {
    setTemplate(tpl);
    if (tpl !== 'custom') setMatrix(toMatrix(templateGrants(tpl, available)));
  };

  const grants = fromMatrix(matrix);
  const expiresAt = expiryFromChoice(choice, date);
  const nsCount = allNamespaces ? t('apiKeys.allNamespacesShort') : t('apiKeys.nsCount', { count: namespaces.length });
  const risky = dangerous(grants, adminScope);
  const valid =
    name.trim() !== '' &&
    grants.length > 0 &&
    clusterId !== undefined &&
    (allNamespaces || namespaces.length > 0) &&
    (editing !== null || expiresAt !== undefined);

  const submit = async () => {
    setBusy(true);
    setError(null);
    const input = {
      name: name.trim(),
      note: note.trim(),
      adminScope,
      clusters,
      allNamespaces,
      namespaces: allNamespaces ? [] : namespaces,
      grants,
    };
    try {
      if (editing) {
        await updateApiKey(editing.id, input);
        navigate('/account/api-keys');
      } else {
        const r = await createApiKey({ ...input, expiresAt: expiresAt ?? null });
        setCreated({ secret: r.secret, cluster: allClusters ? ceiling?.clusters[0]?.name : clusterName });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const back = (
    <Button variant="ghost" size="sm" onClick={() => navigate('/account/api-keys')}>
      <ArrowLeft size={14} />
      {t('apiKeys.backToList')}
    </Button>
  );

  return (
    <Layout user={user}>
      <div className="mx-auto flex max-w-4xl flex-col gap-4">
        <header className="flex flex-wrap items-center gap-3">
          {back}
          <h1 className="flex items-center gap-2 text-lg font-semibold tracking-tight text-slate-900 dark:text-slate-50">
            <KeyRound size={20} className="text-brand-500" aria-hidden="true" />
            {editing ? t('apiKeys.editTitle', { name: editing.name }) : t('apiKeys.new')}
          </h1>
        </header>

        {error && <Alert severity="error">{error}</Alert>}

        {created ? (
          <>
            <SecretBox secret={created.secret} cluster={created.cluster} />
            <div>{back}</div>
          </>
        ) : !ceiling ? (
          !error && (
            <div className="flex justify-center py-10">
              <Spinner />
            </div>
          )
        ) : (
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (valid && !busy) void submit();
            }}
          >
            <Section title={t('apiKeys.sectionName')}>
              <Input label={t('apiKeys.name')} value={name} required maxLength={100} onChange={(e) => setName(e.target.value)} />
              <div className="flex flex-col gap-1.5">
                <label htmlFor={noteId} className={labelClass}>
                  {t('apiKeys.noteOptional')}
                </label>
                <textarea
                  id={noteId}
                  rows={2}
                  maxLength={1000}
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-500/15 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                />
              </div>
            </Section>

            <Section title={t('apiKeys.expiry')}>
              {editing ? (
                <p className="text-sm text-slate-600 dark:text-slate-300">
                  {editing.expiresAt ? new Date(editing.expiresAt).toLocaleString() : t('apiKeys.noExpiry')} ·{' '}
                  <span className="text-slate-500 dark:text-slate-400">{t('apiKeys.expiryReadOnly')}</span>
                </p>
              ) : (
                <ExpiryPicker
                  hideLegend
                  choice={choice}
                  date={date}
                  onChange={(c, d) => {
                    setChoice(c);
                    setDate(d);
                  }}
                />
              )}
            </Section>

            <Section title={t('apiKeys.scope')}>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <span className={labelClass}>{t('apiKeys.cluster')}</span>
                  <div className="flex flex-wrap items-end gap-2">
                    <Segmented
                      label={t('apiKeys.cluster')}
                      value={allClusters ? 'all' : 'some'}
                      options={[
                        ['all', t('apiKeys.allClusters')],
                        ['some', t('apiKeys.selected')],
                      ]}
                      onChange={(v) => setAllClusters(v === 'all')}
                    />
                    {!allClusters && (
                      <Combobox
                        label={t('apiKeys.pickCluster')}
                        value={clusterName}
                        options={ceiling.clusters.map((c) => c.name)}
                        onChange={(v) => setClusterName(v)}
                        className="w-56"
                      />
                    )}
                  </div>
                </div>
                <div className="space-y-2">
                  <span className={labelClass}>{t('apiKeys.namespaces')}</span>
                  <div className="flex flex-col gap-2">
                    <Segmented
                      label={t('apiKeys.namespaces')}
                      value={allNamespaces ? 'all' : 'some'}
                      options={[
                        ['all', t('apiKeys.allMyNamespaces')],
                        ['some', t('apiKeys.selected')],
                      ]}
                      onChange={(v) => setAllNamespaces(v === 'all')}
                    />
                    {allNamespaces ? (
                      <p className="text-xs text-slate-500 dark:text-slate-400">{t('apiKeys.allMyNamespacesHint')}</p>
                    ) : (
                      <MultiSelect
                        label={t('apiKeys.pickNamespaces')}
                        options={nsOptions.map((n) => ({ id: n, label: n }))}
                        value={namespaces.map((n) => ({ id: n, label: n }))}
                        onChange={(v) => setNamespaces(v.map((o) => String(o.id)))}
                        placeholder={t('apiKeys.pickNamespaces')}
                        noOptionsText={t('apiKeys.noNamespaces')}
                      />
                    )}
                  </div>
                </div>
              </div>
            </Section>

            <Section title={t('apiKeys.permissions')}>
              <div role="group" aria-label={t('apiKeys.template')} className="flex flex-wrap gap-1.5">
                {TEMPLATES.map((tpl) => (
                  <button
                    key={tpl}
                    type="button"
                    aria-pressed={template === tpl}
                    onClick={() => applyTemplate(tpl)}
                    className={`cursor-pointer rounded-md border px-2.5 py-1 text-[11px] font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40 ${
                      template === tpl
                        ? 'border-brand-400 bg-brand-50 text-brand-700 dark:border-brand-500/50 dark:bg-brand-500/15 dark:text-brand-200'
                        : 'border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800'
                    }`}
                  >
                    {t(`apiKeys.templates.${tpl}`)}
                  </button>
                ))}
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t(`apiKeys.templateHints.${template}`)}</p>
              {editing && dropped.length > 0 && (
                <Alert severity="warning">{t('apiKeys.dropped', { grants: dropped.join(', ') })}</Alert>
              )}
              <PermissionMatrix
                matrix={matrix}
                onChange={(m) => {
                  setTemplate('custom');
                  setMatrix(m);
                }}
                cell={(resource, a) => {
                  const g = `${resource}:${a.key}`;
                  if (ceiling.disabled.includes(g)) return { disabled: true, title: t('apiKeys.featureOff') };
                  const have = pairs.filter((p) => p.grants.includes(g)).length;
                  if (have === 0) return { disabled: true, title: t('apiKeys.notYours') };
                  if (have < pairs.length)
                    return { partial: `${have}/${pairs.length}`, title: t('apiKeys.partial', { count: have, total: pairs.length }) };
                  return {};
                }}
              />
            </Section>

            {ceiling.isAdmin && (
              <Section title={t('apiKeys.adminApi')}>
                <Checkbox checked={adminScope} onChange={setAdminScope} label={t('apiKeys.adminApiLabel')} />
                <p className="flex items-start gap-2 text-xs text-rose-700 dark:text-rose-300">
                  <ShieldAlert size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
                  {t('apiKeys.adminApiWarning')}
                </p>
              </Section>
            )}

            <div className="sticky bottom-0 flex flex-wrap items-center gap-3 rounded-xl border border-slate-200 bg-white/90 px-4 py-3 backdrop-blur dark:border-slate-800 dark:bg-slate-900/90">
              <p className="text-xs text-slate-600 dark:text-slate-300" aria-live="polite">
                {[
                  nsCount,
                  t('apiKeys.grantCount', { count: grants.length }),
                  ...(risky.length ? [t('apiKeys.includes', { what: risky.join(', ') })] : []),
                  editing ? null : choice === 'never' ? t('apiKeys.noExpiry') : choice === 'custom' ? date || '—' : t('apiKeys.days', { count: Number(choice) }),
                ]
                  .filter(Boolean)
                  .join(' · ')}
              </p>
              <Button type="submit" size="sm" className="ml-auto" disabled={!valid || busy}>
                {busy ? t('yamlEditor.saving') : editing ? t('actions.save') : t('apiKeys.create')}
              </Button>
            </div>
          </form>
        )}
      </div>
    </Layout>
  );
};

export default ApiKeyFormPage;
