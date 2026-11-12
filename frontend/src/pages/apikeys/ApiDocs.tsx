import React, { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ChevronRight, Download } from 'lucide-react';
import { Alert, Badge, Button, Spinner } from '../../components/ui';
import {
  getActiveCluster,
  getOpenApi,
  type ApiKeyCeiling,
  type OpenApiDoc,
  type OpenApiOperation,
  type OpenApiParam,
} from '../../services/api';
import { CopyRow, curlLine } from './ApiKeyParts';

/** ok: a key of yours can call it; policy: you can, the admin's API policy keeps it from keys; off: the operator switched it off. */
export type Reach = 'ok' | 'policy' | 'none' | 'off';

const holds = (grant: string, list: string[]) =>
  grant.startsWith('*:') ? list.some((g) => g.endsWith(grant.slice(1))) : list.includes(grant);

/** What a key of yours can reach for an operation, from the ceiling (admin policy and feature flags applied). */
export const reachOf = (op: OpenApiOperation, ceiling: ApiKeyCeiling): Reach => {
  if (op['x-openconsole-admin']) return ceiling.adminScopeAllowed ? 'ok' : 'policy';
  const need = op['x-openconsole-permission'] ?? [];
  if (need.length === 0) return 'ok';
  if (need.some((g) => holds(g, ceiling.disabled))) return 'off';
  if (ceiling.namespaces.some((n) => need.every((g) => holds(g, n.grants)))) return 'ok';
  if (ceiling.namespaces.some((n) => need.every((g) => holds(g, [...n.grants, ...n.blocked])))) return 'policy';
  return 'none';
};

/** A namespace where the operation works, to fill {namespace} in the curl example. */
const namespaceFor = (op: OpenApiOperation, ceiling: ApiKeyCeiling) => {
  const need = op['x-openconsole-permission'] ?? [];
  return ceiling.namespaces.find((n) => need.every((g) => holds(g, n.grants)))?.namespace ?? ceiling.namespaces[0]?.namespace;
};

type Entry = { method: string; path: string; op: OpenApiOperation; params: OpenApiParam[] };

const METHODS = ['get', 'post', 'put', 'delete'];
const METHOD_VARIANT: Record<string, 'info' | 'success' | 'warning' | 'error'> = {
  GET: 'info',
  POST: 'success',
  PUT: 'warning',
  DELETE: 'error',
};

const refName = (ref?: string) => ref?.split('/').pop() ?? '';

/** Operations an API key can call, by tag; admin ones only for an admin. */
export const entriesByTag = (doc: OpenApiDoc, isAdmin: boolean) => {
  const out = new Map<string, Entry[]>(doc.tags.map((tag) => [tag.name, []]));
  for (const [path, item] of Object.entries(doc.paths)) {
    const shared = (item.parameters as OpenApiParam[] | undefined) ?? [];
    for (const method of METHODS) {
      const op = item[method] as OpenApiOperation | undefined;
      if (!op || op['x-openconsole-api-key'] === false || (op['x-openconsole-admin'] && !isAdmin)) continue;
      const params = [...shared, ...(op.parameters ?? [])].map((p) => (p.$ref ? doc.components.parameters[refName(p.$ref)] : p));
      out.get(op.tags?.[0] ?? '')?.push({ method: method.toUpperCase(), path, op, params });
    }
  }
  return [...out].filter(([, list]) => list.length > 0);
};

const exampleOf = (doc: OpenApiDoc, part?: { $ref?: string; content?: Record<string, { example?: unknown }> }) => {
  const resolved = part?.$ref ? doc.components.responses[refName(part.$ref)] : part;
  const [type, media] = Object.entries(resolved?.content ?? {})[0] ?? [];
  if (media?.example === undefined) return null;
  return typeof media.example === 'string' && !type.includes('json') ? media.example : JSON.stringify(media.example, null, 2);
};

const Pre: React.FC<{ label: string; children: string }> = ({ label, children }) => (
  <div className="space-y-1">
    <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</p>
    <pre className="max-h-64 overflow-auto rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1.5 font-mono text-xs text-slate-800 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-200">
      {children}
    </pre>
  </div>
);

const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <section aria-label={title} className="space-y-3 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
    <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
    {children}
  </section>
);

const Operation: React.FC<{ doc: OpenApiDoc; entry: Entry; ceiling: ApiKeyCeiling; cluster?: string }> = ({ doc, entry, ceiling, cluster }) => {
  const { t } = useTranslation();
  const { method, path, op, params } = entry;
  const reach = reachOf(op, ceiling);
  const ws = path.startsWith('/ws/');
  const body = exampleOf(doc, op.requestBody);
  const okResponse = Object.entries(op.responses ?? {}).find(([code]) => code.startsWith('2'))?.[1];
  const response = exampleOf(doc, okResponse);
  const ns = namespaceFor(op, ceiling);
  const examplePath = ns ? path.replace('{namespace}', ns) : path;
  const dim = reach !== 'ok';
  return (
    <details className="group border-t border-slate-100 first:border-t-0 dark:border-slate-800">
      <summary className="flex cursor-pointer list-none flex-wrap items-center gap-2 px-1 py-2 hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40 dark:hover:bg-slate-800/50 [&::-webkit-details-marker]:hidden">
        <ChevronRight size={14} aria-hidden="true" className="shrink-0 text-slate-400 transition-transform group-open:rotate-90" />
        <Badge variant={dim ? 'default' : ws ? 'default' : METHOD_VARIANT[method]} className="!px-1.5 !py-0 w-14 justify-center font-mono text-[10px]">
          {ws ? 'WS' : method}
        </Badge>
        <code className={`break-all font-mono text-xs ${dim ? 'text-slate-500 dark:text-slate-400' : 'text-slate-900 dark:text-slate-100'}`}>{path}</code>
        <span className={`text-xs ${dim ? 'text-slate-500 dark:text-slate-400' : 'text-slate-600 dark:text-slate-300'}`}>{op.summary}</span>
        <span className="ml-auto flex flex-wrap items-center gap-1">
          {(op['x-openconsole-permission'] ?? []).map((g) => (
            <Badge key={g} className="!px-1.5 !py-0 font-mono text-[10px]">
              {g}
            </Badge>
          ))}
          {op['x-openconsole-admin'] && <Badge variant="error" className="!px-1.5 !py-0 text-[10px]">{t('apiDocs.adminApi')}</Badge>}
          {reach !== 'ok' && (
            <Badge variant={reach === 'policy' ? 'warning' : 'default'} className="!px-1.5 !py-0 text-[10px]">
              {t(`apiDocs.reach.${reach}`)}
            </Badge>
          )}
        </span>
      </summary>
      <div className="space-y-3 px-6 pb-4 pt-1">
        {op.description && <p className="whitespace-pre-line text-xs text-slate-700 dark:text-slate-300">{op.description}</p>}
        {params.length > 0 && (
          <ul className="space-y-0.5 text-xs text-slate-700 dark:text-slate-300">
            {params.map((p) => (
              <li key={`${p.in}-${p.name}`}>
                <code className="font-mono text-slate-900 dark:text-slate-100">{p.name}</code>{' '}
                <span className="text-slate-500 dark:text-slate-400">
                  ({p.in}
                  {p.required ? `, ${t('apiDocs.required')}` : ''}
                  {p.schema?.default !== undefined ? `, ${t('apiDocs.default', { value: String(p.schema.default) })}` : ''})
                </span>
                {p.description && <> · {p.description}</>}
              </li>
            ))}
          </ul>
        )}
        {ws ? (
          <p className="text-xs text-slate-600 dark:text-slate-400">{t('apiDocs.wsHint')}</p>
        ) : (
          <CopyRow value={curlLine(examplePath, cluster, method, body ? JSON.stringify(JSON.parse(body)) : undefined)} label={t('apiDocs.copyExample', { path })} />
        )}
        {body && <Pre label={t('apiDocs.request')}>{body}</Pre>}
        {response && <Pre label={t('apiDocs.response')}>{response}</Pre>}
      </div>
    </details>
  );
};

const ERRORS: Array<[string, string[]]> = [
  ['401', []],
  ['403', ['forbidden', 'api_access_policy', 'api_access_off', 'api_key_not_allowed', 'feature_disabled']],
  ['429', []],
];

/** API keys → Documentation: how to call the API with a key, from /api/openapi.json. */
const ApiDocs: React.FC<{ ceiling: ApiKeyCeiling }> = ({ ceiling }) => {
  const { t } = useTranslation();
  const [doc, setDoc] = useState<OpenApiDoc | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cluster, setCluster] = useState<string>();
  useEffect(() => {
    getOpenApi().then(setDoc, (e) => setError(e instanceof Error ? e.message : String(e)));
    getActiveCluster().then((c) => setCluster(c.active?.name), () => undefined);
  }, []);
  const groups = useMemo(() => (doc ? entriesByTag(doc, ceiling.isAdmin) : []), [doc, ceiling.isAdmin]);

  if (error) return <Alert severity="error">{error}</Alert>;
  if (!doc)
    return (
      <div className="flex justify-center py-10">
        <Spinner />
      </div>
    );

  const origin = window.location.origin;
  const clusterName = cluster ?? ceiling.clusters[0]?.name ?? '<cluster>';
  const download = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'openconsole-openapi.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col gap-4">
      <Section title={t('apiDocs.quickStart')}>
        <p className="text-xs text-slate-600 dark:text-slate-400">{t('apiDocs.quickStartHint')}</p>
        <dl className="grid gap-x-4 gap-y-1 text-xs sm:grid-cols-[max-content_1fr]">
          <dt className="font-medium text-slate-700 dark:text-slate-300">{t('apiDocs.baseUrl')}</dt>
          <dd className="font-mono text-slate-900 dark:text-slate-100">{origin}</dd>
          <dt className="font-medium text-slate-700 dark:text-slate-300">{t('apiDocs.auth')}</dt>
          <dd className="font-mono text-slate-900 dark:text-slate-100">Authorization: Bearer oc_…</dd>
          <dt className="font-medium text-slate-700 dark:text-slate-300">{t('apiDocs.cluster')}</dt>
          <dd className="font-mono text-slate-900 dark:text-slate-100">
            X-OpenConsole-Cluster: {clusterName}{' '}
            <span className="font-sans text-slate-500 dark:text-slate-400">
              ({t('apiDocs.clusters', { names: ceiling.clusters.map((c) => c.name).join(', ') || '—' })})
            </span>
          </dd>
        </dl>
        <p className="text-xs text-slate-600 dark:text-slate-400">{t('apiDocs.firstCall')}</p>
        <CopyRow value={curlLine('/api/auth/me', clusterName)} label={t('apiDocs.copyFirstCall')} />
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={download}>
            <Download size={14} />
            {t('apiDocs.download')}
          </Button>
          <code className="font-mono text-xs text-slate-600 dark:text-slate-400">{origin}/api/openapi.json</code>
        </div>
      </Section>

      <Section title={t('apiDocs.agentText')}>
        <p className="text-xs text-slate-600 dark:text-slate-400">{t('apiDocs.agentTextHint')}</p>
        <CopyRow multiline value={t('apiDocs.agentPrompt', { origin, cluster: clusterName })} label={t('apiDocs.copyAgentText')} />
      </Section>

      <Section title={t('apiDocs.endpoints')}>
        <p className="text-xs text-slate-600 dark:text-slate-400">{t('apiDocs.endpointsHint')}</p>
        {groups.map(([tag, entries]) => (
          <div key={tag} className="space-y-1">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
              {tag} <span className="font-normal normal-case tracking-normal">· {doc.tags.find((x) => x.name === tag)?.description}</span>
            </h3>
            <div className="rounded-lg border border-slate-200 px-2 dark:border-slate-800">
              {entries.map((e) => (
                <Operation key={`${e.method} ${e.path}`} doc={doc} entry={e} ceiling={ceiling} cluster={clusterName} />
              ))}
            </div>
          </div>
        ))}
      </Section>

      <Section title={t('apiDocs.errors')}>
        <ul className="space-y-2 text-xs text-slate-700 dark:text-slate-300">
          {ERRORS.map(([code, reasons]) => (
            <li key={code}>
              <Badge variant={code === '429' ? 'warning' : 'error'} className="!px-1.5 !py-0 mr-2 font-mono text-[10px]">
                {code}
              </Badge>
              {t(`apiDocs.status.${code}`)}
              {reasons.length > 0 && (
                <ul className="ml-12 mt-1 space-y-0.5">
                  {reasons.map((r) => (
                    <li key={r}>
                      <code className="font-mono text-slate-900 dark:text-slate-100">{r}</code> · {t(`apiDocs.reasons.${r}`)}
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
        <Alert severity="info">{t('apiDocs.audited')}</Alert>
      </Section>
    </div>
  );
};

export default ApiDocs;
