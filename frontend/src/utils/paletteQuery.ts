import type { SearchKind } from '../services/api';

/** What a filter word in the ⌘K box narrows to: a search kind, or the palette's namespace list. */
export type PaletteKind = SearchKind | 'namespaces';

// kubectl's short names plus singular / plural names.
// shortcut: only these synonyms; add more when someone asks for one.
const KINDS: Record<string, PaletteKind> = {};
const add = (kind: PaletteKind, ...words: string[]) => words.forEach((w) => (KINDS[w] = kind));
add('pods', 'po', 'pod', 'pods');
add('deployments', 'deploy', 'deployment', 'deployments');
add('statefulsets', 'sts', 'statefulset', 'statefulsets');
add('daemonsets', 'ds', 'daemonset', 'daemonsets');
add('services', 'svc', 'service', 'services');
add('configmaps', 'cm', 'configmap', 'configmaps');
add('ingresses', 'ing', 'ingress', 'ingresses');
add('jobs', 'job', 'jobs');
add('cronjobs', 'cj', 'cronjob', 'cronjobs');
add('hpas', 'hpa', 'hpas', 'horizontalpodautoscaler', 'horizontalpodautoscalers');
add('namespaces', 'ns', 'namespace', 'namespaces');
add('nodes', 'no', 'node', 'nodes');

/**
 * Takes the finished filter words off the front of the ⌘K box: a kind (`svc web`, `svc:web`) and
 * `ns:<name>` followed by a space, in any order. A word with something else after it stays text
 * (`svc-gateway`), and so does a kind word alone (`svc` = a name search). `nodes` only for admins.
 */
export function takeFilters(input: string, nodes: boolean): { kind?: PaletteKind; ns?: string; rest: string } {
  let rest = input.replace(/^\s+/, '');
  let kind: PaletteKind | undefined;
  let ns: string | undefined;
  for (;;) {
    const n = ns === undefined ? /^ns:(\S+)\s+/i.exec(rest) : null;
    if (n) {
      ns = n[1].toLowerCase();
      rest = rest.slice(n[0].length);
      continue;
    }
    const k = kind === undefined ? /^([a-z]+)(?:\s+|:)/i.exec(rest) : null;
    // `ns:` is the namespace filter, never the kind form of `ns`
    const found = k && !/^ns:$/i.test(k[0]) ? KINDS[k[1].toLowerCase()] : undefined;
    if (k && found && (found !== 'nodes' || nodes)) {
      kind = found;
      rest = rest.slice(k[0].length);
      continue;
    }
    return { kind, ns, rest };
  }
}

/** `ns:pro` still being typed at the end of the box narrows like a finished one. */
export function typingNamespace(rest: string): { ns?: string; text: string } {
  const m = /^ns:(\S*)$/i.exec(rest.trim());
  return m ? { ns: m[1].toLowerCase(), text: '' } : { text: rest.trim() };
}

/** The kind's name on a chip and a result row (Kubernetes kind names, the same in every language). */
export const KIND_NAME: Record<PaletteKind, string> = {
  pods: 'Pod', deployments: 'Deployment', statefulsets: 'StatefulSet', daemonsets: 'DaemonSet', services: 'Service',
  configmaps: 'ConfigMap', ingresses: 'Ingress', jobs: 'Job', cronjobs: 'CronJob', hpas: 'HPA', namespaces: 'Namespace',
  nodes: 'Node',
};
