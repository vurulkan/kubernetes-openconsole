import { describe, expect, it } from 'vitest';
import i18n from '../i18n';
import { searchText } from './searchText';

const finds = (tab: string, item: Record<string, unknown>, term: string) => searchText(tab, item).includes(term.toLowerCase());

describe('searchText', () => {
  it('pods: status, container names, controller kind and name; not node, IP or image', () => {
    const pod = {
      metadata: { name: 'web-1', ownerReferences: [{ kind: 'ReplicaSet', name: 'web-7d9f8', controller: true }] },
      spec: { nodeName: 'node-a', containers: [{ name: 'app', image: 'nginx' }], initContainers: [{ name: 'migrate' }] },
      status: {
        podIP: '10.42.0.7',
        containerStatuses: [{ name: 'app', restartCount: 5, state: { waiting: { reason: 'CrashLoopBackOff' } } }],
      },
    };
    for (const term of ['web-1', 'crashloop', 'app', 'migrate', 'replicaset', 'web-7d9f8']) expect(finds('pods', pod, term)).toBe(true);
    for (const term of ['node-a', '10.42', 'nginx']) expect(finds('pods', pod, term)).toBe(false);
  });

  it('pods: a running pod that is not ready matches the text the badge shows', () => {
    const pod = {
      metadata: { name: 'p' },
      spec: { containers: [{ name: 'a' }, { name: 'b' }] },
      status: {
        phase: 'Running',
        containerStatuses: [
          { name: 'a', ready: true, state: { running: {} } },
          { name: 'b', ready: false, state: { running: {} } },
        ],
      },
    };
    expect(finds('pods', pod, 'not ready 1/2')).toBe(true);
  });

  it('deployments / statefulsets / daemonsets: status and replica text', () => {
    const dep = { metadata: { name: 'api' }, spec: { replicas: 3 }, status: { readyReplicas: 2 } };
    expect(finds('deployments', dep, 'progressing')).toBe(true);
    expect(finds('deployments', dep, '2/3')).toBe(true);
    expect(finds('statefulsets', dep, 'progressing 2/3')).toBe(true);
    const ds = { metadata: { name: 'agent' }, status: { desiredNumberScheduled: 4, currentNumberScheduled: 4, numberReady: 4 } };
    expect(finds('daemonsets', ds, 'ready 4/4')).toBe(true);
  });

  it('services: type, cluster IP, external IPs and every part of a port', () => {
    const svc = {
      metadata: { name: 'front' },
      spec: {
        type: 'LoadBalancer',
        clusterIP: '10.43.12.5',
        externalIPs: ['192.0.2.10'],
        ports: [{ name: 'http', port: 80, targetPort: 8080, nodePort: 31080, protocol: 'TCP' }],
      },
      status: { loadBalancer: { ingress: [{ hostname: 'lb.example.com' }] } },
    };
    for (const term of ['loadbalancer', '10.43.', '192.0.2.10', 'lb.example', 'http', '80/TCP', '8080', '31080'])
      expect(finds('services', svc, term)).toBe(true);
    expect(finds('services', svc, '9090')).toBe(false);
  });

  it('configmaps and secrets: key names and secret type, never values', () => {
    expect(finds('configmaps', { metadata: { name: 'cfg' }, data: { 'app.yaml': 'password: hunter2' } }, 'app.yaml')).toBe(true);
    expect(finds('configmaps', { metadata: { name: 'cfg' }, data: { 'app.yaml': 'password: hunter2' } }, 'hunter2')).toBe(false);
    const secret = { metadata: { name: 's' }, type: 'kubernetes.io/tls', keys: [{ name: 'tls.crt', size: 10 }] };
    expect(finds('secrets', secret, 'kubernetes.io/tls')).toBe(true);
    expect(finds('secrets', secret, 'tls.crt')).toBe(true);
  });

  it('ingresses: hosts and paths', () => {
    const ing = { metadata: { name: 'i' }, spec: { rules: [{ host: 'shop.example.com', http: { paths: [{ path: '/api' }] } }] } };
    expect(finds('ingresses', ing, 'shop.example')).toBe(true);
    expect(finds('ingresses', ing, '/api')).toBe(true);
  });

  it('cronjobs and jobs: schedule and status', () => {
    expect(finds('cronjobs', { metadata: { name: 'c' }, spec: { schedule: '*/5 * * * *', suspend: true } }, '*/5')).toBe(true);
    expect(finds('cronjobs', { metadata: { name: 'c' }, spec: { schedule: '0 1 * * *', suspend: true } }, 'suspended')).toBe(true);
    expect(finds('jobs', { metadata: { name: 'j' }, status: { failed: 2 } }, 'failed')).toBe(true);
    expect(finds('jobs', { metadata: { name: 'j' }, status: { succeeded: 1 } }, 'succeeded')).toBe(true);
  });

  it('hpas: target and min / max', () => {
    const hpa = { metadata: { name: 'h' }, spec: { scaleTargetRef: { kind: 'Deployment', name: 'web' }, minReplicas: 2, maxReplicas: 10 } };
    expect(finds('hpas', hpa, 'deployment/web')).toBe(true);
    expect(finds('hpas', hpa, '2-10')).toBe(true);
  });

  it('status texts follow the UI language', async () => {
    const dep = { metadata: { name: 'api' }, spec: { replicas: 0 } };
    await i18n.changeLanguage('tr');
    const tr = searchText('deployments', dep);
    await i18n.changeLanguage('en');
    expect(tr).toContain(i18n.getResourceBundle('tr', 'translation').dashboard.status.scaledToZero.toLowerCase());
    expect(finds('deployments', dep, 'scaled to 0')).toBe(true);
  });

  it('keeps values apart, so a term cannot match across two of them', () => {
    expect(finds('ingresses', { metadata: { name: 'ab' }, spec: { rules: [{ host: 'cd' }] } }, 'bc')).toBe(false);
  });
});
