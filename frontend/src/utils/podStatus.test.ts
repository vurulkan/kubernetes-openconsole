import { describe, expect, it } from 'vitest';
import i18n from '../i18n';
import { containerStates, exitCodeHint, mainContainer, podController, podStatus, type PodLike } from './podStatus';

const running = (name: string, extra: object = {}) => ({
  name,
  ready: true,
  restartCount: 0,
  state: { running: { startedAt: '2026-10-26T08:00:00Z' } },
  ...extra,
});

const pod = (status: PodLike['status'], extra: Partial<PodLike> = {}): PodLike => ({ status, ...extra });

describe('podStatus', () => {
  it.each<[string, PodLike, string, string]>([
    ['healthy', pod({ phase: 'Running', containerStatuses: [running('app'), running('sidecar')] }), 'Running', 'ok'],
    [
      'running but not ready',
      pod({ phase: 'Running', containerStatuses: [running('app', { ready: false })] }),
      'Running',
      'warn',
    ],
    [
      'crash loop',
      pod({
        phase: 'Running',
        containerStatuses: [
          {
            name: 'app',
            restartCount: 7,
            state: { waiting: { reason: 'CrashLoopBackOff' } },
            lastState: { terminated: { exitCode: 1, reason: 'Error', finishedAt: '2026-10-26T08:10:00Z' } },
          },
        ],
      }),
      'CrashLoopBackOff',
      'error',
    ],
    [
      'image pull',
      pod({ phase: 'Pending', containerStatuses: [{ name: 'app', state: { waiting: { reason: 'ImagePullBackOff' } } }] }),
      'ImagePullBackOff',
      'error',
    ],
    [
      'missing configmap',
      pod({
        phase: 'Pending',
        containerStatuses: [{ name: 'app', state: { waiting: { reason: 'CreateContainerConfigError' } } }],
      }),
      'CreateContainerConfigError',
      'error',
    ],
    [
      'container creating',
      pod({ phase: 'Pending', containerStatuses: [{ name: 'app', state: { waiting: { reason: 'ContainerCreating' } } }] }),
      'ContainerCreating',
      'warn',
    ],
    [
      'failed init container',
      pod(
        {
          phase: 'Pending',
          initContainerStatuses: [{ name: 'migrate', state: { terminated: { exitCode: 1, reason: 'Error' } } }],
          containerStatuses: [{ name: 'app', state: { waiting: { reason: 'PodInitializing' } } }],
        },
        { spec: { initContainers: [{}] } },
      ),
      'Init:Error',
      'error',
    ],
    [
      'init in progress',
      pod(
        {
          phase: 'Pending',
          initContainerStatuses: [
            { name: 'a', state: { terminated: { exitCode: 0, reason: 'Completed' } } },
            { name: 'b', state: { running: {} } },
          ],
          containerStatuses: [{ name: 'app', state: { waiting: { reason: 'PodInitializing' } } }],
        },
        { spec: { initContainers: [{}, {}] } },
      ),
      'Init:1/2',
      'warn',
    ],
    [
      'completed job pod',
      pod({
        phase: 'Succeeded',
        containerStatuses: [{ name: 'job', state: { terminated: { exitCode: 0, reason: 'Completed' } } }],
      }),
      'Completed',
      'idle',
    ],
    [
      'unschedulable',
      pod({
        phase: 'Pending',
        conditions: [{ type: 'PodScheduled', status: 'False', reason: 'Unschedulable' }],
      }),
      'Unschedulable',
      'warn',
    ],
    [
      'evicted',
      pod({ phase: 'Failed', reason: 'Evicted' }),
      'Evicted',
      'error',
    ],
    [
      'terminating',
      pod({ phase: 'Running', containerStatuses: [running('app')] }, { metadata: { deletionTimestamp: '2026-10-26T08:00:00Z' } }),
      'Terminating',
      'warn',
    ],
    [
      'exit code without reason',
      pod({ phase: 'Running', containerStatuses: [{ name: 'app', state: { terminated: { exitCode: 3 } } }] }),
      'ExitCode:3',
      'error',
    ],
  ])('%s → %s', (_name, input, label, tone) => {
    const s = podStatus(input);
    expect(s.label).toBe(label);
    expect(s.tone).toBe(tone);
  });

  it('counts ready containers and restarts', () => {
    const s = podStatus(
      pod({ phase: 'Running', containerStatuses: [running('a', { restartCount: 2 }), running('b', { ready: false, restartCount: 1 })] }),
    );
    expect([s.ready, s.total, s.restarts]).toEqual([1, 2, 3]);
  });

  it('picks the most recent termination across containers', () => {
    const s = podStatus(
      pod({
        phase: 'Running',
        containerStatuses: [
          running('a', {
            restartCount: 1,
            lastState: { terminated: { exitCode: 1, reason: 'Error', finishedAt: '2026-10-26T07:00:00Z' } },
          }),
          running('b', {
            restartCount: 4,
            lastState: { terminated: { exitCode: 137, reason: 'OOMKilled', finishedAt: '2026-10-26T08:00:00Z' } },
          }),
        ],
      }),
    );
    expect(s.tone).toBe('ok');
    expect(s.lastTermination).toMatchObject({ container: 'b', exitCode: 137, reason: 'OOMKilled' });
    expect(s.containers[0].lastTermination).toMatchObject({ container: 'a', exitCode: 1 });
  });

  it('counts init container restarts and terminations', () => {
    const s = podStatus(
      pod({
        phase: 'Pending',
        initContainerStatuses: [
          {
            name: 'migrate',
            restartCount: 4,
            state: { waiting: { reason: 'CrashLoopBackOff' } },
            lastState: { terminated: { exitCode: 3, reason: 'Error', finishedAt: '2026-10-26T08:00:00Z' } },
          },
        ],
        containerStatuses: [{ name: 'app', state: { waiting: { reason: 'PodInitializing' } } }],
      }),
    );
    expect([s.label, s.restarts, s.ready, s.total]).toEqual(['Init:CrashLoopBackOff', 4, 0, 1]);
    expect(s.lastTermination).toMatchObject({ container: 'migrate', exitCode: 3 });
  });

  it('has no termination for a pod that never restarted', () => {
    expect(podStatus(pod({ phase: 'Running', containerStatuses: [running('app')] })).lastTermination).toBeUndefined();
  });
});

describe('exitCodeHint', () => {
  it.each([
    [{ exitCode: 137, reason: 'OOMKilled' }, 'dashboard.exitCode.oomKilled', undefined],
    [{ exitCode: 137, reason: 'Error' }, 'dashboard.exitCode.sigkill', undefined],
    [{ exitCode: 0, reason: 'Completed' }, 'dashboard.exitCode.ok', undefined],
    [{ exitCode: 1 }, 'dashboard.exitCode.appError', undefined],
    [{ exitCode: 127 }, 'dashboard.exitCode.notFound', undefined],
    [{ exitCode: 143 }, 'dashboard.exitCode.sigterm', undefined],
    [{ exitCode: 139 }, 'dashboard.exitCode.sigsegv', undefined],
    [{ exitCode: 130 }, 'dashboard.exitCode.signal', 'SIGINT'],
    [{ exitCode: 0, signal: 9 }, 'dashboard.exitCode.ok', undefined],
    [{ exitCode: 42 }, 'dashboard.exitCode.other', undefined],
  ])('%o → %s', (input, key, signal) => {
    expect(exitCodeHint(input)).toEqual(signal ? { key, signal } : { key });
  });

  it('every hint key exists in EN and TR', () => {
    const codes = [0, 1, 2, 126, 127, 130, 137, 139, 143, 42];
    const keys = new Set([...codes.map((exitCode) => exitCodeHint({ exitCode }).key), exitCodeHint({ exitCode: 137, reason: 'OOMKilled' }).key]);
    for (const lng of ['en', 'tr']) {
      for (const key of keys) expect(i18n.exists(key, { lng }), `${lng}: ${key}`).toBe(true);
    }
  });
});

describe('mainContainer', () => {
  const pod = (names: string[], owner?: { kind: string; name: string }, extra: Record<string, unknown> = {}) => ({
    metadata: { ownerReferences: owner ? [{ ...owner, controller: true }] : [], ...extra },
    spec: { containers: names.map((name) => ({ name })) },
  });
  it('skips a sidecar that comes first (real cases from a cluster)', () => {
    const rs = (d: string) => ({ kind: 'ReplicaSet', name: `${d}-7d4f9` });
    const hash = { labels: { 'pod-template-hash': '7d4f9' } };
    expect(mainContainer(pod(['filebeat', 'digital-planet-integration'], rs('digital-planet-integration-bk'), hash))).toBe('digital-planet-integration');
    expect(mainContainer(pod(['metrics-server-vpa', 'metrics-server'], rs('metrics-server'), hash))).toBe('metrics-server');
    expect(mainContainer(pod(['liveness-probe', 'node-driver-registrar', 'azuredisk'], { kind: 'DaemonSet', name: 'csi-azuredisk-node' }))).toBe('azuredisk');
    expect(mainContainer(pod(['redis', 'sentinel', 'metrics'], { kind: 'StatefulSet', name: 'redis-main-node' }))).toBe('redis');
  });
  it('takes the annotation first, else the first container when nothing matches', () => {
    expect(mainContainer(pod(['proxy', 'web'], undefined, { annotations: { 'kubectl.kubernetes.io/default-container': 'web' } }))).toBe('web');
    expect(mainContainer(pod(['topic-operator', 'user-operator'], { kind: 'ReplicaSet', name: 'kafka-entity-operator-1' }))).toBe('topic-operator');
    expect(mainContainer(pod(['istio-proxy', 'api'], undefined, { labels: { app: 'api' } }))).toBe('api');
    expect(mainContainer({})).toBe('');
  });
});

describe('podStatus with native sidecars', () => {
  const spec = { initContainers: [{ name: 'migrate' }, { name: 'log-agent', restartPolicy: 'Always' }] };
  const done = { name: 'migrate', state: { terminated: { exitCode: 0, reason: 'Completed' } } };

  it('a started sidecar no longer holds the pod in Init and counts as a container', () => {
    const s = podStatus({
      spec,
      status: { phase: 'Running', initContainerStatuses: [done, running('log-agent', { started: true })], containerStatuses: [running('app')] },
    });
    expect([s.label, s.tone, s.ready, s.total]).toEqual(['Running', 'ok', 2, 2]);
  });

  it('a sidecar that has not started yet is still Init', () => {
    const s = podStatus({
      spec,
      status: {
        phase: 'Pending',
        initContainerStatuses: [done, { name: 'log-agent', started: false, state: { waiting: { reason: 'PodInitializing' } } }],
        containerStatuses: [{ name: 'app', state: { waiting: { reason: 'PodInitializing' } } }],
      },
    });
    expect(s.label).toBe('Init:1/2');
  });
});

describe('containerStates', () => {
  it('reads every state, containers first, then init containers and sidecars', () => {
    const p = {
      spec: {
        containers: [{ name: 'app' }, { name: 'proxy' }, { name: 'worker' }, { name: 'job' }, { name: 'boom' }, { name: 'pull' }],
        initContainers: [{ name: 'migrate' }, { name: 'logs', restartPolicy: 'Always' }],
      },
      status: {
        initContainerStatuses: [
          { name: 'migrate', state: { terminated: { exitCode: 0, reason: 'Completed', startedAt: '2026-10-26T07:59:00Z' } } },
          running('logs'),
        ],
        containerStatuses: [
          running('app'),
          running('proxy', { restartCount: 2 }),
          running('worker', { ready: false }),
          { name: 'job', state: { terminated: { exitCode: 0, reason: 'Completed' } } },
          { name: 'boom', restartCount: 4, state: { waiting: { reason: 'CrashLoopBackOff' } } },
          { name: 'pull', state: { waiting: { reason: 'ContainerCreating' } } },
        ],
      },
    };
    expect(containerStates(p).map((c) => [c.name, c.kind, c.state, c.look, c.problem])).toEqual([
      ['app', 'container', 'running, ready', 'ok', false],
      ['proxy', 'container', 'running, restarted, ready', 'restarted', false],
      ['worker', 'container', 'running, not ready', 'warn', true],
      ['job', 'container', 'terminated: Completed (0)', 'done', false],
      ['boom', 'container', 'waiting: CrashLoopBackOff', 'error', true],
      ['pull', 'container', 'waiting: ContainerCreating', 'warn', true],
      ['migrate', 'init', 'terminated: Completed (0)', 'done', false],
      ['logs', 'sidecar', 'running, ready', 'ok', false],
    ]);
    expect(containerStates(p)[0].startedAt).toBe('2026-10-26T08:00:00Z');
    expect(containerStates(p)[4].restarts).toBe(4);
  });

  it('marks a failed exit and a container without a status yet', () => {
    const p = {
      spec: { containers: [{ name: 'app' }], initContainers: [{ name: 'init' }] },
      status: { initContainerStatuses: [{ name: 'init', state: { terminated: { exitCode: 2 } } }] },
    };
    expect(containerStates(p).map((c) => [c.name, c.state, c.look])).toEqual([
      ['app', 'waiting', 'warn'],
      ['init', 'terminated: ExitCode (2)', 'failed'],
    ]);
  });
});

describe('podController', () => {
  it('is the direct controller, not resolved to the Deployment', () => {
    const p = (refs: Array<{ kind: string; name: string; controller?: boolean }>) => ({ metadata: { ownerReferences: refs } });
    expect(podController(p([{ kind: 'ReplicaSet', name: 'web-7d9f8', controller: true }]))).toEqual({ kind: 'ReplicaSet', name: 'web-7d9f8' });
    expect(podController(p([{ kind: 'Foo', name: 'x' }, { kind: 'Node', name: 'n1', controller: true }]))).toEqual({ kind: 'Node', name: 'n1' });
    expect(podController({})).toBeUndefined();
  });
});
