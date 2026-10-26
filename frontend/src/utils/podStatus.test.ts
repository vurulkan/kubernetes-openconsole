import { describe, expect, it } from 'vitest';
import i18n from '../i18n';
import { exitCodeHint, podStatus, type PodLike } from './podStatus';

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
