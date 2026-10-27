// Pod status the way `kubectl get pods` prints its STATUS column
// (k8s.io/kubernetes pkg/printers/internalversion printPod), plus the last
// container termination so the UI can say why a pod restarted.

type Terminated = {
  exitCode?: number;
  signal?: number;
  reason?: string;
  message?: string;
  startedAt?: string;
  finishedAt?: string;
};
type ContainerState = {
  waiting?: { reason?: string; message?: string };
  running?: { startedAt?: string };
  terminated?: Terminated;
};
type ContainerStatus = {
  name: string;
  ready?: boolean;
  started?: boolean;
  restartCount?: number;
  state?: ContainerState;
  lastState?: ContainerState;
};
export type PodLike = {
  metadata?: { deletionTimestamp?: string };
  spec?: { initContainers?: Array<{ name?: string; restartPolicy?: string }> };
  status?: {
    phase?: string;
    reason?: string;
    conditions?: Array<{ type?: string; status?: string; reason?: string }>;
    initContainerStatuses?: ContainerStatus[];
    containerStatuses?: ContainerStatus[];
  };
};

export type Tone = 'ok' | 'warn' | 'error' | 'idle';

export type Termination = {
  container: string;
  exitCode: number;
  signal?: number;
  reason?: string;
  finishedAt?: string;
};

export type PodStatus = {
  /** kubectl STATUS text: Running, CrashLoopBackOff, OOMKilled, Init:0/2 … (a Kubernetes term, not translated). */
  label: string;
  tone: Tone;
  ready: number;
  total: number;
  restarts: number;
  /** Most recent previous termination of a restarted container, if any. */
  lastTermination?: Termination;
  containers: Array<{ name: string; ready: boolean; restarts: number; lastTermination?: Termination }>;
};

const ERROR_REASONS = new Set([
  'CrashLoopBackOff',
  'ImagePullBackOff',
  'ErrImagePull',
  'ErrImageNeverPull',
  'InvalidImageName',
  'CreateContainerConfigError',
  'CreateContainerError',
  'RunContainerError',
  'PreStartHookError',
  'PostStartHookError',
  'OOMKilled',
  'Error',
  'Failed',
  'Evicted',
  'Unknown',
  'ContainerStatusUnknown',
  'DeadlineExceeded',
]);

function terminatedLabel(t: Terminated, prefix = ''): string {
  if (t.reason) return prefix + t.reason;
  if (t.signal) return `${prefix}Signal:${t.signal}`;
  return `${prefix}ExitCode:${t.exitCode ?? 0}`;
}

function toTermination(container: string, t?: Terminated): Termination | undefined {
  if (!t) return undefined;
  return { container, exitCode: t.exitCode ?? 0, signal: t.signal, reason: t.reason, finishedAt: t.finishedAt };
}

function toneOf(label: string, ready: number, total: number): Tone {
  const bare = label.startsWith('Init:') ? label.slice(5) : label;
  if (ERROR_REASONS.has(bare) || /^(ExitCode|Signal):/.test(bare)) return 'error';
  if (label === 'Running' && ready === total && total > 0) return 'ok';
  if (label === 'Completed' || label === 'Succeeded') return 'idle';
  return 'warn';
}

export function podStatus(pod: PodLike): PodStatus {
  const status = pod.status ?? {};
  const containers = status.containerStatuses ?? [];
  const inits = status.initContainerStatuses ?? [];
  // Native sidecars (init containers with restartPolicy Always) count as containers once started, like kubectl.
  const sidecars = new Set((pod.spec?.initContainers ?? []).filter((c) => c.restartPolicy === 'Always').map((c) => c.name));
  const total = containers.length + sidecars.size;
  let ready = 0;
  let label = status.reason || status.phase || 'Unknown';

  let initializing = false;
  for (let i = 0; i < inits.length; i++) {
    const s = inits[i].state ?? {};
    if (s.terminated && (s.terminated.exitCode ?? 0) === 0) continue;
    if (sidecars.has(inits[i].name) && inits[i].started) {
      if (inits[i].ready) ready++;
      continue;
    }
    initializing = true;
    if (s.terminated) label = terminatedLabel(s.terminated, 'Init:');
    else if (s.waiting?.reason && s.waiting.reason !== 'PodInitializing') label = `Init:${s.waiting.reason}`;
    else label = `Init:${i}/${pod.spec?.initContainers?.length ?? inits.length}`;
    break;
  }

  if (!initializing) {
    let hasRunning = false;
    // kubectl walks containers last to first, so the first container's state wins.
    for (let i = containers.length - 1; i >= 0; i--) {
      const c = containers[i];
      const s = c.state ?? {};
      if (s.waiting?.reason) label = s.waiting.reason;
      else if (s.terminated) label = terminatedLabel(s.terminated);
      else if (s.running && c.ready) {
        hasRunning = true;
        ready++;
      }
    }
    if (label === 'Completed' && hasRunning) {
      const podReady = status.conditions?.some((c) => c.type === 'Ready' && c.status === 'True');
      label = podReady ? 'Running' : 'NotReady';
    }
    if (label === 'Pending') {
      const sched = status.conditions?.find((c) => c.type === 'PodScheduled');
      if (sched?.status === 'False' && sched.reason === 'Unschedulable') label = 'Unschedulable';
    }
  }

  if (pod.metadata?.deletionTimestamp) label = status.reason === 'NodeLost' ? 'Unknown' : 'Terminating';

  // kubectl counts init container restarts too; a failing init container is often the one that restarted.
  const perContainer = [...inits, ...containers].map((c) => ({
    name: c.name,
    ready: !!c.ready,
    restarts: c.restartCount ?? 0,
    lastTermination: toTermination(c.name, c.lastState?.terminated),
  }));
  const lastTermination = perContainer
    .map((c) => c.lastTermination)
    .filter((t): t is Termination => !!t)
    .sort((a, b) => (b.finishedAt ?? '').localeCompare(a.finishedAt ?? ''))[0];

  return {
    label,
    tone: toneOf(label, ready, total),
    ready,
    total,
    restarts: perContainer.reduce((sum, c) => sum + c.restarts, 0),
    lastTermination,
    containers: perContainer,
  };
}

/** How a container's square looks: filled green / green + amber ring / amber / red, or hollow slate / red. */
export type ContainerLook = 'ok' | 'restarted' | 'warn' | 'error' | 'done' | 'failed';

export type ContainerInfo = {
  name: string;
  kind: 'container' | 'init' | 'sidecar';
  /** Kubernetes terms, not translated: "running, ready", "waiting: CrashLoopBackOff", "terminated: Completed (0)". */
  state: string;
  look: ContainerLook;
  /** Problem containers (amber or red) count for the Containers column sort. */
  problem: boolean;
  restarts: number;
  startedAt?: string;
};

type ContainerPod = PodLike & {
  spec?: { containers?: Array<{ name: string }>; initContainers?: Array<{ name: string; restartPolicy?: string }> };
};

/** Every container of a pod, spec.containers first, then the init containers (a sidecar is an init container with restartPolicy Always). */
export function containerStates(pod: ContainerPod): ContainerInfo[] {
  const statuses = pod.status?.containerStatuses ?? [];
  const initStatuses = pod.status?.initContainerStatuses ?? [];
  const specs = pod.spec?.containers ?? statuses;
  const initSpecs = (pod.spec?.initContainers ?? initStatuses) as Array<{ name: string; restartPolicy?: string }>;
  const info = (name: string, kind: ContainerInfo['kind'], st?: ContainerStatus): ContainerInfo => {
    const s = st?.state ?? {};
    const restarts = st?.restartCount ?? 0;
    let state: string;
    let look: ContainerLook;
    let startedAt: string | undefined;
    if (s.running) {
      state = ['running', restarts > 0 && 'restarted', st?.ready ? 'ready' : 'not ready'].filter(Boolean).join(', ');
      look = !st?.ready ? 'warn' : restarts > 0 ? 'restarted' : 'ok';
      startedAt = s.running.startedAt;
    } else if (s.terminated) {
      const code = s.terminated.exitCode ?? 0;
      state = `terminated: ${s.terminated.reason || 'ExitCode'} (${code})`;
      look = code === 0 ? 'done' : 'failed';
      startedAt = s.terminated.startedAt;
    } else {
      const reason = s.waiting?.reason;
      state = reason ? `waiting: ${reason}` : 'waiting';
      look = reason && ERROR_REASONS.has(reason) ? 'error' : 'warn';
    }
    return { name, kind, state, look, problem: look === 'warn' || look === 'error' || look === 'failed', restarts, startedAt };
  };
  return [
    ...specs.map((c) => info(c.name, 'container', statuses.find((x) => x.name === c.name))),
    ...initSpecs.map((c) => info(c.name, c.restartPolicy === 'Always' ? 'sidecar' : 'init', initStatuses.find((x) => x.name === c.name))),
  ];
}

/** The pod's direct controller from ownerReferences (ReplicaSet, StatefulSet, DaemonSet, Job, Node for a static pod); not resolved to the Deployment like podOwner. */
export function podController(pod: {
  metadata?: { ownerReferences?: Array<{ kind?: string; name?: string; controller?: boolean }> };
}): { kind: string; name: string } | undefined {
  const ref = (pod.metadata?.ownerReferences ?? []).find((o) => o.controller) ?? pod.metadata?.ownerReferences?.[0];
  return ref?.kind && ref.name ? { kind: ref.kind, name: ref.name } : undefined;
}

/**
 * The workload a pod belongs to, as "Deployment/web" (through its
 * ReplicaSet <deployment>-<pod-template-hash>), "StatefulSet/db",
 * "DaemonSet/agent", "Job/x"; undefined for a bare pod.
 */
export function podOwner(pod: {
  metadata?: { labels?: Record<string, string>; ownerReferences?: Array<{ kind?: string; name?: string; controller?: boolean }> };
}): string | undefined {
  const ref = (pod.metadata?.ownerReferences ?? []).find((o) => o.controller) ?? pod.metadata?.ownerReferences?.[0];
  if (!ref?.kind || !ref.name) return undefined;
  const hash = pod.metadata?.labels?.['pod-template-hash'];
  if (ref.kind === 'ReplicaSet' && hash && ref.name.endsWith(`-${hash}`)) return `Deployment/${ref.name.slice(0, -hash.length - 1)}`;
  return `${ref.kind}/${ref.name}`;
}

/**
 * The container a pod's log opens on: the kubectl.kubernetes.io/default-container annotation, else the
 * one named after the workload (a log shipper or proxy often comes first, e.g. [filebeat,
 * digital-planet-integration] in Deployment digital-planet-integration-bk), else the first.
 */
export function mainContainer(pod: {
  metadata?: {
    annotations?: Record<string, string>;
    labels?: Record<string, string>;
    ownerReferences?: Array<{ kind?: string; name?: string; controller?: boolean }>;
  };
  spec?: { containers?: Array<{ name: string }> };
}): string {
  const names = pod.spec?.containers?.map((c) => c.name) ?? [];
  const annotated = pod.metadata?.annotations?.['kubectl.kubernetes.io/default-container'];
  if (annotated && names.includes(annotated)) return annotated;
  const labels = pod.metadata?.labels ?? {};
  const workload = [podOwner(pod)?.split('/')[1], labels['app.kubernetes.io/name'], labels.app].filter((w): w is string => !!w);
  const score = (n: string) =>
    Math.max(0, ...workload.map((w) => (n === w ? 3 : w.startsWith(n) || n.startsWith(w) ? 2 : n.length >= 3 && w.includes(n) ? 1 : 0)));
  let best = names[0] ?? '';
  names.forEach((n) => {
    if (score(n) > score(best)) best = n;
  });
  return best;
}

/** "1 (Error)", "137 (OOMKilled)": the code first, so "1 Error" can't read as "one error". */
export function exitLabel(t: { exitCode: number; reason?: string }): string {
  return `${t.exitCode}${t.reason ? ` (${t.reason})` : ''}`;
}

const SIGNALS: Record<number, string> = { 1: 'SIGHUP', 2: 'SIGINT', 6: 'SIGABRT', 9: 'SIGKILL', 11: 'SIGSEGV', 15: 'SIGTERM' };

/** i18n key (under `dashboard.exitCode.`) and params explaining a container exit. */
export function exitCodeHint(t: Pick<Termination, 'exitCode' | 'reason' | 'signal'>): { key: string; signal?: string } {
  const code = t.exitCode;
  if (t.reason === 'OOMKilled') return { key: 'dashboard.exitCode.oomKilled' };
  if (code === 0) return { key: 'dashboard.exitCode.ok' };
  if (code === 1) return { key: 'dashboard.exitCode.appError' };
  if (code === 2) return { key: 'dashboard.exitCode.misuse' };
  if (code === 126) return { key: 'dashboard.exitCode.cannotExecute' };
  if (code === 127) return { key: 'dashboard.exitCode.notFound' };
  if (code === 137) return { key: 'dashboard.exitCode.sigkill' };
  if (code === 139) return { key: 'dashboard.exitCode.sigsegv' };
  if (code === 143) return { key: 'dashboard.exitCode.sigterm' };
  const sig = t.signal || (code > 128 && code < 160 ? code - 128 : 0);
  if (sig) return { key: 'dashboard.exitCode.signal', signal: SIGNALS[sig] ?? String(sig) };
  return { key: 'dashboard.exitCode.other' };
}
