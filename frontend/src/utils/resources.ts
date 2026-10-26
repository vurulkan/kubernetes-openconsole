import { parseCpu, parseMem } from './format';

type Container = { resources?: { requests?: Record<string, string>; limits?: Record<string, string> } };
export type Resources = { cpu: { request: number; limit: number }; mem: { request: number; limit: number } };

/**
 * Requests / limits summed over containers. A limit is NaN when any container
 * has none: the pod as a whole is then unbounded.
 */
export function podResources(containers: Container[] = []): Resources {
  const sum = (pick: (c: Container) => number) =>
    containers.length ? containers.reduce((acc, c) => acc + pick(c), 0) : NaN;
  return {
    cpu: {
      request: sum((c) => parseCpu(c.resources?.requests?.cpu) || 0),
      limit: sum((c) => parseCpu(c.resources?.limits?.cpu)),
    },
    mem: {
      request: sum((c) => parseMem(c.resources?.requests?.memory) || 0),
      limit: sum((c) => parseMem(c.resources?.limits?.memory)),
    },
  };
}

/** Multiplies a per-pod budget by a pod count (deployment totals). */
export function scaleResources(r: Resources, n: number): Resources {
  return {
    cpu: { request: r.cpu.request * n, limit: r.cpu.limit * n },
    mem: { request: r.mem.request * n, limit: r.mem.limit * n },
  };
}

/** Summed usage of a workload's pods ("Deployment/web") in a metrics snapshot. */
export function ownerUsage(items: Array<{ owner?: string; cpu: number; memory: number }>, owner: string) {
  const mine = items.filter((p) => p.owner === owner);
  return {
    pods: mine.length,
    cpu: mine.reduce((s, p) => s + p.cpu, 0),
    memory: mine.reduce((s, p) => s + p.memory, 0),
  };
}
