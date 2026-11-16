// The Kubernetes objects the Dashboard reads, as structural types with only the
// fields the code uses. The API hands out plain JSON (Record<string, unknown>),
// which is assignable to these (every field is optional), so no cast is needed.
import type { ContainerStatus } from './podStatus';

export type OwnerReference = { kind?: string; name?: string; controller?: boolean };

export type ObjectMeta = {
  name?: string;
  namespace?: string;
  uid?: string;
  creationTimestamp?: string;
  deletionTimestamp?: string;
  resourceVersion?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  ownerReferences?: OwnerReference[];
};

export type Condition = { type?: string; status?: string; reason?: string; message?: string; lastTransitionTime?: string };

type Port = number | string;
export type Probe = {
  httpGet?: { path?: string; port?: Port };
  tcpSocket?: { port?: Port };
  grpc?: { port?: Port };
  exec?: { command?: string[] };
};

export type ContainerSpec = {
  name: string;
  image?: string;
  restartPolicy?: string;
  resources?: { requests?: Record<string, string>; limits?: Record<string, string> };
  livenessProbe?: Probe;
  readinessProbe?: Probe;
  startupProbe?: Probe;
};

export type PodObject = {
  metadata?: ObjectMeta;
  spec?: { nodeName?: string; containers?: ContainerSpec[]; initContainers?: ContainerSpec[] };
  status?: {
    phase?: string;
    reason?: string;
    podIP?: string;
    qosClass?: string;
    conditions?: Condition[];
    initContainerStatuses?: ContainerStatus[];
    containerStatuses?: ContainerStatus[];
  };
};

type RollingUpdate = { maxSurge?: Port; maxUnavailable?: Port; partition?: number };

/** Deployment, StatefulSet or DaemonSet; each kind sets its own subset of the fields. */
export type WorkloadObject = {
  metadata?: ObjectMeta;
  spec?: {
    replicas?: number;
    strategy?: { type?: string; rollingUpdate?: RollingUpdate };
    updateStrategy?: { type?: string; rollingUpdate?: RollingUpdate };
    template?: { spec?: { containers?: ContainerSpec[] } };
  };
  status?: {
    replicas?: number;
    readyReplicas?: number;
    availableReplicas?: number;
    updatedReplicas?: number;
    updateRevision?: string;
    desiredNumberScheduled?: number;
    currentNumberScheduled?: number;
    updatedNumberScheduled?: number;
    numberReady?: number;
    numberAvailable?: number;
    conditions?: Condition[];
  };
};

export type ServiceObject = {
  spec?: { type?: string; clusterIP?: string; ports?: Array<{ port?: number; protocol?: string }> };
};

export type IngressObject = {
  spec?: { rules?: Array<{ host?: string; http?: { paths?: Array<{ path?: string }> } }> };
};

export type CronJobObject = {
  spec?: { schedule?: string; suspend?: boolean };
  status?: { lastScheduleTime?: string };
};

export type JobObject = {
  spec?: { completions?: number };
  status?: { succeeded?: number; failed?: number; active?: number };
};

export type HPAObject = {
  spec?: { scaleTargetRef?: { kind?: string; name?: string }; minReplicas?: number; maxReplicas?: number };
  status?: { currentReplicas?: number; desiredReplicas?: number };
};
