// The Dashboard's small dialogs: events / ConfigMap data, scale, restart, the
// pod shell, and the target the YAML editor opens on.
import React, { Suspense, lazy, useRef, useState } from 'react';
import { Minus, Plus, RefreshCw } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Modal, Spinner } from '../../components/ui';
import type { YamlEditTarget } from '../../components/YamlEditModal';
import { ContainerPicker } from '../../components/ContainerPicker';
import { Events } from './DetailParts';
import type { PodObject } from '../../utils/kubeTypes';
import {
  getConfigMapData,
  getConfigMapYaml,
  getCronJobYaml,
  getDaemonSetYaml,
  getDeploymentEvents,
  getDeploymentYaml,
  getHPAYaml,
  getIngressYaml,
  getJobYaml,
  getPodEvents,
  getPodYaml,
  getSecretYaml,
  getServiceYaml,
  getStatefulSetYaml,
  restartDeployment,
  scaleDeployment,
  scaleStatefulSet,
} from '../../services/api';

// ─── YAML ───────────────────────────────────────────────────────────────────

const YAML: Record<string, { label: string; fetch: (ns: string, name: string) => Promise<{ yaml: string }> }> = {
  pods: { label: 'Pod', fetch: getPodYaml },
  deployments: { label: 'Deployment', fetch: getDeploymentYaml },
  daemonsets: { label: 'DaemonSet', fetch: getDaemonSetYaml },
  statefulsets: { label: 'StatefulSet', fetch: getStatefulSetYaml },
  hpas: { label: 'HPA', fetch: getHPAYaml },
  services: { label: 'Service', fetch: getServiceYaml },
  configmaps: { label: 'ConfigMap', fetch: getConfigMapYaml },
  secrets: { label: 'Secret', fetch: getSecretYaml },
  ingresses: { label: 'Ingress', fetch: getIngressYaml },
  cronjobs: { label: 'CronJob', fetch: getCronJobYaml },
  jobs: { label: 'Job', fetch: getJobYaml },
};

/** What the YAML editor opens on; null for a resource without YAML. */
export function yamlTarget(resource: string, namespace: string, name: string, canEdit: boolean): YamlEditTarget | null {
  const y = YAML[resource];
  if (!y) return null;
  return { resource, resourceLabel: y.label, namespace, name, fetchYaml: y.fetch, canEdit };
}

// ─── Events / ConfigMap data ────────────────────────────────────────────────

type InfoKind = 'configmapData' | 'podEvents' | 'deploymentEvents';
type InfoModalProps = {
  open: boolean;
  subject: { kind: InfoKind; name: string; namespace: string } | null;
  content: string;
  loading: boolean;
  /** Bumped by Refresh: the events list reads again. */
  refreshKey: number;
  onClose: () => void;
  onRefresh: () => void;
};

/**
 * A read-only dialog with a pod's or deployment's events (a live list, as in the drawers) or a
 * ConfigMap's data (text). Refresh reads again in `namespace`.
 */
export function useInfoModal(namespace: string | null) {
  const [open, setOpen] = useState(false);
  const [subject, setSubject] = useState<InfoModalProps['subject']>(null);
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  const show = async (kind: InfoKind, ns: string, name: string) => {
    setOpen(true);
    setSubject({ kind, name, namespace: ns });
    setContent('');
    if (kind !== 'configmapData') {
      setRefreshKey((n) => n + 1); // the events list loads itself
      return;
    }
    setLoading(true);
    try {
      setContent(JSON.stringify((await getConfigMapData(ns, name)).data, null, 2));
    } catch (err) {
      setContent((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const props: InfoModalProps = {
    open,
    subject,
    content,
    loading,
    refreshKey,
    onClose: () => {
      setOpen(false);
      setTimeout(() => {
        setSubject(null);
        setContent('');
        setLoading(false);
      }, 50);
    },
    onRefresh: () => {
      if (namespace && subject) void show(subject.kind, namespace, subject.name);
    },
  };
  return {
    openConfigMapData: (ns: string, name: string) => show('configmapData', ns, name),
    openEvents: (type: 'pods' | 'deployments', ns: string, name: string) =>
      show(type === 'pods' ? 'podEvents' : 'deploymentEvents', ns, name),
    props,
  };
}

export const InfoModal: React.FC<InfoModalProps> = ({ open, subject, content, loading, refreshKey, onClose, onRefresh }) => {
  const { t } = useTranslation();
  const preRef = useRef<HTMLPreElement | null>(null);
  // Ctrl/Cmd+A selects the text, not the whole page.
  const selectAll = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== 'a') return;
    if (!preRef.current) return;
    event.preventDefault();
    const selection = window.getSelection();
    if (!selection) return;
    const range = document.createRange();
    range.selectNodeContents(preRef.current);
    selection.removeAllRanges();
    selection.addRange(range);
  };
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={subject ? t(`dashboard.modalTitles.${subject.kind}`, { name: subject.name }) : ''}
      onKeyDown={selectAll}
      footer={
        <>
          <Button variant="outline" size="sm" onClick={onRefresh}>
            <RefreshCw size={14} />
            {t('actions.refresh')}
          </Button>
          <Button variant="primary" size="sm" onClick={onClose}>
            {t('actions.close')}
          </Button>
        </>
      }
    >
      {subject && subject.kind !== 'configmapData' ? (
        <div className="h-full overflow-auto">
          <Events
            load={() =>
              subject.kind === 'podEvents'
                ? getPodEvents(subject.namespace, subject.name)
                : getDeploymentEvents(subject.namespace, subject.name)
            }
            version={`${subject.kind}:${subject.namespace}/${subject.name}:${refreshKey}`}
            live={{ namespace: subject.namespace, kind: subject.kind === 'podEvents' ? 'Pod' : 'Deployment', name: subject.name }}
          />
        </div>
      ) : loading ? (
        <div className="flex h-full items-center justify-center">
          <Spinner size="md" />
        </div>
      ) : (
        <div className="flex h-full flex-col gap-3">
          <pre
            ref={preRef}
            className="flex-1 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-xs leading-5 text-slate-100 shadow-inner"
            style={{ whiteSpace: 'pre' }}
          >
            {content || t('common.noData')}
          </pre>
        </div>
      )}
    </Modal>
  );
};

// ─── Scale / restart ────────────────────────────────────────────────────────

type ScaleTarget = {
  name: string;
  current: number;
  // Only set when scaling a StatefulSet; deployment scaling leaves this
  // undefined so the modal keeps the historical "scale a Deployment" flow.
  kind?: 'statefulsets';
};

/** Scale and restart, with the page's error / success line; `reload` refreshes the list after either. */
export function useWorkloadActions(namespace: string | null, reload: () => Promise<void>) {
  const { t } = useTranslation();
  const [scaleTarget, setScaleTarget] = useState<ScaleTarget | null>(null);
  const [scaleReplicas, setScaleReplicas] = useState(1);
  const [scaleBusy, setScaleBusy] = useState(false);
  const [restartTarget, setRestartTarget] = useState<string | null>(null);
  // "restart:<name>" while a restart runs; the cards show it on the button.
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const showActionNotice = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice((v) => (v === msg ? null : v)), 4000);
  };

  const restart = async () => {
    if (!namespace || !restartTarget) return;
    const name = restartTarget;
    setActionBusy(`restart:${name}`);
    setActionError(null);
    try {
      await restartDeployment(namespace, name);
      showActionNotice(t('dashboard.restartTriggered', { name }));
      setRestartTarget(null);
      await reload();
    } catch (err) {
      setActionError((err as Error).message || t('dashboard.restartFailed'));
    } finally {
      setActionBusy(null);
    }
  };

  const scale = async () => {
    if (!namespace || !scaleTarget) return;
    setScaleBusy(true);
    setActionError(null);
    try {
      if (scaleTarget.kind === 'statefulsets') {
        await scaleStatefulSet(namespace, scaleTarget.name, scaleReplicas);
      } else {
        await scaleDeployment(namespace, scaleTarget.name, scaleReplicas);
      }
      showActionNotice(t('dashboard.scaled', { name: scaleTarget.name, from: scaleTarget.current, to: scaleReplicas }));
      setScaleTarget(null);
      await reload();
    } catch (err) {
      setActionError((err as Error).message || t('dashboard.scaleFailed'));
    } finally {
      setScaleBusy(false);
    }
  };

  return {
    actionBusy,
    actionError,
    actionNotice,
    openRestart: (name: string) => setRestartTarget(name),
    openScale: (name: string, current: number, kind?: 'statefulsets') => {
      setScaleTarget(kind ? { name, current, kind } : { name, current });
      setScaleReplicas(current);
      setActionError(null);
    },
    modals: {
      scaleTarget,
      scaleReplicas,
      setScaleReplicas,
      scaleBusy,
      closeScale: () => setScaleTarget(null),
      scale,
      restartTarget,
      restartBusy: actionBusy,
      closeRestart: () => setRestartTarget(null),
      restart,
    },
  };
}

type ActionModalsProps = ReturnType<typeof useWorkloadActions>['modals'];

/** The restart confirmation and the scale dialog; each renders only while it has a target. */
export const WorkloadActionModals: React.FC<ActionModalsProps> = ({
  scaleTarget,
  scaleReplicas,
  setScaleReplicas,
  scaleBusy,
  closeScale,
  scale,
  restartTarget,
  restartBusy,
  closeRestart,
  restart,
}) => {
  const { t } = useTranslation();
  return (
    <>
      {restartTarget && (
        <Modal
          open={restartTarget !== null}
          onClose={() => (restartBusy ? undefined : closeRestart())}
          title={t('dashboard.restartConfirm.title', { name: restartTarget })}
          size="sm"
          footer={
            <>
              <Button variant="outline" size="sm" onClick={closeRestart} disabled={restartBusy !== null}>
                {t('actions.cancel')}
              </Button>
              <Button variant="primary" size="sm" disabled={restartBusy !== null} onClick={restart}>
                {restartBusy ? t('dashboard.actions.restarting') : t('dashboard.actions.restart')}
              </Button>
            </>
          }
        >
          <p className="text-sm text-slate-700 dark:text-slate-200">
            {t('dashboard.restartConfirm.message', { name: restartTarget })}
          </p>
        </Modal>
      )}

      {scaleTarget && (
        <Modal
          open={scaleTarget !== null}
          onClose={() => (scaleBusy ? undefined : closeScale())}
          title={t('dashboard.scaleModal.title', { name: scaleTarget.name })}
          size="sm"
          footer={
            <>
              <Button variant="outline" size="sm" onClick={closeScale} disabled={scaleBusy}>
                {t('actions.cancel')}
              </Button>
              <Button
                variant="primary"
                size="sm"
                disabled={scaleBusy || scaleReplicas === scaleTarget.current}
                onClick={scale}
              >
                {scaleBusy ? t('dashboard.scaleModal.applying') : t('dashboard.scaleModal.apply')}
              </Button>
            </>
          }
        >
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-4 rounded-lg bg-slate-50 dark:bg-slate-800/40 px-3 py-2">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                  {t('dashboard.columns.current')}
                </p>
                <p className="font-mono text-lg font-semibold text-slate-900 dark:text-slate-100">
                  {scaleTarget.current}
                </p>
              </div>
              <span className="text-slate-400">→</span>
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wide text-brand-600 dark:text-brand-300">
                  {t('dashboard.columns.target')}
                </p>
                <div className="mt-0.5 flex items-center gap-1.5">
                  <Button
                    variant="outline"
                    size="sm"
                    aria-label={t('dashboard.scaleModal.decrease')}
                    onClick={() => setScaleReplicas(Math.max(0, scaleReplicas - 1))}
                  >
                    <Minus size={12} />
                  </Button>
                  <input
                    type="number"
                    aria-label={t('dashboard.scaleModal.target')}
                    min={0}
                    max={100}
                    value={scaleReplicas}
                    onChange={(e) => setScaleReplicas(Math.max(0, Math.min(100, Number(e.target.value) || 0)))}
                    onKeyDown={(e) => {
                      // Shift+↑/↓ jumps by 10 for faster scaling in large deployments.
                      if (!e.shiftKey) return;
                      if (e.key === 'ArrowUp') {
                        e.preventDefault();
                        setScaleReplicas((v) => Math.min(100, v + 10));
                      } else if (e.key === 'ArrowDown') {
                        e.preventDefault();
                        setScaleReplicas((v) => Math.max(0, v - 10));
                      }
                    }}
                    className="w-16 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-1 text-center font-mono text-base font-semibold focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-500/15 dark:text-slate-100"
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    aria-label={t('dashboard.scaleModal.increase')}
                    onClick={() => setScaleReplicas(Math.min(100, scaleReplicas + 1))}
                  >
                    <Plus size={12} />
                  </Button>
                </div>
              </div>
            </div>

            {scaleReplicas === 0 && (
              <Alert severity="warning">
                {t('dashboard.scaleModal.zeroWarning')}
              </Alert>
            )}
            {scaleReplicas > scaleTarget.current + 5 && (
              <Alert severity="info">
                {t('dashboard.scaleModal.bigStep', { from: scaleTarget.current, to: scaleReplicas })}
              </Alert>
            )}
          </div>
        </Modal>
      )}
    </>
  );
};

// ─── Shell ──────────────────────────────────────────────────────────────────

// xterm is loaded with the first shell, not with the page.
const PodExecModal = lazy(() => import('../../components/PodExecModal'));

/** A pod's shell. A pod with sidecars asks which container first, in a small menu under the Shell button. */
export function useShell() {
  const [execTarget, setExecTarget] = useState<{ name: string; containers: string[]; container?: string } | null>(null);
  const [shellPick, setShellPick] = useState<{ pod: PodObject; anchor: HTMLElement } | null>(null);
  return {
    openShell: (pod: PodObject, anchor: HTMLElement) => {
      const containers = (pod.spec?.containers ?? []).map((c) => c.name);
      if (containers.length > 1) setShellPick({ pod, anchor });
      else setExecTarget({ name: pod.metadata?.name ?? '', containers, container: containers[0] });
    },
    modals: {
      execTarget,
      closeExec: () => setExecTarget(null),
      shellPick,
      closePick: () => setShellPick(null),
      pick: (container: string) => {
        if (!shellPick) return;
        const containers = (shellPick.pod.spec?.containers ?? []).map((c) => c.name);
        setExecTarget({ name: shellPick.pod.metadata?.name ?? '', containers, container });
        setShellPick(null);
      },
    },
  };
}

export const ShellModals: React.FC<ReturnType<typeof useShell>['modals'] & { namespace: string }> = ({
  execTarget,
  closeExec,
  shellPick,
  closePick,
  pick,
  namespace,
}) => (
  <>
    {shellPick && <ContainerPicker pod={shellPick.pod} anchor={shellPick.anchor} onClose={closePick} onPick={pick} />}
    {execTarget && (
      <Suspense fallback={null}>
        <PodExecModal
          key={`${execTarget.name}/${execTarget.container}`}
          open
          onClose={closeExec}
          namespace={namespace}
          pod={execTarget.name}
          containers={execTarget.containers}
          container={execTarget.container}
        />
      </Suspense>
    )}
  </>
);
