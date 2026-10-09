import React, { useCallback, useEffect, useRef, useState } from 'react';
import { AlertTriangle, Download } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Alert, Badge, Button, Modal, Spinner, Toggle } from './ui';
import { confirm } from './ConfirmDialog';
import { downloadRecordingCast, getRecordingCast, SessionRecording } from '../services/api';
import { formatBytes, formatDuration } from '../utils/format';

type PlayerModule = typeof import('asciinema-player');
type Player = ReturnType<PlayerModule['create']>;

// The player (JS + WebAssembly terminal + CSS) is split into its own chunk
// and only fetched the first time someone opens a recording.
let playerModule: Promise<PlayerModule> | null = null;
const loadPlayer = () => {
  if (!playerModule) {
    playerModule = Promise.all([
      import('asciinema-player'),
      import('asciinema-player/dist/bundle/asciinema-player.css'),
    ]).then(([mod]) => mod);
    playerModule.catch(() => {
      playerModule = null; // allow a retry after a network blip
    });
  }
  return playerModule;
};

/**
 * Downloads a recording after the admin acknowledges that the file can hold
 * secrets. Shared by the recordings table and the player. Returns false when
 * the admin cancels.
 */
export async function downloadRecordingWithWarning(
  recording: SessionRecording,
  t: (key: string, opts?: Record<string, unknown>) => string,
): Promise<boolean> {
  const ok = await confirm({
    title: t('recordings.downloadWarnTitle'),
    message: t('recordings.downloadWarnBody', {
      user: recording.user,
      target: `${recording.namespace}/${recording.pod}`,
    }),
    confirmText: t('recordings.downloadWarnConfirm'),
    variant: 'danger',
  });
  if (!ok) return false;
  await downloadRecordingCast(recording.id);
  return true;
}

const SPEEDS = [1, 2, 4] as const;
// Pauses longer than this are squeezed when "skip idle" is on, so a session
// that sat at a prompt for minutes doesn't need to be watched in real time.
const IDLE_LIMIT_SECONDS = 2;

type Props = {
  recording: SessionRecording | null;
  onClose: () => void;
};

export const CastPlayerModal: React.FC<Props> = ({ recording, onClose }) => {
  const { t } = useTranslation();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const playerRef = useRef<Player | null>(null);
  const playingRef = useRef(false);
  const castRef = useRef<string | null>(null);

  const [ready, setReady] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [speed, setSpeed] = useState<number>(1);
  const [skipIdle, setSkipIdle] = useState(true);

  const disposePlayer = useCallback(() => {
    playerRef.current?.dispose();
    playerRef.current = null;
    playingRef.current = false;
    if (containerRef.current) containerRef.current.innerHTML = '';
  }, []);

  // (Re)create the player. Speed and idle limit are creation-time options in
  // asciinema-player, so changing them rebuilds it at the current position.
  const mount = useCallback(
    async (opts: { speed: number; skipIdle: boolean; startAt?: number; autoPlay: boolean }) => {
      const el = containerRef.current;
      const cast = castRef.current;
      if (!el || cast == null) return;
      const mod = await loadPlayer();
      disposePlayer();
      const player = mod.create({ data: cast }, el, {
        autoPlay: opts.autoPlay,
        startAt: opts.startAt,
        speed: opts.speed,
        idleTimeLimit: opts.skipIdle ? IDLE_LIMIT_SECONDS : undefined,
        fit: 'both',
        controls: true,
        terminalFontFamily: '"Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace',
      });
      player.addEventListener('playing', () => { playingRef.current = true; });
      player.addEventListener('play', () => { playingRef.current = true; });
      player.addEventListener('pause', () => { playingRef.current = false; });
      player.addEventListener('ended', () => { playingRef.current = false; });
      playerRef.current = player;
    },
    [disposePlayer],
  );

  // Load the cast + player module whenever a new recording is opened.
  useEffect(() => {
    if (!recording) {
      disposePlayer();
      castRef.current = null;
      setReady(false);
      return;
    }
    let cancelled = false;
    setReady(false);
    setError(null);
    setLoading(true);
    setSpeed(1);
    Promise.all([getRecordingCast(recording.id), loadPlayer()])
      .then(([cast]) => {
        if (cancelled) return;
        castRef.current = cast;
        setReady(true);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [recording, disposePlayer]);

  // First mount once data is in and the modal body is painted.
  useEffect(() => {
    if (!ready) return;
    const raf = requestAnimationFrame(() => {
      mount({ speed: 1, skipIdle, autoPlay: true }).catch((err) =>
        setError(err instanceof Error ? err.message : String(err)),
      );
    });
    return () => cancelAnimationFrame(raf);
    // skipIdle intentionally read once here; later changes go through rebuild()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, mount]);

  useEffect(() => disposePlayer, [disposePlayer]);

  const rebuild = (next: { speed?: number; skipIdle?: boolean }) => {
    const player = playerRef.current;
    const nextSpeed = next.speed ?? speed;
    const nextSkip = next.skipIdle ?? skipIdle;
    // Positions are on the idle-compressed timeline, so toggling idle
    // compression restarts from the beginning instead of jumping somewhere odd.
    const startAt = next.skipIdle === undefined ? player?.getCurrentTime() ?? 0 : 0;
    setSpeed(nextSpeed);
    setSkipIdle(nextSkip);
    mount({ speed: nextSpeed, skipIdle: nextSkip, startAt, autoPlay: playingRef.current }).catch((err) =>
      setError(err instanceof Error ? err.message : String(err)),
    );
  };

  const handleDownload = async () => {
    if (!recording) return;
    try {
      await downloadRecordingWithWarning(recording, t);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const title = recording
    ? t('recordings.playerTitle', { target: `${recording.namespace}/${recording.pod}` })
    : '';

  return (
    <Modal open={recording !== null} onClose={onClose} title={title} size="full">
      {recording && (
        <div className="flex h-full flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-300">
              <span className="font-mono font-medium text-slate-900 dark:text-slate-100">{recording.user}</span>
              {recording.cluster && <Badge variant="default">{recording.cluster}</Badge>}
              {recording.container && (
                <span className="font-mono text-slate-500 dark:text-slate-400">{recording.container}</span>
              )}
              <span>{new Date(recording.startedAt).toLocaleString()}</span>
              <span>· {formatDuration(recording.durationMs)}</span>
              <span>· {formatBytes(recording.sizeBytes)}</span>
              {recording.truncated && <Badge variant="warning">{t('recordings.truncated')}</Badge>}
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Toggle
                checked={skipIdle}
                onChange={(v) => rebuild({ skipIdle: v })}
                label={t('recordings.skipIdle')}
              />
              <div
                className="inline-flex overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700"
                role="group"
                aria-label={t('recordings.speed')}
              >
                {SPEEDS.map((s) => (
                  <button
                    key={s}
                    type="button"
                    disabled={!ready}
                    onClick={() => rebuild({ speed: s })}
                    className={`px-2.5 py-1 text-xs font-medium transition-colors ${
                      speed === s
                        ? 'bg-brand-600 text-white'
                        : 'bg-white text-slate-600 hover:bg-slate-100 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800'
                    }`}
                  >
                    {s}x
                  </button>
                ))}
              </div>
              <Button variant="outline" size="sm" onClick={handleDownload}>
                <Download size={13} />
                {t('recordings.download')}
              </Button>
            </div>
          </div>

          {error && (
            <Alert severity="error">
              <AlertTriangle size={14} className="mr-1 inline" />
              {error}
            </Alert>
          )}

          <div className="relative min-h-0 flex-1 overflow-hidden rounded-xl bg-slate-950">
            {loading && (
              <div className="absolute inset-0 flex items-center justify-center">
                <Spinner />
              </div>
            )}
            <div ref={containerRef} className="h-full w-full" />
          </div>
        </div>
      )}
    </Modal>
  );
};

export default CastPlayerModal;
