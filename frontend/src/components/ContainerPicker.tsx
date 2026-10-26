import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { mainContainer } from '../utils/podStatus';

type PodLike = Parameters<typeof mainContainer>[0] & {
  status?: { containerStatuses?: Array<{ name: string; state?: { running?: unknown } }> };
};

/**
 * Which container a shell opens in, for a pod with sidecars: a small menu under the Shell
 * button, the main container first and focused (Enter opens it). A container that isn't
 * running can't take a shell, so it's shown but disabled. Like the "New user" menu, it is
 * portalled with fixed positioning so a table or card can't clip it.
 */
export const ContainerPicker: React.FC<{
  pod: PodLike;
  anchor: HTMLElement;
  onPick: (container: string) => void;
  onClose: () => void;
}> = ({ pod, anchor, onPick, onClose }) => {
  const { t } = useTranslation();
  const menuRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; right: number } | null>(null);
  const main = mainContainer(pod);
  const names = (pod.spec?.containers ?? []).map((c) => c.name);
  const ordered = [main, ...names.filter((n) => n !== main)];
  const running = (n: string) => !!pod.status?.containerStatuses?.find((c) => c.name === n)?.state?.running;

  // Under the button, right edges aligned; above it when there is no room below.
  useLayoutEffect(() => {
    const place = () => {
      const r = anchor.getBoundingClientRect();
      const h = menuRef.current?.offsetHeight ?? 0;
      const below = r.bottom + 4 + h <= window.innerHeight;
      setPos({ top: below ? r.bottom + 4 : Math.max(4, r.top - 4 - h), right: window.innerWidth - r.right });
    };
    place();
    window.addEventListener('resize', place);
    window.addEventListener('scroll', place, true);
    return () => {
      window.removeEventListener('resize', place);
      window.removeEventListener('scroll', place, true);
    };
  }, [anchor]);

  useEffect(() => {
    menuRef.current?.querySelector<HTMLButtonElement>('[role="menuitem"]:not([disabled])')?.focus();
  }, []);

  const close = () => {
    onClose();
    anchor.focus();
  };

  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (!menuRef.current?.contains(e.target as Node) && !anchor.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.stopPropagation();
      close();
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey, true);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey, true);
    };
    // close / onClose are stable for the menu's short life
  }, [anchor]);

  return createPortal(
    <div
      ref={menuRef}
      role="menu"
      aria-label={t('shellPicker.label')}
      style={{ position: 'fixed', top: pos?.top ?? -9999, right: pos?.right ?? 0 }}
      className="z-[70] w-56 overflow-hidden rounded-xl border border-slate-200 bg-white py-1 shadow-elevated dark:border-slate-800 dark:bg-slate-900"
      onKeyDown={(e) => {
        if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
        e.preventDefault();
        const items = Array.from(e.currentTarget.querySelectorAll<HTMLButtonElement>('[role="menuitem"]:not([disabled])'));
        const i = items.indexOf(document.activeElement as HTMLButtonElement);
        items[e.key === 'ArrowDown' ? (i + 1) % items.length : (i - 1 + items.length) % items.length]?.focus();
      }}
    >
      {ordered.map((n) => {
        const up = running(n);
        return (
          <button
            key={n}
            type="button"
            role="menuitem"
            disabled={!up}
            onClick={() => onPick(n)}
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-slate-50 focus:bg-slate-100 focus:outline-none disabled:cursor-not-allowed disabled:opacity-60 dark:hover:bg-slate-800 dark:focus:bg-slate-800"
          >
            <span className="min-w-0 flex-1 truncate font-mono text-slate-800 dark:text-slate-100">{n}</span>
            {n === main && (
              <span className="shrink-0 rounded bg-brand-50 px-1.5 py-0.5 text-[10px] font-medium text-brand-700 dark:bg-brand-500/15 dark:text-brand-200">
                {t('shellPicker.main')}
              </span>
            )}
            {!up && <span className="shrink-0 text-[10px] text-slate-500 dark:text-slate-400">{t('shellPicker.notRunning')}</span>}
          </button>
        );
      })}
    </div>,
    document.body,
  );
};
