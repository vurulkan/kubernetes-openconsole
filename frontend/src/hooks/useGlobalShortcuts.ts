import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

type Options = {
  isAdmin: boolean;
  setTheme: (mode: 'light' | 'dark' | 'system') => void;
};

const SHORTCUTS_EVENT = 'openconsole:open-shortcuts';
const PALETTE_EVENT = 'openconsole:open-palette';
const EVENTS_PANEL_EVENT = 'openconsole:toggle-events';
const CLUSTER_SWITCHER_EVENT = 'openconsole:open-cluster-switcher';

export const dispatchOpenShortcuts = () => {
  window.dispatchEvent(new CustomEvent(SHORTCUTS_EVENT));
};
export const dispatchOpenPalette = () => {
  window.dispatchEvent(new CustomEvent(PALETTE_EVENT));
};
export const dispatchToggleEvents = () => {
  window.dispatchEvent(new CustomEvent(EVENTS_PANEL_EVENT));
};
export const dispatchOpenClusterSwitcher = () => {
  window.dispatchEvent(new CustomEvent(CLUSTER_SWITCHER_EVENT));
};
export const SHORTCUTS_EVENT_NAME = SHORTCUTS_EVENT;
export const PALETTE_EVENT_NAME = PALETTE_EVENT;
export const EVENTS_PANEL_EVENT_NAME = EVENTS_PANEL_EVENT;
export const CLUSTER_SWITCHER_EVENT_NAME = CLUSTER_SWITCHER_EVENT;

const isTypingTarget = (el: EventTarget | null): boolean => {
  if (!el || !(el instanceof HTMLElement)) return false;
  const tag = el.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
  if (el.isContentEditable) return true;
  return false;
};

const CHORD_TIMEOUT_MS = 900;

/**
 * useGlobalShortcuts wires document-level keyboard shortcuts that do NOT
 * require focus on a specific element. All handlers skip when the user is
 * typing into an input/textarea/select/contenteditable so they can never
 * eat form input. Chord sequences are supported (e.g. `g d`) with a short
 * timeout between presses — any non-letter key resets the pending prefix.
 */
export const useGlobalShortcuts = ({ isAdmin, setTheme }: Options) => {
  const navigate = useNavigate();

  useEffect(() => {
    let pending: 'g' | 't' | null = null;
    let pendingTimer: number | null = null;

    const resetPending = () => {
      pending = null;
      if (pendingTimer !== null) {
        window.clearTimeout(pendingTimer);
        pendingTimer = null;
      }
    };

    const armPending = (p: 'g' | 't') => {
      pending = p;
      if (pendingTimer !== null) window.clearTimeout(pendingTimer);
      pendingTimer = window.setTimeout(() => {
        pending = null;
        pendingTimer = null;
      }, CHORD_TIMEOUT_MS);
    };

    const handler = (e: KeyboardEvent) => {
      // Never interfere with modifier combos — browser & CommandPalette own those.
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      // Typing in a form should always win. Esc is handled by individual
      // modals; we only care about printable keys here.
      if (isTypingTarget(e.target)) return;

      const key = e.key;

      // ? → open shortcuts help. Browsers deliver '?' as Shift+/, with .key = '?'.
      if (key === '?' && !pending) {
        e.preventDefault();
        dispatchOpenShortcuts();
        return;
      }

      // Chord second step
      if (pending === 'g') {
        if (key === 'd') {
          e.preventDefault();
          navigate('/');
          resetPending();
          return;
        }
        if (key === 'a' && isAdmin) {
          e.preventDefault();
          navigate('/admin');
          resetPending();
          return;
        }
        resetPending();
        return;
      }
      if (pending === 't') {
        if (key === 'l') {
          e.preventDefault();
          setTheme('light');
          resetPending();
          return;
        }
        if (key === 'd') {
          e.preventDefault();
          setTheme('dark');
          resetPending();
          return;
        }
        if (key === 's') {
          e.preventDefault();
          setTheme('system');
          resetPending();
          return;
        }
        resetPending();
        return;
      }

      // Chord first step
      if (key === 'g') {
        armPending('g');
        return;
      }
      if (key === 't') {
        armPending('t');
        return;
      }

      // Single-key: toggle the Live Events panel.
      if (key === 'e') {
        e.preventDefault();
        dispatchToggleEvents();
        return;
      }
      // Single-key: open the cluster switcher dropdown. Inside the menu
      // 1..9 pick a cluster by index, arrows navigate, Enter commits, Esc
      // closes — all handled by ClusterSwitcher itself.
      if (key === 'c') {
        e.preventDefault();
        dispatchOpenClusterSwitcher();
        return;
      }
    };

    document.addEventListener('keydown', handler);
    return () => {
      document.removeEventListener('keydown', handler);
      resetPending();
    };
  }, [isAdmin, navigate, setTheme]);
};
