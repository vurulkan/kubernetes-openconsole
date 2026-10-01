import { useEffect } from 'react';

type Binding = {
  /**
   * The event.key value to match (case-insensitive). Examples: `[`, `]`, `/`,
   * `r`, `p`, `w`. Modifiers (ctrl/cmd/alt/shift) are matched exactly: by
   * default a binding fires only when NO modifier is held.
   */
  key: string;
  handler: (event: KeyboardEvent) => void;
  /** When true, allow the binding to fire even if an input is focused. */
  allowInInput?: boolean;
  /** Require Cmd/Ctrl (⌘/Ctrl) to be held. */
  meta?: boolean;
  /** Require Shift to be held. */
  shift?: boolean;
};

const isTypingTarget = (el: EventTarget | null): boolean => {
  if (!el || !(el instanceof HTMLElement)) return false;
  const tag = el.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
  if (el.isContentEditable) return true;
  return false;
};

// Global counter tracked by Modal so scoped page shortcuts stop firing while
// any modal is open. Modal(s) register their own shortcuts separately.
let modalDepth = 0;
export const pushModalScope = () => {
  modalDepth += 1;
};
export const popModalScope = () => {
  modalDepth = Math.max(0, modalDepth - 1);
};
export const isModalScopeActive = () => modalDepth > 0;

/**
 * Register page-scoped shortcuts. They stop firing while a Modal is open or
 * while the user is typing (unless the binding opts in with allowInInput).
 *
 * Pass stable handlers (useCallback / inline is fine as long as the deps
 * array below matches). The second argument reinstalls the listener when
 * the bindings' identity changes.
 */
export const useScopedShortcuts = (bindings: Binding[], enabled = true) => {
  useEffect(() => {
    if (!enabled) return;
    const handler = (e: KeyboardEvent) => {
      if (isModalScopeActive()) return;
      for (const b of bindings) {
        if (b.key.toLowerCase() !== e.key.toLowerCase()) continue;
        if (!b.allowInInput && isTypingTarget(e.target)) continue;
        const metaHeld = e.metaKey || e.ctrlKey;
        if (Boolean(b.meta) !== metaHeld) continue;
        if (Boolean(b.shift) !== e.shiftKey) continue;
        if (!b.meta && (e.altKey)) continue;
        e.preventDefault();
        b.handler(e);
        return;
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [bindings, enabled]);
};
