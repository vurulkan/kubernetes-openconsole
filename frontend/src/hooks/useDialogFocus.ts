import { useEffect, type RefObject } from 'react';

// Focus management of a modal dialog (WAI-ARIA APG "Dialog (Modal)"):
// on open, focus moves into the dialog; Tab and Shift+Tab stay inside it; on
// close, focus returns to the element that opened it. Only the topmost open
// dialog keeps focus (a confirm over a drawer, a shell over a pod drawer).

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), ' +
  'textarea:not([disabled]), [tabindex]:not([tabindex="-1"]), [contenteditable="true"]';

export const focusableIn = (root: HTMLElement): HTMLElement[] =>
  Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => !el.closest('[inert]') && !el.closest('[aria-hidden="true"]'),
  );

// Where focus lands when the dialog opens: the first form field, else the
// first control other than the header's close button (a confirm's Cancel),
// else that button, else the dialog itself.
const initialFocus = (root: HTMLElement): HTMLElement => {
  const all = focusableIn(root);
  return (
    all.find((el) => el.matches('input, select, textarea')) ??
    all.find((el) => el.matches('a[href], button') && !el.hasAttribute('data-dialog-close')) ??
    all.find((el) => el.hasAttribute('data-dialog-close')) ??
    root
  );
};

const stack: HTMLElement[] = [];

export const useDialogFocus = (ref: RefObject<HTMLElement | null>, open: boolean) => {
  useEffect(() => {
    const root = ref.current;
    if (!open || !root) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    stack.push(root);
    if (!root.contains(document.activeElement)) initialFocus(root).focus();

    const onKeyDown = (e: KeyboardEvent) => {
      // A control inside that uses Tab itself (the terminal) has handled it.
      if (e.key !== 'Tab' || e.defaultPrevented || stack[stack.length - 1] !== root) return;
      const items = focusableIn(root);
      const active = document.activeElement;
      if (items.length === 0) {
        e.preventDefault();
        root.focus();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && (active === first || !root.contains(active))) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (active === last || !root.contains(active))) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      stack.splice(stack.indexOf(root), 1);
      // Back to the opener if it's still on the page (a row action button may
      // have been re-rendered away: then the browser's default applies).
      if (opener?.isConnected) opener.focus();
    };
  }, [open, ref]);
};
