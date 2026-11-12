import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { popModalScope, pushModalScope } from '../hooks/useScopedShortcuts';

export const menuItemClass =
  'flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-slate-800 hover:bg-slate-50 focus:bg-slate-100 focus:outline-none disabled:cursor-not-allowed disabled:opacity-60 dark:text-slate-100 dark:hover:bg-slate-800 dark:focus:bg-slate-800';

/**
 * A menu under its anchor button (above when there is no room), portalled with fixed positioning so
 * a table or card can't clip it. The first item gets focus, arrow keys move, Esc / Tab / a click
 * outside close it and focus returns to the anchor; page shortcuts are off while it's open (modal scope).
 */
export const MenuPopover: React.FC<{
  anchor: HTMLElement;
  label: string;
  onClose: () => void;
  className?: string;
  children: React.ReactNode;
}> = ({ anchor, label, onClose, className = 'w-52', children }) => {
  const menuRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; right: number } | null>(null);

  useLayoutEffect(() => {
    const place = () => {
      const r = anchor.getBoundingClientRect();
      const h = menuRef.current?.offsetHeight ?? 0;
      const below = r.bottom + 4 + h <= window.innerHeight;
      setPos({ top: below ? r.bottom + 4 : Math.max(4, r.top - 4 - h), right: Math.max(4, window.innerWidth - r.right) });
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
    pushModalScope();
    menuRef.current?.querySelector<HTMLButtonElement>('button:not([disabled])')?.focus();
    const close = () => {
      onClose();
      anchor.focus();
    };
    const onDown = (e: MouseEvent) => {
      if (!menuRef.current?.contains(e.target as Node) && !anchor.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' && e.key !== 'Tab') return;
      e.preventDefault();
      e.stopPropagation();
      close();
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey, true);
    return () => {
      popModalScope();
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey, true);
    };
    // onClose is stable for the menu's short life
  }, [anchor]);

  return createPortal(
    <div
      ref={menuRef}
      role="menu"
      aria-label={label}
      style={{ position: 'fixed', top: pos?.top ?? -9999, right: pos?.right ?? 0 }}
      className={`z-[70] overflow-hidden rounded-xl border border-slate-200 bg-white py-1 shadow-elevated dark:border-slate-800 dark:bg-slate-900 ${className}`}
      onKeyDown={(e) => {
        if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
        e.preventDefault();
        const items = Array.from(e.currentTarget.querySelectorAll<HTMLButtonElement>('button:not([disabled])'));
        const i = items.indexOf(document.activeElement as HTMLButtonElement);
        items[e.key === 'ArrowDown' ? (i + 1) % items.length : (i - 1 + items.length) % items.length]?.focus();
      }}
    >
      {children}
    </div>,
    // Inside <main> so the menu stays in a landmark (axe "region"); main has no transform, so fixed still works.
    document.querySelector('main') ?? document.body,
  );
};
