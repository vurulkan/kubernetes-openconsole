import React, { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';
import { modalScopeDepth, popModalScope, pushModalScope } from '../hooks/useScopedShortcuts';

type DrawerProps = {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  /** Width hint; drawers always clamp to 100vw on small screens. */
  width?: 'sm' | 'md' | 'lg';
};

const widthClass = (w: DrawerProps['width']) => {
  switch (w) {
    case 'sm':
      return 'sm:w-[380px]';
    case 'lg':
      return 'sm:w-[640px]';
    default:
      return 'sm:w-[480px]';
  }
};

/**
 * Right-side slide-in panel. Portaled to document.body so it is immune to
 * overflow:hidden ancestors (table rows, cards, etc.) that routinely trap
 * absolute-positioned descendants. Esc closes. Click outside the panel
 * closes. Header + footer stay fixed while the body scrolls.
 */
export const Drawer: React.FC<DrawerProps> = ({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  width = 'md',
}) => {
  // Kept in a ref so a new onClose identity doesn't re-register the scope (and its depth) on every render.
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  useEffect(() => {
    if (!open) return;
    // A drawer is a modal scope too: page shortcuts (table j / k, …) pause.
    pushModalScope();
    const depth = modalScopeDepth();
    const handler = (e: KeyboardEvent) => {
      // A modal opened from the drawer (logs, shell) closes first.
      if (e.key === 'Escape' && modalScopeDepth() === depth) {
        e.preventDefault();
        onCloseRef.current();
      }
    };
    document.addEventListener('keydown', handler);
    return () => {
      document.removeEventListener('keydown', handler);
      popModalScope();
    };
  }, [open]);

  if (!open) return null;

  return createPortal(
    <div className="fixed inset-0 z-[70]" role="dialog" aria-modal="true" aria-label={title}>
      <div
        className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm animate-fade-in"
        onClick={onClose}
      />
      <aside
        className={`absolute right-0 top-0 flex h-full w-full ${widthClass(width)} flex-col bg-white shadow-elevated animate-slide-up dark:bg-slate-900`}
      >
        <header className="flex items-start justify-between gap-3 border-b border-slate-200 bg-slate-50/60 px-5 py-3 dark:border-slate-800 dark:bg-slate-800/40">
          <div>
            <h2 className="text-sm font-semibold tracking-tight text-slate-900 dark:text-slate-100">
              {title}
            </h2>
            {description && (
              <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                {description}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 dark:hover:bg-slate-800 dark:hover:text-slate-100"
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </header>
        <div className="flex-1 overflow-auto p-5">{children}</div>
        {footer && (
          <footer className="flex justify-end gap-2 border-t border-slate-200 bg-slate-50/60 px-5 py-3 dark:border-slate-800 dark:bg-slate-800/40">
            {footer}
          </footer>
        )}
      </aside>
    </div>,
    document.body
  );
};

export default Drawer;
